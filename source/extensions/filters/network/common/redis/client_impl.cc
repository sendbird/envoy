#include "source/extensions/filters/network/common/redis/client_impl.h"

#include "envoy/extensions/filters/network/redis_proxy/v3/redis_proxy.pb.h"

#include "source/common/common/macros.h"
#include "source/common/runtime/runtime_features.h"
#include "source/extensions/filters/network/common/redis/aws_iam_authenticator_impl.h"

#include "absl/strings/ascii.h"
#include "client.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace Common {
namespace Redis {
namespace Client {
namespace {
// null_pool_callbacks is used for requests that must be filtered and not redirected such as
// "asking".
Common::Redis::Client::DoNothingPoolCallbacks null_pool_callbacks;

// Custom authentication callback handler for AWS IAM authentication
class AuthCallbackHandler : public DoNothingPoolCallbacks {
  void onResponse(Common::Redis::RespValuePtr&& resp) override {
    ENVOY_LOG_MISC(debug, "AWS IAM Authentication Response: {}", resp->toString());
  }
};

AuthCallbackHandler auth_callbacks;
} // namespace

ConfigImpl::ConfigImpl(
    const envoy::extensions::filters::network::redis_proxy::v3::RedisProxy::ConnPoolSettings&
        config)
    : op_timeout_(PROTOBUF_GET_MS_REQUIRED(config, op_timeout)),
      enable_hashtagging_(config.enable_hashtagging()),
      enable_redirection_(config.enable_redirection()),
      max_buffer_size_before_flush_(
          config.max_buffer_size_before_flush()), // This is a scalar, so default is zero.
      buffer_flush_timeout_(PROTOBUF_GET_MS_OR_DEFAULT(
          config, buffer_flush_timeout,
          3)), // Default timeout is 3ms. If max_buffer_size_before_flush is zero, this is not used
               // as the buffer is flushed on each request immediately.
      max_upstream_unknown_connections_(
          PROTOBUF_GET_WRAPPED_OR_DEFAULT(config, max_upstream_unknown_connections, 100)),
      enable_command_stats_(config.enable_command_stats()),
      enable_per_shard_stats_(config.enable_per_shard_stats()),
      enable_per_shard_latency_stats_(config.enable_per_shard_latency_stats()) {
  switch (config.read_policy()) {
    PANIC_ON_PROTO_ENUM_SENTINEL_VALUES;
  case envoy::extensions::filters::network::redis_proxy::v3::RedisProxy::ConnPoolSettings::MASTER:
    read_policy_ = ReadPolicy::Primary;
    break;
  case envoy::extensions::filters::network::redis_proxy::v3::RedisProxy::ConnPoolSettings::
      PREFER_MASTER:
    read_policy_ = ReadPolicy::PreferPrimary;
    break;
  case envoy::extensions::filters::network::redis_proxy::v3::RedisProxy::ConnPoolSettings::REPLICA:
    read_policy_ = ReadPolicy::Replica;
    break;
  case envoy::extensions::filters::network::redis_proxy::v3::RedisProxy::ConnPoolSettings::
      PREFER_REPLICA:
    read_policy_ = ReadPolicy::PreferReplica;
    break;
  case envoy::extensions::filters::network::redis_proxy::v3::RedisProxy::ConnPoolSettings::ANY:
    read_policy_ = ReadPolicy::Any;
    break;
  case envoy::extensions::filters::network::redis_proxy::v3::RedisProxy::ConnPoolSettings::
      LOCAL_ZONE_AFFINITY:
    read_policy_ = ReadPolicy::LocalZoneAffinity;
    break;
  case envoy::extensions::filters::network::redis_proxy::v3::RedisProxy::ConnPoolSettings::
      LOCAL_ZONE_AFFINITY_REPLICAS_AND_PRIMARY:
    read_policy_ = ReadPolicy::LocalZoneAffinityReplicasAndPrimary;
    break;
  }

  if (config.has_connection_rate_limit()) {
    connection_rate_limit_enabled_ = true;
    connection_rate_limit_per_sec_ = config.connection_rate_limit().connection_rate_limit_per_sec();
  } else {
    connection_rate_limit_enabled_ = false;
    connection_rate_limit_per_sec_ = 100;
  }
}

ClientPtr ClientImpl::create(
    Upstream::HostConstSharedPtr host, Event::Dispatcher& dispatcher, EncoderPtr&& encoder,
    DecoderFactory& decoder_factory, const ConfigSharedPtr& config,
    const RedisCommandStatsSharedPtr& redis_command_stats, Stats::Scope& scope,
    bool is_transaction_client, const std::string& auth_username,
    std::optional<envoy::extensions::filters::network::redis_proxy::v3::AwsIam> aws_iam_config,
    std::optional<Common::Redis::AwsIamAuthenticator::AwsIamAuthenticatorSharedPtr>
        aws_iam_authenticator) {

  auto client = std::make_unique<ClientImpl>(
      host, dispatcher, std::move(encoder), decoder_factory, config, redis_command_stats, scope,
      is_transaction_client, aws_iam_config, aws_iam_authenticator);
  client->connection_ = host->createConnection(dispatcher, nullptr, nullptr).connection_;
  client->connection_->addConnectionCallbacks(*client);
  client->connection_->addReadFilter(Network::ReadFilterSharedPtr{new UpstreamReadFilter(*client)});
  client->connection_->connect();
  client->connection_->noDelay(true);

  // The presence of a valid auth_username is checked during filter initialization
  if (aws_iam_authenticator.has_value() && aws_iam_config.has_value()) {
    client->sendAwsIamAuth(auth_username, aws_iam_config.value());
  }

  return client;
}

void ClientImpl::sendAwsIamAuth(
    const std::string& auth_username,
    const envoy::extensions::filters::network::redis_proxy::v3::AwsIam& aws_iam_config) {
  queueRequests(true);
  auto add_auth = [this, auth_username, &aws_iam_config]() {
    const auto auth_password =
        aws_iam_authenticator_.value()->getAuthToken(auth_username, aws_iam_config);
    Envoy::Extensions::NetworkFilters::Common::Redis::Utility::AuthRequest auth_request(
        auth_username, auth_password);
    makeRequestImmediate(auth_request, auth_callbacks);
    queueRequests(false);
  };

  if (aws_iam_authenticator_.value()->addCallbackIfCredentialsPending(
          [add_auth]() { add_auth(); }) == false) {
    add_auth();
  }
}

ClientImpl::ClientImpl(
    Upstream::HostConstSharedPtr host, Event::Dispatcher& dispatcher, EncoderPtr&& encoder,
    DecoderFactory& decoder_factory, const ConfigSharedPtr& config,
    const RedisCommandStatsSharedPtr& redis_command_stats, Stats::Scope& scope,
    bool is_transaction_client,
    std::optional<envoy::extensions::filters::network::redis_proxy::v3::AwsIam> aws_iam_config,
    std::optional<Common::Redis::AwsIamAuthenticator::AwsIamAuthenticatorSharedPtr>
        aws_iam_authenticator)
    : host_(host), encoder_(std::move(encoder)), decoder_(decoder_factory.create(*this)),
      config_(config),
      connect_or_op_timer_(dispatcher.createTimer([this]() { onConnectOrOpTimeout(); })),
      flush_timer_(dispatcher.createTimer([this]() { flushBufferAndResetTimer(); })),
      time_source_(dispatcher.timeSource()), redis_command_stats_(redis_command_stats),
      scope_(scope), is_transaction_client_(is_transaction_client), aws_iam_config_(aws_iam_config),
      aws_iam_authenticator_(aws_iam_authenticator) {

  Upstream::ClusterTrafficStats& traffic_stats = *host->cluster().trafficStats();
  traffic_stats.upstream_cx_total_.inc();
  host->stats().cx_total_.inc();
  traffic_stats.upstream_cx_active_.inc();
  host->stats().cx_active_.inc();
  connect_or_op_timer_->enableTimer(host->cluster().connectTimeout());
}

ClientImpl::~ClientImpl() {
  ASSERT(pending_requests_.empty());
  ASSERT(connection_->state() == Network::Connection::State::Closed);
  host_->cluster().trafficStats()->upstream_cx_active_.dec();
  host_->stats().cx_active_.dec();
}

void ClientImpl::close() { connection_->close(Network::ConnectionCloseType::NoFlush); }

void ClientImpl::flushBufferAndResetTimer() {
  if (flush_timer_->enabled()) {
    flush_timer_->disableTimer();
  }
  connection_->write(encoder_buffer_, false);
}

PoolRequest* ClientImpl::makeRequest(const RespValue& request, ClientCallbacks& callbacks) {
  ASSERT(connection_->state() == Network::Connection::State::Open);

  const bool empty_buffer = encoder_buffer_.length() == 0;

  Stats::StatName command;
  if (config_->enableCommandStats()) {
    // Only lowercase command and get StatName if we enable command stats
    command = redis_command_stats_->getCommandFromRequest(request);
    redis_command_stats_->updateStatsTotal(scope_, command);
  } else {
    // If disabled, we use a placeholder stat name "unused" that is not used
    command = redis_command_stats_->getUnusedStatName();
  }

  pending_requests_.emplace_back(*this, callbacks, command, replyCheckFor(request));
  encoder_->encode(request, encoder_buffer_);

  // If we have enabled queuing (to pause AUTH while credentials are being used), don't flush our
  // buffers
  if (!queue_enabled_) {
    // If buffer is full, flush. If the buffer was empty before the request, start the timer.
    if (encoder_buffer_.length() >= config_->maxBufferSizeBeforeFlush()) {
      flushBufferAndResetTimer();
    } else if (empty_buffer) {
      flush_timer_->enableTimer(std::chrono::milliseconds(config_->bufferFlushTimeoutInMs()));
    }
  }

  // Only boost the op timeout if:
  // - We are not already connected. Otherwise, we are governed by the connect timeout and the timer
  //   will be reset when/if connection occurs. This allows a relatively long connection spin up
  //   time for example if TLS is being used.
  // - This is the first request on the pipeline. Otherwise the timeout would effectively start on
  //   the last operation.
  if (connected_ && pending_requests_.size() == 1) {
    connect_or_op_timer_->enableTimer(config_->opTimeout());
  }

  return &pending_requests_.back();
}

PoolRequest* ClientImpl::makeRequestImmediate(const RespValue& request,
                                              ClientCallbacks& callbacks) {
  ASSERT(connection_->state() == Network::Connection::State::Open);

  Stats::StatName command;
  if (config_->enableCommandStats()) {
    // Only lowercase command and get StatName if we enable command stats
    command = redis_command_stats_->getCommandFromRequest(request);
    redis_command_stats_->updateStatsTotal(scope_, command);
  } else {
    // If disabled, we use a placeholder stat name "unused" that is not used
    command = redis_command_stats_->getUnusedStatName();
  }
  Buffer::OwnedImpl immediate_buffer;
  pending_requests_.emplace_back(*this, callbacks, command, replyCheckFor(request));
  encoder_->encode(request, immediate_buffer);
  connection_->write(immediate_buffer, false);
  // Flush buffer if we've queued up any requests while waiting for authentication credentials
  if (encoder_buffer_.length()) {
    flushBufferAndResetTimer();
  }
  return &pending_requests_.back();
}

void ClientImpl::onConnectOrOpTimeout() {
  putOutlierEvent(Upstream::Outlier::Result::LocalOriginTimeout);
  if (connected_) {
    host_->cluster().trafficStats()->upstream_rq_timeout_.inc();
    host_->stats().rq_timeout_.inc();
  } else {
    host_->cluster().trafficStats()->upstream_cx_connect_timeout_.inc();
    host_->stats().cx_connect_fail_.inc();
  }

  connection_->close(Network::ConnectionCloseType::NoFlush);
}

// Only commands whose RESP2 reply type never varies with arguments or server state belong here.
// Revisit when this pin decodes RESP3: HGETALL then replies with a map and SMEMBERS with a set.
const ClientImpl::ExpectedReplyMap& ClientImpl::expectedReplies() {
  CONSTRUCT_ON_FIRST_USE(ExpectedReplyMap, {{"append", ExpectedReply::Integer},
                                            {"decr", ExpectedReply::Integer},
                                            {"decrby", ExpectedReply::Integer},
                                            {"del", ExpectedReply::Integer},
                                            {"exists", ExpectedReply::Integer},
                                            {"expire", ExpectedReply::Integer},
                                            {"expireat", ExpectedReply::Integer},
                                            {"hdel", ExpectedReply::Integer},
                                            {"hexists", ExpectedReply::Integer},
                                            {"hincrby", ExpectedReply::Integer},
                                            {"hlen", ExpectedReply::Integer},
                                            {"hset", ExpectedReply::Integer},
                                            {"hsetnx", ExpectedReply::Integer},
                                            {"incr", ExpectedReply::Integer},
                                            {"incrby", ExpectedReply::Integer},
                                            {"llen", ExpectedReply::Integer},
                                            {"lpush", ExpectedReply::Integer},
                                            {"persist", ExpectedReply::Integer},
                                            {"pexpire", ExpectedReply::Integer},
                                            {"pexpireat", ExpectedReply::Integer},
                                            {"pttl", ExpectedReply::Integer},
                                            {"publish", ExpectedReply::Integer},
                                            {"rpush", ExpectedReply::Integer},
                                            {"sadd", ExpectedReply::Integer},
                                            {"scard", ExpectedReply::Integer},
                                            {"setnx", ExpectedReply::Integer},
                                            {"sismember", ExpectedReply::Integer},
                                            {"spublish", ExpectedReply::Integer},
                                            {"srem", ExpectedReply::Integer},
                                            {"strlen", ExpectedReply::Integer},
                                            {"touch", ExpectedReply::Integer},
                                            {"ttl", ExpectedReply::Integer},
                                            {"unlink", ExpectedReply::Integer},
                                            {"zcard", ExpectedReply::Integer},
                                            {"get", ExpectedReply::BulkStringOrNull},
                                            {"getdel", ExpectedReply::BulkStringOrNull},
                                            {"getset", ExpectedReply::BulkStringOrNull},
                                            {"hget", ExpectedReply::BulkStringOrNull},
                                            {"lindex", ExpectedReply::BulkStringOrNull},
                                            {"hgetall", ExpectedReply::Array},
                                            {"hkeys", ExpectedReply::Array},
                                            {"hmget", ExpectedReply::Array},
                                            {"hvals", ExpectedReply::Array},
                                            {"lrange", ExpectedReply::Array},
                                            {"mget", ExpectedReply::Array},
                                            {"smembers", ExpectedReply::Array}});
}

ClientImpl::ReplyCheck ClientImpl::replyCheckFor(const RespValue& request) const {
  // Inside MULTI the server answers every command with +QUEUED.
  if (is_transaction_client_) {
    return {};
  }
  const RespValue* command = nullptr;
  if (request.type() == RespType::Array && !request.asArray().empty()) {
    command = &request.asArray().front();
  } else if (request.type() == RespType::CompositeArray) {
    command = request.asCompositeArray().command();
  }
  if (command == nullptr ||
      (command->type() != RespType::BulkString && command->type() != RespType::SimpleString)) {
    return {};
  }
  const auto it = expectedReplies().find(absl::AsciiStrToLower(command->asString()));
  if (it == expectedReplies().end()) {
    return {};
  }
  return {it->second, it->first};
}

bool ClientImpl::replyMatches(ExpectedReply expected_reply, RespType reply_type) {
  if (reply_type == RespType::Error) {
    return true;
  }
  switch (expected_reply) {
  case ExpectedReply::Unchecked:
    return true;
  case ExpectedReply::Integer:
    return reply_type == RespType::Integer;
  case ExpectedReply::BulkStringOrNull:
    return reply_type == RespType::BulkString || reply_type == RespType::Null;
  case ExpectedReply::Array:
    return reply_type == RespType::Array;
  }
  PANIC_DUE_TO_CORRUPT_ENUM;
}

absl::string_view ClientImpl::expectedReplyName(ExpectedReply expected_reply) {
  switch (expected_reply) {
  case ExpectedReply::Unchecked:
    return "any";
  case ExpectedReply::Integer:
    return "integer";
  case ExpectedReply::BulkStringOrNull:
    return "bulk string or null";
  case ExpectedReply::Array:
    return "array";
  }
  PANIC_DUE_TO_CORRUPT_ENUM;
}

absl::string_view ClientImpl::respTypeName(RespType type) {
  switch (type) {
  case RespType::Null:
    return "null";
  case RespType::SimpleString:
    return "simple string";
  case RespType::BulkString:
    return "bulk string";
  case RespType::Integer:
    return "integer";
  case RespType::Error:
    return "error";
  case RespType::Array:
    return "array";
  case RespType::CompositeArray:
    return "composite array";
  }
  PANIC_DUE_TO_CORRUPT_ENUM;
}

void ClientImpl::onData(Buffer::Instance& data) {
  TRY_NEEDS_AUDIT { decoder_->decode(data); }
  END_TRY catch (ProtocolError&) { onProtocolError(); }
}

void ClientImpl::onProtocolError() {
  // The decoder keeps parsing the buffer after a reply type mismatch closes the connection, so a
  // later decoder error would count the same failure twice.
  if (protocol_error_reported_) {
    return;
  }
  protocol_error_reported_ = true;
  putOutlierEvent(Upstream::Outlier::Result::ExtOriginRequestFailed);
  host_->cluster().trafficStats()->upstream_cx_protocol_error_.inc();
  host_->stats().rq_error_.inc();
  connection_->close(Network::ConnectionCloseType::NoFlush);
}

void ClientImpl::putOutlierEvent(Upstream::Outlier::Result result) {
  if (!config_->disableOutlierEvents()) {
    host_->outlierDetector().putResult(result);
  }
}

void ClientImpl::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::RemoteClose ||
      event == Network::ConnectionEvent::LocalClose) {

    Upstream::reportUpstreamCxDestroy(host_, event);
    if (!pending_requests_.empty()) {
      Upstream::reportUpstreamCxDestroyActiveRequest(host_, event);
      if (event == Network::ConnectionEvent::RemoteClose) {
        putOutlierEvent(Upstream::Outlier::Result::LocalOriginConnectFailed);
      }
    }

    while (!pending_requests_.empty()) {
      PendingRequest& request = pending_requests_.front();
      if (!request.canceled_) {
        request.callbacks_.onFailure();
      } else {
        host_->cluster().trafficStats()->upstream_rq_cancelled_.inc();
      }
      pending_requests_.pop_front();
    }

    connect_or_op_timer_->disableTimer();
  } else if (event == Network::ConnectionEvent::Connected) {
    connected_ = true;
    ASSERT(!pending_requests_.empty());
    connect_or_op_timer_->enableTimer(config_->opTimeout());
  }

  if (event == Network::ConnectionEvent::RemoteClose && !connected_) {
    host_->cluster().trafficStats()->upstream_cx_connect_fail_.inc();
    host_->stats().cx_connect_fail_.inc();
  }
}

void ClientImpl::onRespValue(RespValuePtr&& value) {
  // A frame can reach onRespValue with no outstanding request: the upstream sent a surplus or
  // unsolicited reply, or a callback closed the connection from within this very call while the
  // decoder is still draining the same buffer. Guard against front() on an empty list (undefined
  // behavior in release builds) and drop the frame.
  //
  // Backport of the guard upstream carries on main, added by envoyproxy/envoy#44936 and covered by
  // tests in envoyproxy/envoy#48205. release/v1.36 through release/v1.39 are still affected, and
  // the envoy this fork pins (ae1505b84c, v1.39.2-dev) is in that range -- stock
  // istio/proxyv2:1.31.1 crashes on a fake upstream that answers one command with two replies.
  //
  // Kept textually close to upstream so the next envoy bump absorbs it instead of conflicting.
  // Two forced differences: upstream also drops RESP3 Push frames first, which cannot be ported
  // because this pin's RespType has no Push member; and upstream only logs, so no stat is
  // incremented here either.
  if (pending_requests_.empty()) {
    ENVOY_LOG(debug, "redis: dropping upstream frame with no outstanding request");
    return;
  }
  PendingRequest& request = pending_requests_.front();

  // RESP has no request id, so one lost or surplus reply shifts every later reply onto another.
  // A wrong reply type exposes the shift (envoyproxy/envoy#48205): fail the connection instead.
  if (!replyMatches(request.reply_check_.expected_, value->type()) &&
      Runtime::runtimeFeatureEnabled(
          "envoy.reloadable_features.redis_close_on_reply_type_mismatch")) {
    ENVOY_LOG_PERIODIC(warn, std::chrono::seconds(1),
                       "redis: closing upstream connection to {}: {} expects a {} reply, got {}",
                       host_->observabilityName(), request.reply_check_.command_,
                       expectedReplyName(request.reply_check_.expected_),
                       respTypeName(value->type()));
    onProtocolError();
    return;
  }

  const bool canceled = request.canceled_;

  if (config_->enableCommandStats()) {
    bool success = !canceled && (value->type() != Common::Redis::RespType::Error);
    redis_command_stats_->updateStats(scope_, request.command_, success);
    request.command_request_timer_->complete();
  }
  request.aggregate_request_timer_->complete();

  ClientCallbacks& callbacks = request.callbacks_;

  // We need to ensure the request is popped before calling the callback, since the callback might
  // result in closing the connection.
  pending_requests_.pop_front();
  if (canceled) {
    host_->cluster().trafficStats()->upstream_rq_cancelled_.inc();
  } else if (config_->enableRedirection() && !is_transaction_client_ &&
             (value->type() == Common::Redis::RespType::Error)) {
    std::vector<absl::string_view> err = StringUtil::splitToken(value->asString(), " ", false);
    if (err.size() == 3 &&
        (err[0] == RedirectionResponse::get().MOVED || err[0] == RedirectionResponse::get().ASK)) {
      // MOVED and ASK redirection errors have the following substrings: MOVED or ASK (err[0]), hash
      // key slot (err[1]), and IP address and TCP port separated by a colon (err[2])
      callbacks.onRedirection(std::move(value), std::string(err[2]),
                              err[0] == RedirectionResponse::get().ASK);
    } else {
      if (err[0] == RedirectionResponse::get().CLUSTER_DOWN) {
        callbacks.onFailure();
      } else {
        callbacks.onResponse(std::move(value));
      }
    }
  } else {
    callbacks.onResponse(std::move(value));
  }

  // If there are no remaining ops in the pipeline we need to disable the timer.
  // Otherwise we boost the timer since we are receiving responses and there are more to flush
  // out.
  if (pending_requests_.empty()) {
    connect_or_op_timer_->disableTimer();
  } else {
    connect_or_op_timer_->enableTimer(config_->opTimeout());
  }

  putOutlierEvent(Upstream::Outlier::Result::ExtOriginRequestSuccess);
}

ClientImpl::PendingRequest::PendingRequest(ClientImpl& parent, ClientCallbacks& callbacks,
                                           Stats::StatName command, ReplyCheck reply_check)
    : parent_(parent), callbacks_(callbacks), command_{command}, reply_check_(reply_check),
      aggregate_request_timer_(parent_.redis_command_stats_->createAggregateTimer(
          parent_.scope_, parent_.time_source_)) {
  if (parent_.config_->enableCommandStats()) {
    command_request_timer_ = parent_.redis_command_stats_->createCommandTimer(
        parent_.scope_, command_, parent_.time_source_);
  }
  parent.host_->cluster().trafficStats()->upstream_rq_total_.inc();
  parent.host_->stats().rq_total_.inc();
  parent.host_->cluster().trafficStats()->upstream_rq_active_.inc();
  parent.host_->stats().rq_active_.inc();
}

ClientImpl::PendingRequest::~PendingRequest() {
  parent_.host_->cluster().trafficStats()->upstream_rq_active_.dec();
  parent_.host_->stats().rq_active_.dec();
}

void ClientImpl::PendingRequest::cancel() {
  // If we get a cancellation, we just mark the pending request as cancelled, and then we drop
  // the response as it comes through. There is no reason to blow away the connection when the
  // remote is already responding as fast as possible.
  canceled_ = true;
}

void ClientImpl::initialize(const std::string& auth_username, const std::string& auth_password) {
  if (!auth_username.empty()) {
    // Send an AUTH command to the upstream server with username and password.
    Utility::AuthRequest auth_request(auth_username, auth_password);
    makeRequest(auth_request, null_pool_callbacks);
  } else if (!auth_password.empty()) {
    // Send an AUTH command to the upstream server.
    Utility::AuthRequest auth_request(auth_password);
    makeRequest(auth_request, null_pool_callbacks);
  }
  // Any connection to replica requires the READONLY command in order to perform read.
  // Also the READONLY command is a no-opt for the primary.
  // We only need to send the READONLY command iff it's possible that the host is a replica.
  if (config_->readPolicy() != Common::Redis::Client::ReadPolicy::Primary) {
    makeRequest(Utility::ReadOnlyRequest::instance(), null_pool_callbacks);
  }
}

ClientFactoryImpl ClientFactoryImpl::instance_;

ClientPtr ClientFactoryImpl::create(
    Upstream::HostConstSharedPtr host, Event::Dispatcher& dispatcher, const ConfigSharedPtr& config,
    const RedisCommandStatsSharedPtr& redis_command_stats, Stats::Scope& scope,
    const std::string& auth_username, const std::string& auth_password, bool is_transaction_client,
    std::optional<envoy::extensions::filters::network::redis_proxy::v3::AwsIam> aws_iam_config,
    std::optional<Common::Redis::AwsIamAuthenticator::AwsIamAuthenticatorSharedPtr>
        aws_iam_authenticator) {

  ClientPtr client =
      ClientImpl::create(host, dispatcher, EncoderPtr{new EncoderImpl()}, decoder_factory_, config,
                         redis_command_stats, scope, is_transaction_client, auth_username,
                         aws_iam_config, aws_iam_authenticator);

  if (!aws_iam_authenticator.has_value()) {
    client->initialize(auth_username, auth_password);
  }
  return client;
}

} // namespace Client
} // namespace Redis
} // namespace Common
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
