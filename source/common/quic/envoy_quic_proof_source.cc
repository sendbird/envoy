#include "source/common/quic/envoy_quic_proof_source.h"

#include <openssl/bio.h>

#include <cstdlib>
#include <fstream>

#include "envoy/ssl/tls_certificate_config.h"

#include "source/common/quic/cert_compression.h"
#include "source/common/quic/envoy_quic_utils.h"
#include "source/common/quic/quic_io_handle_wrapper.h"
#include "source/common/runtime/runtime_features.h"
#include "source/common/stream_info/stream_info_impl.h"
#include "source/common/tls/context_config_impl.h"
#include "source/common/network/utility.h"

#include "openssl/bytestring.h"
#include "quiche/quic/core/crypto/certificate_view.h"

namespace Envoy {
namespace Quic {

quiche::QuicheReferenceCountedPointer<quic::ProofSource::Chain>
EnvoyQuicProofSource::GetCertChain(const quic::QuicSocketAddress& server_address,
                                   const quic::QuicSocketAddress& client_address,
                                   const std::string& hostname, bool* cert_matched_sni) {

  // Ensure this is set even in error paths.
  *cert_matched_sni = false;

  auto res = getTransportSocketAndFilterChain(server_address, client_address, hostname);
  if (!res.has_value()) {
    return nullptr;
  }

  return getTlsCertAndFilterChain(*res, hostname, cert_matched_sni, server_address, client_address).cert_;
}

void EnvoyQuicProofSource::signPayload(
    const quic::QuicSocketAddress& server_address, const quic::QuicSocketAddress& client_address,
    const std::string& hostname, uint16_t signature_algorithm, absl::string_view in,
    std::unique_ptr<quic::ProofSource::SignatureCallback> callback) {
  auto data = getTransportSocketAndFilterChain(server_address, client_address, hostname);
  if (!data.has_value()) {
    ENVOY_LOG(warn, "No matching filter chain found for handshake.");
    callback->Run(false, "", nullptr);
    return;
  }

  CertWithFilterChain res =
      getTlsCertAndFilterChain(*data, hostname, nullptr /* cert_matched_sni */, server_address, client_address);
  if (res.private_key_ == nullptr) {
    ENVOY_LOG(warn, "No matching filter chain found for handshake.");
    callback->Run(false, "", nullptr);
    return;
  }

  // Verify the signature algorithm is as expected.
  std::string error_details;
  int sign_alg =
      deduceSignatureAlgorithmFromPublicKey(res.private_key_->private_key(), &error_details);
  if (sign_alg != signature_algorithm) {
    ENVOY_LOG(warn,
              fmt::format("The signature algorithm {} from the private key is not expected: {}",
                          sign_alg, error_details));
    callback->Run(false, "", nullptr);
    return;
  }

  // Sign.
  std::string sig = res.private_key_->Sign(in, signature_algorithm);
  bool success = !sig.empty();
  ASSERT(res.filter_chain_.has_value());
  callback->Run(success, sig,
                std::make_unique<EnvoyQuicProofSourceDetails>(res.filter_chain_.value().get()));
}

EnvoyQuicProofSource::CertWithFilterChain
EnvoyQuicProofSource::getTlsCertAndFilterChain(const TransportSocketFactoryWithFilterChain& data,
                                               const std::string& hostname,
                                               bool* cert_matched_sni,
                                               const quic::QuicSocketAddress& server_address,
                                               const quic::QuicSocketAddress& client_address) {
  auto [cert, key] =
      data.transport_socket_factory_.getTlsCertificateAndKey(hostname, cert_matched_sni);
  if (cert == nullptr || key == nullptr) {
    ENVOY_LOG(warn, "No certificate is configured in transport socket config.");
    return {};
  }

  // Cache the keylog configuration and connection info for this filter chain
  try {
    const auto& context_config = data.transport_socket_factory_.getContextConfig();
    storeKeylogInfo(data.filter_chain_, 
                   std::shared_ptr<const Ssl::ContextConfig>(&context_config, [](const Ssl::ContextConfig*){}),
                   server_address, client_address);
  } catch (const std::exception& e) {
    ENVOY_LOG(debug, "Failed to cache keylog info for filter chain: {}", e.what());
  }

  return {std::move(cert), std::move(key), data.filter_chain_};
}

absl::optional<EnvoyQuicProofSource::TransportSocketFactoryWithFilterChain>
EnvoyQuicProofSource::getTransportSocketAndFilterChain(
    const quic::QuicSocketAddress& server_address, const quic::QuicSocketAddress& client_address,
    const std::string& hostname) {
  ENVOY_LOG(trace, "Getting cert chain for {}", hostname);
  // TODO(danzh) modify QUICHE to make quic session or ALPN accessible to avoid hard-coded ALPN.
  Network::ConnectionSocketPtr connection_socket = createServerConnectionSocket(
      listen_socket_.ioHandle(), server_address, client_address, hostname, "h3");
  StreamInfo::StreamInfoImpl info(time_source_,
                                  connection_socket->connectionInfoProviderSharedPtr(),
                                  StreamInfo::FilterState::LifeSpan::Connection);
  const Network::FilterChain* filter_chain =
      filter_chain_manager_->findFilterChain(*connection_socket, info);

  if (filter_chain == nullptr) {
    listener_stats_.no_filter_chain_match_.inc();
    ENVOY_LOG(warn, "No matching filter chain found for handshake.");
    return {};
  }
  ENVOY_LOG(trace, "Got a matching cert chain {}", filter_chain->name());

  auto& transport_socket_factory =
      dynamic_cast<const QuicServerTransportSocketFactory&>(filter_chain->transportSocketFactory());
  return TransportSocketFactoryWithFilterChain{transport_socket_factory, *filter_chain};
}

void EnvoyQuicProofSource::updateFilterChainManager(
    Network::FilterChainManager& filter_chain_manager) {
  filter_chain_manager_ = &filter_chain_manager;
}

void EnvoyQuicProofSource::OnNewSslCtx(SSL_CTX* ssl_ctx) {
  CertCompression::registerSslContext(ssl_ctx, &stats_scope_);

  // Try to set up keylog callback for QUIC SSL contexts
  setupQuicKeylogCallback(ssl_ctx);
}

void EnvoyQuicProofSource::setupQuicKeylogCallback(SSL_CTX* ssl_ctx) {
  // Store reference to this proof source in SSL_CTX for use in keylog callback
  SSL_CTX_set_app_data(ssl_ctx, this);

  // Set up the keylog callback - the actual keylog configuration will be
  // determined per-connection in the callback based on the filter chain
  SSL_CTX_set_keylog_callback(ssl_ctx, quicKeylogCallback);
}

// Helper function to convert Envoy address to QUICHE address
quic::QuicSocketAddress envoyAddressToQuicAddress(const Network::Address::Instance& envoy_addr) {
  if (envoy_addr.type() == Network::Address::Type::Ip) {
    const auto& ip_addr = *envoy_addr.ip();
    quiche::QuicheIpAddress quiche_addr;
    if (quiche_addr.FromString(ip_addr.addressAsString())) {
      return quic::QuicSocketAddress(quic::QuicIpAddress(quiche_addr), ip_addr.port());
    }
  }
  // Return any address for non-IP addresses
  return quic::QuicSocketAddress();
}

// Static keylog callback for QUIC SSL contexts
void EnvoyQuicProofSource::quicKeylogCallback(const SSL* ssl, const char* line) {
  ASSERT(ssl != nullptr);

  // Get the proof source instance from SSL_CTX
  auto* proof_source =
      static_cast<EnvoyQuicProofSource*>(SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl)));
  ASSERT(proof_source != nullptr);

  ENVOY_LOG(debug, "QUIC keylog callback invoked for line: {}", line);

  // Try to find keylog configuration from cached filter chain information
  // We iterate through all cached filter chains to find one with keylog configuration
  bool keylog_written = false;
  {
    absl::MutexLock lock(&proof_source->keylog_cache_mutex_);
    for (const auto& entry : proof_source->keylog_config_cache_) {
      const auto& keylog_info = entry.second;
      if (keylog_info.config) {
        try {
          // Convert QUIC addresses back to Envoy addresses for the bridge
          std::string server_addr_str = absl::StrCat(
              keylog_info.server_address.host().ToString(), ":",
              keylog_info.server_address.port());
          std::string client_addr_str = absl::StrCat(
              keylog_info.client_address.host().ToString(), ":",
              keylog_info.client_address.port());

          Network::Address::InstanceConstSharedPtr local_addr =
              Network::Utility::parseInternetAddressAndPortNoThrow(server_addr_str);
          Network::Address::InstanceConstSharedPtr remote_addr =
              Network::Utility::parseInternetAddressAndPortNoThrow(client_addr_str);

          if (local_addr && remote_addr) {
            QuicKeylogBridge::writeKeylog(*keylog_info.config, *local_addr, *remote_addr, line);
            keylog_written = true;
            ENVOY_LOG(debug, "QUIC keylog written using cached configuration");
            break; // Successfully handled by built-in system
          }
        } catch (const std::exception& e) {
          ENVOY_LOG(debug, "Failed to write keylog using cached config: {}", e.what());
        }
      }
    }
  }

  if (keylog_written) {
    return;
  }

  // Fallback: Use environment variable for backward compatibility
  const char* keylog_path = std::getenv("SSLKEYLOGFILE");
  if (keylog_path != nullptr) {
    std::ofstream keylog_file(keylog_path, std::ios::app);
    if (keylog_file.is_open()) {
      keylog_file << line << "\n";
      keylog_file.close();
      ENVOY_LOG(debug, "QUIC keylog written to {}: {}", keylog_path, line);
    }
  }
}

void EnvoyQuicProofSource::QuicKeylogBridge::writeKeylog(
    const Ssl::ContextConfig& config,
    const Network::Address::Instance& local_addr,
    const Network::Address::Instance& remote_addr,
    const char* line) {

  const std::string& keylog_path = config.tlsKeyLogPath();
  if (keylog_path.empty()) {
    return;
  }

  // Check address filtering
  const auto& local_ip_list = config.tlsKeyLogLocal();
  const auto& remote_ip_list = config.tlsKeyLogRemote();

  bool local_match = (local_ip_list.getIpListSize() == 0 || local_ip_list.contains(local_addr));
  bool remote_match = (remote_ip_list.getIpListSize() == 0 || remote_ip_list.contains(remote_addr));

  if (!local_match || !remote_match) {
    ENVOY_LOG(debug, "QUIC keylog filtered out by address match (local={}, remote={})",
             local_match, remote_match);
    return;
  }

  // Use access log manager to write keylog
  try {
    auto& access_log_manager = config.accessLogManager();
    auto file_or_error = access_log_manager.createAccessLog(
        Filesystem::FilePathAndType{Filesystem::DestinationType::File, keylog_path});

    if (file_or_error.ok()) {
      auto keylog_file = file_or_error.value();
      keylog_file->write(absl::StrCat(line, "\n"));
      ENVOY_LOG(debug, "QUIC keylog written via bridge to {}: {}", keylog_path, line);
    } else {
      ENVOY_LOG(warn, "Failed to create keylog file {}: {}", keylog_path,
               file_or_error.status().message());
    }
  } catch (const std::exception& e) {
    ENVOY_LOG(warn, "Failed to write QUIC keylog: {}", e.what());
  }
}

// Get SSL socket index for storing transport socket callbacks
int EnvoyQuicProofSource::sslSocketIndex() {
  static int ssl_socket_index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  return ssl_socket_index;
}

void EnvoyQuicProofSource::storeKeylogInfo(const Network::FilterChain& filter_chain,
                                          std::shared_ptr<const Ssl::ContextConfig> config,
                                          const quic::QuicSocketAddress& server_address,
                                          const quic::QuicSocketAddress& client_address) const {
  absl::MutexLock lock(&keylog_cache_mutex_);
  keylog_config_cache_[&filter_chain] = KeylogInfo{std::move(config), server_address, client_address};
}

absl::optional<EnvoyQuicProofSource::KeylogInfo> EnvoyQuicProofSource::getKeylogInfo(const Network::FilterChain& filter_chain) const {
  absl::MutexLock lock(&keylog_cache_mutex_);
  auto it = keylog_config_cache_.find(&filter_chain);
  if (it != keylog_config_cache_.end()) {
    return it->second;
  }
  return absl::nullopt;
}

} // namespace Quic
} // namespace Envoy
