#pragma once

#include "envoy/extensions/transport_sockets/quic/v3/quic_transport.pb.h"
#include "envoy/network/transport_socket.h"
#include "envoy/server/transport_socket_config.h"
#include "envoy/ssl/context_config.h"
#include "envoy/ssl/handshaker.h"

#include "source/common/common/assert.h"
#include "source/common/network/raw_buffer_socket.h"
#include "source/common/network/transport_socket_options_impl.h"
#include "source/common/quic/quic_transport_socket_factory.h"
#include "source/common/tls/server_ssl_socket.h"

namespace Envoy {
namespace Quic {

// TODO(danzh): when implement ProofSource, examine of it's necessary to
// differentiate server and client side context config.
class QuicServerTransportSocketFactory : public Network::DownstreamTransportSocketFactory,
                                         public QuicTransportSocketFactoryBase {
public:
  static absl::StatusOr<std::unique_ptr<QuicServerTransportSocketFactory>>
  create(bool enable_early_data, Stats::Scope& store, Ssl::ServerContextConfigPtr config,
         Envoy::Ssl::ContextManager& manager, const std::vector<std::string>& server_names);
  ~QuicServerTransportSocketFactory() override;

  // Network::DownstreamTransportSocketFactory
  // QUIC uses a different transport socket mechanism, but some code paths may call this
  // Return a raw buffer socket as a safe fallback
  Network::TransportSocketPtr createDownstreamTransportSocket() const override {
    ENVOY_LOG(warn, "createDownstreamTransportSocket called on QUIC transport socket factory. "
                    "This should not happen in normal QUIC operation.");
    return std::make_unique<Network::RawBufferSocket>();
  }
  bool implementsSecureTransport() const override { return true; }

  void initialize() override;

  std::pair<quiche::QuicheReferenceCountedPointer<quic::ProofSource::Chain>,
            std::shared_ptr<quic::CertificatePrivateKey>>
  getTlsCertificateAndKey(absl::string_view sni, bool* cert_matched_sni) const;

  bool earlyDataEnabled() const { return enable_early_data_; }

  // Access the TLS context configuration (for keylog integration)
  const Ssl::ServerContextConfig& getContextConfig() const { return *config_; }

protected:
  QuicServerTransportSocketFactory(bool enable_early_data, Stats::Scope& store,
                                   Ssl::ServerContextConfigPtr config,
                                   Envoy::Ssl::ContextManager& manager,
                                   const std::vector<std::string>& server_names,
                                   absl::Status& creation_status);

  absl::Status onSecretUpdated() override;

private:
  absl::StatusOr<Envoy::Ssl::ServerContextSharedPtr> createSslServerContext() const;

  Envoy::Ssl::ContextManager& manager_;
  Stats::Scope& stats_scope_;
  Ssl::ServerContextConfigPtr config_;
  const std::vector<std::string> server_names_;
  mutable absl::Mutex ssl_ctx_mu_;
  Envoy::Ssl::ServerContextSharedPtr ssl_ctx_ ABSL_GUARDED_BY(ssl_ctx_mu_);
  bool enable_early_data_;
};

class QuicServerTransportSocketConfigFactory
    : public QuicTransportSocketConfigFactory,
      public Server::Configuration::DownstreamTransportSocketConfigFactory {
public:
  // Server::Configuration::DownstreamTransportSocketConfigFactory
  absl::StatusOr<Network::DownstreamTransportSocketFactoryPtr>
  createTransportSocketFactory(const Protobuf::Message& config,
                               Server::Configuration::TransportSocketFactoryContext& context,
                               const std::vector<std::string>& server_names) override;

  // Server::Configuration::TransportSocketConfigFactory
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
};

DECLARE_FACTORY(QuicServerTransportSocketConfigFactory);

} // namespace Quic
} // namespace Envoy
