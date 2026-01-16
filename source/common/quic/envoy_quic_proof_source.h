#pragma once

#include <unordered_map>

#include "envoy/ssl/context_config.h"
#include "envoy/stats/scope.h"

#include "source/common/common/thread.h"
#include "source/common/quic/envoy_quic_proof_source_base.h"
#include "source/common/quic/quic_server_transport_socket_factory.h"
#include "source/server/listener_stats.h"

#include "absl/synchronization/mutex.h"
#include "absl/types/optional.h"
#include "quiche/quic/platform/api/quic_socket_address.h"

namespace Envoy {
namespace Quic {

// A ProofSource implementation which supplies a proof instance with certs from filter chain.
class EnvoyQuicProofSource : public EnvoyQuicProofSourceBase {
public:
  // Cache for keylog configurations by filter chain
  struct KeylogInfo {
    std::shared_ptr<const Ssl::ContextConfig> config;
    quic::QuicSocketAddress server_address;
    quic::QuicSocketAddress client_address;
  };
  EnvoyQuicProofSource(Network::Socket& listen_socket,
                       Network::FilterChainManager& filter_chain_manager,
                       Server::ListenerStats& listener_stats, TimeSource& time_source,
                       Stats::Scope& stats_scope)
      : listen_socket_(listen_socket), filter_chain_manager_(&filter_chain_manager),
        listener_stats_(listener_stats), time_source_(time_source), stats_scope_(stats_scope) {}

  ~EnvoyQuicProofSource() override = default;

  // quic::ProofSource
  void OnNewSslCtx(SSL_CTX* ssl_ctx) override;
  quiche::QuicheReferenceCountedPointer<quic::ProofSource::Chain>
  GetCertChain(const quic::QuicSocketAddress& server_address,
               const quic::QuicSocketAddress& client_address, const std::string& hostname,
               bool* cert_matched_sni) override;

  void updateFilterChainManager(Network::FilterChainManager& filter_chain_manager);

  // Bridge interface for QUIC-TLS keylog integration
  class QuicKeylogBridge {
  public:
    static void writeKeylog(const Ssl::ContextConfig& config, 
                           const Network::Address::Instance& local_addr,
                           const Network::Address::Instance& remote_addr, 
                           const char* line);
  };

protected:
  // quic::ProofSource
  void signPayload(const quic::QuicSocketAddress& server_address,
                   const quic::QuicSocketAddress& client_address, const std::string& hostname,
                   uint16_t signature_algorithm, absl::string_view in,
                   std::unique_ptr<quic::ProofSource::SignatureCallback> callback) override;

private:
  struct TransportSocketFactoryWithFilterChain {
    const QuicServerTransportSocketFactory& transport_socket_factory_;
    const Network::FilterChain& filter_chain_;
  };

  struct CertWithFilterChain {
    quiche::QuicheReferenceCountedPointer<quic::ProofSource::Chain> cert_;
    std::shared_ptr<quic::CertificatePrivateKey> private_key_;
    absl::optional<std::reference_wrapper<const Network::FilterChain>> filter_chain_;
  };

  CertWithFilterChain getTlsCertAndFilterChain(const TransportSocketFactoryWithFilterChain& data,
                                               const std::string& hostname, bool* cert_matched_sni,
                                               const quic::QuicSocketAddress& server_address,
                                               const quic::QuicSocketAddress& client_address);

  absl::optional<TransportSocketFactoryWithFilterChain>
  getTransportSocketAndFilterChain(const quic::QuicSocketAddress& server_address,
                                   const quic::QuicSocketAddress& client_address,
                                   const std::string& hostname);

  void setupQuicKeylogCallback(SSL_CTX* ssl_ctx);

  // Static callback function for QUIC keylog
  static void quicKeylogCallback(const SSL* ssl, const char* line);

  // Get SSL socket index for storing transport socket callbacks
  static int sslSocketIndex();

  // Store keylog configuration and connection info for a filter chain
  void storeKeylogInfo(const Network::FilterChain& filter_chain, 
                      std::shared_ptr<const Ssl::ContextConfig> config,
                      const quic::QuicSocketAddress& server_address,
                      const quic::QuicSocketAddress& client_address) const;
  
  // Get cached keylog information for a filter chain
  absl::optional<KeylogInfo> getKeylogInfo(const Network::FilterChain& filter_chain) const;

  Network::Socket& listen_socket_;
  Network::FilterChainManager* filter_chain_manager_{nullptr};
  Server::ListenerStats& listener_stats_;
  TimeSource& time_source_;
  Stats::Scope& stats_scope_;

  mutable absl::Mutex keylog_cache_mutex_;
  mutable std::unordered_map<const Network::FilterChain*, KeylogInfo> keylog_config_cache_ ABSL_GUARDED_BY(keylog_cache_mutex_);
};

} // namespace Quic
} // namespace Envoy
