#pragma once

#include "envoy/network/address.h"

#include "source/common/quic/envoy_quic_proof_source_base.h"
#include "source/common/quic/quic_server_transport_socket_factory.h"
#include "source/server/listener_stats.h"

#include "openssl/ssl.h"

namespace Envoy {
namespace Quic {

// Extended context stored in SSL ex_data during QUIC handshakes.
// Used for session ticket processing, keylog, and other SSL callbacks.
struct QuicSslConnectionContext {
  const Network::FilterChain* filter_chain;
  Network::Address::InstanceConstSharedPtr local_address;
  Network::Address::InstanceConstSharedPtr remote_address;
};

// A ProofSource implementation which supplies a proof instance with certs from filter chain.
class EnvoyQuicProofSource : public EnvoyQuicProofSourceBase {
public:
  EnvoyQuicProofSource(Network::Socket& listen_socket,
                       Network::FilterChainManager& filter_chain_manager,
                       Server::ListenerStats& listener_stats, TimeSource& time_source)
      : listen_socket_(listen_socket), filter_chain_manager_(&filter_chain_manager),
        listener_stats_(listener_stats), time_source_(time_source) {}

  ~EnvoyQuicProofSource() override = default;

  // quic::ProofSource
  void OnNewSslCtx(SSL_CTX* ssl_ctx) override;
  quiche::QuicheReferenceCountedPointer<quic::ProofSource::Chain>
  GetCertChain(const quic::QuicSocketAddress& server_address,
               const quic::QuicSocketAddress& client_address, const std::string& hostname,
               bool* cert_matched_sni) override;

  void updateFilterChainManager(Network::FilterChainManager& filter_chain_manager);

  // Returns the SSL ex_data index used to store QuicSslConnectionContext during QUIC handshakes.
  static int filterChainExDataIndex();

  // Static callback for TLS key logging (NSS Key Log Format).
  static void quicKeylogCallback(const SSL* ssl, const char* line);

  struct TransportSocketFactoryWithFilterChain {
    const QuicServerTransportSocketFactory& transport_socket_factory_;
    const Network::FilterChain& filter_chain_;
  };

  absl::optional<TransportSocketFactoryWithFilterChain>
  getTransportSocketAndFilterChain(const quic::QuicSocketAddress& server_address,
                                   const quic::QuicSocketAddress& client_address,
                                   const std::string& hostname);

protected:
  // quic::ProofSource
  void signPayload(const quic::QuicSocketAddress& server_address,
                   const quic::QuicSocketAddress& client_address, const std::string& hostname,
                   uint16_t signature_algorithm, absl::string_view in,
                   std::unique_ptr<quic::ProofSource::SignatureCallback> callback) override;

private:
  struct CertWithFilterChain {
    quiche::QuicheReferenceCountedPointer<quic::ProofSource::Chain> cert_;
    std::shared_ptr<quic::CertificatePrivateKey> private_key_;
    absl::optional<std::reference_wrapper<const Network::FilterChain>> filter_chain_;
  };

  CertWithFilterChain getTlsCertAndFilterChain(const TransportSocketFactoryWithFilterChain& data,
                                               const std::string& hostname, bool* cert_matched_sni);

  Network::Socket& listen_socket_;
  Network::FilterChainManager* filter_chain_manager_{nullptr};
  Server::ListenerStats& listener_stats_;
  TimeSource& time_source_;
};

} // namespace Quic
} // namespace Envoy
