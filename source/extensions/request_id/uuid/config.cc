#include "source/extensions/request_id/uuid/config.h"

#include <chrono>

#include "envoy/http/header_map.h"
#include "envoy/tracing/tracer.h"

#include "source/common/common/hex.h"
#include "source/common/common/random_generator.h"
#include "source/common/common/utility.h"
#include "source/common/stream_info/stream_id_provider_impl.h"

#include "absl/strings/str_cat.h"

namespace Envoy {
namespace Extensions {
namespace RequestId {

void UUIDRequestIDExtension::set(Http::RequestHeaderMap& request_headers, bool edge_request,
                                 bool keep_external_id) {
  const Http::HeaderEntry* request_id_header = request_headers.RequestId();

  // No request ID then set new one anyway.
  if (request_id_header == nullptr || request_id_header->value().empty()) {
    request_headers.setRequestId(generateUuidV7());
    return;
  }

  // There is request ID already set and this is not an edge request. Then this is trusted
  // request ID. Do nothing.
  if (!edge_request) {
    return;
  }

  // There is request ID already set and this is an edge request. Then this is ID may cannot
  // be trusted.

  if (!keep_external_id) {
    // If we are not keeping external request ID, then set new one anyway.
    request_headers.setRequestId(generateUuidV7());
    return;
  }

  // If we are keeping external request ID, and `pack_trace_reason` is enabled, then clear
  // the trace reason in the external request ID.
  if (pack_trace_reason_) {
    setTraceReason(request_headers, Tracing::Reason::NotTraceable);
  }
}

void UUIDRequestIDExtension::setInResponse(Http::ResponseHeaderMap& response_headers,
                                           const Http::RequestHeaderMap& request_headers) {
  if (request_headers.RequestId()) {
    response_headers.setRequestId(request_headers.getRequestIdValue());
  }
}

absl::optional<absl::string_view>
UUIDRequestIDExtension::get(const Http::RequestHeaderMap& request_headers) const {
  if (request_headers.RequestId() == nullptr) {
    return absl::nullopt;
  }
  return request_headers.getRequestIdValue();
}

absl::optional<uint64_t>
UUIDRequestIDExtension::getInteger(const Http::RequestHeaderMap& request_headers) const {
  if (request_headers.RequestId() == nullptr) {
    return absl::nullopt;
  }
  const std::string uuid(request_headers.getRequestIdValue());
  // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars)
  // For UUIDv7: first 8 chars contain timestamp, use last 8 hex chars (rand_b) for randomness.
  // Position 28-35 contains the last 8 hex digits.
  if (uuid.length() < 36) {
    return absl::nullopt;
  }

  uint64_t value;
  if (!StringUtil::atoull(uuid.substr(28, 8).c_str(), value, 16)) {
    return absl::nullopt;
  }

  return value;
}

Tracing::Reason
UUIDRequestIDExtension::getTraceReason(const Http::RequestHeaderMap& request_headers) {
  // If the request ID is not present or the pack trace reason is not enabled, return
  // NotTraceable directly.
  if (!pack_trace_reason_ || request_headers.RequestId() == nullptr) {
    return Tracing::Reason::NotTraceable;
  }
  absl::string_view uuid = request_headers.getRequestIdValue();
  if (uuid.length() != Random::RandomGeneratorImpl::UUID_LENGTH) {
    return Tracing::Reason::NotTraceable;
  }

  switch (uuid[TRACE_BYTE_POSITION]) {
  case TRACE_FORCED:
    return Tracing::Reason::ServiceForced;
  case TRACE_SAMPLED:
    return Tracing::Reason::Sampling;
  case TRACE_CLIENT:
    return Tracing::Reason::ClientForced;
  case NO_TRACE_V4: // UUIDv4 freshly generated (version bit '4')
  case NO_TRACE_V7: // UUIDv7 freshly generated (version bit '7')
  default:
    return Tracing::Reason::NotTraceable;
  }
}

void UUIDRequestIDExtension::setTraceReason(Http::RequestHeaderMap& request_headers,
                                            Tracing::Reason reason) {
  if (!pack_trace_reason_ || request_headers.RequestId() == nullptr) {
    return;
  }
  absl::string_view uuid_view = request_headers.getRequestIdValue();
  if (uuid_view.length() != Random::RandomGeneratorImpl::UUID_LENGTH) {
    return;
  }
  std::string uuid(uuid_view);

  switch (reason) {
  case Tracing::Reason::ServiceForced:
    uuid[TRACE_BYTE_POSITION] = TRACE_FORCED;
    break;
  case Tracing::Reason::ClientForced:
    uuid[TRACE_BYTE_POSITION] = TRACE_CLIENT;
    break;
  case Tracing::Reason::Sampling:
    uuid[TRACE_BYTE_POSITION] = TRACE_SAMPLED;
    break;
  case Tracing::Reason::NotTraceable:
    // Preserve the original version bit ('4' for UUIDv4, '7' for UUIDv7).
    // Only reset if currently set to a trace reason marker.
    if (uuid[TRACE_BYTE_POSITION] == TRACE_SAMPLED ||
        uuid[TRACE_BYTE_POSITION] == TRACE_FORCED ||
        uuid[TRACE_BYTE_POSITION] == TRACE_CLIENT) {
      // Default to UUIDv7 version bit when clearing trace reason.
      uuid[TRACE_BYTE_POSITION] = NO_TRACE_V7;
    }
    // If already NO_TRACE_V4 or NO_TRACE_V7, leave unchanged.
    break;
  default:
    break;
  }
  request_headers.setRequestId(uuid);
}

std::string UUIDRequestIDExtension::generateUuidV7() {
  // Modified UUIDv7: 상위 4비트를 0xF 마커로 설정하여 trace_id와 구분
  // request_id: fxxxxxxx-xxxx-7xxx-yxxx-xxxxxxxxxxxx ('f'로 시작)
  // trace_id:   0xxxxxxx-xxxx-7xxx-yxxx-xxxxxxxxxxxx ('0'으로 시작)
  //
  // Bit layout:
  //   [0-3]    4-bit marker (1111 = 0xF for request_id)
  //   [4-47]   44-bit Unix timestamp in milliseconds (~557 years until ~2527 AD)
  //   [48-51]  4-bit version (0111 = 7)
  //   [52-63]  12-bit rand_a
  //   [64-65]  2-bit variant (10 = RFC 4122)
  //   [66-127] 62-bit rand_b
  //
  // Result format: fxxxxxxx-xxxx-7xxx-yxxx-xxxxxxxxxxxx
  // where y is one of [8, 9, a, b] (variant bits).

  const uint64_t timestamp_ms = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          time_source_.systemTime().time_since_epoch())
          .count());

  // 실제 timestamp는 44비트만 사용 (상위 4비트는 마커용)
  // 44비트로 약 557년 표현 가능 (서기 ~2527년까지)
  const uint64_t timestamp_44bit = timestamp_ms & 0x0FFFFFFFFFFFULL;

  // 상위 4비트에 0xF 마커 설정 → request_id가 'f'로 시작하게 됨
  constexpr uint64_t kRequestIdMarker = 0xFULL;
  const uint64_t marked_timestamp = (kRequestIdMarker << 44) | timestamp_44bit;

  // rand_a: 12 bits of randomness for sub-millisecond ordering
  const uint64_t rand_a = random_.random() & 0x0FFFULL;
  // rand_b: 62 bits of randomness (2 bits reserved for variant)
  const uint64_t rand_b = random_.random() & 0x3FFFFFFFFFFFFFFFULL;

  constexpr uint64_t kVersion7 = 0x7ULL;
  constexpr uint64_t kVariantRfc4122 = 0x2ULL;

  // Build high 64 bits: marked_timestamp (48) | version (4) | rand_a (12)
  const uint64_t uuid_high = (marked_timestamp << 16) | (kVersion7 << 12) | rand_a;
  // Build low 64 bits: variant (2) | rand_b (62)
  const uint64_t uuid_low = (kVariantRfc4122 << 62) | rand_b;

  // Convert to hex strings (16 chars each, zero-padded)
  std::string high_hex = Hex::uint64ToHex(uuid_high);
  std::string low_hex = Hex::uint64ToHex(uuid_low);

  // Format: fxxxxxxx-xxxx-7xxx-yxxx-xxxxxxxxxxxx
  return absl::StrCat(high_hex.substr(0, 8), "-", high_hex.substr(8, 4), "-",
                      high_hex.substr(12, 4), "-", low_hex.substr(0, 4), "-", low_hex.substr(4, 12));
}

REGISTER_FACTORY(UUIDRequestIDExtensionFactory, Server::Configuration::RequestIDExtensionFactory);

} // namespace RequestId
} // namespace Extensions
} // namespace Envoy
