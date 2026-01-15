#include <string>

#include "source/common/common/random_generator.h"
#include "source/extensions/request_id/uuid/config.h"

#include "test/mocks/common.h"
#include "test/mocks/stream_info/mocks.h"
#include "test/test_common/simulated_time_system.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"

using testing::Return;

namespace Envoy {
namespace Extensions {
namespace RequestId {

TEST(UUIDRequestIDExtensionTest, SetRequestID) {
  testing::NiceMock<Random::MockRandomGenerator> random;
  Event::SimulatedTimeSystem time_system;
  UUIDRequestIDExtension uuid_utils(envoy::extensions::request_id::uuid::v3::UuidRequestIdConfig(),
                                    random, time_system);

  {
    // edge_request: true, keep_external_id: false.

    Http::TestRequestHeaderMapImpl request_headers;

    // Without request ID. generateUuidV7() calls random.random() twice.
    uuid_utils.set(request_headers, true, false);
    std::string first_request_id = std::string(request_headers.get_(Http::Headers::get().RequestId));
    EXPECT_EQ(36, first_request_id.length());
    EXPECT_EQ('f', first_request_id[0]); // UUIDv7 request_id marker
    EXPECT_EQ('7', first_request_id[14]); // UUIDv7 version

    // With request ID. Previous one will be overwritten.
    uuid_utils.set(request_headers, true, false);
    std::string second_request_id =
        std::string(request_headers.get_(Http::Headers::get().RequestId));
    EXPECT_EQ(36, second_request_id.length());
    EXPECT_EQ('f', second_request_id[0]);
    EXPECT_EQ('7', second_request_id[14]);
  }

  {
    // edge_request: true, keep_external_id: true.

    Http::TestRequestHeaderMapImpl request_headers;

    // Without request ID. generateUuidV7() calls random.random() twice.
    uuid_utils.set(request_headers, true, true);
    std::string first_request_id = std::string(request_headers.get_(Http::Headers::get().RequestId));
    EXPECT_EQ(36, first_request_id.length());

    // With request ID. Previous one will be kept.
    uuid_utils.set(request_headers, true, true);
    EXPECT_EQ(first_request_id, request_headers.get_(Http::Headers::get().RequestId));
  }

  {
    // edge_request: false, keep_external_id: false.

    Http::TestRequestHeaderMapImpl request_headers;

    // Without request ID. generateUuidV7() calls random.random() twice.
    uuid_utils.set(request_headers, false, false);
    std::string first_request_id = std::string(request_headers.get_(Http::Headers::get().RequestId));
    EXPECT_EQ(36, first_request_id.length());

    // With request ID. Previous one will be kept.
    uuid_utils.set(request_headers, false, false);
    EXPECT_EQ(first_request_id, request_headers.get_(Http::Headers::get().RequestId));
  }

  {
    // edge_request: false, keep_external_id: true.

    Http::TestRequestHeaderMapImpl request_headers;

    // Without request ID. generateUuidV7() calls random.random() twice.
    uuid_utils.set(request_headers, false, true);
    std::string first_request_id = std::string(request_headers.get_(Http::Headers::get().RequestId));
    EXPECT_EQ(36, first_request_id.length());

    // With request ID. Previous one will be kept.
    uuid_utils.set(request_headers, false, true);
    EXPECT_EQ(first_request_id, request_headers.get_(Http::Headers::get().RequestId));
  }
}

TEST(UUIDRequestIDExtensionTest, SetRequestIDWhenEmpty) {
  testing::NiceMock<Random::MockRandomGenerator> random;
  Event::SimulatedTimeSystem time_system;
  UUIDRequestIDExtension uuid_utils(envoy::extensions::request_id::uuid::v3::UuidRequestIdConfig(),
                                    random, time_system);

  {
    // Request ID not set.

    Http::TestRequestHeaderMapImpl request_headers;

    // A new request ID will be set. generateUuidV7() calls random.random() twice.
    uuid_utils.set(request_headers, false, true);
    std::string first_request_id = std::string(request_headers.get_(Http::Headers::get().RequestId));
    EXPECT_EQ(36, first_request_id.length());
    EXPECT_EQ('f', first_request_id[0]); // UUIDv7 request_id marker
    EXPECT_EQ('7', first_request_id[14]); // UUIDv7 version
  }

  {
    // Request ID is empty.

    Http::TestRequestHeaderMapImpl request_headers{{
        "x-request-id",
        "",
    }};

    // A new request ID will be set. generateUuidV7() calls random.random() twice.
    uuid_utils.set(request_headers, false, true);
    std::string first_request_id = std::string(request_headers.get_(Http::Headers::get().RequestId));
    EXPECT_EQ(36, first_request_id.length());
    EXPECT_EQ('f', first_request_id[0]);
    EXPECT_EQ('7', first_request_id[14]);
  }

  {
    // Request ID is not empty.

    Http::TestRequestHeaderMapImpl request_headers{{
        "x-request-id",
        "some-request-id",
    }};

    // The request ID will be kept.
    uuid_utils.set(request_headers, false, true);
    EXPECT_EQ("some-request-id", request_headers.get_(Http::Headers::get().RequestId));
  }
}

TEST(UUIDRequestIDExtensionTest, ClearExternalTraceReason) {
  testing::NiceMock<Random::MockRandomGenerator> random;
  Event::SimulatedTimeSystem time_system;
  UUIDRequestIDExtension uuid_utils(envoy::extensions::request_id::uuid::v3::UuidRequestIdConfig(),
                                    random, time_system);

  std::string uuid_with_trace_reason = random.uuid_;

  uuid_with_trace_reason[14] = 'b'; // 'b' means TRACE_CLIENT.

  // edge_request: true, keep_external_id: true.

  Http::TestRequestHeaderMapImpl request_headers{{
      "x-request-id",
      uuid_with_trace_reason,
  }};

  std::string expected_uuid_with_trace_reason = uuid_with_trace_reason;
  expected_uuid_with_trace_reason[14] = '7'; // Clear to NO_TRACE (UUIDv7 version bit).

  uuid_utils.set(request_headers, true, true);

  // External request ID will be kept but the trace reason will be cleared.
  EXPECT_EQ(expected_uuid_with_trace_reason, request_headers.get_(Http::Headers::get().RequestId));
}

TEST(UUIDRequestIDExtensionTest, PreserveRequestIDInResponse) {
  testing::NiceMock<Random::MockRandomGenerator> random;
  Event::SimulatedTimeSystem time_system;
  UUIDRequestIDExtension uuid_utils(envoy::extensions::request_id::uuid::v3::UuidRequestIdConfig(),
                                    random, time_system);
  Http::TestRequestHeaderMapImpl request_headers;
  Http::TestResponseHeaderMapImpl response_headers;

  uuid_utils.setInResponse(response_headers, request_headers);
  EXPECT_TRUE(response_headers.get(Http::Headers::get().RequestId).empty());

  request_headers.setRequestId("some-request-id");
  uuid_utils.setInResponse(response_headers, request_headers);
  EXPECT_EQ("some-request-id", response_headers.get_(Http::Headers::get().RequestId));

  request_headers.removeRequestId();
  response_headers.setRequestId("another-request-id");
  uuid_utils.setInResponse(response_headers, request_headers);
  EXPECT_EQ("another-request-id", response_headers.get_(Http::Headers::get().RequestId));

  request_headers.setRequestId("");
  uuid_utils.setInResponse(response_headers, request_headers);
  EXPECT_EQ("", response_headers.get_(Http::Headers::get().RequestId));
}

TEST(UUIDRequestIDExtensionTest, GetRequestIdAndModRequestIDBy) {
  testing::NiceMock<Random::MockRandomGenerator> random;
  Event::SimulatedTimeSystem time_system;
  UUIDRequestIDExtension uuid_utils(envoy::extensions::request_id::uuid::v3::UuidRequestIdConfig(),
                                    random, time_system);
  Http::TestRequestHeaderMapImpl request_headers;

  EXPECT_FALSE(uuid_utils.get(request_headers));
  EXPECT_FALSE(uuid_utils.getInteger(request_headers).has_value());

  // UUID too short (< 36 chars).
  request_headers.setRequestId("fffffff");
  EXPECT_EQ("fffffff", uuid_utils.get(request_headers).value());
  EXPECT_FALSE(uuid_utils.getInteger(request_headers).has_value());

  // UUID with invalid hex char 'z' in the last 8 chars (position 28-35).
  request_headers.setRequestId("fffffffz-0012-0110-00ff-0c00400600fz");
  EXPECT_EQ("fffffffz-0012-0110-00ff-0c00400600fz", uuid_utils.get(request_headers).value());
  EXPECT_FALSE(uuid_utils.getInteger(request_headers).has_value());

  // getInteger() now uses last 8 hex chars (position 28-35).
  // UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  //       0       8    13   18   23   28     35
  //                                   ^^^^^^^^ (last 8 hex chars)

  // "00000000-0000-0000-0000-000000000000" -> last 8 chars = "00000000" = 0
  request_headers.setRequestId("00000000-0000-0000-0000-000000000000");
  EXPECT_EQ("00000000-0000-0000-0000-000000000000", uuid_utils.get(request_headers).value());
  EXPECT_EQ(0, uuid_utils.getInteger(request_headers).value());

  // "00000001-0000-0000-0000-000000000001" -> last 8 chars = "00000001" = 1
  request_headers.setRequestId("00000001-0000-0000-0000-000000000001");
  EXPECT_EQ("00000001-0000-0000-0000-000000000001", uuid_utils.get(request_headers).value());
  EXPECT_EQ(1, uuid_utils.getInteger(request_headers).value());

  // "0000000f-0000-0000-0000-0000000000ff" -> last 8 chars = "000000ff" = 255
  request_headers.setRequestId("0000000f-0000-0000-0000-0000000000ff");
  EXPECT_EQ("0000000f-0000-0000-0000-0000000000ff", uuid_utils.get(request_headers).value());
  EXPECT_EQ(255, uuid_utils.getInteger(request_headers).value());

  request_headers.setRequestId("");
  EXPECT_EQ("", uuid_utils.get(request_headers).value());
  EXPECT_FALSE(uuid_utils.getInteger(request_headers).has_value());

  // "000000ff-0000-0000-0000-000012345678" -> last 8 chars = "12345678" = 0x12345678
  request_headers.setRequestId("000000ff-0000-0000-0000-000012345678");
  EXPECT_EQ("000000ff-0000-0000-0000-000012345678", uuid_utils.get(request_headers).value());
  EXPECT_EQ(0x12345678, uuid_utils.getInteger(request_headers).value());

  // "a0090100-0012-0110-00ff-0c00400600ff" -> last 8 chars = "400600ff" = 0x400600ff
  request_headers.setRequestId("a0090100-0012-0110-00ff-0c00400600ff");
  EXPECT_EQ("a0090100-0012-0110-00ff-0c00400600ff", uuid_utils.get(request_headers).value());
  EXPECT_EQ(0x400600ff, uuid_utils.getInteger(request_headers).value());

  // "ffffffff-0012-0110-00ff-0c00ffffffff" -> last 8 chars = "ffffffff" = 0xffffffff
  request_headers.setRequestId("ffffffff-0012-0110-00ff-0c00ffffffff");
  EXPECT_EQ("ffffffff-0012-0110-00ff-0c00ffffffff", uuid_utils.get(request_headers).value());
  EXPECT_EQ(0xffffffff, uuid_utils.getInteger(request_headers).value());

  // Test modulo operations for sampling distribution.
  // "ffffffff-0012-0110-00ff-0c00400600ff" -> last 8 chars = "400600ff" = 0x400600ff = 1073873151
  request_headers.setRequestId("ffffffff-0012-0110-00ff-0c00400600ff");
  EXPECT_EQ("ffffffff-0012-0110-00ff-0c00400600ff", uuid_utils.get(request_headers).value());
  EXPECT_EQ(1073873151 % 100, uuid_utils.getInteger(request_headers).value() % 100);
  EXPECT_EQ(1073873151 % 10000, uuid_utils.getInteger(request_headers).value() % 10000);
}

TEST(UUIDRequestIDExtensionTest, RequestIDModDistribution) {
  Random::RandomGeneratorImpl random;
  Event::SimulatedTimeSystem time_system;
  UUIDRequestIDExtension uuid_utils(envoy::extensions::request_id::uuid::v3::UuidRequestIdConfig(),
                                    random, time_system);
  Http::TestRequestHeaderMapImpl request_headers;

  const int mod = 100;
  const int required_percentage = 11;
  int total_samples = 0;
  int interesting_samples = 0;

  for (int i = 0; i < 500000; ++i) {
    // Generate UUIDv7 via uuid_utils.set() instead of random.uuid().
    uuid_utils.set(request_headers, true, false);
    std::string uuid = std::string(request_headers.getRequestIdValue());

    const char c = uuid[19];
    ASSERT_TRUE(uuid[0] == 'f');                               // Request ID marker
    ASSERT_TRUE(uuid[14] == '7');                              // UUID version 7
    ASSERT_TRUE(c == '8' || c == '9' || c == 'a' || c == 'b'); // UUID variant 1 (RFC4122)

    const uint64_t value = uuid_utils.getInteger(request_headers).value() % mod;

    if (value < required_percentage) {
      interesting_samples++;
    }
    total_samples++;
  }

  EXPECT_NEAR(required_percentage / 100.0, interesting_samples * 1.0 / total_samples, 0.002);
}

TEST(UUIDRequestIDExtensionTest, DISABLED_benchmark) {
  Random::RandomGeneratorImpl random;
  Event::SimulatedTimeSystem time_system;
  UUIDRequestIDExtension uuid_utils(envoy::extensions::request_id::uuid::v3::UuidRequestIdConfig(),
                                    random, time_system);
  Http::TestRequestHeaderMapImpl request_headers;

  for (int i = 0; i < 100000000; ++i) {
    uuid_utils.set(request_headers, true, false);
  }
}

TEST(UUIDRequestIDExtensionTest, SetTraceStatus) {
  Random::RandomGeneratorImpl random;
  Event::SimulatedTimeSystem time_system;
  UUIDRequestIDExtension uuid_utils(envoy::extensions::request_id::uuid::v3::UuidRequestIdConfig(),
                                    random, time_system);
  Http::TestRequestHeaderMapImpl request_headers;

  // Generate UUIDv7 via uuid_utils.set() instead of random.uuid().
  uuid_utils.set(request_headers, true, false);

  EXPECT_EQ(Tracing::Reason::NotTraceable, uuid_utils.getTraceReason(request_headers));

  uuid_utils.setTraceReason(request_headers, Tracing::Reason::Sampling);
  EXPECT_EQ(Tracing::Reason::Sampling, uuid_utils.getTraceReason(request_headers));

  uuid_utils.setTraceReason(request_headers, Tracing::Reason::ClientForced);
  EXPECT_EQ(Tracing::Reason::ClientForced, uuid_utils.getTraceReason(request_headers));

  uuid_utils.setTraceReason(request_headers, Tracing::Reason::ServiceForced);
  EXPECT_EQ(Tracing::Reason::ServiceForced, uuid_utils.getTraceReason(request_headers));

  uuid_utils.setTraceReason(request_headers, Tracing::Reason::NotTraceable);
  EXPECT_EQ(Tracing::Reason::NotTraceable, uuid_utils.getTraceReason(request_headers));

  // Invalid request ID.
  request_headers.setRequestId("");
  uuid_utils.setTraceReason(request_headers, Tracing::Reason::ServiceForced);
  EXPECT_EQ(request_headers.getRequestIdValue(), "");
}

TEST(UUIDRequestIDExtensionTest, SetTraceStatusPackingDisabled) {
  Random::RandomGeneratorImpl random;
  Event::SimulatedTimeSystem time_system;
  envoy::extensions::request_id::uuid::v3::UuidRequestIdConfig config;
  config.mutable_pack_trace_reason()->set_value(false);
  UUIDRequestIDExtension uuid_utils(config, random, time_system);

  // Generate UUIDv7 and manually set trace reason marker.
  Http::TestRequestHeaderMapImpl temp_headers;
  uuid_utils.set(temp_headers, true, false);
  std::string uuid_with_trace_reason = std::string(temp_headers.getRequestIdValue());
  uuid_with_trace_reason[14] = 'b'; // 'b' means TRACE_CLIENT.

  Http::TestRequestHeaderMapImpl request_headers;
  request_headers.setRequestId(uuid_with_trace_reason);

  EXPECT_EQ(Tracing::Reason::NotTraceable, uuid_utils.getTraceReason(request_headers));
  EXPECT_EQ(uuid_with_trace_reason, request_headers.getRequestIdValue());

  uuid_utils.setTraceReason(request_headers, Tracing::Reason::Sampling);
  EXPECT_EQ(Tracing::Reason::NotTraceable, uuid_utils.getTraceReason(request_headers));
  EXPECT_EQ(uuid_with_trace_reason, request_headers.getRequestIdValue());
}

TEST(UUIDRequestIDExtensionTest, GenerateUuidV7Format) {
  testing::NiceMock<Random::MockRandomGenerator> random;
  Event::SimulatedTimeSystem time_system;
  UUIDRequestIDExtension uuid_utils(
      envoy::extensions::request_id::uuid::v3::UuidRequestIdConfig(), random, time_system);

  Http::TestRequestHeaderMapImpl request_headers;

  EXPECT_CALL(random, random()).Times(2).WillRepeatedly(Return(0x123456789ABCDEFULL));
  uuid_utils.set(request_headers, true, false);

  std::string uuid = std::string(request_headers.getRequestIdValue());

  // Verify UUID length.
  EXPECT_EQ(36, uuid.length());

  // Verify marker: request_id starts with 'f'.
  EXPECT_EQ('f', uuid[0]);

  // Verify version: position 14 = '7' (UUIDv7).
  EXPECT_EQ('7', uuid[14]);

  // Verify variant: position 19 = '8', '9', 'a', or 'b' (RFC 4122).
  EXPECT_TRUE(uuid[19] == '8' || uuid[19] == '9' || uuid[19] == 'a' || uuid[19] == 'b');

  // Verify UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  EXPECT_EQ('-', uuid[8]);
  EXPECT_EQ('-', uuid[13]);
  EXPECT_EQ('-', uuid[18]);
  EXPECT_EQ('-', uuid[23]);
}

} // namespace RequestId
} // namespace Extensions
} // namespace Envoy
