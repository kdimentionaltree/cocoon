// Minimal TDX/SGX helpers and SSL context

#include "cocoon/openssl_utils.h"
#include "tee/cocoon/tdx/tdx.h"
#include "tee/cocoon/utils.h"
#include "cocoon/AttestationCache.h"
#include "td/utils/misc.h"
#include "td/utils/filesystem.h"
#include "td/utils/format.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/tl_helpers.h"
#include "td/utils/overloaded.h"
#include "td/net/utils.h"

#include <functional>
#include <limits>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "td/utils/Time.h"
#include "td/utils/Variant.h"
#include <cstring>
#include <mutex>
#include <optional>
#include <unordered_map>

// TODO: Replace OBJ_* calls with NID_* equivalents for better performance
namespace tdx {
using cocoon::cut;
using cocoon::to;

td::StringBuilder &operator<<(td::StringBuilder &sb, const TdxAttestationData &data) {
  sb << "TDX attestation data\n";
  auto p = [&](td::Slice name, auto value) {
    sb << name << ": " << td::Slice(td::hex_encode(value.as_slice())) << "\n";
  };
  p("MRTD", data.mr_td);
  p("MRCONFIGID", data.mr_config_id);
  p("MROWNER", data.mr_owner);
  p("MROWNERCONFIG", data.mr_owner_config);
  for (int i = 0; i < 4; i++) {
    p(PSLICE() << "RTMR" << i, data.rtmr[i]);
  }
  p("REPORTDATA", data.reportdata);
  return sb;
}
td::StringBuilder &operator<<(td::StringBuilder &sb, const SgxAttestationData &data) {
  sb << "SGX attestation data\n";
  return sb;
}

td::UInt512 UserClaims::to_hash() const {
  auto str = serialize();
  td::UInt512 hash;
  td::sha512(str, hash.as_mutable_slice());
  return hash;
}

std::string UserClaims::serialize() const {
  // TODO: proper serialization with structured format
  // For now, use a more efficient approach than string concatenation
  return public_key.to_secure_string().as_slice().str();
}

// (Removed string printers for attestation data)

#if TD_TDX_ATTESTATION
td::CSlice to_str(quote3_error_t result) {
  switch (result) {
    case SGX_QL_SUCCESS:
      return "SGX_QL_SUCCESS";
    case SGX_QL_ERROR_UNEXPECTED:
      return "SGX_QL_ERROR_UNEXPECTED";
    case SGX_QL_ERROR_INVALID_PARAMETER:
      return "SGX_QL_ERROR_INVALID_PARAMETER";
    case SGX_QL_ERROR_OUT_OF_MEMORY:
      return "SGX_QL_ERROR_OUT_OF_MEMORY";
    case SGX_QL_ERROR_ECDSA_ID_MISMATCH:
      return "SGX_QL_ERROR_ECDSA_ID_MISMATCH";
    case SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR:
      return "SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR";
    case SGX_QL_FILE_ACCESS_ERROR:
      return "SGX_QL_FILE_ACCESS_ERROR";
    case SGX_QL_ERROR_STORED_KEY:
      return "SGX_QL_ERROR_STORED_KEY";
    case SGX_QL_ERROR_PUB_KEY_ID_MISMATCH:
      return "SGX_QL_ERROR_PUB_KEY_ID_MISMATCH";
    case SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME:
      return "SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME";
    case SGX_QL_ATT_KEY_BLOB_ERROR:
      return "SGX_QL_ATT_KEY_BLOB_ERROR";
    case SGX_QL_UNSUPPORTED_ATT_KEY_ID:
      return "SGX_QL_UNSUPPORTED_ATT_KEY_ID";
    case SGX_QL_UNSUPPORTED_LOADING_POLICY:
      return "SGX_QL_UNSUPPORTED_LOADING_POLICY";
    case SGX_QL_INTERFACE_UNAVAILABLE:
      return "SGX_QL_INTERFACE_UNAVAILABLE";
    case SGX_QL_PLATFORM_LIB_UNAVAILABLE:
      return "SGX_QL_PLATFORM_LIB_UNAVAILABLE";
    case SGX_QL_ATT_KEY_NOT_INITIALIZED:
      return "SGX_QL_ATT_KEY_NOT_INITIALIZED";
    case SGX_QL_ATT_KEY_CERT_DATA_INVALID:
      return "SGX_QL_ATT_KEY_CERT_DATA_INVALID";
    case SGX_QL_NO_PLATFORM_CERT_DATA:
      return "SGX_QL_NO_PLATFORM_CERT_DATA";
    case SGX_QL_OUT_OF_EPC:
      return "SGX_QL_OUT_OF_EPC";
    case SGX_QL_ERROR_REPORT:
      return "SGX_QL_ERROR_REPORT";
    case SGX_QL_ENCLAVE_LOST:
      return "SGX_QL_ENCLAVE_LOST";
    case SGX_QL_INVALID_REPORT:
      return "SGX_QL_INVALID_REPORT";
    case SGX_QL_ENCLAVE_LOAD_ERROR:
      return "SGX_QL_ENCLAVE_LOAD_ERROR";
    case SGX_QL_UNABLE_TO_GENERATE_QE_REPORT:
      return "SGX_QL_UNABLE_TO_GENERATE_QE_REPORT";
    case SGX_QL_KEY_CERTIFCATION_ERROR:
      return "SGX_QL_KEY_CERTIFCATION_ERROR";
    case SGX_QL_NETWORK_ERROR:
      return "SGX_QL_NETWORK_ERROR";
    case SGX_QL_MESSAGE_ERROR:
      return "SGX_QL_MESSAGE_ERROR";
    case SGX_QL_NO_QUOTE_COLLATERAL_DATA:
      return "SGX_QL_NO_QUOTE_COLLATERAL_DATA";
    case SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED:
      return "SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED";
    case SGX_QL_QUOTE_FORMAT_UNSUPPORTED:
      return "SGX_QL_QUOTE_FORMAT_UNSUPPORTED";
    case SGX_QL_UNABLE_TO_GENERATE_REPORT:
      return "SGX_QL_UNABLE_TO_GENERATE_REPORT";
    case SGX_QL_QE_REPORT_INVALID_SIGNATURE:
      return "SGX_QL_QE_REPORT_INVALID_SIGNATURE";
    case SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT:
      return "SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT";
    case SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT:
      return "SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT";
    case SGX_QL_PCK_CERT_CHAIN_ERROR:
      return "SGX_QL_PCK_CERT_CHAIN_ERROR";
    case SGX_QL_TCBINFO_UNSUPPORTED_FORMAT:
      return "SGX_QL_TCBINFO_UNSUPPORTED_FORMAT";
    case SGX_QL_TCBINFO_MISMATCH:
      return "SGX_QL_TCBINFO_MISMATCH";
    case SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT:
      return "SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT";
    case SGX_QL_QEIDENTITY_MISMATCH:
      return "SGX_QL_QEIDENTITY_MISMATCH";
    case SGX_QL_TCB_OUT_OF_DATE:
      return "SGX_QL_TCB_OUT_OF_DATE";
    case SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED:
      return "SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED";
    case SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE:
      return "SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE";
    case SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE:
      return "SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE";
    case SGX_QL_QE_IDENTITY_OUT_OF_DATE:
      return "SGX_QL_QE_IDENTITY_OUT_OF_DATE";
    case SGX_QL_SGX_TCB_INFO_EXPIRED:
      return "SGX_QL_SGX_TCB_INFO_EXPIRED";
    case SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED:
      return "SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED";
    case SGX_QL_SGX_CRL_EXPIRED:
      return "SGX_QL_SGX_CRL_EXPIRED";
    case SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED:
      return "SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED";
    case SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED:
      return "SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED";
    case SGX_QL_PCK_REVOKED:
      return "SGX_QL_PCK_REVOKED";
    case SGX_QL_TCB_REVOKED:
      return "SGX_QL_TCB_REVOKED";
    case SGX_QL_TCB_CONFIGURATION_NEEDED:
      return "SGX_QL_TCB_CONFIGURATION_NEEDED";
    case SGX_QL_UNABLE_TO_GET_COLLATERAL:
      return "SGX_QL_UNABLE_TO_GET_COLLATERAL";
    case SGX_QL_ERROR_INVALID_PRIVILEGE:
      return "SGX_QL_ERROR_INVALID_PRIVILEGE";
    case SGX_QL_NO_QVE_IDENTITY_DATA:
      return "SGX_QL_NO_QVE_IDENTITY_DATA";
    case SGX_QL_CRL_UNSUPPORTED_FORMAT:
      return "SGX_QL_CRL_UNSUPPORTED_FORMAT";
    case SGX_QL_QEIDENTITY_CHAIN_ERROR:
      return "SGX_QL_QEIDENTITY_CHAIN_ERROR";
    case SGX_QL_TCBINFO_CHAIN_ERROR:
      return "SGX_QL_TCBINFO_CHAIN_ERROR";
    case SGX_QL_ERROR_QVL_QVE_MISMATCH:
      return "SGX_QL_ERROR_QVL_QVE_MISMATCH";
    case SGX_QL_TCB_SW_HARDENING_NEEDED:
      return "SGX_QL_TCB_SW_HARDENING_NEEDED";
    case SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED:
      return "SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED";
    case SGX_QL_UNSUPPORTED_MODE:
      return "SGX_QL_UNSUPPORTED_MODE";
    case SGX_QL_NO_DEVICE:
      return "SGX_QL_NO_DEVICE";
    case SGX_QL_SERVICE_UNAVAILABLE:
      return "SGX_QL_SERVICE_UNAVAILABLE";
    case SGX_QL_NETWORK_FAILURE:
      return "SGX_QL_NETWORK_FAILURE";
    case SGX_QL_SERVICE_TIMEOUT:
      return "SGX_QL_SERVICE_TIMEOUT";
    case SGX_QL_ERROR_BUSY:
      return "SGX_QL_ERROR_BUSY";
    case SGX_QL_UNKNOWN_MESSAGE_RESPONSE:
      return "SGX_QL_UNKNOWN_MESSAGE_RESPONSE";
    case SGX_QL_PERSISTENT_STORAGE_ERROR:
      return "SGX_QL_PERSISTENT_STORAGE_ERROR";
    case SGX_QL_ERROR_MESSAGE_PARSING_ERROR:
      return "SGX_QL_ERROR_MESSAGE_PARSING_ERROR";
    case SGX_QL_PLATFORM_UNKNOWN:
      return "SGX_QL_PLATFORM_UNKNOWN";
    case SGX_QL_UNKNOWN_API_VERSION:
      return "SGX_QL_UNKNOWN_API_VERSION";
    case SGX_QL_CERTS_UNAVAILABLE:
      return "SGX_QL_CERTS_UNAVAILABLE";
    case SGX_QL_QVEIDENTITY_MISMATCH:
      return "SGX_QL_QVEIDENTITY_MISMATCH";
    case SGX_QL_QVE_OUT_OF_DATE:
      return "SGX_QL_QVE_OUT_OF_DATE";
    case SGX_QL_PSW_NOT_AVAILABLE:
      return "SGX_QL_PSW_NOT_AVAILABLE";
    case SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED:
      return "SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED";
    case SGX_QL_TDX_MODULE_MISMATCH:
      return "SGX_QL_TDX_MODULE_MISMATCH";
    case SGX_QL_QEIDENTITY_NOT_FOUND:
      return "SGX_QL_QEIDENTITY_NOT_FOUND";
    case SGX_QL_TCBINFO_NOT_FOUND:
      return "SGX_QL_TCBINFO_NOT_FOUND";
    case SGX_QL_INTERNAL_SERVER_ERROR:
      return "SGX_QL_INTERNAL_SERVER_ERROR";
    case SGX_QL_SUPPLEMENTAL_DATA_VERSION_NOT_SUPPORTED:
      return "SGX_QL_SUPPLEMENTAL_DATA_VERSION_NOT_SUPPORTED";
    case SGX_QL_ROOT_CA_UNTRUSTED:
      return "SGX_QL_ROOT_CA_UNTRUSTED";
    case SGX_QL_TCB_NOT_SUPPORTED:
      return "SGX_QL_TCB_NOT_SUPPORTED";
    case SGX_QL_CONFIG_INVALID_JSON:
      return "SGX_QL_CONFIG_INVALID_JSON";
    case SGX_QL_RESULT_INVALID_SIGNATURE:
      return "SGX_QL_RESULT_INVALID_SIGNATURE";
    case SGX_QL_QAEIDENTITY_MISMATCH:
      return "SGX_QL_QAEIDENTITY_MISMATCH";
    case SGX_QL_QAE_OUT_OF_DATE:
      return "SGX_QL_QAE_OUT_OF_DATE";
    case SGX_QL_QUOTE_HASH_MISMATCH:
      return "SGX_QL_QUOTE_HASH_MISMATCH";
    case SGX_QL_REPORT_DATA_MISMATCH:
      return "SGX_QL_REPORT_DATA_MISMATCH";
    default:
      return "UNKNOWN_QUOTE3_ERROR";
  }
}

td::CSlice to_str(sgx_ql_qv_result_t result) {
  switch (result) {
    case TEE_QV_RESULT_OK:
      return "TEE_QV_RESULT_OK";
    case TEE_QV_RESULT_CONFIG_NEEDED:
      return "TEE_QV_RESULT_CONFIG_NEEDED";
    case TEE_QV_RESULT_OUT_OF_DATE:
      return "TEE_QV_RESULT_OUT_OF_DATE";
    case TEE_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
      return "TEE_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED";
    case TEE_QV_RESULT_INVALID_SIGNATURE:
      return "TEE_QV_RESULT_INVALID_SIGNATURE";
    case TEE_QV_RESULT_REVOKED:
      return "TEE_QV_RESULT_REVOKED";
    case TEE_QV_RESULT_UNSPECIFIED:
      return "TEE_QV_RESULT_UNSPECIFIED";
    case TEE_QV_RESULT_SW_HARDENING_NEEDED:
      return "TEE_QV_RESULT_SW_HARDENING_NEEDED";
    case TEE_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
      return "TEE_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED";
    case TEE_QV_RESULT_TD_RELAUNCH_ADVISED:
      return "TEE_QV_RESULT_TD_RELAUNCH_ADVISED";
    case TEE_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED:
      return "TEE_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED";
    case TEE_QV_RESULT_MAX:
      return "TEE_QL_QV_RESULT_MAX";
    default:
      return "UNKNOWN_QV_RESULT";
  }
}

td::CSlice to_str(tdx_attest_error_t result) {
  switch (result) {
    case TDX_ATTEST_SUCCESS:
      return "TDX_ATTEST_SUCCESS";
    case TDX_ATTEST_ERROR_UNEXPECTED:
      return "TDX_ATTEST_ERROR_UNEXPECTED";
    case TDX_ATTEST_ERROR_INVALID_PARAMETER:
      return "TDX_ATTEST_ERROR_INVALID_PARAMETER";
    case TDX_ATTEST_ERROR_OUT_OF_MEMORY:
      return "TDX_ATTEST_ERROR_OUT_OF_MEMORY";
    case TDX_ATTEST_ERROR_VSOCK_FAILURE:
      return "TDX_ATTEST_ERROR_VSOCK_FAILURE";
    case TDX_ATTEST_ERROR_REPORT_FAILURE:
      return "TDX_ATTEST_ERROR_REPORT_FAILURE";
    case TDX_ATTEST_ERROR_EXTEND_FAILURE:
      return "TDX_ATTEST_ERROR_EXTEND_FAILURE";
    case TDX_ATTEST_ERROR_NOT_SUPPORTED:
      return "TDX_ATTEST_ERROR_NOT_SUPPORTED";
    case TDX_ATTEST_ERROR_QUOTE_FAILURE:
      return "TDX_ATTEST_ERROR_QUOTE_FAILURE";
    case TDX_ATTEST_ERROR_BUSY:
      return "TDX_ATTEST_ERROR_BUSY";
    case TDX_ATTEST_ERROR_DEVICE_FAILURE:
      return "TDX_ATTEST_ERROR_DEVICE_FAILURE";
    case TDX_ATTEST_ERROR_INVALID_RTMR_INDEX:
      return "TDX_ATTEST_ERROR_INVALID_RTMR_INDEX";
    case TDX_ATTEST_ERROR_UNSUPPORTED_ATT_KEY_ID:
      return "TDX_ATTEST_ERROR_UNSUPPORTED_ATT_KEY_ID";
    default:
      return "UNKNOWN_TDX_ATTEST_ERROR";
  }
}

#endif  // TD_TDX_ATTESTATION

// TEE (Trusted Execution Environment) type constants
static constexpr td::uint32 TEE_TYPE_SGX = 0x00000000;
static constexpr td::uint32 TEE_TYPE_TDX = 0x00000081;

// Quote body type constants
static constexpr td::uint16 BODY_SGX_ENCLAVE_REPORT_TYPE = 1;
static constexpr td::uint16 BODY_TD_REPORT10_TYPE = 2;  // TDX 1.0
static constexpr td::uint16 BODY_TD_REPORT15_TYPE = 3;  // TDX 1.5

// Quote version constants
static constexpr td::uint16 QUOTE_VERSION_3 = 3;
static constexpr td::uint16 QUOTE_VERSION_4 = 4;
static constexpr td::uint16 QUOTE_VERSION_5 = 5;

// TDX report constants
static constexpr td::uint8 TDX_REPORT_TYPE = 0x81;
static constexpr td::uint8 TDX_REPORT_SUBTYPE_CURRENT = 0;
static constexpr td::uint8 TDX_REPORT_VERSION_1_0 = 0;
static constexpr td::uint8 TDX_REPORT_VERSION_1_5 = 1;

static constexpr size_t TDX_TD_INFO_OFFSET = 512;
static constexpr size_t TDX_FULL_REPORT_SIZE = 1024;

#pragma pack(push, 1)
struct QuoteHeader {
  uint16_t version;               // Quote format version (3, 4, or 5)
  uint16_t attestation_key_type;  // Attestation Key type (2 = ECDSA-256)
  uint32_t tee_type;              // TEE type (0x00000000 for SGX, 0x00000081 for TDX)
  uint8_t reserved1[2];           // Reserved (must be 0)
  uint8_t reserved2[2];           // Reserved (must be 0)
  uint8_t qe_vendor_id[16];       // QE vendor ID (16-byte UUID)
  uint8_t user_data[20];          // User data (e.g., platform ID in first 16 bytes)
};

struct BodyHeader {
  uint16_t body_type;  // Type of quote body (1=SGX, 2=TDX1.0, 3=TDX1.5)
  uint32_t size;       // Size of the quote body in bytes
};

struct TdxQuoteBody10 {
  uint8_t tee_tcb_svn[16];      // TEE TCB Security Version Number
  td::UInt384 mr_seam;          // Measurement of SEAM module
  td::UInt384 mr_signer_seam;   // Measurement of SEAM signer
  uint8_t seam_attributes[8];   // SEAM attributes
  uint8_t td_attributes[8];     // TD attributes
  uint8_t xfam[8];              // Extended Feature Allow Mask
  td::UInt384 mr_td;            // Measurement of initial TD contents (MRTD)
  td::UInt384 mr_config_id;     // Software-defined config ID (MRCONFIGID)
  td::UInt384 mr_owner;         // TD owner identifier (MROWNER)
  td::UInt384 mr_owner_config;  // Owner-defined config (MROWNERCONFIG)
  td::UInt384 rtmr0;            // Runtime measurement register 0 (RTMR0)
  td::UInt384 rtmr1;            // Runtime measurement register 1 (RTMR1)
  td::UInt384 rtmr2;            // Runtime measurement register 2 (RTMR2)
  td::UInt384 rtmr3;            // Runtime measurement register 3 (RTMR3)
  td::UInt512 report_data;      // 64-byte REPORTDATA (user-defined report data)
};

struct TdxQuoteBody15 {
  TdxQuoteBody10 body10;      // All TDX 1.0 fields
  uint8_t tee_tcb_svn_2[16];  // Additional TEE TCB SVN for TDX 1.5
  td::UInt384 mr_service_td;  // Measurement of Service TD (new in TDX 1.5)
};

struct SgxQuoteBody {
  uint8_t cpu_svn[16];      // CPU Security Version Number
  uint32_t misc_select;     // Miscellaneous select bits
  uint8_t reserved1[28];    // Reserved space
  uint8_t attributes[16];   // Enclave attributes
  td::UInt256 mr_enclave;   // Measurement of enclave (MRENCLAVE)
  uint8_t reserved2[32];    // Reserved space
  td::UInt256 mr_signer;    // Measurement of enclave signer (MRSIGNER)
  uint8_t reserved3[96];    // Reserved space
  uint16_t isv_prod_id;     // Independent Software Vendor Product ID
  uint16_t isv_svn;         // Independent Software Vendor Security Version Number
  uint8_t reserved4[60];    // Reserved space
  td::UInt512 report_data;  // 64-byte REPORTDATA (user-defined report data)
};
#pragma pack(pop)

using QuoteBody = td::Variant<TdxQuoteBody10, TdxQuoteBody15, SgxQuoteBody>;

td::Result<QuoteBody> tdx_quote_to_body(td::Slice quote) {
  // Validate minimum quote size
  if (quote.size() < sizeof(QuoteHeader)) {
    return td::Status::Error(PSLICE() << "Quote too small: got " << quote.size() << " bytes, need at least "
                                      << sizeof(QuoteHeader));
  }

  // Parse quote header
  TRY_RESULT(header, cut<QuoteHeader>(quote));
  auto body_slice = quote;

  uint16_t version = header.version;
  LOG(INFO) << "Parsing quote v" << version << ", TEE 0x" << td::format::as_hex(header.tee_type);

  switch (version) {
    case QUOTE_VERSION_3: {
      if (header.tee_type == TEE_TYPE_SGX) {
        return cut<SgxQuoteBody, QuoteBody>(body_slice);
      }
      return td::Status::Error(PSLICE() << "Unsupported TEE type for quote version 3: 0x"
                                        << td::format::as_hex(header.tee_type));
    }

    case QUOTE_VERSION_4: {
      if (header.tee_type == TEE_TYPE_SGX) {
        return cut<SgxQuoteBody, QuoteBody>(body_slice);
      }
      if (header.tee_type == TEE_TYPE_TDX) {
        return cut<TdxQuoteBody10, QuoteBody>(body_slice);
      }
      return td::Status::Error(PSLICE() << "Unsupported TEE type for quote version 4: 0x"
                                        << td::format::as_hex(header.tee_type));
    }

    case QUOTE_VERSION_5: {
      TRY_RESULT(body_header, cut<BodyHeader>(body_slice));
      if (body_header.size > body_slice.size()) {
        return td::Status::Error("Truncated v5 quote body");
      }
      if ((body_header.body_type == BODY_SGX_ENCLAVE_REPORT_TYPE && header.tee_type != TEE_TYPE_SGX) ||
          (body_header.body_type != BODY_SGX_ENCLAVE_REPORT_TYPE && header.tee_type != TEE_TYPE_TDX)) {
        return td::Status::Error("Quote platform and body type disagree");
      }
      body_slice.truncate(body_header.size);

      // v5 body type and size

      switch (body_header.body_type) {
        case BODY_SGX_ENCLAVE_REPORT_TYPE:
          return to<SgxQuoteBody, QuoteBody>(body_slice);
        case BODY_TD_REPORT10_TYPE:
          return to<TdxQuoteBody10, QuoteBody>(body_slice);
        case BODY_TD_REPORT15_TYPE:
          return to<TdxQuoteBody15, QuoteBody>(body_slice);
        default:
          return td::Status::Error(PSLICE() << "Unsupported body type: " << body_header.body_type);
      }
    }

    default:
      return td::Status::Error(PSLICE() << "Unsupported quote version: " << version << " (expected 3, 4, or 5)");
  }
}

TdxAttestationData from_body(const TdxQuoteBody10 &body) {
  TdxAttestationData result{};
  result.mr_td = body.mr_td;
  result.mr_config_id = body.mr_config_id;
  result.mr_owner = body.mr_owner;
  result.mr_owner_config = body.mr_owner_config;

  // Copy the four RTMR values
  result.rtmr[0] = body.rtmr0;
  result.rtmr[1] = body.rtmr1;
  result.rtmr[2] = body.rtmr2;
  result.rtmr[3] = body.rtmr3;

  result.reportdata = body.report_data;

  return result;
}
TdxAttestationData from_body(const TdxQuoteBody15 &body) {
  return from_body(body.body10);
}

SgxAttestationData from_body(const SgxQuoteBody &body) {
  SgxAttestationData result{};
  result.mr_enclave = body.mr_enclave;
  result.reportdata = body.report_data;
  return result;
}

td::Result<ParsedQuote> tdx_parse_quote(const Quote &quote) {
  if (quote.raw_quote.size() > 32768) {
    return td::Status::Error("TDX quote exceeds 32 KiB limit");
  }
  td::Slice input(quote.raw_quote);
  TRY_RESULT(header, cut<QuoteHeader>(input));
  if (header.tee_type != TEE_TYPE_TDX || header.attestation_key_type != 2) {
    return td::Status::Error("Expected an ECDSA-P256 TDX quote");
  }
  size_t body_size = sizeof(TdxQuoteBody10);
  td::uint16 body_type = BODY_TD_REPORT10_TYPE;
  if (header.version == QUOTE_VERSION_5) {
    TRY_RESULT(body_header, cut<BodyHeader>(input));
    body_type = body_header.body_type;
    body_size = body_header.size;
    if (!((body_type == BODY_TD_REPORT10_TYPE && body_size == sizeof(TdxQuoteBody10)) ||
          (body_type == BODY_TD_REPORT15_TYPE && body_size == sizeof(TdxQuoteBody15)))) {
      return td::Status::Error("Unsupported TDX v5 body type or size");
    }
  } else if (header.version != QUOTE_VERSION_4) {
    return td::Status::Error("Expected TDX quote version 4 or 5");
  }
  if (input.size() < body_size + sizeof(td::uint32)) {
    return td::Status::Error("Truncated TDX quote body or signature length");
  }
  auto body = input.substr(0, body_size);
  input.remove_prefix(body_size);
  TRY_RESULT(signature_size, cut<td::uint32>(input));
  if (signature_size == 0 || signature_size != input.size()) {
    return td::Status::Error("Invalid TDX quote signature length");
  }
  TRY_RESULT(body10, to<TdxQuoteBody10>(body.substr(0, sizeof(TdxQuoteBody10))));
  ParsedQuote result;
  result.attestation = from_body(body10);
  // Quote fields use little endian, independently of the host representation.
  for (unsigned i = 0; i < 8; ++i) {
    result.td_attributes |= static_cast<td::uint64>(body10.td_attributes[i]) << (8 * i);
  }
  if (body_type == BODY_TD_REPORT15_TYPE) {
    TRY_RESULT(body15, to<TdxQuoteBody15>(body));
    result.has_service_td = body15.mr_service_td != td::UInt384::zero();
  }
  return result;
}

#pragma pack(push, 1)
struct TdxReportType {
  uint8_t type;      // Report type: 0x81 for TDX (0 for SGX)
  uint8_t sub_type;  // Report subtype (0 for current versions)
  uint8_t version;   // Report version (0 for TDX 1.0, 1 for TDX 1.5)
  uint8_t reserved;  // Reserved byte (must be 0 in current spec)
};

struct TdxReportMac {
  TdxReportType type_hdr;         // Report type header (4 bytes)
  uint8_t reserved1[12];          // Reserved for future use
  uint8_t cpu_svn[16];            // CPU Security Version Number
  td::UInt384 tee_tcb_info_hash;  // SHA384 hash of TEE TCB info section
  td::UInt384 tee_td_info_hash;   // SHA384 hash of TD Info section
  td::UInt512 report_data;        // User-provided REPORTDATA
  uint8_t reserved2[32];          // Reserved for future use
  uint8_t mac[32];                // 32-byte MAC tag for integrity verification
};

struct TdxTdInfo {
  uint8_t attributes[8];        // TD attributes (ATTRIBUTES field)
  uint8_t xfam[8];              // Extended Feature Allow Mask (XFAM)
  td::UInt384 mr_td;            // Measurement of initial TD contents (MRTD)
  td::UInt384 mr_config_id;     // Measurement of TD configuration (MRCONFIGID)
  td::UInt384 mr_owner;         // TD owner identifier (MROWNER)
  td::UInt384 mr_owner_config;  // TD owner configuration (MROWNERCONFIG)
  td::UInt384 rtmr0;            // Runtime Measurement Register 0 (RTMR0)
  td::UInt384 rtmr1;            // Runtime Measurement Register 1 (RTMR1)
  td::UInt384 rtmr2;            // Runtime Measurement Register 2 (RTMR2)
  td::UInt384 rtmr3;            // Runtime Measurement Register 3 (RTMR3)
  uint8_t reserved[112];        // Reserved space (includes SERVTD_HASH if version=1)
};
#pragma pack(pop)

td::Result<TdxAttestationData> parse_tdx_report(td::Slice report) {
  // Validate report size
  static_assert(TDX_TD_INFO_OFFSET <= TDX_FULL_REPORT_SIZE);
  if (report.size() < TDX_FULL_REPORT_SIZE) {
    return td::Status::Error(PSLICE() << "TDX report too small: got " << report.size() << " bytes, expected "
                                      << TDX_FULL_REPORT_SIZE);
  }

  // Parse the REPORTMAC structure (first 256 bytes)
  auto report_copy = report;
  TRY_RESULT(report_mac, cut<TdxReportMac>(report_copy));

  // Validate report type
  if (report_mac.type_hdr.type != TDX_REPORT_TYPE) {
    return td::Status::Error(PSLICE() << "Invalid TDX report type: got 0x"
                                      << td::format::as_hex(report_mac.type_hdr.type) << ", expected 0x"
                                      << td::format::as_hex(TDX_REPORT_TYPE));
  }

  if (report_mac.type_hdr.sub_type != TDX_REPORT_SUBTYPE_CURRENT) {
    return td::Status::Error(PSLICE() << "Unsupported TDX report subtype: " << int(report_mac.type_hdr.sub_type)
                                      << " (expected 0)");
  }

  uint8_t version = report_mac.type_hdr.version;
  if (version != TDX_REPORT_VERSION_1_0 && version != TDX_REPORT_VERSION_1_5) {
    return td::Status::Error(PSLICE() << "Unsupported TDX report version: " << int(version) << " (expected 0 or 1)");
  }

  // Parse the TD Info section (512 bytes at offset 512)
  TRY_RESULT(td_info, to<TdxTdInfo>(report.substr(TDX_TD_INFO_OFFSET)));

  // Build attestation data structure
  TdxAttestationData result;

  // Copy 48-byte measurement fields (td::UInt384 is 48-byte type)
  result.mr_td = td_info.mr_td;
  result.mr_config_id = td_info.mr_config_id;
  result.mr_owner = td_info.mr_owner;
  result.mr_owner_config = td_info.mr_owner_config;

  // Copy the four Runtime Measurement Registers (each 48 bytes)
  result.rtmr[0] = td_info.rtmr0;
  result.rtmr[1] = td_info.rtmr1;
  result.rtmr[2] = td_info.rtmr2;
  result.rtmr[3] = td_info.rtmr3;

  // Copy the 64-byte REPORTDATA from the MAC structure
  result.reportdata = report_mac.report_data;

  // Note: SERVTD_HASH is available in td_info.reserved[0..47] if version==1

  return result;
}

#if TD_TDX_ATTESTATION

td::Result<Report> tdx_make_report(const td::UInt512 &user_claims_hash) {
  // Prepare report data structure
  tdx_report_data_t report_data;
  static_assert(TDX_REPORT_DATA_SIZE == 64, "TDX report data must be 64 bytes");
  static_assert(sizeof(report_data.d) == TDX_REPORT_DATA_SIZE, "Report data structure size mismatch");

  // Copy user claims hash into report data
  td::as<td::UInt512>(report_data.d) = user_claims_hash;

  // Generate TDX report
  tdx_report_t tdx_report;
  auto status = tdx_att_get_report(&report_data, &tdx_report);

  if (status != TDX_ATTEST_SUCCESS) {
    return td::Status::Error(PSLICE() << "Failed to generate TDX report: " << to_str(status) << " (0x"
                                      << td::format::as_hex(status) << ")");
  }

  return Report{td::Slice(tdx_report.d, TDX_REPORT_SIZE).str()};
}

namespace {

td::Result<std::vector<uint8_t>> validate_quote(const Quote &quote) {
  // Prepare verification parameters
  uint32_t collateral_expiration_status = 0;
  time_t current_time = std::time(nullptr);
  sgx_ql_qv_result_t verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
  quote3_error_t status = SGX_QL_SUCCESS;

  td::uint32 data_version = 0;
  td::uint32 data_size = 0;
  status = tee_get_supplemental_data_version_and_size(td::Slice(quote.raw_quote).ubegin(),
                                                      td::narrow_cast<uint32_t>(quote.raw_quote.size()), &data_version,
                                                      &data_size);
  if (status != SGX_QL_SUCCESS) {
    return td::Status::Error(PSLICE() << "Failed to get suppemental data size from collateral" << to_str(status)
                                      << " (0x" << td::format::as_hex(status) << ")");
  }
  if (data_size < sizeof(sgx_ql_qv_supplemental_t) || data_size > (1 << 20)) {
    return td::Status::Error(PSLICE() << "Supplemental data size is too large: " << data_size);
  }
  std::vector<uint8_t> supplemental_data(data_size);
  tee_supp_data_descriptor_t supplemental_data_descriptor = {
      .major_version = 0,
      .data_size = data_size,
      .p_data = supplemental_data.data(),
  };

  // Verify the quote using Intel's quote verification library
  status = tee_verify_quote(td::Slice(quote.raw_quote).ubegin(), td::narrow_cast<uint32_t>(quote.raw_quote.size()),
                            nullptr,  // No additional collateral
                            current_time, &collateral_expiration_status, &verification_result, nullptr,
                            &supplemental_data_descriptor);

  if (status != SGX_QL_SUCCESS) {
    return td::Status::Error(PSLICE() << "Quote verification failed: " << to_str(status) << " (0x"
                                      << td::format::as_hex(status) << ")");
  }

  if (verification_result != SGX_QL_QV_RESULT_OK) {
    return td::Status::Error(PSLICE() << "Quote verification result invalid: " << to_str(verification_result) << " (0x"
                                      << td::format::as_hex(verification_result) << ")");
  }

  if (collateral_expiration_status != 0) {
    return td::Status::Error(PSLICE() << "Collateral expired or invalid (status=" << collateral_expiration_status
                                      << ")");
  }

  return supplemental_data;
}

}  // namespace

td::Result<std::pair<SgxAttestationData, td::UInt384>> sgx_validate_quote(const Quote &quote) {
  TRY_RESULT(supplemental_data, validate_quote(quote));

  LOG(INFO) << "Extracting data from quote (" << quote.raw_quote.size() << ")";
  TRY_RESULT(quote_body, tdx_quote_to_body(quote.raw_quote));
  const SgxQuoteBody &sgx_quote_body = quote_body.get<const SgxQuoteBody &>();
  auto sgx_attestation_data = from_body(sgx_quote_body);
  TRY_RESULT(supplemental, to<sgx_ql_qv_supplemental_t>(td::Slice(supplemental_data.data(), supplemental_data.size())))
  td::UInt384 root_key_id = td::as<td::UInt384>(supplemental.root_key_id);

  return std::make_pair(sgx_attestation_data, root_key_id);
}

td::Result<VerifiedQuote> tdx_verify_quote(const Quote &quote) {
  TRY_RESULT(parsed, tdx_parse_quote(quote));
  TRY_RESULT(supplemental_data, validate_quote(quote));
  TRY_RESULT(supplemental, to<sgx_ql_qv_supplemental_t>(td::Slice(supplemental_data.data(), supplemental_data.size())));
  auto root_key_id = td::as<td::UInt384>(supplemental.root_key_id);
  return VerifiedQuote{std::move(parsed), root_key_id};
}

td::Result<std::pair<TdxAttestationData, td::UInt384>> tdx_validate_quote(const Quote &quote) {
  TRY_RESULT(verified, tdx_verify_quote(quote));
  return std::make_pair(verified.parsed.attestation, verified.collateral_root_hash);
}

td::Result<TdxAttestationData> tdx_parse_report(const Report &report) {
  if (report.raw_report.size() != TDX_FULL_REPORT_SIZE) {
    return td::Status::Error(PSLICE() << "Invalid TDX report size: got " << report.raw_report.size()
                                      << " bytes, expected " << TDX_FULL_REPORT_SIZE);
  }

  LOG(INFO) << "Parsing TDX report (" << report.raw_report.size() << ")";

  // Cast to SGX report structure for compatibility with existing code
  auto *sgx_report = reinterpret_cast<const sgx_report2_t *>(report.raw_report.data());

  // These pointers are used for accessing TEE info structures but not used in current implementation
  [[maybe_unused]] auto *tee_tcb_info_v1 = reinterpret_cast<const tee_tcb_info_t *>(sgx_report->tee_tcb_info);
  [[maybe_unused]] auto *tee_info_v1 = reinterpret_cast<const tee_info_t *>(sgx_report->tee_info);
  [[maybe_unused]] auto *tee_tcb_info_v1_5 = reinterpret_cast<const tee_tcb_info_v1_5_t *>(sgx_report->tee_tcb_info);
  [[maybe_unused]] auto *tee_info_v1_5 = reinterpret_cast<const tee_info_v1_5_t *>(sgx_report->tee_info);

  TRY_RESULT(tdx_attestation_data, parse_tdx_report(report.raw_report));
  return tdx_attestation_data;
}
#else

td::Result<VerifiedQuote> tdx_verify_quote(const Quote &quote) {
  return td::Status::Error("TDX is not supported on this platform");
}

td::Result<Report> tdx_make_report(const td::UInt512 &user_claims_hash) {
  return td::Status::Error("TDX is not supported on this platform");
}

td::Result<std::pair<SgxAttestationData, td::UInt384>> sgx_validate_quote(const Quote &quote) {
  return td::Status::Error("TDX is not supported on this platform");
}

td::Result<std::pair<TdxAttestationData, td::UInt384>> tdx_validate_quote(const Quote &quote) {
  return td::Status::Error("TDX is not supported on this platform");
}

td::Result<TdxAttestationData> tdx_parse_report(const Report &report) {
  return td::Status::Error("TDX is not supported on this platform");
}
#endif

td::Result<Quote> tdx_make_quote(const td::UInt512 &reportdata) {
#if TD_TDX_ATTESTATION
  tdx_report_data_t data{};
  static_assert(sizeof(data.d) == 64);
  std::memcpy(data.d, reportdata.as_slice().data(), sizeof(data.d));
  tdx_uuid_t selected_key{};
  uint8_t *buffer = nullptr;
  uint32_t size = 0;
  auto status = tdx_att_get_quote(&data, nullptr, 0, &selected_key, &buffer, &size, 0);
  std::unique_ptr<uint8_t, decltype(&tdx_att_free_quote)> owner(buffer, tdx_att_free_quote);
  if (status != TDX_ATTEST_SUCCESS || !buffer || size == 0 || size > 32768) {
    return td::Status::Error("TDX quote generation failed or exceeded the size limit");
  }
  return Quote{td::Slice(buffer, size).str()};
#else
  return td::Status::Error("TDX is not supported on this platform");
#endif
}

td::UInt256 image_hash(const TdxAttestationData &data) {
  TdxAttestationData tdx_copy = data;
  tdx_copy.reportdata = td::UInt512{};

  auto serialized = td::serialize(tdx_copy);

  td::UInt256 hash;
  td::sha256(serialized, hash.as_mutable_slice());
  return hash;
}

}  // namespace tdx
