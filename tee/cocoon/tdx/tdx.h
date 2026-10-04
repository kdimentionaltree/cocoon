#pragma once
#include "td/e2e/Keys.h"
#include "td/net/SslCtx.h"
#include "td/utils/UInt.h"
#include "td/utils/Variant.h"
#include "td/utils/crypto.h"
#include "td/utils/format.h"
#include "tee/cocoon/tdx/PolicyConfig.h"
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#if TD_TDX_ATTESTATION
#include "sgx_dcap_quoteverify.h"
#include "sgx_default_quote_provider.h"
#include "sgx_quote_5.h"
#include "tdx_attest.h"
#endif

namespace cocoon {
class AttestationCache;
}

// Forward declarations to reduce compilation dependencies
namespace tde2e_core {
class PrivateKey;
class PublicKey;
}  // namespace tde2e_core

namespace tdx {

/**
 * @brief Structure to hold extracted TDX measurement fields
 * 
 * Contains all the measurement registers and report data from a TDX attestation
 */
struct TdxAttestationData {
  td::UInt384 mr_td;                ///< Measurement of initial TD contents
  td::UInt384 mr_config_id;         ///< Software-defined config ID
  td::UInt384 mr_owner;             ///< TD owner identifier
  td::UInt384 mr_owner_config;      ///< Owner-defined config
  std::array<td::UInt384, 4> rtmr;  ///< Runtime measurement registers [0..3]
  td::UInt512 reportdata;           ///< User-defined report data

  template <class StorerT>
  void store(StorerT &storer) const {
    using td::store;
    store(mr_td, storer);
    store(mr_config_id, storer);
    store(mr_owner, storer);
    store(mr_owner_config, storer);
    for (size_t i = 0; i < 4; i++) {
      store(rtmr[i], storer);
    }
    store(reportdata, storer);
  }

  template <class ParserT>
  void parse(ParserT &parser) {
    using td::parse;
    parse(mr_td, parser);
    parse(mr_config_id, parser);
    parse(mr_owner, parser);
    parse(mr_owner_config, parser);
    for (size_t i = 0; i < 4; i++) {
      parse(rtmr[i], parser);
    }
    parse(reportdata, parser);
  }
};

/**
 * @brief Structure to hold extracted SGX measurement fields
 * 
 * Contains enclave measurements and report data from SGX attestation
 */
struct SgxAttestationData {
  //TODO: Add more SGX-specific fields
  td::UInt256 mr_enclave;  ///< Measurement of enclave
  td::UInt512 reportdata;  ///< User-defined report data

  template <class StorerT>
  void store(StorerT &storer) const {
    using td::store;
    store(mr_enclave, storer);
    store(reportdata, storer);
  }

  template <class ParserT>
  void parse(ParserT &parser) {
    using td::parse;
    parse(mr_enclave, parser);
    parse(reportdata, parser);
  }
};

td::StringBuilder &operator<<(td::StringBuilder &sb, const SgxAttestationData &data);
td::StringBuilder &operator<<(td::StringBuilder &sb, const TdxAttestationData &data);

/**
 * @brief User claims structure for attestation
 * 
 * Contains user-specific data that will be included in attestation reports
 */
struct UserClaims {
  tde2e_core::PublicKey public_key;  ///< User's public key
  // TODO: Add other claims like user ID, permissions, etc.

  /**
   * @brief Generate hash of user claims for inclusion in attestation
   * @return SHA-512 hash of serialized claims
   */
  td::UInt512 to_hash() const;

  /**
   * @brief Serialize user claims to string format
   * @return Serialized claims as string
   */
  std::string serialize() const;

  template <class StorerT>
  void store(StorerT &storer) const {
    using td::store;
    auto key_str = public_key.to_secure_string();
    store(key_str, storer);
  }

  template <class ParserT>
  void parse(ParserT &parser) {
    using td::parse;
    std::string key_str;
    parse(key_str, parser);
    auto r_key = tde2e_core::PublicKey::from_slice(td::Slice(key_str));
    if (r_key.is_error()) {
      parser.set_error(PSTRING() << "Failed to parse PublicKey: " << r_key.error());
      return;
    }
    public_key = r_key.move_as_ok();
  }
};

/**
 * @brief Raw quote data from TDX/SGX attestation
 */
struct Quote {
  std::string raw_quote;  ///< Raw binary quote data
};

/**
 * @brief Raw report data from TDX attestation
 */
struct Report {
  std::string raw_report;  ///< Raw binary report data
};

// Kept separate from serialized reports: existing image hashes and certificate ABI are unchanged.
struct ParsedQuote {
  TdxAttestationData attestation;
  td::uint64 td_attributes{0};
  bool has_service_td{false};
};
struct VerifiedQuote {
  ParsedQuote parsed;
  td::UInt384 collateral_root_hash;
};

td::Result<Quote> tdx_make_quote(const td::UInt512 &reportdata);
// Structural parsing is not cryptographic verification.
td::Result<ParsedQuote> tdx_parse_quote(const Quote &quote);
td::Result<VerifiedQuote> tdx_verify_quote(const Quote &quote);

td::Result<Report> tdx_make_report(const td::UInt512 &user_claims_hash);
td::Result<std::pair<SgxAttestationData, td::UInt384>> sgx_validate_quote(const Quote &quote);
td::Result<std::pair<TdxAttestationData, td::UInt384>> tdx_validate_quote(const Quote &quote);
td::Result<TdxAttestationData> tdx_parse_report(const Report &report);
td::UInt256 image_hash(const TdxAttestationData &data);

#if TD_TDX_ATTESTATION
td::CSlice to_str(quote3_error_t result);
td::CSlice to_str(sgx_ql_qv_result_t result);
td::CSlice to_str(tdx_attest_error_t result);
#endif

}  // namespace tdx
