#include "tee/cocoon/tdx/Tee.h"

#include "tee/cocoon/tdx/RATLS.h"
#include "tee/cocoon/tdx/tdx.h"

namespace tdx {

namespace {

// XXX:
// TODO
// It seems that quote isn't needed here

class FakeTdxTee : public cocoon::TeeInterface {
 public:
  td::Status prepare_cert_config(cocoon::TeeCertConfig& config,
                                 const tde2e_core::PublicKey& public_key) const override {
    UserClaims user_claims{public_key};
    RATLSAttestationReport report{};
    report.reportdata = user_claims.to_hash();
    config.extra_extensions.emplace_back(OID::TDX_QUOTE.c_str(), td::serialize(report));
    config.extra_extensions.emplace_back(OID::TDX_USER_CLAIMS.c_str(), user_claims.serialize());

    return td::Status::OK();
  }

  td::Result<cocoon::RATLSAttestationReport> make_report(const td::UInt512& user_claims) const override {
    RATLSAttestationReport report;

    report.reportdata = user_claims;

    return report;
  }
};

class TdxTee : public cocoon::TeeInterface {
 public:
  td::Status prepare_cert_config(cocoon::TeeCertConfig& config,
                                 const tde2e_core::PublicKey& public_key) const override {
    UserClaims user_claims{public_key};
    TRY_RESULT(quote, tdx_make_quote(user_claims.to_hash()));
    config.extra_extensions.emplace_back(OID::TDX_QUOTE.c_str(), quote.raw_quote);
    config.extra_extensions.emplace_back(OID::TDX_USER_CLAIMS.c_str(), user_claims.serialize());

    return td::Status::OK();
  }

  td::Result<cocoon::RATLSAttestationReport> make_report(const td::UInt512& user_claims) const override {
    TRY_RESULT(tdx_raw_report, tdx_make_report(user_claims));
    TRY_RESULT(attestation, tdx_parse_report(tdx_raw_report));

    return tdx::make_report(attestation, td::UInt384::zero());
  }

};

}  // namespace

td::Result<cocoon::TeeInterfaceRef> make_tee(bool fake, const TeeConfig& config) {
  if (fake) {
    return std::make_shared<FakeTdxTee>();
  }

  return std::make_shared<TdxTee>();
}

}  // namespace tdx
