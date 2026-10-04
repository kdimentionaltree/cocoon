#include "tee/cocoon/RATLS.h"

#include <algorithm>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "td/utils/misc.h"

#include "tee/cocoon/AttestationCache.h"
#include "tee/cocoon/utils.h"

namespace cocoon {

namespace {

constexpr size_t ED25519_PUBLIC_KEY_SIZE = 32;
constexpr size_t MAX_OID_BUFFER_SIZE = 128;
constexpr size_t MAX_CERT_NAME_BUFFER_SIZE = 1024;
constexpr int WARNING_THROTTLE_SECONDS = 60 * 5;

template <typename T>
bool is_allowed(const std::vector<T> &allowed_values, const T &actual) {
  if (!allowed_values.empty()) {
    return std::find(allowed_values.begin(), allowed_values.end(), actual) != allowed_values.end();
  }

  return true;
}

class DefaultPolicy : public RATLSPolicy {
 public:
  explicit DefaultPolicy(RATLSInterfaceRef ratls, RATLSPolicyConfig config = {})
      : ratls_(std::move(ratls)), config_(std::move(config)) {
  }

  td::Result<RATLSAttestationReport> validate(const tde2e_core::PublicKey &public_key) const override {
    if (ratls_) {
      return td::Status::Error("Attestation evidence is required by this policy");
    }
    // This is the special case when no expected extensions are present by client side
    if (config_.tdx_config.allowed_image_hashes.empty() && config_.sev_config.allowed_image_hashes.empty()) {
      // Just treat at tdx attestation report
      return tdx::RATLSAttestationReport{};
    }

    return td::Status::Error("No extensions present and allowed image hashes aren't empty");
  }

  td::Result<RATLSAttestationReport> validate(const tde2e_core::PublicKey &public_key,
                                              const tdx::RATLSExtensions &extensions) const override {
    // If there is no ratls interface, this is the "any" policy: allow without attestation
    if (!ratls_) {
      if (!config_.tdx_config.allowed_image_hashes.empty()) {
        return td::Status::Error("Image hash verification required but policy has no RATLS interface");
      }

      return tdx::RATLSAttestationReport{};
    }

    const auto reportdata = hash_public_key(public_key);
    TRY_RESULT(report, ratls_->attest(reportdata, extensions));

    // Verify reportdata matches user claims
    if (reportdata != report.reportdata) {
      return td::Status::Error("Report data mismatch (user claims don't match attestation)");
    }

    // Verify MRTD is in allowed list
    if (!is_allowed(config_.tdx_config.allowed_mrtd, report.mr_td)) {
      return td::Status::Error(PSLICE() << "MRTD not in policy allowlist: " << td::hex_encode(report.mr_td.as_slice()));
    }

    // Verify RTMR set is in allowed list
    if (!is_allowed(config_.tdx_config.allowed_rtmr, report.rtmr)) {
      return td::Status::Error("RTMR set not in policy allowlist");
    }

    // Verify image hash is in allowed list
    if (auto h = image_hash(report); !is_allowed(config_.tdx_config.allowed_image_hashes, h)) {
      return td::Status::Error(PSLICE() << "Image hash not in policy allowlist: " << td::hex_encode(h.as_slice()));
    }

    // Verify collateral root hash (Intel DCAP root key ID)
    if (!is_allowed(config_.tdx_config.allowed_collateral_root_hashes, report.collateral_root_hash)) {
      return td::Status::Error(PSLICE() << "Collateral root hash not in policy allowlist: "
                                        << td::hex_encode(report.collateral_root_hash.as_slice()));
    }

    return report;
  }

  td::Result<RATLSAttestationReport> validate(const tde2e_core::PublicKey &public_key,
                                              const sev::RATLSExtensions &extensions) const override {
    if (!ratls_) {
      if (!config_.sev_config.allowed_image_hashes.empty()) {
        return td::Status::Error("Image hash verification required but policy has no RATLS interface");
      }

      return sev::RATLSAttestationReport{};
    }

    const auto reportdata = hash_public_key(public_key);
    TRY_RESULT(report, ratls_->attest(reportdata, extensions));

    if (reportdata != report.reportdata) {
      return td::Status::Error("Report data mismatch (user claims don't match attestation)");
    }

    if (!is_allowed(config_.sev_config.allowed_measurement, report.measurement)) {
      return td::Status::Error(PSLICE() << "Measuremenet not in policy allowlist: "
                                        << td::hex_encode(report.measurement.as_slice()));
    }

    if (auto h = image_hash(report); !is_allowed(config_.sev_config.allowed_image_hashes, h)) {
      return td::Status::Error(PSLICE() << "Image hash not in policy allowlist: " << td::hex_encode(h.as_slice()));
    }

    return report;
  }

 private:
  RATLSInterfaceRef ratls_;
  RATLSPolicyConfig config_;
};

void append_cert_info(X509 *cert, td::StringBuilder &sb) {
  BIO *bio = BIO_new(BIO_s_mem());
  if (bio) {
    if (X509_print(bio, cert) == 1) {
      char *data = nullptr;
      long len = BIO_get_mem_data(bio, &data);
      if (data && len > 0) {
        sb << "Certificate details:\n" << td::Slice(data, len);
      }
    } else {
      sb << "Failed to print certificate details\n";
    }
    BIO_free(bio);
  } else {
    sb << "Failed to create BIO for certificate printing\n";
  }

  sb << "\nExtensions:\n";
  int num_ext = X509_get_ext_count(cert);
  for (int i = 0; i < num_ext; ++i) {
    X509_EXTENSION *ext = X509_get_ext(cert, i);
    if (!ext) {
      continue;
    }
    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);

    char oid_buf[MAX_OID_BUFFER_SIZE];
    int oid_len = OBJ_obj2txt(oid_buf, sizeof(oid_buf), obj, 1);
    auto oid = td::Slice(oid_buf, oid_len);

    if (oid == tdx::OID::TDX_QUOTE) {
      sb << "  Extension " << i << ": OID = TDX_QUOTE";
    } else if (oid == tdx::OID::TDX_USER_CLAIMS) {
      sb << "  Extension " << i << ": OID = TDX_USER_CLAIMS";
    } else if (oid == sev::OID::SEV_REPORT_DATA) {
      sb << "  Extension " << i << ": OID = SEV_REPORT_DATA";
    } else if (oid == sev::OID::SEV_ATTESTATION_REPORT) {
      sb << "  Extension " << i << ": OID = SEV_ATTESTATION_REPORT";
    } else if (oid == sev::OID::SEV_VCEK) {
      sb << "  Extension " << i << ": OID = SEV_VCEK";
    } else {
      continue;
    }

    ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(ext);
    if (ext_data) {
      const unsigned char *data = ASN1_STRING_get0_data(ext_data);
      int len = ASN1_STRING_length(ext_data);
      sb << ", Value (hex): " << td::format::as_hex_dump<0>(td::Slice(data, len)) << "\n";
    } else {
      sb << " (no data)\n";
    }
  }
}

td::Result<std::optional<std::string>> get_extension(X509 *cert, td::CSlice oid) {
  OPENSSL_MAKE_PTR(custom_oid, OBJ_txt2obj(oid.c_str(), 1), ASN1_OBJECT_free,
                   PSLICE() << "Failed to create OID object for: " << oid);  // 1 means allow numerical OID
  int ext_pos = X509_get_ext_by_OBJ(cert, custom_oid.get(), -1);
  if (ext_pos < 0) {
    return std::nullopt;
  }
  if (X509_get_ext_by_OBJ(cert, custom_oid.get(), ext_pos) >= 0) {
    return td::Status::Error("Duplicate attestation extension");
  }
  auto *ext = X509_get_ext(cert, ext_pos);
  CHECK(ext != nullptr);
  ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(ext);
  if (!ext_data) {
    return td::Status::Error(PSLICE() << "Failed to get extention data: " << oid);
  }
  const unsigned char *data = ASN1_STRING_get0_data(ext_data);
  int len = ASN1_STRING_length(ext_data);
  constexpr size_t MAX_TDX_QUOTE_EXTENSION_SIZE = 32 * 1024;  // 32 KiB hard cap for quote in X.509 extension
  if (oid == tdx::OID::TDX_QUOTE && len > td::narrow_cast<int>(MAX_TDX_QUOTE_EXTENSION_SIZE)) {
    return td::Status::Error(PSLICE() << "Quote extension too large: " << len << ", max "
                                      << MAX_TDX_QUOTE_EXTENSION_SIZE);
  }
  return td::Slice(data, len).str();
}

class RATLSVerifier {
 public:
  explicit RATLSVerifier(RATLSPolicyRef policy) : policy_(std::move(policy)) {
  }

 public:
  int verify_callback(int preverify_ok, void *ctx) const {
    auto *x509_ctx = static_cast<X509_STORE_CTX *>(ctx);
    if (!preverify_ok) {
      int err = X509_STORE_CTX_get_error(x509_ctx);
      if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
        return 1;
      }
      if (err == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION) {
        return 1;
      }

      char buf[MAX_CERT_NAME_BUFFER_SIZE];
      X509_NAME_oneline(X509_get_subject_name(X509_STORE_CTX_get_current_cert(x509_ctx)), buf,
                        MAX_CERT_NAME_BUFFER_SIZE);

      auto warning = PSTRING() << "verify error:num=" << err << ":" << X509_verify_cert_error_string(err)
                               << ":depth=" << X509_STORE_CTX_get_error_depth(x509_ctx) << ":"
                               << td::Slice(buf, std::strlen(buf));
      double now = td::Time::now();

      static std::mutex warning_mutex;
      static std::unordered_map<std::string, double> next_warning_time;

      {
        std::lock_guard<std::mutex> lock(warning_mutex);
        double &next = next_warning_time[warning];
        if (next <= now) {
          next = now + WARNING_THROTTLE_SECONDS;  // one warning per 5 minutes
          LOG(WARNING) << warning;
        }
      }

      return 0;
    }

    auto *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    FLOG(DEBUG) {
      sb << "Certificate verification callback called:\n";
      sb << "  Preverify result: " << (preverify_ok ? "OK" : "FAILED") << "\n";
      sb << "  Context pointer: " << ctx << "\n";
      if (cert) {
        append_cert_info(cert, sb);
      }
    };

    auto error_depth = X509_STORE_CTX_get_error_depth(x509_ctx);

    auto status = do_verify(cert, error_depth);
    if (status.is_error()) {
      FLOG(ERROR) {
        sb << "Certificate verification callback:\n";
        sb << "  Preverify result: " << (preverify_ok ? "OK" : "FAILED") << "\n";
        sb << "  Context pointer: " << ctx << "\n";
        if (cert) {
          append_cert_info(cert, sb);
        }
      };
      LOG(ERROR) << "Invalid certificate: " << status;
      return 0;
    }

    return 1;  // always allow
  }

  td::Status do_verify(X509 *cert, int error_depth) const {
    if (error_depth != 0) {
      return td::Status::Error("We currently allow only self signed certificates of depth 0");
    }

    if (!cert) {
      return td::Status::Error("Certificate is null");
    }

    int ext_count = X509_get_ext_count(cert);
    bool has_tdx_extensions = false, has_sev_extensions = false;

    for (int i = 0; i < ext_count; i++) {
      X509_EXTENSION *ex = X509_get_ext(cert, i);
      int crit = X509_EXTENSION_get_critical(ex);
      if (!crit || X509_supported_extension(ex)) {
        continue;
      }
      ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
      char oid_raw[MAX_OID_BUFFER_SIZE];
      OBJ_obj2txt(oid_raw, sizeof(oid_raw), obj, 1);
      auto oid = td::CSlice(oid_raw, oid_raw + strlen(oid_raw));

      if (oid == tdx::OID::TDX_QUOTE || oid == tdx::OID::TDX_USER_CLAIMS) {
        has_tdx_extensions = true;
        continue;
      }

      if (oid == sev::OID::SEV_REPORT_DATA || oid == sev::OID::SEV_ATTESTATION_REPORT || oid == sev::OID::SEV_VCEK) {
        has_sev_extensions = true;
        continue;
      }

      return td::Status::Error(PSLICE() << "Unknown critical oid=" << oid);
    }

    if (has_tdx_extensions && has_sev_extensions) {
      return td::Status::Error("TDX and SEV extensions are mutually exclusive");
    }

    OPENSSL_MAKE_PTR(pkey, X509_get_pubkey(cert), EVP_PKEY_free, "No public key found in the certificate");
    // TODO: use hash of key?
    if (EVP_PKEY_get_base_id(pkey.get()) != EVP_PKEY_ED25519) {
      return td::Status::Error("Public key is not Ed25519");
    }
    size_t pkey_length = ED25519_PUBLIC_KEY_SIZE;
    unsigned char buf[ED25519_PUBLIC_KEY_SIZE];
    OPENSSL_CHECK_OK(EVP_PKEY_get_raw_public_key(pkey.get(), buf, &pkey_length), "can't read public key's length");

    if (pkey_length != ED25519_PUBLIC_KEY_SIZE) {
      return td::Status::Error(PSLICE() << "Invalid Ed25519 key length: " << pkey_length);
    }

    TRY_RESULT(public_key, tde2e_core::PublicKey::from_slice(td::Slice(buf, ED25519_PUBLIC_KEY_SIZE)));

    if (has_tdx_extensions) {
      tdx::RATLSExtensions extensions;

      TRY_RESULT_ASSIGN(extensions.quote, get_extension(cert, tdx::OID::TDX_QUOTE));
      TRY_RESULT_ASSIGN(extensions.user_claims, get_extension(cert, tdx::OID::TDX_USER_CLAIMS));

      TRY_STATUS(policy_->validate(public_key, extensions));

      return td::Status::OK();
    }

    if (has_sev_extensions) {
      sev::RATLSExtensions extensions;

      TRY_RESULT_ASSIGN(extensions.report_data, get_extension(cert, sev::OID::SEV_REPORT_DATA));
      TRY_RESULT_ASSIGN(extensions.attestation_report, get_extension(cert, sev::OID::SEV_ATTESTATION_REPORT));
      TRY_RESULT_ASSIGN(extensions.vcek, get_extension(cert, sev::OID::SEV_VCEK));

      TRY_STATUS(policy_->validate(public_key, extensions));

      return td::Status::OK();
    }

    TRY_STATUS(policy_->validate(public_key));

    return td::Status::OK();
  }

 private:
  RATLSPolicyRef policy_;
};

class FakeRATLSInterface : public RATLSInterface {
 public:
  td::Result<sev::RATLSAttestationReport> attest(const td::UInt512 &user_claims,
                                                 const sev::RATLSExtensions &extensions) const override {
    sev::RATLSAttestationReport report{};

    report.reportdata = user_claims;

    return report;
  }

  td::Result<tdx::RATLSAttestationReport> attest(const td::UInt512 &user_claims,
                                                 const tdx::RATLSExtensions &extensions) const override {
    tdx::RATLSAttestationReport report{};

    report.reportdata = user_claims;

    return report;
  }
};

class RealRATLSInterface : public RATLSInterface {
 public:
  RealRATLSInterface(tdx::RATLSVerifier tdx_verifier, sev::RATLSVerifier sev_verifier)
      : tdx_verifier_(std::move(tdx_verifier)), sev_verifier_(std::move(sev_verifier)) {
  }

 public:
  td::Result<sev::RATLSAttestationReport> attest(const td::UInt512 &user_claims,
                                                 const sev::RATLSExtensions &extensions) const override {
    return sev_verifier_.verify(user_claims, extensions);
  }

  td::Result<tdx::RATLSAttestationReport> attest(const td::UInt512 &user_claims,
                                                 const tdx::RATLSExtensions &extensions) const override {
    return tdx_verifier_.verify(user_claims, extensions);
  }

 private:
  tdx::RATLSVerifier tdx_verifier_;
  sev::RATLSVerifier sev_verifier_;
};

class CachedRATLSInterface : public RATLSInterface {
 public:
  CachedRATLSInterface(RATLSInterfaceRef ratls, std::shared_ptr<cocoon::AttestationCache> cache)
      : ratls_(std::move(ratls)), cache_(std::move(cache)) {
  }

 public:
  // RATLSInterface
  td::Result<sev::RATLSAttestationReport> attest(const td::UInt512 &user_claims,
                                                 const sev::RATLSExtensions &extensions) const override {
    if (extensions.attestation_report) {
      const auto h = hash(*extensions.attestation_report);
      if (auto cached = cache_->get(h)) {
        if (cached->report.type() == TeeType::Sev) {
          LOG(DEBUG) << "Cache hit for quote hash " << h.as_slice();
          return cached->report.as_sev();
        }
      }

      TRY_RESULT(report, ratls_->attest(user_claims, extensions));

      cache_->put(h, RATLSAttestationReport(report));

      return report;
    }

    return td::Status::Error ("No extension SEV_ATTESTATION_REPORT");
  }

  td::Result<tdx::RATLSAttestationReport> attest(const td::UInt512 &user_claims,
                                                 const tdx::RATLSExtensions &extensions) const override {
    if (extensions.quote) {
      const auto h = hash(*extensions.quote);
      if (auto cached = cache_->get(h)) {
        if (cached->report.type() == TeeType::Tdx) {
          LOG(DEBUG) << "Cache hit for quote hash " << h.as_slice();
          return cached->report.as_tdx();
        }
      }

      TRY_RESULT(report, ratls_->attest(user_claims, extensions));

      cache_->put(h, RATLSAttestationReport(report));

      return report;
    }

    return td::Status::Error ("No extension TDX_QUOTE");
  }

 private:
  static td::UInt256 hash(td::Slice report_data) {
    td::UInt256 h;

    td::sha256(report_data, h.as_mutable_slice());

    return h;
  }

 private:
  RATLSInterfaceRef ratls_;
  std::shared_ptr<cocoon::AttestationCache> cache_;
};

}  // namespace

td::Result<RATLSAttestationReport> RATLSPolicy::validate(const tde2e_core::PublicKey &public_key) const {
  return td::Status::Error("No extensions present and allowed image hashes aren't empty");
}

td::UInt512 hash_public_key(const tde2e_core::PublicKey &public_key) {
  td::UInt512 hash;

  td::sha512(public_key.to_secure_string(), hash.as_mutable_slice());

  return hash;
}

td::StringBuilder &operator<<(td::StringBuilder &sb, const RATLSAttestationReport &report) {
  switch (report.type()) {
    case TeeType::Tdx:
      return sb << report.as_tdx();
    case TeeType::Sev:
      return sb << report.as_sev();
  }

  UNREACHABLE();
}

td::Result<RATLSPolicyConfig> parse_ratls_policy_from_json(td::JsonObject &obj) {
  RATLSPolicyConfig policy;

  auto r_tdx_config_field = obj.extract_optional_field("tdx_config", td::JsonValue::Type::Object);
  if (r_tdx_config_field.is_ok() && r_tdx_config_field.ok().type() == td::JsonValue::Type::Object) {
    TRY_RESULT(tdx_config, tdx::parse_policy_config(r_tdx_config_field.ok_ref().get_object()));
    policy.tdx_config = std::move(tdx_config);
  }

  auto r_sev_config_field = obj.extract_optional_field("sev_config", td::JsonValue::Type::Object);
  if (r_sev_config_field.is_ok() && r_sev_config_field.ok().type() == td::JsonValue::Type::Object) {
    TRY_RESULT(sev_config, sev::parse_policy_config(r_sev_config_field.ok_ref().get_object()));
    policy.sev_config = std::move(sev_config);
  }

  return policy;
}

td::StringBuilder &operator<<(td::StringBuilder &sb, const RATLSPolicyConfig &config) {
  sb << "{\n";
  sb << "  tdx_config:" << config.tdx_config;
  sb << ", sev_config:" << config.sev_config;
  sb << "}";

  return sb;
}

RATLSAttestationReport::RATLSAttestationReport(const tdx::RATLSAttestationReport &report) : report_(std::move(report)) {
}

RATLSAttestationReport::RATLSAttestationReport(const sev::RATLSAttestationReport &report) : report_(std::move(report)) {
}

td::CSlice RATLSAttestationReport::short_description() const {
  const auto t = type();

  if (t == TeeType::Tdx) {
    const auto &report = report_.get<tdx::RATLSAttestationReport>();
    if (report.rtmr[0].is_zero()) {
      return "fake TDX";
    }

    return "TDX";
  }

  if (t == TeeType::Sev) {
    const auto &report = report_.get<sev::RATLSAttestationReport>();
    if (report.measurement.is_zero()) {
      return "fake SEV";
    }

    return "SEV";
  }

  UNREACHABLE();
}

td::UInt256 RATLSAttestationReport::image_hash() const {
  const auto t = type ();

  if (t == TeeType::Tdx) {
    return tdx::image_hash(report_.get<const tdx::RATLSAttestationReport &>());
  }

  if (t == TeeType::Sev) {
    return sev::image_hash(report_.get<const sev::RATLSAttestationReport &>());
  }

  UNREACHABLE();
}

td::Slice RATLSAttestationReport::as_slice() const {
  const auto t = type();

  if (t == TeeType::Tdx) {
    const auto &report = report_.get<const tdx::RATLSAttestationReport &>();

    return td::Slice(reinterpret_cast<const char *>(&report), sizeof(report));
  }

  if (t == TeeType::Sev) {
    const auto &report = report_.get<const sev::RATLSAttestationReport &>();

    return td::Slice(reinterpret_cast<const char *>(&report), sizeof(report));
  }

  UNREACHABLE();
}

td::Result<RATLSInterfaceRef> RATLSInterface::make(td::actor::Scheduler *scheduler, bool fake, const Config &config) {
  if (fake) {
    return std::make_shared<FakeRATLSInterface>();
  }

  TRY_RESULT(tdx_verifier, tdx::RATLSVerifier::make(config.tdx_config));
  TRY_RESULT(sev_verifier, sev::RATLSVerifier::make(scheduler, config.sev_config));

  return std::make_shared<RealRATLSInterface>(std::move(tdx_verifier), std::move(sev_verifier));
}

td::Result<RATLSInterfaceRef> RATLSInterface::add_cache(RATLSInterfaceRef ratls,
                                                        std::shared_ptr<cocoon::AttestationCache> cache) {
  if (!ratls || !cache) {
    return td::Status::Error("Attestation verifier and cache must both be present");
  }
  return std::make_shared<CachedRATLSInterface>(std::move(ratls), std::move(cache));
}

RATLSPolicyRef RATLSPolicy::make(RATLSInterfaceRef ratls) {
  return std::make_shared<DefaultPolicy>(std::move(ratls));
}

RATLSPolicyRef RATLSPolicy::make(RATLSInterfaceRef ratls, RATLSPolicyConfig config) {
  return std::make_shared<DefaultPolicy>(std::move(ratls), std::move(config));
}

td::Result<RATLSAttestationReport> RATLSPolicyHelper::validate(const tde2e_core::PublicKey &public_key) const {
  auto maybe_report = policy_->validate(public_key);
  if (maybe_report.is_error()) {
    promise_.set_error(maybe_report.error().clone());
    return maybe_report.move_as_error();
  }

  auto report = maybe_report.move_as_ok();
  promise_.set_value(make_peer_info(public_key, report));

  return report;
}

td::Result<RATLSAttestationReport> RATLSPolicyHelper::validate(const tde2e_core::PublicKey &public_key,
                                                               const tdx::RATLSExtensions &extensions) const {
  auto maybe_report = policy_->validate(public_key, extensions);
  if (maybe_report.is_error()) {
    promise_.set_error(maybe_report.error().clone());
    return maybe_report.move_as_error();
  }

  auto report = maybe_report.move_as_ok();
  CHECK(report.type() == TeeType::Tdx);
  promise_.set_value(make_peer_info(public_key, report));

  return report;
}

td::Result<RATLSAttestationReport> RATLSPolicyHelper::validate(const tde2e_core::PublicKey &public_key,
                                                               const sev::RATLSExtensions &extensions) const {
  auto maybe_report = policy_->validate(public_key, extensions);
  if (maybe_report.is_error()) {
    promise_.set_error(maybe_report.error().clone());
    return maybe_report.move_as_error();
  }

  auto report = maybe_report.move_as_ok();
  CHECK(report.type() == TeeType::Sev);
  promise_.set_value(make_peer_info(public_key, report));

  return report;
}

RATLSAttestedPeerInfo RATLSPolicyHelper::make_peer_info(const tde2e_core::PublicKey &public_key,
                                                        const RATLSAttestationReport &report) const {
  RATLSPeerInfo peer_info;
  peer_info.source_ip = src_.get_ip_str().str();
  peer_info.source_port = src_.get_port();
  peer_info.destination_ip = dst_.get_ip_str().str();
  peer_info.destination_port = dst_.get_port();

  return RATLSAttestedPeerInfo(report, public_key, peer_info);
}

std::function<int(int, void *)> RATLSVerifyCallbackBuilder::from_policy(RATLSPolicyRef policy) {
  auto verifier = std::shared_ptr<const RATLSVerifier>(std::make_shared<RATLSVerifier>(std::move(policy)));
  return [verifier = std::move(verifier)](int preverify_ok, void *ctx) {
    return verifier->verify_callback(preverify_ok, ctx);
  };
}

RATLSContext *RATLS_extract_context(SSL_CTX *ssl_ctx, bool create_if_empty) {
  static int index = SSL_CTX_get_ex_new_index(
      0, nullptr, nullptr, nullptr, [](void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp) {
        delete static_cast<RATLSContext *>(ptr);
      });
  auto context = reinterpret_cast<RATLSContext *>(SSL_CTX_get_ex_data(ssl_ctx, index));
  if (!context && create_if_empty) {
    context = new RATLSContext{};
    SSL_CTX_set_ex_data(ssl_ctx, index, context);
  }
  return context;
}

int RATLS_verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
  SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
  SSL_CTX *ssl_ctx = ssl ? SSL_get_SSL_CTX(ssl) : nullptr;
  auto *custom_ctx = ssl_ctx ? RATLS_extract_context(ssl_ctx, false) : nullptr;
  CHECK(custom_ctx->custom_verify_callback);
  return custom_ctx->custom_verify_callback(preverify_ok, static_cast<void *>(ctx));
}

}  // namespace cocoon
