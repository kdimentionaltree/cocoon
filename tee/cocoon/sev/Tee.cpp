#include "tee/cocoon/sev/Tee.h"

#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include "td/utils/filesystem.h"

#include "tee/cocoon/RATLS.h"
#include "tee/cocoon/sev/ABI.h"
#include "tee/cocoon/sev/GuestDevice.h"
#include "tee/cocoon/sev/PKI.h"
#include "tee/cocoon/sev/RATLS.h"

namespace sev {

namespace {

td::Result<openssl_ptr<EVP_PKEY, EVP_PKEY_free>> make_pkey() {
  OPENSSL_MAKE_PTR(ctx, EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free,
                   "Failed to create EVP_PKEY_CTX");
  OPENSSL_CHECK_OK(EVP_PKEY_keygen_init(ctx.get()), "Cannot init PKEY keygen");
  const OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string("group", (char *)"secp384r1", 0),
                               OSSL_PARAM_construct_end()};

  OPENSSL_CHECK_OK(EVP_PKEY_CTX_set_params(ctx.get(), params), "Cannot set EVP_PKEY_CTX");
  EVP_PKEY *pkey = nullptr;
  OPENSSL_CHECK_OK(EVP_PKEY_keygen(ctx.get(), &pkey), "Cannot generate EVP_PKEY");

  return pkey;
}

td::Result<std::string> generate_vcek_cert(EVP_PKEY *pkey, const cocoon::TeeCertConfig &config) {
  // Validate configuration parameters
  if (config.country.size() != 2) {
    return td::Status::Error(
        PSLICE() << "Invalid country code: must be exactly 2 characters (ISO 3166-1 alpha-2), got '" << config.country
                 << "' (" << config.country.size() << " chars)");
  }

  if (config.common_name.empty()) {
    return td::Status::Error("Certificate common name cannot be empty");
  }

  if (config.validity_seconds == 0) {
    return td::Status::Error("Certificate validity must be positive");
  }

  constexpr td::uint32 MAX_VALIDITY_SECONDS = (1u << 30);
  if (config.validity_seconds > MAX_VALIDITY_SECONDS) {
    return td::Status::Error(PSLICE() << "Certificate validity too large: " << config.validity_seconds
                                      << " seconds (max: " << MAX_VALIDITY_SECONDS << ")");
  }

  // Create X.509 certificate structure
  OPENSSL_MAKE_PTR(certificate, X509_new(), X509_free, "Failed to create X509 certificate structure");
  OPENSSL_CHECK_OK(X509_set_pubkey(certificate.get(), pkey), "Cannot set X509 certificate public key");

  // Set certificate serial number: 128-bit random
  unsigned char serial_bytes[16];
  OPENSSL_CHECK_OK(RAND_bytes(serial_bytes, sizeof(serial_bytes)), "Failed to generate random serial");
  OPENSSL_MAKE_PTR(serial_bn, BN_bin2bn(serial_bytes, sizeof(serial_bytes), nullptr), BN_free,
                   "Failed to create BIGNUM for serial");
  OPENSSL_CHECK_PTR(BN_to_ASN1_INTEGER(serial_bn.get(), X509_get_serialNumber(certificate.get())),
                    "Failed to set certificate serial number");

  // Set certificate validity period
  if (config.current_time.has_value()) {
    // Use provided time instead of system time
    td::uint32 not_before = config.current_time.value();

    // Check for overflow when adding validity_seconds
    if (not_before > std::numeric_limits<td::uint32>::max() - config.validity_seconds) {
      return td::Status::Error(PSLICE() << "Certificate validity would overflow: notBefore=" << not_before
                                        << " + validity_seconds=" << config.validity_seconds);
    }
    td::uint32 not_after = not_before + config.validity_seconds;

    OPENSSL_MAKE_PTR(asn1_not_before, ASN1_TIME_set(nullptr, not_before), ASN1_TIME_free,
                     "Failed to create ASN1_TIME for notBefore");
    OPENSSL_MAKE_PTR(asn1_not_after, ASN1_TIME_set(nullptr, not_after), ASN1_TIME_free,
                     "Failed to create ASN1_TIME for notAfter");

    OPENSSL_CHECK_OK(X509_set1_notBefore(certificate.get(), asn1_not_before.get()),
                     "Failed to set certificate notBefore time");
    OPENSSL_CHECK_OK(X509_set1_notAfter(certificate.get(), asn1_not_after.get()),
                     "Failed to set certificate notAfter time");
  } else {
    // Use system time (backwards compatible)
    OPENSSL_CHECK_PTR(X509_gmtime_adj(X509_get_notBefore(certificate.get()), 0),
                      "Failed to set certificate notBefore time");
    OPENSSL_CHECK_PTR(X509_gmtime_adj(X509_get_notAfter(certificate.get()), config.validity_seconds),
                      "Failed to set certificate notAfter time");
  }

  // Set certificate public key
  OPENSSL_CHECK_OK(X509_set_pubkey(certificate.get(), pkey), "Failed to set certificate public key");

  X509V3_CTX v3;
  memset(&v3, 0, sizeof(v3));
  X509V3_set_ctx_nodb(&v3);
  X509V3_set_ctx(&v3, /*issuer*/ certificate.get(), /*subject*/ certificate.get(), nullptr, nullptr, 0);
  X509V3_CTX *v3_ptr = &v3;

  // Add Basic Constraints (critical, CA:FALSE)
  OPENSSL_MAKE_PTR(basic_constraints_extension,
                   X509V3_EXT_conf_nid(nullptr, v3_ptr, NID_basic_constraints, "critical,CA:FALSE"),
                   X509_EXTENSION_free, "Failed to create Basic Constraints extension");
  OPENSSL_CHECK_OK(X509_add_ext(certificate.get(), basic_constraints_extension.get(), -1),
                   "Failed to add Basic Constraints extension to certificate");

  // Add Key Usage (critical, digitalSignature only for Ed25519)
  OPENSSL_MAKE_PTR(key_usage_extension,
                   X509V3_EXT_conf_nid(nullptr, v3_ptr, NID_key_usage, "critical,digitalSignature"),
                   X509_EXTENSION_free, "Failed to create Key Usage extension");
  OPENSSL_CHECK_OK(X509_add_ext(certificate.get(), key_usage_extension.get(), -1),
                   "Failed to add Key Usage extension to certificate");

  // Add Extended Key Usage (critical)
  OPENSSL_MAKE_PTR(extended_key_usage_extension,
                   X509V3_EXT_conf_nid(nullptr, v3_ptr, NID_ext_key_usage, "critical,serverAuth,clientAuth"),
                   X509_EXTENSION_free, "Failed to create Extended Key Usage extension");
  OPENSSL_CHECK_OK(X509_add_ext(certificate.get(), extended_key_usage_extension.get(), -1),
                   "Failed to add Extended Key Usage extension to certificate");

  // Add Subject Key Identifier (hash)
  OPENSSL_MAKE_PTR(ski_extension, X509V3_EXT_conf_nid(nullptr, v3_ptr, NID_subject_key_identifier, "hash"),
                   X509_EXTENSION_free, "Failed to create Subject Key Identifier extension");
  OPENSSL_CHECK_OK(X509_add_ext(certificate.get(), ski_extension.get(), -1),
                   "Failed to add Subject Key Identifier extension to certificate");

  /*
  // Add Authority Key Identifier (keyid,issuer)
  OPENSSL_MAKE_PTR(aki_extension, X509V3_EXT_conf_nid(nullptr, v3_ptr, NID_authority_key_identifier, "keyid,issuer"),
                   X509_EXTENSION_free, "Failed to create Authority Key Identifier extension");
  OPENSSL_CHECK_OK(X509_add_ext(certificate.get(), aki_extension.get(), -1),
                   "Failed to add Authority Key Identifier extension to certificate");
  */

  // Build Subject Alternative Name extension
  std::string san_value;
  for (size_t i = 0; i < config.san_names.size(); ++i) {
    if (i > 0) {
      san_value += ",";
    }

    const auto &name = config.san_names[i];
    if (name.find(':') != std::string::npos && name != "localhost") {
      // Contains colon - likely IPv6 address
      san_value += "IP:" + name;
    } else if (name.find('.') != std::string::npos || name == "localhost") {
      // Contains dot or is localhost - treat as DNS name
      san_value += "DNS:" + name;
    } else {
      // Assume IPv4 address or other IP format
      san_value += "IP:" + name;
    }
  }

  OPENSSL_MAKE_PTR(san_extension, X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, san_value.c_str()),
                   X509_EXTENSION_free, "Failed to create Subject Alternative Name extension");

  OPENSSL_CHECK_OK(X509_add_ext(certificate.get(), san_extension.get(), -1),
                   "Failed to add Subject Alternative Name extension to certificate");

  // Set certificate subject name (also issuer, since self-signed)
  X509_NAME *subject_name = X509_get_subject_name(certificate.get());
  if (!subject_name) {
    return td::Status::Error("Failed to get certificate subject name structure");
  }

  // Add subject name components
  OPENSSL_CHECK_OK(X509_NAME_add_entry_by_txt(subject_name, "C", MBSTRING_ASC,
                                              (const unsigned char *)config.country.c_str(), -1, -1, 0),
                   PSLICE() << "Failed to add country '" << config.country << "' to certificate subject");

  OPENSSL_CHECK_OK(X509_NAME_add_entry_by_txt(subject_name, "ST", MBSTRING_ASC,
                                              (const unsigned char *)config.state.c_str(), -1, -1, 0),
                   PSLICE() << "Failed to add state '" << config.state << "' to certificate subject");

  if (!config.locality.empty()) {
    OPENSSL_CHECK_OK(X509_NAME_add_entry_by_txt(subject_name, "L", MBSTRING_ASC,
                                                (const unsigned char *)config.locality.c_str(), -1, -1, 0),
                     PSLICE() << "Failed to add locality '" << config.locality << "' to certificate subject");
  }

  OPENSSL_CHECK_OK(X509_NAME_add_entry_by_txt(subject_name, "O", MBSTRING_ASC,
                                              (const unsigned char *)config.organization.c_str(), -1, -1, 0),
                   PSLICE() << "Failed to add organization '" << config.organization << "' to certificate subject");

  OPENSSL_CHECK_OK(
      X509_NAME_add_entry_by_txt(subject_name, "OU", MBSTRING_ASC,
                                 (const unsigned char *)config.organizational_unit.c_str(), -1, -1, 0),
      PSLICE() << "Failed to add organizational unit '" << config.organizational_unit << "' to certificate subject");

  OPENSSL_CHECK_OK(X509_NAME_add_entry_by_txt(subject_name, "CN", MBSTRING_ASC,
                                              (const unsigned char *)config.common_name.c_str(), -1, -1, 0),
                   PSLICE() << "Failed to add common name '" << config.common_name << "' to certificate subject");

  // Set issuer name (same as subject for self-signed certificates)
  OPENSSL_CHECK_OK(X509_set_issuer_name(certificate.get(), subject_name), "Failed to set certificate issuer name");

  // Sign the certificate with the private key
  OPENSSL_CHECK_OK(X509_sign(certificate.get(), pkey, EVP_sha384()), "Failed to sign certificate with private key");

  // Convert certificate to PEM format
  OPENSSL_MAKE_PTR(certificate_bio, BIO_new(BIO_s_mem()), BIO_free,
                   "Failed to create memory BIO for certificate output");
  OPENSSL_CHECK_OK(PEM_write_bio_X509(certificate_bio.get(), certificate.get()),
                   "Failed to write certificate to PEM format");

  // Extract PEM data from BIO
  char *certificate_data = nullptr;
  long certificate_length = BIO_get_mem_data(certificate_bio.get(), &certificate_data);

  if (certificate_length <= 0 || !certificate_data) {
    return td::Status::Error("Failed to extract certificate data from BIO");
  }

  return std::string(certificate_data, certificate_length);
}

class FakeSevTee : public cocoon::TeeInterface {
 public:
  explicit FakeSevTee(std::string vcek) : vcek_(std::move(vcek)) {
  }

 public:
  td::Status prepare_cert_config(cocoon::TeeCertConfig &config,
                                 const tde2e_core::PublicKey &public_key) const override {
    td::UInt512 hash = cocoon::hash_public_key(public_key);

    sev::AttestationReport report = {};
    report.report_data = hash;

    config.extra_extensions.emplace_back(OID::SEV_REPORT_DATA.c_str(), hash.as_slice().str());
    config.extra_extensions.emplace_back(OID::SEV_ATTESTATION_REPORT.c_str(),
                                         td::Slice(reinterpret_cast<const char *>(&report), sizeof(report)).str());
    config.extra_extensions.emplace_back(OID::SEV_VCEK.c_str(), vcek_);

    return td::Status::OK();
  }

  td::Result<cocoon::RATLSAttestationReport> make_report(const td::UInt512 &user_claims) const override {
    RATLSAttestationReport report{};

    report.reportdata = user_claims;

    return report;
  }

 private:
  std::string vcek_;
};

class SevTee : public cocoon::TeeInterface {
 public:
  SevTee(std::string vcek, GuestDevice guest_device) : vcek_(std::move(vcek)), guest_device_(std::move(guest_device)) {
  }

 public:
  td::Status prepare_cert_config(cocoon::TeeCertConfig &config,
                                 const tde2e_core::PublicKey &public_key) const override {
    td::UInt512 hash = cocoon::hash_public_key(public_key);
    TRY_RESULT(report, guest_device_.get_report(hash));

    config.extra_extensions.emplace_back(OID::SEV_REPORT_DATA.c_str(), hash.as_slice().str());
    config.extra_extensions.emplace_back(OID::SEV_ATTESTATION_REPORT.c_str(),
                                         td::Slice(reinterpret_cast<const char *>(&report), sizeof(report)).str());
    config.extra_extensions.emplace_back(OID::SEV_VCEK.c_str(), vcek_);

    return td::Status::OK();
  }

  td::Result<cocoon::RATLSAttestationReport> make_report(const td::UInt512 &user_claims) const override {
    TRY_RESULT(report, guest_device_.get_report(user_claims));

    return RATLSAttestationReport{.measurement = report.measurement, .reportdata = report.report_data};
  }

 private:
  std::string vcek_;
  GuestDevice guest_device_;
};

}  // namespace

td::Result<cocoon::TeeInterfaceRef> make_tee(bool fake, const TeeConfig &config) {
  if (fake) {
    TRY_RESULT(pkey, make_pkey());
    TRY_RESULT(vcek, generate_vcek_cert(pkey.get(), cocoon::TeeCertConfig{}));

    return std::make_shared<FakeSevTee>(std::move(vcek));
  }

  TRY_RESULT(trust_chain_manager, TrustChainManager::make(nullptr, config.PKI_ROOT_DIR));
  TRY_RESULT(vcek_path, make_vcek_path(config.PKI_ROOT_DIR));
  TRY_RESULT(vcek_bytes, td::read_file_str(vcek_path));
  TRY_RESULT(vcek_cert, VCEKCertificate::create(vcek_bytes));
  TRY_RESULT(vcek_product_name_and_stepping, vcek_cert.productName());
  TRY_RESULT(vcek_product_name, product_name_from_name_and_stepping(vcek_product_name_and_stepping));
  TRY_STATUS(trust_chain_manager.verify_cert(vcek_product_name, vcek_cert.native_handle()));

  td::UInt512 user_claims;
  OPENSSL_CHECK_OK(RAND_bytes(user_claims.raw, sizeof(user_claims.raw)), "Failed to generate random user claims");
  TRY_RESULT(guest_device, GuestDevice::open());
  TRY_RESULT(report, guest_device.get_report(user_claims));
  TRY_STATUS(vcek_cert.verify_report(report, user_claims));

  return std::make_shared<SevTee>(std::move(vcek_bytes), std::move(guest_device));
}

}  // namespace sev
