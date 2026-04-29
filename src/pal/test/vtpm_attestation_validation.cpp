// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/pem.h"
#include "ccf/crypto/rsa_public_key.h"
#include "ccf/crypto/sha256.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/hex.h"
#include "ccf/ds/quote_info.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/attestation_vtpm.h"
#include "pal/test/vtpm_attestation_validation_data.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

using namespace ccf;
using namespace ccf::pal::vtpm;
using namespace ccf::pal::vtpm::testing;

TEST_CASE("parse_tpm2b_attest: valid GCP C2D quote parses correctly")
{
  auto parsed = parse_tpm2b_attest(
    std::span<const uint8_t>(c2d_tpm_quote.data(), c2d_tpm_quote.size()));

  const std::string actual_nonce(parsed.nonce.begin(), parsed.nonce.end());
  CHECK_EQ(actual_nonce, std::string(c2d_expected_nonce));
  CHECK_EQ(parsed.firmware_version, c2d_expected_firmware_version);
  REQUIRE_EQ(parsed.pcr_selection.size(), 1u);
  CHECK_EQ(parsed.pcr_selection[0].hash_algo, c2d_expected_hash_algo);
  CHECK_EQ(parsed.pcr_selection[0].pcr_indices, c2d_expected_pcr_indices);
  const auto expected_digest = ds::from_hex(c2d_expected_pcr_digest);
  CHECK_EQ(parsed.pcr_digest, expected_digest);
}

TEST_CASE("parse_tpm2b_attest: bad magic throws")
{
  auto bad_quote = c2d_tpm_quote;
  bad_quote[2] ^= 0xFF;
  CHECK_THROWS_AS(
    parse_tpm2b_attest(
      std::span<const uint8_t>(bad_quote.data(), bad_quote.size())),
    std::logic_error);
}

TEST_CASE("parse_tpm2b_attest: empty buffer throws")
{
  const std::vector<uint8_t> empty;
  CHECK_THROWS_AS(
    parse_tpm2b_attest(std::span<const uint8_t>(empty.data(), empty.size())),
    std::logic_error);
}

TEST_CASE("verify_tpm_quote_signature: valid GCP C2D quote verifies")
{
  ccf::crypto::Pem ak_pem(c2d_ak_pub_pem);
  ParsedAttest parsed;
  CHECK_NOTHROW(
    parsed =
      verify_tpm_quote_signature(c2d_tpm_quote, c2d_tpm_signature, ak_pem));
  const std::string actual_nonce(parsed.nonce.begin(), parsed.nonce.end());
  CHECK_EQ(actual_nonce, std::string(c2d_expected_nonce));
  CHECK_EQ(parsed.firmware_version, c2d_expected_firmware_version);
  REQUIRE_EQ(parsed.pcr_selection.size(), 1u);
  CHECK_EQ(parsed.pcr_selection[0].pcr_indices, c2d_expected_pcr_indices);
}

TEST_CASE("verify_tpm_quote_signature: corrupted quote fails verification")
{
  ccf::crypto::Pem ak_pem(c2d_ak_pub_pem);
  auto bad_quote = c2d_tpm_quote;
  bad_quote[bad_quote.size() - 1] ^= 0xFF;
  CHECK_THROWS_AS(
    verify_tpm_quote_signature(bad_quote, c2d_tpm_signature, ak_pem),
    std::logic_error);
}

TEST_CASE("verify_tpm_quote_signature: corrupted signature fails verification")
{
  ccf::crypto::Pem ak_pem(c2d_ak_pub_pem);
  auto bad_sig = c2d_tpm_signature;
  bad_sig[bad_sig.size() - 1] ^= 0xFF;
  CHECK_THROWS_AS(
    verify_tpm_quote_signature(c2d_tpm_quote, bad_sig, ak_pem),
    std::logic_error);
}

TEST_CASE("N2D: parse_tpm2b_attest: valid GCP N2D quote parses correctly")
{
  auto parsed = parse_tpm2b_attest(
    std::span<const uint8_t>(n2d_tpm_quote.data(), n2d_tpm_quote.size()));

  CHECK_EQ(parsed.firmware_version, n2d_expected_firmware_version);
  REQUIRE_EQ(parsed.pcr_selection.size(), 1u);
  CHECK_EQ(parsed.pcr_selection[0].hash_algo, n2d_expected_hash_algo);
  const std::vector<uint32_t> expected_pcrs = {0, 1, 2, 3, 4, 5, 6, 7};
  CHECK_EQ(parsed.pcr_selection[0].pcr_indices, expected_pcrs);
  const auto expected_digest = ds::from_hex(n2d_expected_pcr_digest);
  CHECK_EQ(parsed.pcr_digest, expected_digest);
}

TEST_CASE("N2D: verify_tpm_quote_signature: valid GCP N2D quote verifies")
{
  ccf::crypto::Pem ak_pem(n2d_ak_pub_pem);
  ParsedAttest parsed;
  CHECK_NOTHROW(
    parsed =
      verify_tpm_quote_signature(n2d_tpm_quote, n2d_tpm_signature, ak_pem));
  CHECK_EQ(parsed.firmware_version, n2d_expected_firmware_version);
  REQUIRE_EQ(parsed.pcr_selection.size(), 1u);
  CHECK_EQ(
    parsed.pcr_selection[0].pcr_indices,
    std::vector<uint32_t>({0, 1, 2, 3, 4, 5, 6, 7}));
}

TEST_CASE("N2D: verify_tpm_quote_signature: corrupted N2D quote fails")
{
  ccf::crypto::Pem ak_pem(n2d_ak_pub_pem);
  auto bad_quote = n2d_tpm_quote;
  bad_quote[bad_quote.size() - 1] ^= 0xFF;
  CHECK_THROWS_AS(
    verify_tpm_quote_signature(bad_quote, n2d_tpm_signature, ak_pem),
    std::logic_error);
}

TEST_CASE("N2D: SNP report_data contains SHA256(EK_pub_DER)")
{
  constexpr size_t REPORT_DATA_OFFSET = 0x50;
  constexpr size_t HASH_SIZE = 32;

  REQUIRE_GE(n2d_snp_report.size(), REPORT_DATA_OFFSET + HASH_SIZE);

  ccf::crypto::Pem ek_pem(n2d_ek_pub_pem);
  auto ek_verifier = ccf::crypto::make_rsa_public_key(ek_pem);
  auto ek_der = ek_verifier->public_key_der();
  auto ek_hash =
    ccf::crypto::sha256(std::span<const uint8_t>(ek_der.data(), ek_der.size()));

  const uint8_t* report_data = n2d_snp_report.data() + REPORT_DATA_OFFSET;
  CHECK_EQ(memcmp(report_data, ek_hash.data(), HASH_SIZE), 0);

  const auto expected = ds::from_hex(n2d_ek_pub_hash);
  CHECK_EQ(ek_hash, expected);
}

TEST_CASE("N2D: Step 1: verify_snp_attestation_report with real N2D data")
{
  ccf::QuoteInfo quote_info;
  quote_info.format = ccf::QuoteFormat::amd_sev_snp_v1;
  quote_info.quote = n2d_snp_report;

  const std::string_view endorsements_sv(n2d_snp_endorsements);
  quote_info.endorsements =
    std::vector<uint8_t>(endorsements_sv.begin(), endorsements_sv.end());

  ccf::pal::PlatformAttestationMeasurement measurement;
  ccf::pal::PlatformAttestationReportData report_data;

  CHECK_NOTHROW(ccf::pal::verify_snp_attestation_report(
    quote_info, measurement, report_data));
}

TEST_CASE("Step 3: AK certificate signed by wrong CA fails verification")
{
  ccf::crypto::Pem wrong_ek_cert(test_ak_cert_pem);
  ccf::crypto::Pem ak_cert(test_ak_cert_pem);

  auto ak_verifier = ccf::crypto::make_verifier(ak_cert);
  const ccf::crypto::Pem* wrong_ptr = &wrong_ek_cert;
  CHECK_FALSE(ak_verifier->verify_certificate({wrong_ptr}, {}, true));
}

TEST_CASE("CS: parse_tpm2b_attest: valid GCP CS quote parses correctly")
{
  auto parsed = parse_tpm2b_attest(
    std::span<const uint8_t>(cs_tpm_quote.data(), cs_tpm_quote.size()));

  CHECK_EQ(parsed.firmware_version, cs_expected_firmware_version);
  REQUIRE_EQ(parsed.pcr_selection.size(), 1u);
  CHECK_EQ(parsed.pcr_selection[0].hash_algo, 0x000bu);
  const std::vector<uint32_t> expected_pcrs = {0, 1, 2, 3, 4, 5, 6, 7};
  CHECK_EQ(parsed.pcr_selection[0].pcr_indices, expected_pcrs);
  const auto expected_digest = ds::from_hex(cs_expected_pcr_digest);
  CHECK_EQ(parsed.pcr_digest, expected_digest);
}

TEST_CASE("CS: verify_tpm_quote_signature: valid GCP CS quote verifies")
{
  ccf::crypto::Pem ak_pem(cs_ak_pub_pem);
  ParsedAttest parsed;
  CHECK_NOTHROW(
    parsed =
      verify_tpm_quote_signature(cs_tpm_quote, cs_tpm_signature, ak_pem));
  CHECK_EQ(parsed.firmware_version, cs_expected_firmware_version);
  REQUIRE_EQ(parsed.pcr_selection.size(), 1u);
  CHECK_EQ(
    parsed.pcr_selection[0].pcr_indices,
    std::vector<uint32_t>({0, 1, 2, 3, 4, 5, 6, 7}));
  const auto expected_digest = ds::from_hex(cs_expected_pcr_digest);
  CHECK_EQ(parsed.pcr_digest, expected_digest);
}

TEST_CASE(
  "CS: verify_tpm_quote_signature: corrupted Confidential Space quote fails")
{
  ccf::crypto::Pem ak_pem(cs_ak_pub_pem);
  auto bad_quote = cs_tpm_quote;
  bad_quote[bad_quote.size() - 1] ^= 0xFF;
  CHECK_THROWS_AS(
    verify_tpm_quote_signature(bad_quote, cs_tpm_signature, ak_pem),
    std::logic_error);
}

TEST_CASE("CS: Step 1: verify_snp_attestation_report with real CS data")
{
  ccf::QuoteInfo quote_info;
  quote_info.format = ccf::QuoteFormat::amd_sev_snp_v1;
  quote_info.quote = cs_snp_report;

  const std::string_view endorsements_sv(cs_snp_endorsements);
  quote_info.endorsements =
    std::vector<uint8_t>(endorsements_sv.begin(), endorsements_sv.end());

  ccf::pal::PlatformAttestationMeasurement measurement;
  ccf::pal::PlatformAttestationReportData report_data;

  CHECK_NOTHROW(ccf::pal::verify_snp_attestation_report(
    quote_info, measurement, report_data));
}

TEST_CASE("CS: Step 2: SHA256(EK_pub_DER) == snp.report_data[0:32]")
{
  constexpr size_t REPORT_DATA_OFFSET = 0x50;
  constexpr size_t HASH_SIZE = 32;

  REQUIRE_GE(cs_snp_report.size(), REPORT_DATA_OFFSET + HASH_SIZE);

  ccf::crypto::Pem ek_pem(cs_ek_pub_pem);
  auto ek_verifier = ccf::crypto::make_rsa_public_key(ek_pem);
  auto ek_der = ek_verifier->public_key_der();
  auto ek_hash =
    ccf::crypto::sha256(std::span<const uint8_t>(ek_der.data(), ek_der.size()));

  const uint8_t* report_data = cs_snp_report.data() + REPORT_DATA_OFFSET;
  CHECK_EQ(memcmp(report_data, ek_hash.data(), HASH_SIZE), 0);

  const auto expected = ds::from_hex(cs_ek_pub_hash);
  CHECK_EQ(ek_hash, expected);
}

TEST_CASE("AZ: parse_tpm2b_attest: valid Azure CVM quote parses correctly")
{
  auto parsed = parse_tpm2b_attest(
    std::span<const uint8_t>(az_tpm_quote.data(), az_tpm_quote.size()));

  CHECK_EQ(parsed.firmware_version, az_expected_firmware_version);
  REQUIRE_EQ(parsed.pcr_selection.size(), 1u);
  CHECK_EQ(parsed.pcr_selection[0].hash_algo, az_expected_hash_algo);
  CHECK_EQ(parsed.pcr_selection[0].pcr_indices, az_expected_pcr_indices);
  const auto expected_digest = ds::from_hex(az_expected_pcr_digest);
  CHECK_EQ(parsed.pcr_digest, expected_digest);
  const std::string actual_nonce(parsed.nonce.begin(), parsed.nonce.end());
  CHECK_EQ(actual_nonce, az_expected_nonce);
}

TEST_CASE("AZ: verify_tpm_quote_signature: valid Azure CVM quote verifies")
{
  ccf::crypto::Pem ak_pem(az_ak_pub_pem);
  ParsedAttest parsed;
  CHECK_NOTHROW(
    parsed =
      verify_tpm_quote_signature(az_tpm_quote, az_tpm_signature, ak_pem));
  CHECK_EQ(parsed.firmware_version, az_expected_firmware_version);
  REQUIRE_EQ(parsed.pcr_selection.size(), 1u);
  CHECK_EQ(parsed.pcr_selection[0].pcr_indices, az_expected_pcr_indices);
  const auto expected_digest = ds::from_hex(az_expected_pcr_digest);
  CHECK_EQ(parsed.pcr_digest, expected_digest);
}

TEST_CASE("AZ: verify_tpm_quote_signature: corrupted Azure CVM quote fails")
{
  ccf::crypto::Pem ak_pem(az_ak_pub_pem);
  auto bad_quote = az_tpm_quote;
  bad_quote[bad_quote.size() - 1] ^= 0xFF;
  CHECK_THROWS_AS(
    verify_tpm_quote_signature(bad_quote, az_tpm_signature, ak_pem),
    std::logic_error);
}

TEST_CASE("AZ: Step 1: verify_snp_attestation_report with real Azure CVM data")
{
  ccf::QuoteInfo quote_info;
  quote_info.format = ccf::QuoteFormat::amd_sev_snp_v1;
  quote_info.quote = az_snp_report;

  const std::string_view endorsements_sv(az_snp_endorsements);
  quote_info.endorsements =
    std::vector<uint8_t>(endorsements_sv.begin(), endorsements_sv.end());

  ccf::pal::PlatformAttestationMeasurement measurement;
  ccf::pal::PlatformAttestationReportData report_data;

  CHECK_NOTHROW(ccf::pal::verify_snp_attestation_report(
    quote_info, measurement, report_data));
}

TEST_CASE("AZ: Step 2: SHA256(HCL_variable_data) == snp.report_data[0:32]")
{
  constexpr size_t REPORT_DATA_OFFSET = 0x50;
  constexpr size_t HASH_SIZE = 32;

  REQUIRE_GE(az_snp_report.size(), REPORT_DATA_OFFSET + HASH_SIZE);

  auto var_hash = ccf::crypto::sha256(std::span<const uint8_t>(
    az_hcl_variable_data.data(), az_hcl_variable_data.size()));

  const uint8_t* report_data_field = az_snp_report.data() + REPORT_DATA_OFFSET;
  CHECK_EQ(memcmp(report_data_field, var_hash.data(), HASH_SIZE), 0);

  const auto expected = ds::from_hex(az_expected_snp_report_data_hash);
  CHECK_EQ(var_hash, expected);
}

TEST_CASE("AZ: Step 3: AK cert verified against Azure Virtual TPM CA chain")
{
  // Azure provisions AK certs from their Virtual TPM CA hierarchy
  // (Root-2023 → CA-2025 → ICA-11 → AK cert), not EK-signed like GCP.
  // Use ignore_time=false: the AK cert is currently valid (expires 2027-04-12).
  // ignore_time=true cannot be used here because X509_STORE_CTX_set0_param
  // replaces inherited store params (including X509_V_FLAG_PARTIAL_CHAIN) with
  // a fresh X509_VERIFY_PARAM that lacks it, causing ICA-11 to fail as a trust
  // anchor.
  ccf::crypto::Pem ak_cert(az_ak_cert_pem);
  auto ak_verifier = ccf::crypto::make_verifier(ak_cert);

  auto ca_certs = ccf::crypto::split_x509_cert_bundle(az_vtpm_ca_chain_pem);
  REQUIRE_GE(ca_certs.size(), 3u);

  const ccf::crypto::Pem* ica11_ptr = &ca_certs[0];
  CHECK(ak_verifier->verify_certificate({ica11_ptr}, {}, false));
}

int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  return context.run();
}
