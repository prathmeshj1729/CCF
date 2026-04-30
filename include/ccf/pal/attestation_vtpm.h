// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/ds/quote_info.h"
#include "ccf/pal/measurement.h"
#include "ccf/pal/report_data.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace ccf::pal::vtpm
{
  /// TPM2_GENERATED_VALUE — magic number that must appear in every TPMS_ATTEST
  static constexpr uint32_t TPM_GENERATED_VALUE = 0xFF544347u;

  /// TPM_ST_ATTEST_QUOTE — structure tag for a PCR quote
  static constexpr uint16_t TPM_ST_ATTEST_QUOTE = 0x8018u;

  /// Hash algorithm IDs (TPMI_ALG_HASH)
  static constexpr uint16_t TPM_ALG_SHA1 = 0x0004u;
  static constexpr uint16_t TPM_ALG_SHA256 = 0x000Bu;
  static constexpr uint16_t TPM_ALG_SHA384 = 0x000Cu;
  static constexpr uint16_t TPM_ALG_SHA512 = 0x000Du;

  /// Signature algorithm IDs (TPMI_ALG_SIG_SCHEME)
  static constexpr uint16_t TPM_ALG_RSASSA = 0x0014u;
  static constexpr uint16_t TPM_ALG_ECDSA = 0x0018u;

  /// Decoded TPMS_PCR_SELECTION — which PCRs are covered and with what hash
  struct PcrSelection
  {
    uint16_t hash_algo = 0;
    std::vector<uint32_t> pcr_indices; ///< decoded from per-byte bitmask
  };

  /// Parsed fields from a TPMS_ATTEST structure
  struct ParsedAttest
  {
    std::vector<uint8_t> nonce; ///< extraData field
    std::vector<uint8_t> pcr_digest; ///< SHA-N digest over selected PCRs
    std::vector<PcrSelection> pcr_selection; ///< which PCRs were quoted
    uint64_t firmware_version = 0;
  };

  struct VtpmAttestationClaims
  {
    /// SNP attestation measurement (48 bytes for AMD SEV-SNP)
    PlatformAttestationMeasurement snp_measurement;
    /// SNP report_data field (64 bytes for AMD SEV-SNP)
    PlatformAttestationReportData snp_report_data;

    /// True if SHA256(EK_pub_DER) matched a field in the SNP report
    bool ek_pub_hash_verified = false;
    /// Which SNP field matched
    std::string ek_pub_hash_field;

    /// SHA-N digest over the concatenated selected PCR values (from the quote)
    std::vector<uint8_t> pcr_digest;
    /// Which PCRs were included in the digest and with what hash algorithm
    std::vector<PcrSelection> pcr_selection;
    /// UEFI firmware version from the TPM quote
    uint64_t firmware_version = 0;
    /// Nonce (extraData) from the TPM quote
    std::vector<uint8_t> nonce;
  };

  /// Cursor over a fixed byte buffer for big-endian parsing.
  /// Throws std::logic_error with an offset on any buffer overrun.
  class BigEndianReader
  {
  public:
    BigEndianReader(const uint8_t* data, size_t size);

    uint8_t read_u8();
    uint16_t read_u16_be();
    uint32_t read_u32_be();
    uint64_t read_u64_be();

    /// Read a TPM2B: u16 big-endian size prefix followed by that many bytes
    std::vector<uint8_t> read_tpm2b();

    /// Read exactly n bytes
    std::vector<uint8_t> read_bytes(size_t n);

    size_t remaining() const;

  private:
    const uint8_t* data_;
    size_t size_;
    size_t pos_ = 0;
  };

  /**
   * Parse a raw TPMS_ATTEST blob
   * Validates the TPM_GENERATED_VALUE magic and TPM_ST_ATTEST_QUOTE type tag.
   * Throws std::logic_error on any structural error or buffer overrun.
   */
  ParsedAttest parse_tpm2b_attest(std::span<const uint8_t> raw_quote);

  /**
   * Verify the TPM2 quote and signature
   * @param raw_tpm_quote     TPMS_ATTEST bytes
   * @param raw_tpm_signature TPMT_SIGNATURE bytes
   * @param ak_pub_pem        AK public key in PEM format (RSA only)
   * @throws std::logic_error on any parse or signature verification failure
   */
  ParsedAttest verify_tpm_quote_signature(
    const std::vector<uint8_t>& raw_tpm_quote,
    const std::vector<uint8_t>& raw_tpm_signature,
    const ccf::crypto::Pem& ak_pub_pem);

  /**
   * Verify a vTPM quote rooted in AMD SEV-SNP hardware.
   *
   * @param raw_tpm_quote     TPMS_ATTEST bytes
   * @param raw_tpm_signature TPMT_SIGNATURE bytes
   * @param snp_quote_info  QuoteInfo with SNP report and first 3 certs
   *                          (ARK, ASK, VCEK) from the endorsements bundle
   * @param certs             All 5 certs from the endorsements PEM bundle:
   *                          [0]=ARK, [1]=ASK, [2]=VCEK, [3]=EK, [4]=AK
   * @throws std::logic_error on any verification failure
   */
  VtpmAttestationClaims verify_vtpm_attestation_report(
    const std::vector<uint8_t>& raw_tpm_quote,
    const std::vector<uint8_t>& raw_tpm_signature,
    const QuoteInfo& snp_quote_info,
    const std::vector<ccf::crypto::Pem>& certs);

}
