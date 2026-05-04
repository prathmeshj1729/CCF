// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/pal/attestation_vtpm.h"

#include "ccf/crypto/md_type.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/rsa_public_key.h"
#include "ccf/crypto/sha256.h"
#include "ccf/crypto/sha256_hash.h"
#include "ccf/crypto/verifier.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/attestation_sev_snp.h"

#include <cstring>
#include <fmt/format.h>
#include <stdexcept>

namespace ccf::pal::vtpm
{
  BigEndianReader::BigEndianReader(const uint8_t* data, size_t size) :
    data_(data),
    size_(size),
    pos_(0)
  {}

  uint8_t BigEndianReader::read_u8()
  {
    if (pos_ + 1 > size_)
    {
      throw std::logic_error(fmt::format(
        "TPM2 parse: buffer overrun reading u8 at offset {}", pos_));
    }
    return data_[pos_++];
  }

  uint16_t BigEndianReader::read_u16_be()
  {
    if (pos_ + 2 > size_)
    {
      throw std::logic_error(fmt::format(
        "TPM2 parse: buffer overrun reading u16 at offset {}", pos_));
    }
    uint16_t v = (static_cast<uint16_t>(data_[pos_]) << 8) |
      static_cast<uint16_t>(data_[pos_ + 1]);
    pos_ += 2;
    return v;
  }

  uint32_t BigEndianReader::read_u32_be()
  {
    if (pos_ + 4 > size_)
    {
      throw std::logic_error(fmt::format(
        "TPM2 parse: buffer overrun reading u32 at offset {}", pos_));
    }
    uint32_t v = (static_cast<uint32_t>(data_[pos_]) << 24) |
      (static_cast<uint32_t>(data_[pos_ + 1]) << 16) |
      (static_cast<uint32_t>(data_[pos_ + 2]) << 8) |
      static_cast<uint32_t>(data_[pos_ + 3]);
    pos_ += 4;
    return v;
  }

  uint64_t BigEndianReader::read_u64_be()
  {
    uint64_t hi = read_u32_be();
    uint64_t lo = read_u32_be();
    return (hi << 32) | lo;
  }

  std::vector<uint8_t> BigEndianReader::read_tpm2b()
  {
    uint16_t len = read_u16_be();
    return read_bytes(len);
  }

  std::vector<uint8_t> BigEndianReader::read_bytes(size_t n)
  {
    if (pos_ + n > size_)
    {
      throw std::logic_error(fmt::format(
        "TPM2 parse: buffer overrun reading {} bytes at offset {}", n, pos_));
    }
    std::vector<uint8_t> out(data_ + pos_, data_ + pos_ + n);
    pos_ += n;
    return out;
  }

  size_t BigEndianReader::remaining() const
  {
    return size_ - pos_;
  }

  // TPMS_ATTEST wire layout (all fields big-endian):
  //   u32 magic                   (must be TPM_GENERATED_VALUE = 0xFF544347)
  //   u16 type                    (must be TPM_ST_ATTEST_QUOTE  = 0x8018)
  //   TPM2B qualifiedSigner       (u16 len + bytes; ignored)
  //   TPM2B extraData             (u16 len + bytes; the nonce)
  //   TPMS_CLOCK_INFO:            (8+4+4+1 = 17 bytes; skipped)
  //   u64 firmwareVersion
  //   TPML_PCR_SELECTION:
  //     u32 count
  //     [count x TPMS_PCR_SELECTION]:
  //       u16 hash
  //       u8  sizeofSelect
  //       sizeofSelect bytes      (PCR bitmask; bit i of byte b → PCR 8*b+i)
  //   TPM2B pcrDigest             (u16 len + bytes)

  ParsedAttest parse_tpm2b_attest(std::span<const uint8_t> raw_quote)
  {
    BigEndianReader r(raw_quote.data(), raw_quote.size());

    uint32_t magic = r.read_u32_be();
    if (magic != TPM_GENERATED_VALUE)
    {
      throw std::logic_error(fmt::format(
        "TPMS_ATTEST: magic mismatch — expected 0x{:08X}, got 0x{:08X}",
        TPM_GENERATED_VALUE,
        magic));
    }

    uint16_t type = r.read_u16_be();
    if (type != TPM_ST_ATTEST_QUOTE)
    {
      throw std::logic_error(fmt::format(
        "TPMS_ATTEST: type mismatch — expected TPM_ST_ATTEST_QUOTE "
        "(0x{:04X}), got 0x{:04X}",
        TPM_ST_ATTEST_QUOTE,
        type));
    }

    r.read_tpm2b(); // qualifiedSigner — not needed for verification

    auto nonce = r.read_tpm2b(); // extraData

    r.read_u64_be(); // TPMS_CLOCK_INFO: clock
    r.read_u32_be(); // resetCount
    r.read_u32_be(); // restartCount
    r.read_u8(); // safe

    uint64_t firmware_version = r.read_u64_be();

    uint32_t sel_count = r.read_u32_be();
    if (sel_count > 16)
    {
      throw std::logic_error(fmt::format(
        "TPML_PCR_SELECTION: count {} exceeds sanity bound 16", sel_count));
    }

    std::vector<PcrSelection> pcr_selection;
    pcr_selection.reserve(sel_count);

    for (uint32_t i = 0; i < sel_count; ++i)
    {
      PcrSelection sel;
      sel.hash_algo = r.read_u16_be();
      uint8_t sizeof_select = r.read_u8();
      auto bitmask = r.read_bytes(sizeof_select);

      // Decode PCR bitmask: byte b, bit p → PCR index 8*b + p
      for (uint8_t b = 0; b < sizeof_select; ++b)
      {
        for (uint8_t p = 0; p < 8; ++p)
        {
          if (bitmask[b] & (1u << p))
          {
            sel.pcr_indices.push_back(static_cast<uint32_t>(b) * 8 + p);
          }
        }
      }
      pcr_selection.push_back(std::move(sel));
    }

    auto pcr_digest = r.read_tpm2b();

    return ParsedAttest{
      .nonce = std::move(nonce),
      .pcr_digest = std::move(pcr_digest),
      .pcr_selection = std::move(pcr_selection),
      .firmware_version = firmware_version,
    };
  }

  // TPMT_SIGNATURE wire layout (big-endian):
  //   u16 sigAlg        (TPMI_ALG_SIG_SCHEME)
  //   If sigAlg == TPM_ALG_RSASSA (0x0014):
  //     u16 hash        (TPMI_ALG_HASH, discarded)
  //     TPM2B sig       (raw RSA signature bytes)
  //   If sigAlg == TPM_ALG_ECDSA (0x0018):
  //     u16 hash        (TPMI_ALG_HASH, discarded)
  //     TPM2B signatureR
  //     TPM2B signatureS
  //     (r and s are DER-encoded as SEQUENCE{INTEGER r, INTEGER s} for OpenSSL)

  namespace
  {
    /// Encode a big-endian unsigned integer as a DER INTEGER element.
    /// Prepends 0x00 if the high bit is set (to preserve sign).
    /// Strips leading zero bytes (but keeps at least one byte).
    std::vector<uint8_t> der_integer(const std::vector<uint8_t>& val)
    {
      size_t start = 0;
      while (start + 1 < val.size() && val[start] == 0x00)
      {
        ++start;
      }

      bool need_pad = (val[start] & 0x80) != 0;
      size_t content_len = (val.size() - start) + (need_pad ? 1 : 0);

      std::vector<uint8_t> out;
      out.reserve(2 + content_len);
      out.push_back(0x02); // INTEGER tag
      out.push_back(static_cast<uint8_t>(content_len));
      if (need_pad)
      {
        out.push_back(0x00);
      }
      out.insert(out.end(), val.begin() + start, val.end());
      return out;
    }

    /// Assemble a DER SEQUENCE { INTEGER r, INTEGER s } from raw r and s bytes.
    /// Total length must fit in one byte (< 0x80), which holds for P-256.
    std::vector<uint8_t> encode_ecdsa_der_sig(
      const std::vector<uint8_t>& r_bytes, const std::vector<uint8_t>& s_bytes)
    {
      auto r_enc = der_integer(r_bytes);
      auto s_enc = der_integer(s_bytes);
      size_t inner_len = r_enc.size() + s_enc.size();

      std::vector<uint8_t> out;
      out.reserve(2 + inner_len);
      out.push_back(0x30); // SEQUENCE tag
      out.push_back(static_cast<uint8_t>(inner_len));
      out.insert(out.end(), r_enc.begin(), r_enc.end());
      out.insert(out.end(), s_enc.begin(), s_enc.end());
      return out;
    }

    /// Parse TPMT_SIGNATURE and return bytes ready for Verifier::verify().
    /// RSA: raw bytes. ECDSA: DER SEQUENCE{INTEGER r, INTEGER s}.
    std::vector<uint8_t> parse_tpmt_signature(std::span<const uint8_t> raw_sig)
    {
      BigEndianReader r(raw_sig.data(), raw_sig.size());

      uint16_t sig_alg = r.read_u16_be();

      if (sig_alg == TPM_ALG_RSASSA)
      {
        r.read_u16_be(); // hash algorithm — ignore, passed separately to verify
        return r.read_tpm2b();
      }
      else if (sig_alg == TPM_ALG_ECDSA)
      {
        r.read_u16_be(); // hash algorithm — ignore
        auto sig_r = r.read_tpm2b();
        auto sig_s = r.read_tpm2b();
        return encode_ecdsa_der_sig(sig_r, sig_s);
      }
      else
      {
        throw std::logic_error(fmt::format(
          "TPMT_SIGNATURE: unsupported sigAlg 0x{:04X} "
          "(only RSASSA=0x0014 and ECDSA=0x0018 are supported)",
          sig_alg));
      }
    }

  } // anonymous namespace

  ParsedAttest verify_tpm_quote_signature(
    const std::vector<uint8_t>& raw_tpm_quote,
    const std::vector<uint8_t>& raw_tpm_signature,
    const ccf::crypto::Pem& ak_pub_pem)
  {
    auto parsed = parse_tpm2b_attest(
      std::span<const uint8_t>(raw_tpm_quote.data(), raw_tpm_quote.size()));

    auto sig_bytes = parse_tpmt_signature(std::span<const uint8_t>(
      raw_tpm_signature.data(), raw_tpm_signature.size()));

    auto ak_rsa = ccf::crypto::make_rsa_public_key(ak_pub_pem);
    if (!ak_rsa->verify(
          raw_tpm_quote.data(),
          raw_tpm_quote.size(),
          sig_bytes.data(),
          sig_bytes.size(),
          ccf::crypto::MDType::SHA256,
          ccf::crypto::RSAPadding::PKCS1v15))
    {
      throw std::logic_error(
        "TPM quote signature verification failed: AK signature over "
        "TPMS_ATTEST does not match the provided AK public key");
    }

    return parsed;
  }

  VtpmAttestationClaims verify_vtpm_attestation_report(
    const std::vector<uint8_t>& raw_tpm_quote,
    const std::vector<uint8_t>& raw_tpm_signature,
    const QuoteInfo& snp_quote_info,
    const std::vector<ccf::crypto::Pem>& certs)
  {
    // Step 1: Verify SNP attestation report
    PlatformAttestationMeasurement snp_measurement;
    PlatformAttestationReportData snp_report_data;

    verify_snp_attestation_report(
      snp_quote_info, snp_measurement, snp_report_data);

    if (snp_quote_info.quote.size() < sizeof(snp::Attestation))
    {
      throw std::logic_error(fmt::format(
        "SNP evidence buffer is too short: {} bytes, need at least {}",
        snp_quote_info.quote.size(),
        sizeof(snp::Attestation)));
    }
    const auto& snp_attest =
      *reinterpret_cast<const snp::Attestation*>(snp_quote_info.quote.data());

    // Step 2: Verify EK public key is bound in the SNP report
    // certs[0..2] = ARK/ASK/VCEK, certs[3] = EK cert, certs[4] = AK cert
    if (certs.size() < 5)
    {
      throw std::logic_error(fmt::format(
        "Endorsements bundle must contain at least 5 certificates "
        "(ARK, ASK, VCEK, EK, AK); got {}",
        certs.size()));
    }

    const auto& ek_cert = certs[3];
    const auto& ak_cert = certs[4];

    auto ek_verifier = ccf::crypto::make_verifier(ek_cert);
    auto ek_pub_der = ek_verifier->public_key_der();
    auto ek_hash = ccf::crypto::sha256(
      std::span<const uint8_t>(ek_pub_der.data(), ek_pub_der.size()));

    bool ek_verified = false;
    std::string ek_field;

    // Google Confidential Spaces
    static_assert(
      sizeof(snp_attest.report_data) >= 32,
      "SNP report_data field must be at least 32 bytes");
    if (
      ek_hash.size() == 32 &&
      memcmp(snp_attest.report_data, ek_hash.data(), 32) == 0)
    {
      ek_verified = true;
      ek_field = "report_data";
    }
    // Azure Confidential VMs
    else
    {
      static const std::array<uint8_t, 32> zero32{};
      const bool host_data_nonzero =
        memcmp(snp_attest.host_data, zero32.data(), 32) != 0;
      if (
        host_data_nonzero && ek_hash.size() == 32 &&
        memcmp(snp_attest.host_data, ek_hash.data(), 32) == 0)
      {
        ek_verified = true;
        ek_field = "host_data";
      }
    }

    if (!ek_verified)
    {
      throw std::logic_error(
        "vTPM: SHA256(EK_pub_DER) does not match report_data or host_data in "
        "the SNP report — EK is not bound to this attestation");
    }

    // Step 3: Verify AK certificate is signed by EK
    const ccf::crypto::Pem* ek_cert_ptr = &ek_cert;
    auto ak_verifier = ccf::crypto::make_verifier(ak_cert);
    if (!ak_verifier->verify_certificate({ek_cert_ptr}, {}, true))
    {
      throw std::logic_error(
        "vTPM: AK certificate is not signed by the EK certificate");
    }

    // Steps 4-5: Parse TPMS_ATTEST and TPMT_SIGNATURE
    auto parsed = parse_tpm2b_attest(
      std::span<const uint8_t>(raw_tpm_quote.data(), raw_tpm_quote.size()));

    auto sig_bytes = parse_tpmt_signature(std::span<const uint8_t>(
      raw_tpm_signature.data(), raw_tpm_signature.size()));

    // Step 6: Verify TPM quote signature
    auto ak_rsa =
      ccf::crypto::make_rsa_public_key(ak_verifier->public_key_pem());
    if (!ak_rsa->verify(
          raw_tpm_quote.data(),
          raw_tpm_quote.size(),
          sig_bytes.data(),
          sig_bytes.size(),
          ccf::crypto::MDType::SHA256,
          ccf::crypto::RSAPadding::PKCS1v15))
    {
      throw std::logic_error(
        "vTPM: TPM quote signature verification failed — "
        "the AK did not sign this quote");
    }

    // Step 7: Return all claims
    return VtpmAttestationClaims{
      .snp_measurement = snp_measurement,
      .snp_report_data = snp_report_data,
      .ek_pub_hash_field = ek_field,
      .pcr_digest = parsed.pcr_digest,
      .pcr_selection = parsed.pcr_selection,
      .firmware_version = parsed.firmware_version,
    };
  }

}
