// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js/extensions/vtpm_attestation.h"

#include "ccf/crypto/pem.h"
#include "ccf/ds/quote_info.h"
#include "ccf/js/core/context.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/attestation_vtpm.h"
#include "js/checks.h"
#include "js/extensions/snp_attestation_helpers.h"
#include "node/uvm_endorsements.h"

#include <fmt/format.h>
#include <quickjs/quickjs.h>

namespace ccf::js::extensions
{
#pragma clang diagnostic push
  namespace
  {

    JSValue js_verify_vtpm_attestation(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      if (argc < 4 || argc > 6)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected between 4 and 6", argc);
      }

      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      size_t quote_size = 0;
      uint8_t* quote_buf = JS_GetArrayBuffer(ctx, &quote_size, argv[0]);
      if (quote_buf == nullptr)
      {
        return ccf::js::core::constants::Exception;
      }
      std::vector<uint8_t> raw_tpm_quote(quote_buf, quote_buf + quote_size);

      size_t sig_size = 0;
      uint8_t* sig_buf = JS_GetArrayBuffer(ctx, &sig_size, argv[1]);
      if (sig_buf == nullptr)
      {
        return ccf::js::core::constants::Exception;
      }
      std::vector<uint8_t> raw_tpm_signature(sig_buf, sig_buf + sig_size);

      size_t evidence_size = 0;
      uint8_t* evidence_buf = JS_GetArrayBuffer(ctx, &evidence_size, argv[2]);
      if (evidence_buf == nullptr)
      {
        return ccf::js::core::constants::Exception;
      }

      size_t endorsements_size = 0;
      uint8_t* endorsements_buf =
        JS_GetArrayBuffer(ctx, &endorsements_size, argv[3]);
      if (endorsements_buf == nullptr)
      {
        return ccf::js::core::constants::Exception;
      }

      std::optional<std::vector<uint8_t>> uvm_endorsements;
      if (argc > 4 && JS_IsUndefined(argv[4]) == 0)
      {
        size_t uvm_size = 0;
        uint8_t* uvm_buf = JS_GetArrayBuffer(ctx, &uvm_size, argv[4]);
        if (uvm_buf == nullptr)
        {
          return ccf::js::core::constants::Exception;
        }
        uvm_endorsements = std::vector<uint8_t>(uvm_buf, uvm_buf + uvm_size);
      }

      std::optional<std::string> endorsed_tcb;
      if (argc > 5 && JS_IsUndefined(argv[5]) == 0)
      {
        endorsed_tcb = jsctx.to_str(argv[5]);
        if (!endorsed_tcb)
        {
          return ccf::js::core::constants::Exception;
        }
      }

      const std::string endorsements_pem(
        reinterpret_cast<const char*>(endorsements_buf), endorsements_size);
      std::vector<ccf::crypto::Pem> certs =
        ccf::crypto::split_x509_cert_bundle(endorsements_pem);

      if (certs.size() < 5)
      {
        return JS_ThrowRangeError(
          ctx,
          "endorsements PEM bundle must contain at least 5 certificates "
          "(ARK, ASK, VCEK, EK, AK); got %zu",
          certs.size());
      }

      QuoteInfo snp_quote_info = {};
      snp_quote_info.format = QuoteFormat::amd_sev_snp_v1;
      snp_quote_info.quote =
        std::vector<uint8_t>(evidence_buf, evidence_buf + evidence_size);

      std::string snp_endorsements_pem;
      for (size_t i = 0; i < 3 && i < certs.size(); ++i)
      {
        snp_endorsements_pem += certs[i].str();
      }
      snp_quote_info.endorsements = std::vector<uint8_t>(
        snp_endorsements_pem.begin(), snp_endorsements_pem.end());

      if (uvm_endorsements.has_value())
      {
        snp_quote_info.uvm_endorsements = uvm_endorsements;
      }
      if (endorsed_tcb.has_value())
      {
        snp_quote_info.endorsed_tcb = endorsed_tcb;
      }

      pal::vtpm::VtpmAttestationClaims claims;
      std::optional<pal::UVMEndorsements> parsed_uvm_endorsements;

      try
      {
        claims = pal::vtpm::verify_vtpm_attestation_report(
          raw_tpm_quote, raw_tpm_signature, snp_quote_info, certs);

        if (uvm_endorsements.has_value())
        {
          parsed_uvm_endorsements =
            verify_uvm_endorsements_against_roots_of_trust(
              uvm_endorsements.value(),
              claims.snp_measurement,
              default_uvm_roots_of_trust);
        }
      }
      catch (const std::exception& e)
      {
        return JS_ThrowRangeError(ctx, "%s", e.what());
      }

      auto r = jsctx.new_obj();
      JS_CHECK_EXC(r);

      if (evidence_size < sizeof(pal::snp::Attestation))
      {
        return JS_ThrowRangeError(
          ctx,
          "SNP evidence too small: %zu bytes (need at least %zu)",
          evidence_size,
          sizeof(pal::snp::Attestation));
      }
      const auto& snp_attest =
        *reinterpret_cast<const pal::snp::Attestation*>(evidence_buf);

      auto snp_obj =
        jsctx.wrap(marshal_snp_attestation_to_js(jsctx, snp_attest));
      JS_CHECK_EXC(snp_obj);
      JS_CHECK_SET(r.set("attestation", std::move(snp_obj)));

      {
        auto field = jsctx.new_string(claims.ek_pub_hash_field);
        JS_CHECK_EXC(field);
        JS_CHECK_SET(r.set("ek_pub_hash_field", std::move(field)));
      }

      {
        auto pcr_digest = jsctx.new_array_buffer_copy(claims.pcr_digest);
        JS_CHECK_EXC(pcr_digest);
        JS_CHECK_SET(r.set("pcr_digest", std::move(pcr_digest)));
      }

      // pcr_selection: array of { hash_algo: number, pcr_indices: number[] }
      {
        auto sel_array = jsctx.new_array();
        JS_CHECK_EXC(sel_array);

        for (size_t i = 0; i < claims.pcr_selection.size(); ++i)
        {
          const auto& sel = claims.pcr_selection[i];
          auto sel_obj = jsctx.new_obj();
          JS_CHECK_EXC(sel_obj);

          JS_CHECK_SET(sel_obj.set_uint32(
            "hash_algo", static_cast<uint32_t>(sel.hash_algo)));

          auto indices_array = jsctx.new_array();
          JS_CHECK_EXC(indices_array);
          for (size_t j = 0; j < sel.pcr_indices.size(); ++j)
          {
            auto idx = jsctx.new_val(JS_NewUint32(ctx, sel.pcr_indices[j]));
            JS_CHECK_EXC(idx);
            if (JS_SetPropertyUint32(ctx, indices_array.val, j, idx.take()) < 0)
            {
              return ccf::js::core::constants::Exception;
            }
          }
          JS_CHECK_SET(sel_obj.set("pcr_indices", std::move(indices_array)));

          if (JS_SetPropertyUint32(ctx, sel_array.val, i, sel_obj.take()) < 0)
          {
            return ccf::js::core::constants::Exception;
          }
        }
        JS_CHECK_SET(r.set("pcr_selection", std::move(sel_array)));
      }

      // firmware_version as hex string to avoid JS number precision loss
      {
        auto fw_str =
          jsctx.new_string(fmt::format("{:#018x}", claims.firmware_version));
        JS_CHECK_EXC(fw_str);
        JS_CHECK_SET(r.set("firmware_version", std::move(fw_str)));
      }

      if (parsed_uvm_endorsements.has_value())
      {
        auto u = jsctx.new_obj();
        JS_CHECK_EXC(u);

        {
          auto did = jsctx.new_string(parsed_uvm_endorsements.value().did);
          JS_CHECK_EXC(did);
          JS_CHECK_SET(u.set("did", std::move(did)));
        }

        {
          auto feed = jsctx.new_string(parsed_uvm_endorsements.value().feed);
          JS_CHECK_EXC(feed);
          JS_CHECK_SET(u.set("feed", std::move(feed)));
        }

        {
          auto svn = jsctx.new_string(parsed_uvm_endorsements.value().svn);
          JS_CHECK_EXC(svn);
          JS_CHECK_SET(u.set("svn", std::move(svn)));
          JS_CHECK_SET(r.set("uvm_endorsements", std::move(u)));
        }
      }

      return r.take();
    }

#pragma clang diagnostic pop

  }

  void VtpmAttestationExtension::install(js::core::Context& ctx)
  {
    auto vtpm_attestation = ctx.new_obj();

    JS_CHECK_OR_THROW(vtpm_attestation.set(
      "verifyTpmAttestation",
      ctx.new_c_function(
        js_verify_vtpm_attestation, "verifyTpmAttestation", 6)));

    auto global_obj = ctx.get_global_obj();
    JS_CHECK_OR_THROW(
      global_obj.set("vtpm_attestation", std::move(vtpm_attestation)));
  }
}
