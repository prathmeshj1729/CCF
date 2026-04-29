// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js/extensions/snp_attestation.h"

#include "ccf/js/core/context.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/version.h"
#include "js/checks.h"
#include "js/extensions/snp_attestation_helpers.h"
#include "node/uvm_endorsements.h"

#include <algorithm>
#include <quickjs/quickjs.h>
#include <regex>
#include <vector>

namespace ccf::js::extensions
{
#pragma clang diagnostic push
  namespace
  {

    JSValue js_verify_snp_attestation(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      if (argc < 2 || argc > 4)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected between 2 and 4", argc);
      }
      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      size_t evidence_size = 0;
      uint8_t* evidence = JS_GetArrayBuffer(ctx, &evidence_size, argv[0]);
      if (evidence == nullptr)
      {
        return ccf::js::core::constants::Exception;
      }

      size_t endorsements_size = 0;
      uint8_t* endorsements =
        JS_GetArrayBuffer(ctx, &endorsements_size, argv[1]);
      if (endorsements == nullptr)
      {
        return ccf::js::core::constants::Exception;
      }

      std::optional<std::vector<uint8_t>> uvm_endorsements;
      if (JS_IsUndefined(argv[2]) == 0)
      {
        size_t uvm_endorsements_size = 0;
        uint8_t* uvm_endorsements_array =
          JS_GetArrayBuffer(ctx, &uvm_endorsements_size, argv[2]);
        if (uvm_endorsements_array == nullptr)
        {
          return ccf::js::core::constants::Exception;
        }
        uvm_endorsements = std::vector<uint8_t>(
          uvm_endorsements_array,
          uvm_endorsements_array + uvm_endorsements_size);
      }

      std::optional<std::string> endorsed_tcb;
      if (JS_IsUndefined(argv[3]) == 0)
      {
        endorsed_tcb = jsctx.to_str(argv[3]);
        if (!endorsed_tcb)
        {
          return ccf::js::core::constants::Exception;
        }
      }

      QuoteInfo quote_info = {};
      quote_info.format = QuoteFormat::amd_sev_snp_v1;
      quote_info.quote =
        std::vector<uint8_t>(evidence, evidence + evidence_size);
      quote_info.endorsements =
        std::vector<uint8_t>(endorsements, endorsements + endorsements_size);
      if (endorsed_tcb.has_value())
      {
        quote_info.endorsed_tcb = endorsed_tcb.value();
      }

      pal::PlatformAttestationMeasurement measurement = {};
      pal::PlatformAttestationReportData report_data = {};
      std::optional<pal::UVMEndorsements> parsed_uvm_endorsements;

      try
      {
        pal::verify_snp_attestation_report(
          quote_info, measurement, report_data);
        if (uvm_endorsements.has_value())
        {
          parsed_uvm_endorsements =
            verify_uvm_endorsements_against_roots_of_trust(
              uvm_endorsements.value(),
              measurement,
              default_uvm_roots_of_trust);
        }
      }
      catch (const std::exception& e)
      {
        return JS_ThrowRangeError(ctx, "%s", e.what());
      }

      auto attestation = *reinterpret_cast<const pal::snp::Attestation*>(
        quote_info.quote.data());

      auto r = jsctx.new_obj();
      JS_CHECK_EXC(r);

      auto snp_obj =
        jsctx.wrap(marshal_snp_attestation_to_js(jsctx, attestation));
      JS_CHECK_EXC(snp_obj);
      JS_CHECK_SET(r.set("attestation", std::move(snp_obj)));

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

  void SnpAttestationExtension::install(js::core::Context& ctx)
  {
    auto snp_attestation = ctx.new_obj();

    JS_CHECK_OR_THROW(snp_attestation.set(
      "verifySnpAttestation",
      ctx.new_c_function(
        js_verify_snp_attestation, "verifySnpAttestation", 4)));

    auto global_obj = ctx.get_global_obj();
    JS_CHECK_OR_THROW(
      global_obj.set("snp_attestation", std::move(snp_attestation)));
  }
}
