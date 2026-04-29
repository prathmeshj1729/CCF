// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/core/context.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "js/checks.h"

#include <quickjs/quickjs.h>

namespace ccf::js::extensions
{
  namespace
  {
    inline JSValue make_js_tcb_version(
      js::core::Context& jsctx, pal::snp::TcbVersionRaw tcb)
    {
      auto data_hex = jsctx.new_string(tcb.to_hex());
      JS_CHECK_EXC(data_hex);
      return data_hex.take();
    }

    inline JSValue marshal_snp_attestation_to_js(
      js::core::Context& jsctx, const pal::snp::Attestation& attestation)
    {
      auto a = jsctx.new_obj();
      JS_CHECK_EXC(a);

      JS_CHECK_SET(a.set_uint32("version", attestation.version));
      JS_CHECK_SET(a.set_uint32("guest_svn", attestation.guest_svn));

      auto policy = jsctx.new_obj();
      JS_CHECK_EXC(policy);

      JS_CHECK_SET(
        policy.set_uint32("abi_minor", attestation.policy.abi_minor));
      JS_CHECK_SET(
        policy.set_uint32("abi_major", attestation.policy.abi_major));
      JS_CHECK_SET(policy.set_uint32("smt", attestation.policy.smt));
      JS_CHECK_SET(
        policy.set_uint32("migrate_ma", attestation.policy.migrate_ma));
      JS_CHECK_SET(policy.set_uint32("debug", attestation.policy.debug));
      JS_CHECK_SET(
        policy.set_uint32("single_socket", attestation.policy.single_socket));

      JS_CHECK_SET(a.set("policy", std::move(policy)));

      {
        auto family_id = jsctx.new_array_buffer_copy(attestation.family_id);
        JS_CHECK_EXC(family_id);
        JS_CHECK_SET(a.set("family_id", std::move(family_id)));
      }

      {
        auto image_id = jsctx.new_array_buffer_copy(attestation.image_id);
        JS_CHECK_EXC(image_id);
        JS_CHECK_SET(a.set("image_id", std::move(image_id)));
      }

      JS_CHECK_SET(a.set_uint32("vmpl", attestation.vmpl));
      JS_CHECK_SET(a.set_uint32(
        "signature_algo", static_cast<uint32_t>(attestation.signature_algo)));

      {
        auto platform_version =
          jsctx.wrap(make_js_tcb_version(jsctx, attestation.platform_version));
        JS_CHECK_EXC(platform_version);
        JS_CHECK_SET(a.set("platform_version", std::move(platform_version)));
      }

      {
        auto platform_info = jsctx.new_obj();
        JS_CHECK_EXC(platform_info);
        JS_CHECK_SET(
          platform_info.set_uint32("smt_en", attestation.platform_info.smt_en));
        JS_CHECK_SET(platform_info.set_uint32(
          "tsme_en", attestation.platform_info.tsme_en));
        JS_CHECK_SET(a.set("plaform_info", std::move(platform_info)));
      }

      {
        auto flags = jsctx.new_obj();
        JS_CHECK_EXC(flags);
        JS_CHECK_SET(
          flags.set_uint32("author_key_en", attestation.flags.author_key_en));
        JS_CHECK_SET(
          flags.set_uint32("mask_chip_key", attestation.flags.mask_chip_key));
        JS_CHECK_SET(
          flags.set_uint32("signing_key", attestation.flags.signing_key));
        JS_CHECK_SET(a.set("flags", std::move(flags)));
      }

      {
        auto report_data =
          jsctx.new_array_buffer_copy(attestation.report_data);
        JS_CHECK_EXC(report_data);
        JS_CHECK_SET(a.set("report_data", std::move(report_data)));
      }

      {
        auto measurement =
          jsctx.new_array_buffer_copy(attestation.measurement);
        JS_CHECK_EXC(measurement);
        JS_CHECK_SET(a.set("measurement", std::move(measurement)));
      }

      {
        auto host_data = jsctx.new_array_buffer_copy(attestation.host_data);
        JS_CHECK_EXC(host_data);
        JS_CHECK_SET(a.set("host_data", std::move(host_data)));
      }

      {
        auto id_key_digest =
          jsctx.new_array_buffer_copy(attestation.id_key_digest);
        JS_CHECK_EXC(id_key_digest);
        JS_CHECK_SET(a.set("id_key_digest", std::move(id_key_digest)));
      }

      {
        auto author_key_digest =
          jsctx.new_array_buffer_copy(attestation.author_key_digest);
        JS_CHECK_EXC(author_key_digest);
        JS_CHECK_SET(a.set("author_key_digest", std::move(author_key_digest)));
      }

      {
        auto report_id = jsctx.new_array_buffer_copy(attestation.report_id);
        JS_CHECK_EXC(report_id);
        JS_CHECK_SET(a.set("report_id", std::move(report_id)));
      }

      {
        auto report_id_ma =
          jsctx.new_array_buffer_copy(attestation.report_id_ma);
        JS_CHECK_EXC(report_id_ma);
        JS_CHECK_SET(a.set("report_id_ma", std::move(report_id_ma)));
      }

      {
        auto reported_tcb =
          jsctx.wrap(make_js_tcb_version(jsctx, attestation.reported_tcb));
        JS_CHECK_EXC(reported_tcb);
        JS_CHECK_SET(a.set("reported_tcb", std::move(reported_tcb)));
      }

      JS_CHECK_SET(a.set_uint32("cpuid_fam_id", attestation.cpuid_fam_id));
      JS_CHECK_SET(a.set_uint32("cpuid_mod_id", attestation.cpuid_mod_id));
      JS_CHECK_SET(a.set_uint32("cpuid_step", attestation.cpuid_step));

      {
        auto chip_id = jsctx.new_array_buffer_copy(attestation.chip_id);
        JS_CHECK_EXC(chip_id);
        JS_CHECK_SET(a.set("chip_id", std::move(chip_id)));
      }

      {
        auto committed_tcb =
          jsctx.wrap(make_js_tcb_version(jsctx, attestation.committed_tcb));
        JS_CHECK_EXC(committed_tcb);
        JS_CHECK_SET(a.set("committed_tcb", std::move(committed_tcb)));
      }

      JS_CHECK_SET(a.set_uint32("current_minor", attestation.current_minor));
      JS_CHECK_SET(a.set_uint32("current_build", attestation.current_build));
      JS_CHECK_SET(a.set_uint32("current_major", attestation.current_major));
      JS_CHECK_SET(
        a.set_uint32("committed_build", attestation.committed_build));
      JS_CHECK_SET(
        a.set_uint32("committed_minor", attestation.committed_minor));
      JS_CHECK_SET(
        a.set_uint32("committed_major", attestation.committed_major));

      {
        auto launch_tcb =
          jsctx.wrap(make_js_tcb_version(jsctx, attestation.launch_tcb));
        JS_CHECK_EXC(launch_tcb);
        JS_CHECK_SET(a.set("launch_tcb", std::move(launch_tcb)));
      }

      auto signature = jsctx.new_obj();
      JS_CHECK_EXC(signature);

      {
        auto signature_r =
          jsctx.new_array_buffer_copy(attestation.signature.r);
        JS_CHECK_EXC(signature_r);
        JS_CHECK_SET(signature.set("r", std::move(signature_r)));
      }

      {
        auto signature_s =
          jsctx.new_array_buffer_copy(attestation.signature.s);
        JS_CHECK_EXC(signature_s);
        JS_CHECK_SET(signature.set("s", std::move(signature_s)));
      }

      JS_CHECK_SET(a.set("signature", std::move(signature)));

      return a.take();
    }
  } // anonymous namespace
} // namespace ccf::js::extensions
