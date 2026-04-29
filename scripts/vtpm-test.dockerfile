# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

FROM mcr.microsoft.com/azurelinux/base/core:3.0

RUN tdnf -y install \
    build-essential clang cmake ninja-build \
    openssl-devel libuv-devel nghttp2-devel curl-devel \
    rust git ca-certificates

WORKDIR /CCF
