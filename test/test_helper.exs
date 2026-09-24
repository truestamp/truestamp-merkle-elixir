# Copyright (c) 2025-2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

# :go_interop runs the Go programs in interop/go/, which need go and, the first time,
# network access; `mix test --include go_interop` runs them.
ExUnit.start(exclude: [:go_interop])
