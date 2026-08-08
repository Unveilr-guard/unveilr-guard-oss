#!/usr/bin/env sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# ADR-007: the AGPL binary must never import proprietary Unveilr code. A licence
# boundary that is only a convention gets crossed by accident, so CI asserts it.
set -eu

FORBIDDEN='unveilr-security/|unveilr_api|unveilr-mcp|unveilr-enterprise'

if go list -deps ./... | grep -Eq "$FORBIDDEN"; then
  echo "FAIL: proprietary import found in the module graph:" >&2
  go list -deps ./... | grep -E "$FORBIDDEN" >&2
  exit 1
fi
echo "ok: no proprietary imports"
