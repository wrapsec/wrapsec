# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Hard limits on decode work. This is untrusted input on a security path: without
caps, nested encodings (base64-of-base64...) or view-multiplying payloads could
exhaust CPU/memory. Enforced centrally in the pipeline runner so no stage --
present or future -- can bypass them.
"""

MAX_DECODE_DEPTH = 2      # deepest nested decode (e.g. base64 inside base64)
MAX_VIEWS        = 8      # total decode-views kept per input; excess dropped
MAX_VIEW_BYTES   = 8192   # a single view is truncated to this (a tiny blob can expand hugely)
