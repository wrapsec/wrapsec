# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Transactional email subsystem (v1.8.3).

A small, self-contained boundary for sending minimal informational security
notifications. Application code never touches SMTP directly: it calls
EmailService.queue() to write a durable outbox row inside its own database
transaction, and a background worker delivers the row through an EmailProvider.

See docs/internal/WrapSec_V1_Email_Notification_Implementation_Plan.md.
"""
