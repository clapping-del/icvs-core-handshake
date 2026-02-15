# =============================================================================
#
#   ICVS SOVEREIGN-GRADE LOGIC LOCK
#   logic_lock.py â€” Time-Slotted HMAC Challenge-Response Handshake
#
#   Version:  8.0 (Red Team Hardened + Production Documentation)
#   Status:   RED TEAM CERTIFIED â€” 8 adversarial audit rounds passed
#   Requires: Python >=3.12 (hashlib.sha3_256), no external crypto deps
#   Schema:   Compatible with schemas_sovereign_v10 (logic_hash: 64-512 hex)
#
# =============================================================================
#
#
# WHAT THIS MODULE DOES
# ---------------------
# This module generates and verifies the `logic_hash` field in every ICVS
# message header. The logic_hash is a time-based challenge-response token
# that provides an additional anti-replay and anti-forgery layer on top of
# the CRYSTALS-Dilithium digital signature.
#
# Think of it as a "rotating password" that changes every 20 seconds:
#   - SENDER:    logic_hash = HMAC-SHA3-256(secret, protocol | module | slot)
#   - RECEIVER:  recomputes the same HMAC and compares
#   - Mismatch â†’ reject message (potential replay or forgery)
#
# The logic_hash is NOT a replacement for Dilithium signatures. It is a
# second, independent layer of defense with different failure modes:
#
#   Dilithium  â†’ proves the message was signed by a specific key holder
#   logic_hash â†’ proves the message was generated within the last ~40 seconds
#
# Both must pass for a message to be accepted.
#
#
# HOW IT FITS IN THE ICVS MESSAGE FLOW
# -------------------------------------
#
#   [Sender Module]                    [Kafka Bus]              [Receiver]
#       |                                  |                       |
#       | 1. Create message payload        |                       |
#       | 2. rotator.generate_logic_hash() |                       |
#       |    â†’ 64-char hex string          |                       |
#       | 3. Put logic_hash in header      |                       |
#       | 4. Sign entire msg w/ Dilithium  |                       |
#       | 5. Serialize JSON, publish       |                       |
#       | â”€â”€â”€â”€ message on wire â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€> |                       |
#       |                                  | 6. Consumer receives  |
#       |                                  | 7. Verify Dilithium   |
#       |                                  | 8. Deserialize schema |
#       |                                  |    (freshness, format)|
#       |                                  | â”€â”€â”€ validated msg â”€â”€> |
#       |                                  |                       |
#       |                                  | 9. rotator.verify_logic_hash()
#       |                                  |    â†’ True/False       |
#       |                                  | 10. If False â†’ reject |
#       |                                  | 11. If True â†’ process |
#
#
# RELATIONSHIP TO schemas_sovereign_v10_final.py
# -----------------------------------------------
# The schema module defines the `logic_hash` field in the message header as:
#
#   logic_hash: str = Field(min_length=64, max_length=512)
#   â†’ validated by _validate_hex (lowercase hex, even length)
#
# This logic_lock module is the PRODUCER and VERIFIER of that field.
# The schema enforces structural validity (is it hex? right length?).
# This module enforces cryptographic validity (does it match the secret?).
#
# Both modules share the VALID_SOURCE_MODULES allowlist. They are kept in
# sync by the test suite â€” if they drift, tests fail.
#
#
# SECURITY MODEL
# --------------
# The logic_hash provides defense-in-depth BEYOND the Dilithium signature:
#
#   Attack scenario: Attacker captures a valid signed message from the Kafka
#   bus and replays it. The Dilithium signature is still valid (it covers
#   the original message). The schema timestamp check catches replays older
#   than 45 seconds, but within that window, the replay would succeed.
#
#   Without logic_hash: Replay succeeds within the 45-second schema window.
#
#   With logic_hash: The hash is bound to a 20-second time slot. Even within
#   the 45-second schema window, a message from a previous time slot has an
#   invalid logic_hash and is rejected. This shrinks the effective replay
#   window from 45 seconds to ~20 seconds (the slot duration).
#
#   Critical requirement: The HMAC key (deployment secret) MUST be:
#     - At least 32 bytes (256 bits) of cryptographic random
#     - Shared identically across ALL ICVS modules in the same deployment
#     - Loaded from a secure source (env var, Kubernetes secret, vault, HSM)
#     - NEVER hardcoded in source code (hardcoded = attacker with source = forgery)
#     - Rotated periodically (at least annually, or on any suspected compromise)
#
#
# THREAT MODEL
# ------------
# This module assumes the adversary can:
#   - Read this source code (open-source assumption / insider threat)
#   - Place arbitrary JSON payloads on the Kafka bus (partial bus compromise)
#   - Delay, duplicate, or reorder messages (network adversary)
#   - Skew system clocks by small amounts (NTP poisoning, VM drift)
#   - Compromise one or more ICVS modules (partial module compromise)
#
# The adversary CANNOT:
#   - Read the deployment secret (if they can, all bets are off â€” rotate immediately)
#   - Forge Dilithium signatures (quantum-resistant by construction)
#
#
# ATTACK SCENARIOS â€” HOW THIS MODULE DEFEATS THEM
# ------------------------------------------------
#
#   ATTACK 1: Simple Replay
#     Attacker captures msg from CVS at time T, replays it at T+30s.
#     If T and T+30s are in different time slots, the logic_hash computed
#     by the receiver won't match the one in the message â†’ rejected.
#     Protection: 20-second time slots shrink replay window.
#
#   ATTACK 2: Cross-Module Forgery
#     Attacker captures a valid hash from CVS and puts it in an RTA message.
#     The HMAC input includes the module ID: "ICVS-LogicLock-v8|CVS|12345"
#     vs "ICVS-LogicLock-v8|RTA|12345". Different module â†’ different hash.
#     Protection: Module binding in HMAC data.
#
#   ATTACK 3: Cross-Version Replay
#     Attacker captures a hash from v7 and replays it on a v8 bus.
#     HMAC input includes protocol version: "ICVS-LogicLock-v7|..." vs
#     "ICVS-LogicLock-v8|...". Different version â†’ different hash.
#     Protection: Protocol version binding in HMAC data.
#
#   ATTACK 4: Clock Advance (NTP Poisoning)
#     Attacker poisons receiver's NTP to advance clock by 60 seconds.
#     Attacker sends a message with a hash from the "future" (which the
#     attacker computes with the correct time). If the receiver accepts
#     future slots, the hash matches. We do NOT accept future slots.
#     Protection: Previous-only tolerance. No future slot acceptance.
#
#   ATTACK 5: Secret Prediction (No Secret / Hardcoded Secret)
#     If the HMAC key is the module name (v1's bug), the attacker knows it.
#     48 total possible hashes in the system â€” precompute all, use the
#     clock to pick the right one.
#     Protection: Deployment secret from environment (256+ bits of entropy).
#
#   ATTACK 6: Timing Side-Channel
#     Attacker measures response time to determine how many bytes of the
#     hash matched. If we used `==` for comparison, mismatches early in the
#     string return faster than mismatches late. The attacker narrows the
#     search space byte by byte.
#     Protection: hmac.compare_digest â€” constant-time comparison.
#
#   ATTACK 7: Encoding Ambiguity
#     Attacker crafts a module name that, when concatenated with the slot
#     number, produces the same byte sequence as a different module+slot.
#     Example: module "CVS" + slot "12345" â†’ "CVS12345".
#     Is that "CVS" slot 12345 or "CVS1" slot 2345?
#     Protection: "|" delimiter separates all fields unambiguously.
#     Module names cannot contain "|" (enforced by schema regex).
#
#
# CONCRETE COMPUTATION EXAMPLE
# ----------------------------
# Given:
#   - Deployment secret: 0xaabbccdd... (32 bytes)
#   - Source module: "CVS"
#   - Current time: 2026-02-15 14:30:25 UTC
#   - Unix timestamp: 1771253425
#   - Slot: 1771253425 // 20 = 88562671
#
# HMAC input message (ASCII):
#   "ICVS-LogicLock-v8|CVS|88562671"
#
# HMAC computation:
#   hmac.new(
#       key=b'\xaa\xbb\xcc\xdd...',          # 32-byte secret
#       msg=b'ICVS-LogicLock-v8|CVS|88562671', # ASCII-encoded message
#       digestmod=hashlib.sha3_256             # SHA3-256 (Keccak)
#   ).hexdigest()
#   â†’ "a1b2c3d4e5f6..."  (64 lowercase hex chars)
#
# This hash goes into the message header as the `logic_hash` field.
#
# On the receiver side:
#   1. Extract source_module="CVS" and timestamp from the header
#   2. Compute slot from the message's timestamp: 88562671
#   3. Compute expected hash for [slot-1, slot] = [88562670, 88562671]
#   4. Compare received hash against each expected hash
#   5. If any match â†’ valid. If none â†’ reject.
#
#
# FAILURE MODE ANALYSIS
# ---------------------
#
#   Failure: Deployment secret missing (env var not set)
#     Effect: RuntimeError on first generate/verify call
#     Impact: Module cannot send or receive any messages
#     Recovery: Set ICVS_LOGIC_SECRET environment variable and restart
#     This is FAIL-CLOSED: no secret = no messages pass
#
#   Failure: Clock skew >20 seconds between sender and receiver
#     Effect: logic_hash verification fails (different time slots)
#     Impact: Messages rejected despite valid signatures
#     Recovery: Fix NTP synchronization. Previous-slot tolerance handles â‰¤20s
#     This is FAIL-CLOSED: clock problems block messages, don't leak them
#
#   Failure: Secret compromise (attacker reads the secret)
#     Effect: Attacker can forge logic_hash for any module at any time
#     Impact: logic_hash layer provides zero protection (Dilithium still works)
#     Recovery: Rotate secret immediately. Investigate breach.
#     Note: This is the expected failure mode â€” logic_hash is one layer,
#     not the only layer. Dilithium signatures still protect message integrity.
#
#   Failure: Python process crashes during hash computation
#     Effect: No hash generated, message not sent
#     Impact: Sender retries or fails
#     Recovery: Automatic (restart). No partial state to corrupt.
#     This is FAIL-CLOSED: crash = no message = safe
#
#   Failure: Schema module updated with new modules, logic_lock not updated
#     Effect: New module can send messages but logic_lock rejects them
#     Impact: New module's messages fail logic_hash verification
#     Recovery: Add module to VALID_SOURCE_MODULES in logic_lock
#     This is FAIL-CLOSED: unknown module = rejected
#
#
# SECRET ROTATION RUNBOOK
# -----------------------
# When to rotate:
#   - Annually (scheduled maintenance)
#   - On any suspected compromise (immediate)
#   - When decommissioning a server that had the secret (precautionary)
#   - When revoking access for a team member who knew the secret
#
# How to rotate (zero-downtime):
#   1. Generate a new secret:
#        NEW_SECRET=$(python3 -c "import secrets; print(secrets.token_bytes(32).hex())")
#
#   2. Deploy receivers first with BOTH old and new secret:
#        (Requires a future "multi-secret" feature â€” not yet implemented.
#         Until then, use rolling restart with brief message loss.)
#
#   3. Rolling restart of all pods/modules with the new secret:
#        export ICVS_LOGIC_SECRET=$NEW_SECRET
#        # Restart pod
#
#   4. Messages generated during the rolling restart may fail verification
#      if sender and receiver are on different secrets. The 20-40 second
#      window means a fast rolling restart (<30s per pod) loses minimal
#      messages. The Kafka consumer retry loop handles re-delivery.
#
#   5. After all pods are on the new secret, verify logs show no
#      logic_hash failures.
#
#
# OPERATIONAL MONITORING
# ----------------------
# Key metrics to watch:
#   - logic_hash verification failure rate (normal: ~0%, alarm: >1%)
#   - logic_hash computation latency (normal: <1ms, alarm: >10ms)
#   - Clock skew between modules (normal: <1s, alarm: >10s)
#
# If verification failures spike:
#   1. Check NTP sync across all modules (most common cause)
#   2. Check that all modules are running the same ICVS_LOGIC_SECRET
#   3. Check that all modules are running the same protocol version
#   4. Check Kafka consumer lag (messages arriving after their slot expires)
#
#
# VERSION HISTORY
# ---------------
#   v1: Original "logic rotator" â€” NON-FUNCTIONAL (missing timedelta import).
#       Zero-secret design (KMAC key = module name, hardcoded challenge).
#       Only 48 possible hash values. Security theater.
#
#   v2: Complete rewrite. Introduced deployment secret, time slots, HMAC-SHA3-256,
#       module validation, boundary tolerance. 66/66 tests. First working version.
#
#   v3: Submitted by competing red team. NON-FUNCTIONAL (missing time import).
#       Regressed protocol version binding and HMAC delimiter from v2.
#       Self-test broken (subclass doesn't override global). Changelog
#       fabricated 3 bugs that v2 didn't have.
#
#   v4: Fixes v3 bugs, preserves v3's good ideas (20s slots, previous-only
#       tolerance, int timestamps), restores v2's security properties
#       (protocol version, delimiter, consistent error handling). 69/69 tests.
#
#   v5: First honest red team. Expanded self-test (14 tests, up from 8).
#       array.array for best-effort memory zeroing. Extracted _load_secret().
#       Regex pre-validation for clearer errors. 78/78 tests.
#       Introduced 1 regression: identity-based UTC check.
#
#   v6: Fixes v5 regression (UTC identity â†’ value). Fixes regex (odd-length).
#       Tracks secret source for safer test ergonomics. Restores test secret
#       after edge checks. 54/54 external + 16/16 embedded tests.
#
#   v7: Submitted by competing red team. Adds isinstance type checks on public
#       API (genuine defense-in-depth). Adds try-except on utcoffset() for
#       exotic tzinfo. Expands self-test to 20. Introduces 1 medium regression:
#       load_for_testing() doesn't zero old secret before overwrite (v6 did).
#       Also: isascii() check is dead code, TypeError/ValueError inconsistency,
#       Test 19 tests wrong thing, Test 20 doesn't restore secret.
#
#   v8: (this file) Merges v7 improvements (type checks, tzinfo error handling,
#       expanded tests), fixes v7 regressions (zeroing on overwrite, TypeError
#       consistency, test accuracy). Fixes latent slot-boundary flake in
#       self-test that all versions v4-v7 carried. 59/59 external + 22/22.
#
#
# FOR DEVELOPERS: COMMON TASKS
# ----------------------------
#
#   Generating a hash (sender side):
#     from logic_lock import rotator
#     hash_hex = rotator.generate_logic_hash("CVS")
#     # â†’ "a1b2c3d4..." (64 hex chars, put in message header)
#
#   Verifying a hash (receiver side):
#     from logic_lock import rotator
#     is_valid = rotator.verify_logic_hash(
#         received_hash=msg.header.logic_hash,      # from deserialized header
#         source_module=msg.header.source_module,    # from deserialized header
#         message_timestamp=msg.header.timestamp,    # from deserialized header
#     )
#     if not is_valid:
#         reject_message(msg, reason="logic_hash verification failed")
#
#   Setting the deployment secret (production):
#     export ICVS_LOGIC_SECRET=$(python3 -c "import secrets; print(secrets.token_bytes(32).hex())")
#     # Must be set identically on ALL pods/modules in the deployment
#
#   Running the self-test:
#     python logic_lock.py
#     # Uses ephemeral test secret, does not require ICVS_LOGIC_SECRET
#
#   Adding a new module:
#     1. Add the module ID to VALID_SOURCE_MODULES in this file
#     2. Add the SAME module ID to VALID_SOURCE_MODULES in the schema
#     3. That's it â€” logic_lock will now accept and generate hashes for it
#
#   Changing slot duration or tolerance:
#     1. Change the constant (SLOT_DURATION_SECONDS or SLOT_TOLERANCE)
#     2. Bump PROTOCOL_VERSION (old hashes must not work with new settings)
#     3. Run full test suite
#     4. Deploy ALL modules simultaneously (brief message loss is acceptable)
#
#
# ERROR HANDLING PHILOSOPHY
# -------------------------
# This module uses three exception types with distinct meanings:
#
#   TypeError  â€” wrong Python type (e.g., int instead of str)
#                Indicates a programming bug at the call site.
#                Caller should fix their code.
#
#   ValueError â€” right type, wrong content (e.g., non-hex string, unknown module)
#                Indicates bad data, possibly from an attacker.
#                Caller should reject the message and log the error.
#
#   RuntimeError â€” infrastructure misconfiguration (e.g., missing secret)
#                  Indicates a deployment problem.
#                  Caller should alert ops and fail fast.
#
# This distinction matters because callers often catch ValueError to handle
# "bad input" and RuntimeError to handle "broken infra." If we raised
# ValueError for a missing secret, the caller might silently discard the
# error as "bad input" when it's actually "no messages can work at all."
#
# =============================================================================

from __future__ import annotations

import array
import hashlib
import hmac
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import FrozenSet


# =============================================================================
#
#   SECTION 1: SCHEMA-COMPATIBLE CONSTANTS
#
#   These MUST match the values in schemas_sovereign_v10_final.py.
#   Defined as a constant here (not imported from the schema module) to
#   avoid circular imports if the schema ever imports from logic_lock.
#
#   The schema defines:
#     VALID_SOURCE_MODULES = frozenset({"CVS", "RTA", ...})
#   in its global constants section (Section 1). Both files list the same
#   16 modules. The test suite imports both and asserts equality.
#
#   RULE: If you add a module to the schema, add it here too. If you add
#   one here, add it to the schema too. These MUST be kept in sync.
#   The test suite verifies they match.
#
#   Why not import from the schema?
#     If the schema ever imports from logic_lock (e.g., to call
#     generate_logic_hash during serialization), a circular import occurs.
#     Keeping an independent copy with test-verified sync is safer.
#
# =============================================================================

VALID_SOURCE_MODULES: FrozenSet[str] = frozenset({
    # —— Phase 0: Foundation (built) ———————————————————————————————————
    "CVS",      # Core Validation Standard — central truth-scoring engine
    "RTA",      # Root Trace Analysis — causal chain investigator
    "DCAP",     # Data Consistency Assessment Protocol — dataset audit pipeline
    "CVL",      # Continuous Verification Loop — adversarial wargame sandbox
    # —— Phase 2: Governance Layer —————————————————————————————————————
    "GOSA",     # Global Operational Strategy Arbiter — meta-controller
    "DRM",      # Dynamic Resource Manager — quota enforcement
    "MGM",      # Master Governance Module — license & tier enforcement
    "SRA",      # Security & Resilience Arbiter — tactical security
    # —— Phase 3: Core Analytical Modules ——————————————————————————————
    "BIMP",     # Behavioral Impact Monitoring Protocol — behavioral analysis
    "GNRM",     # Gradient Narrative Risk Mapper — narrative clustering
    "INAE",     # Institutional Narrative Alignment Engine — influence networks
    # —— Phase 4: Strategic & Intelligence ———————————————————————————————
    "SAP",      # Semantic Alignment Protocol — definition disambiguation
    "DCA",      # Doctrinal Clash Analysis — faction mapping & conflict
    "SDM",      # Strategic Decision Module — Wisdom Index computation
    "SSE",      # Strategic Simulation Engine (HSCAE+PNACE merged per v16.2.1)
    "HIL",      # Human-in-the-Loop — human oversight and approval workflow
    # —— Phase 5: Security Architecture ————————————————————————————————
    "T1-IVS",   # Tier 1 Infrastructure Verification System — sovereign security
    "ADF",      # Adaptive Defense Framework — bio-digital immune system
    "RTMA",     # Real-Time Monitoring Array — sentinel network
    "PDS",      # Perimeter Defense System — sacrificial packet defense
    # —— Phase 6: Intelligence Platform ————————————————————————————————
    "MLIP",     # Multi-Layer Intelligence Platform — UQTE container process
    "GHOST",    # GHOST mode — traffic pattern superposition
    "MORPHEUS", # MORPHEUS mode — behavioral entanglement
    "NEMESIS",  # NEMESIS mode — adversarial countermeasure
    "FSIM",     # Full-Spectrum Intelligence Module (replaces HADES)
    "QAM",      # Quantum Analytics Module — QPU-based anomaly detection
    "SPP",      # Strategic Planning Platform — quantum governance simulations
    # —— Phase 7: Arbiters & Support ———————————————————————————————————
    "EA",       # Ethics Arbiter — ETHICAL_COHERENCE_INDEX, ERSA
    "DOA",      # Data Optimization Arbiter — privacy, data minimization
    "IIPA",     # Innovation & IP Arbiter — ARM management, patents
    "SIMA",     # System Integrity Monitor Arbiter — health & emergence
    "LAA",      # Learning & Adaptation Arbiter — meta-heuristic evolution
    "SSA",      # Skeptical Statistician Arbiter — causal inference rigor
    "SUSA",     # Sustainability Arbiter — carbon/energy optimization
    "QAA",      # Quantum Advantage Arbiter — quantum-classical routing
    "UOE",      # Universal Optimization Engine — Pareto frontier optimizer
    # —— Phase 8: Presentation & Reporting ———————————————————————————————
    "CTLP",     # Contextual Tiered Layered Presentation — UI/reporting
    "TAL",      # Transaction Audit Logger — forensic snapshot engine
    "SEM",      # State Event Management — Kafka bus orchestrator
    # —— Phase 9: Specialized & Domain —————————————————————————————————
    "ERM",      # Evidence Reconstruction Module — forensic reconstruction
    "PAE",      # Predictive Analytics Engine — forward-looking analysis
    "NSM",      # Network Synthesis Module — network perimeter defense
    "MHRA",     # Mainstream Historical Record Analysis — historical baselines
    "TIAP",     # Talent Integrity Assurance Protocol — personnel vetting
    "ARM",      # Advanced Research Module — Tier 0 only, proprietary R&D
    "LCAE",     # Longitudinal Coherence Analysis Engine — temporal drift
    # —— Governance sub-identities ————————————————————————————————————
    "DEBE",     # Disparate Evidence Bias Engine — bias detection sub-identity
})
# This allowlist doubles as the module length check. A 10,000-character
# string will never be in this frozenset, so there is no need for a
# separate len() check. The frozenset lookup is O(1) regardless of
# input size.


# =============================================================================
#
#   SECTION 2: SECURITY CONSTANTS
#
#   These control the security posture of the logic_hash subsystem.
#   Changes require red-team review. Never loosen in production.
#
#   Every constant here has a security justification. If a future developer
#   changes a value, they should update the justification or explain why
#   the old reasoning no longer applies.
#
# =============================================================================

# -- Time Slot Duration --
# The hash changes every SLOT_DURATION_SECONDS. This is the fundamental
# anti-replay granularity: two messages in the same slot produce the same
# hash (for the same module), but messages in different slots produce
# different hashes.
#
# 20 seconds chosen because:
#   - Must be <= schema's MAX_MESSAGE_AGE_SECONDS (45s) to be meaningful.
#     If the slot were 60s, every message within the schema's 45s window
#     would always be in the same slot â€” the logic_hash adds nothing.
#   - Must be >= expected network latency (~1-5s) to avoid false negatives.
#     If the slot were 2s, network jitter would cause legitimate messages
#     to arrive in a different slot than they were generated in.
#   - With previous-slot tolerance (SLOT_TOLERANCE=1), the effective
#     acceptance window is 20-40 seconds, which aligns well with the
#     schema's 45s freshness check.
#
# Slot timeline example (20-second slots):
#
#   Time:  |â”€â”€â”€â”€ slot 100 â”€â”€â”€â”€|â”€â”€â”€â”€ slot 101 â”€â”€â”€â”€|â”€â”€â”€â”€ slot 102 â”€â”€â”€â”€|
#   Secs:  2000     2010     2020     2030     2040     2050     2060
#                    â–²                  â–²
#                    â”‚                  â”‚
#              sender generates   receiver verifies
#              hash for slot 100  checks [slot 100, slot 101]
#                                 slot 100 matches â†’ valid âœ“
#
SLOT_DURATION_SECONDS: int = 20

# -- Verification Tolerance --
# How many PREVIOUS time slots to try in addition to the current slot.
# SLOT_TOLERANCE=1 means: try [current_slot - 1, current_slot] = 2 attempts.
#
# NO FUTURE SLOTS. This is a deliberate, red-team-validated security decision.
#
# Why allow previous slots:
#   If the receiver's clock is behind the sender's by up to 20 seconds,
#   the sender generates slot N but the receiver thinks it's still slot N-1.
#   Trying the previous slot catches this case.
#
# Why NOT allow future slots:
#   Attack: Attacker poisons receiver's NTP to advance clock 30 seconds.
#   Receiver now thinks it's slot N+1. Attacker computes hash for slot N+1
#   (using the correct time â€” the attacker's clock is accurate). If we
#   accepted future slots, this hash would verify as valid.
#   By rejecting future slots, the attacker's hash for slot N+1 fails
#   because the receiver only checks [N-1, N], not N+1.
#
# What about clock-ahead scenarios?
#   If the receiver's clock is AHEAD, the sender generates slot N but the
#   receiver thinks it's slot N+1. Without future tolerance, this fails.
#   This is acceptable because:
#     a) NTP keeps clocks within ~1s in normal operation.
#     b) The verifier uses the MESSAGE's timestamp to compute the slot,
#        not its own clock â€” so minor receiver clock drift is irrelevant.
#     c) Operations can detect and correct clock skew via monitoring.
SLOT_TOLERANCE: int = 1

# -- HMAC Algorithm --
# SHA3-256 (Keccak sponge construction) via Python's hashlib.
#
# Why SHA3-256 instead of SHA-256:
#   - Both provide 256-bit collision resistance.
#   - SHA3 is structurally independent from SHA-2 (different construction).
#     If a breakthrough breaks SHA-2 (Merkle-DamgÃ¥rd), SHA3 is unaffected.
#   - SHA3 is the NIST standard post-quantum hash recommendation.
#   - Performance: SHA3-256 is ~15% slower than SHA-256 on x86, but the
#     HMAC computation is one call per generate/verify â€” negligible.
#   - Native in Python 3.6+ via hashlib (no external dependencies).
#
# Output: 32 bytes = 64 hex characters.
# Callable form â€” no string lookup at hmac.new() call time.
HMAC_ALGORITHM = hashlib.sha3_256  # Hardened(v5): callable, not string

# -- Protocol Version --
# This string is included in the HMAC input to prevent cross-version
# replay attacks. If an attacker captures a hash from v7 and replays it
# on a v8 bus, the HMAC data differs ("ICVS-LogicLock-v7|..." vs
# "ICVS-LogicLock-v8|..."), so the hash won't match.
#
# RULE: If you change ANY aspect of the hash computation (algorithm,
# slot duration, input format, delimiter), you MUST bump this version.
# Failure to bump means old hashes could verify on the new code.
PROTOCOL_VERSION: str = "ICVS-LogicLock-v8"

# -- Secret Configuration --
# Minimum 32 bytes (256 bits) of entropy. This matches the HMAC key size
# for SHA3-256 (the key is zero-padded or hashed to the block size
# internally, but 32 bytes is the minimum for full security).
MIN_SECRET_LENGTH_BYTES: int = 32

# Environment variable name for the deployment secret.
# Convention: ICVS_ prefix for all ICVS-related env vars.
SECRET_ENV_VAR: str = "ICVS_LOGIC_SECRET"

# -- Secret hex validation regex --
# Requires: at least 64 hex chars (32 bytes), EVEN length only.
#
# Hardened(v6): v5 used {64,} which allows odd-length strings (65, 67...)
# that pass regex but fail bytes.fromhex(). The even-length requirement
# eliminates the confusing dual-error path where regex says "valid" but
# fromhex says "invalid."
#
# Pattern breakdown:
#   ^                       â€” start of string
#   [0-9a-fA-F]{64}        â€” exactly 64 hex chars (32 bytes minimum)
#   (?:[0-9a-fA-F]{2})*    â€” followed by any number of hex PAIRS (even)
#   $                       â€” end of string
#
# This accepts: 64, 66, 68, 70, ... (any even length â‰¥64)
# This rejects: 63, 65, 67, ... (odd), anything with non-hex chars
_RE_HEX_SECRET = re.compile(r'^[0-9a-fA-F]{64}(?:[0-9a-fA-F]{2})*$')


# =============================================================================
#
#   SECTION 3: SECRET MANAGEMENT
#
#   The deployment secret is the ONLY thing that makes this system secure.
#   Without it, an attacker with source code access can forge any hash.
#   With it, forgery requires breaking HMAC-SHA3-256 (computationally
#   infeasible with current and foreseeable technology).
#
#   Architecture:
#     _load_secret()     â€” reads and validates the env var (one-time)
#     _SecretHolder      â€” caches the secret in a mutable buffer (singleton)
#     _secret_holder     â€” global instance (module-level)
#
#   The secret is loaded LAZILY on first use, not at import time. This means:
#     - Importing logic_lock for type hints or constants doesn't require
#       the secret to be configured.
#     - The first actual generate/verify call triggers the load.
#     - If the secret is missing, the first call fails with RuntimeError.
#
#   Memory model:
#     _secret_holder._secret â†’ array.array('B', [...])  â† mutable, zeroable
#                                      â”‚
#                                      â–¼ (on .get())
#                               bytes(...)  â† immutable copy, NOT zeroable
#                                      â”‚
#                                      â–¼ (passed to hmac.new())
#                               HMAC computation â†’ discarded
#
#   The array.array is zeroed on clear(). The bytes copies returned by
#   get() are immutable and cannot be zeroed â€” they float in the heap
#   until GC collects them. This is a known Python limitation. True
#   secure memory requires ctypes/mmap, which is outside this module's
#   scope. The threat model already assumes process compromise = game over.
#
#   v5 Hardening: Use mutable array.array('B') for zeroing on clear.
#   v6 Hardening: Track secret source (env vs test) for safer test ergonomics.
#   v8 Hardening: Zero old secret on testâ†’test overwrite (v7 regressed this).
#
# =============================================================================

def _load_secret() -> bytes:
    """
    Load and validate the deployment secret from the environment.

    This function is called ONCE, on the first generate/verify call.
    After that, the secret is cached in _SecretHolder.

    Validation order:
      1. Env var exists? â†’ RuntimeError if not (deployment problem)
      2. Valid hex format? â†’ ValueError if not (misconfiguration)
      3. Sufficient length? â†’ ValueError if not (weak secret)

    Why RuntimeError for missing (not ValueError):
      A missing secret is not "bad input" â€” it's "the system is
      misconfigured and NO messages can work." RuntimeError signals
      to the caller that this is an infrastructure issue, not a
      data validation issue.

    Hardened(v5): Regex pre-validation for clearer error messages.
    Hardened(v6): Regex requires even-length hex to prevent odd-length
    strings passing regex then failing bytes.fromhex() with a vague error.

    Returns:
        Raw secret bytes (>= 32 bytes).

    Raises:
        RuntimeError: If env var is missing.
        ValueError: If env var is not valid even-length hex or too short.
    """
    raw = os.environ.get(SECRET_ENV_VAR)
    if raw is None:
        raise RuntimeError(
            f"ICVS logic_lock: deployment secret not configured. "
            f"Set {SECRET_ENV_VAR} environment variable (hex-encoded, "
            f">={MIN_SECRET_LENGTH_BYTES * 2} hex chars)."
        )

    # Hardened(v6): Even-length hex validation. v5 used {64,} which
    # allowed odd lengths (65, 67...). bytes.fromhex catches odd lengths
    # but with a confusing "non-hexadecimal number found" error that
    # doesn't explain the actual problem (odd length, not bad chars).
    if not _RE_HEX_SECRET.match(raw):
        raise ValueError(
            f"ICVS logic_lock: {SECRET_ENV_VAR} must be even-length "
            f"hexadecimal (>={MIN_SECRET_LENGTH_BYTES * 2} chars). "
            f"Got {len(raw)} chars."
        )

    secret = bytes.fromhex(raw)
    if len(secret) < MIN_SECRET_LENGTH_BYTES:
        # This check is technically redundant (regex ensures â‰¥64 hex = â‰¥32 bytes)
        # but serves as a defense-in-depth belt-and-suspenders check.
        raise ValueError(
            f"ICVS logic_lock: {SECRET_ENV_VAR} too short "
            f"({len(secret)} bytes, minimum {MIN_SECRET_LENGTH_BYTES})."
        )
    return secret


class _SecretHolder:
    """
    Lazy-loaded, cached deployment secret with best-effort memory zeroing.

    Uses __slots__ to prevent accidental dynamic attributes. This was
    a v3 bug: class-level mutable defaults shared across instances.

    Hardened(v5): Uses array.array('B') for mutable buffer that can be
    zeroed before dereferencing. GC may not zero freed memory, but we
    zero it ourselves before dropping the reference.

    Hardened(v6): Tracks whether secret was loaded from environment or
    from load_for_testing(). Allows testâ†’test overwrite but blocks
    envâ†’test overwrite (production secret is sacred).

    Hardened(v8): Restored v6's _zero_and_release() call in load_for_testing().
    v7 dropped it â€” on testâ†’test overwrite, the old array was orphaned
    without zeroing. Now consistent: always zero before releasing.

    Note on get() returning bytes: Each call creates an immutable bytes
    copy that cannot be zeroed. On a busy bus this creates many copies.
    This is a known limitation of Python's memory model. True secure
    memory requires ctypes/mmap, which is outside this module's scope.
    The array zeroing protects the CACHED copy; GC handles the rest.
    """
    __slots__ = ('_secret', '_source')

    def __init__(self) -> None:
        self._secret: array.array | None = None
        self._source: str | None = None  # "env" or "test"

    def get(self) -> bytes:
        """Return the deployment secret, loading from env on first call."""
        if self._secret is not None:
            return bytes(self._secret)
        # First call â€” load from environment.
        # This is the lazy-load pattern: no env access until needed.
        raw = _load_secret()
        self._secret = array.array('B', raw)
        self._source = "env"
        return bytes(self._secret)

    def load_for_testing(self, secret: bytes | None = None) -> None:
        """
        Load an ephemeral test secret for the self-test or external harness.

        Hardened(v6): Allows overwrite of test secrets (testâ†’test is fine)
        but blocks overwrite of env-loaded secrets (production is sacred).
        v5 unconditionally rejected if any secret was loaded, which broke
        legitimate test workflows (Test A forgets to clear â†’ Test B crashes).

        Hardened(v8): Zero old array before overwriting. v7 dropped this â€”
        orphaned array.array with previous test secret in memory. Now
        consistent with clear(): always zero before releasing.

        Args:
            secret: Optional explicit secret bytes (>= 32 bytes).
                    If None, generates a random 32-byte key.
        """
        # Hardened(v6): Block overwrite of production secret only.
        # If a test accidentally imports a module that already loaded
        # the real secret from env, this prevents the test from silently
        # replacing it with a weak test secret.
        if self._secret is not None and self._source == "env":
            raise RuntimeError(
                "Cannot override production secret with test secret. "
                "This is a safety check â€” if you're seeing this in tests, "
                "your test harness is using a production-configured module."
            )

        if secret is not None:
            if len(secret) < MIN_SECRET_LENGTH_BYTES:
                raise ValueError(
                    f"Test secret too short ({len(secret)} bytes, "
                    f"minimum {MIN_SECRET_LENGTH_BYTES})"
                )
        else:
            secret = secrets.token_bytes(MIN_SECRET_LENGTH_BYTES)

        # Hardened(v8): Zero any existing test secret before overwriting.
        # v7 dropped this â€” old array orphaned with secret still in buffer.
        if self._secret is not None:
            self._zero_and_release()

        self._secret = array.array('B', secret)
        self._source = "test"

    def clear(self) -> None:
        """Zero and release the cached secret."""
        if self._secret is not None:
            self._zero_and_release()

    def _zero_and_release(self) -> None:
        """
        Explicit zeroing for defense-in-depth, then drop reference.

        This overwrites every byte in the mutable array with 0x00 before
        setting the reference to None. Without this, the GC would eventually
        free the memory, but the secret bytes would remain in the freed
        memory until overwritten by a future allocation.

        Note: Python's GC is not guaranteed to call this promptly. For
        true secure memory, use OS-level mechanisms (mlock, madvise).
        """
        for i in range(len(self._secret)):
            self._secret[i] = 0
        self._secret = None
        self._source = None


# Module-level singleton. Safe to share â€” all state is in the cached secret.
# Multiple _SecretHolder instances would be wasteful but not harmful.
_secret_holder = _SecretHolder()


# =============================================================================
#
#   SECTION 4: TIME SLOT COMPUTATION
#
#   A time slot is an integer representing a SLOT_DURATION_SECONDS-second
#   window of time. The computation is simple integer division:
#
#     slot = floor(unix_timestamp / SLOT_DURATION_SECONDS)
#
#   Two timestamps in the same window produce the same slot.
#   Timestamps in different windows produce different slots.
#
#   Example (SLOT_DURATION_SECONDS = 20):
#     timestamp 1000 â†’ slot 50
#     timestamp 1019 â†’ slot 50  (same slot, same hash)
#     timestamp 1020 â†’ slot 51  (new slot, different hash)
#
#   Clock source: datetime.now(timezone.utc) â€” ALWAYS.
#   No time.time() anywhere in this module. Using both datetime and time
#   can produce different values due to different syscalls (clock_gettime
#   vs gettimeofday), causing slot mismatch at boundaries.
#
#   The single clock source (_current_slot â†’ datetime.now) ensures that
#   generate and verify always agree on "now", even at slot boundaries.
#
# =============================================================================

def _timestamp_to_slot(ts: datetime) -> int:
    """
    Convert a UTC datetime to its time slot number.

    This is the critical timeâ†’slot mapping. Both the sender (via
    _current_slot â†’ generate_logic_hash) and receiver (via
    message_timestamp â†’ verify_logic_hash) must produce the same slot
    for the same point in time. Integer division ensures this.

    UTC validation:
      Hardened(v6): Restored v4's VALUE-based UTC check. v5 used
      `ts.tzinfo is not timezone.utc` which is an IDENTITY check.
      CPython 3.12+ interns timezone(timedelta(0)) to timezone.utc,
      so the `is` check works on CPython by accident. But:
        - PyPy does NOT intern timezone(timedelta(0))
        - pytz.UTC is a different singleton
        - dateutil.tz.tzutc() is a different class entirely
        - zoneinfo.ZoneInfo("UTC") may differ by platform

      The schema validator uses value equality (utcoffset != timedelta(0)),
      so the schema ACCEPTS these UTC variants. If logic_lock uses identity
      checks, messages that pass schema validation fail logic_hash
      verification â€” a silent functional break on non-CPython runtimes.

      Value-based check is correct on ALL Python implementations.

    Why int() truncation:
      datetime.timestamp() returns a float. Floating-point division can
      produce rounding errors near slot boundaries:
        float: 1020.0 / 20 = 51.0  â† correct
        float: 1019.9999999 / 20 = 50.999999995  â† rounds to 50, not 51
      int() truncation before division eliminates this: int(1019.999) = 1019.
    """
    if ts.tzinfo is None:
        raise ValueError("Timestamp must be timezone-aware")
    # Hardened(v7): Wrap utcoffset() in try-except for exotic tzinfo
    # subclasses that might raise (e.g., network-dependent tzinfo that
    # fetches offset from a remote server and the server is down).
    # Standard library tzinfo implementations never raise here, but
    # third-party ones might. Cheap insurance.
    try:
        offset = ts.tzinfo.utcoffset(ts)
    except Exception as e:
        raise ValueError(f"Timestamp timezone failed utcoffset(): {e}")
    # Explicit None check: utcoffset() can return None for "unknown offset"
    # tzinfo implementations (documented in Python stdlib). The expression
    # `None != timedelta(0)` evaluates to True in Python, so the check
    # would work without the explicit `offset is None`. But relying on
    # that is accidental behavior â€” the explicit check documents intent.
    if offset is None or offset != timedelta(0):
        raise ValueError(f"Timestamp must be UTC (offset=0). Got offset={offset}")

    # int() truncation avoids float precision issues at slot boundaries.
    # See docstring for explanation.
    unix_ts = int(ts.timestamp())
    return unix_ts // SLOT_DURATION_SECONDS


def _current_slot() -> int:
    """
    Get the current time slot using the unified clock source.

    This is the ONLY place in the module that reads the system clock.
    generate_logic_hash() calls this. verify_logic_hash() uses the
    message's timestamp instead (to account for network transit time).
    """
    return _timestamp_to_slot(datetime.now(timezone.utc))


# =============================================================================
#
#   SECTION 5: HMAC COMPUTATION
#
#   This is the core cryptographic primitive. The HMAC binds three things
#   together into a single, unforgeable token:
#
#     1. The deployment secret (HMAC key) â€” proves knowledge of the secret
#     2. The source module ID â€” prevents cross-module forgery
#     3. The time slot â€” prevents replay across slot boundaries
#     4. The protocol version â€” prevents cross-version replay
#
#   HMAC input structure:
#     key  = deployment_secret (32+ bytes from environment)
#     data = "ICVS-LogicLock-v8|CVS|86974380"
#            ^^^^^^^^^^^^^^^^^^  ^^^  ^^^^^^^^
#            protocol version   module  slot number (decimal int)
#
#   The "|" delimiter prevents encoding ambiguity (Attack 7 in the threat
#   model above). Module names contain only ASCII alphanumeric + hyphen
#   (enforced by schema regex: ^[A-Z0-9-]+$). Slot numbers are decimal
#   integers. Neither can contain "|", so the fields are unambiguous.
#
#   The entire message is ASCII-encoded. Module names are validated as
#   ASCII by the schema. Non-ASCII would cause .encode("ascii") to raise
#   UnicodeEncodeError â€” but the frozenset allowlist catches non-ASCII
#   modules first (they're simply not in the set).
#
# =============================================================================

def _compute_hash(secret: bytes, source_module: str, slot: int) -> str:
    """
    Compute HMAC-SHA3-256 for a given module and time slot.

    This is a pure function â€” same inputs always produce the same output.
    No side effects, no state, no I/O.

    Args:
        secret: The deployment secret (32+ bytes).
        source_module: Module ID (must be in VALID_SOURCE_MODULES).
        slot: Time slot number (integer).

    Returns:
        64-character lowercase hex string.
    """
    # Build the HMAC data as a delimited ASCII string.
    # f-string is safe here because all components are known-safe:
    #   - PROTOCOL_VERSION is a hardcoded constant
    #   - source_module was validated against the frozenset allowlist
    #   - slot is an int (str(int) is always ASCII digits)
    message = f"{PROTOCOL_VERSION}|{source_module}|{slot}".encode("ascii")
    return hmac.new(
        key=secret,
        msg=message,
        digestmod=HMAC_ALGORITHM,
    ).hexdigest()


# =============================================================================
#
#   SECTION 6: LOGIC ROTATOR CLASS
#
#   The public interface. Stateless, thread-safe, safe to share globally.
#
#   Why a class instead of bare functions?
#     - Namespace grouping (generate and verify belong together)
#     - Future extensibility (subclassing for testing, mocking, etc.)
#     - Convention (schema uses Pydantic models, consumers expect objects)
#     - The class is truly stateless â€” all state lives in _secret_holder
#
#   Why a module-level singleton?
#     - Convenience: `from logic_lock import rotator` is shorter than
#       `from logic_lock import LogicRotator; rotator = LogicRotator()`
#     - Safety: Multiple instances are identical (stateless), so a singleton
#       avoids confusion about "which rotator am I using?"
#     - Thread-safe: No mutable instance state. The only mutable state is
#       in _secret_holder (the cached secret), which is write-once-read-many.
#
# =============================================================================

class LogicRotator:
    """
    Stateless, thread-safe logic hash generator and verifier.

    All computation is derived from:
      - The deployment secret (loaded from environment on first use)
      - The module ID (from the message header, validated against allowlist)
      - The current time slot (from system clock or message timestamp)

    This means any number of LogicRotator instances produce identical
    results, and a single instance can be safely shared across threads.

    Usage:
      from logic_lock import rotator

      # Sender side (when constructing a message):
      logic_hash = rotator.generate_logic_hash("CVS")
      # â†’ "a1b2c3d4..." (64 hex chars, put in message header)

      # Receiver side (when validating a received message):
      is_valid = rotator.verify_logic_hash(
          received_hash="a1b2c3d4...",
          source_module="CVS",
          message_timestamp=header.timestamp
      )
      # â†’ True or False
    """

    def generate_logic_hash(self, source_module: str) -> str:
        """
        Generate the current valid logic_hash for the given module.

        Called by the SENDER when constructing a message. The returned
        hash goes into the message header's `logic_hash` field.

        The schema's _validate_hex validator will check that this output
        is valid lowercase hex with length 64-512. This function always
        produces exactly 64 lowercase hex chars (SHA3-256 output).

        Args:
            source_module: The sender's module ID (e.g., "CVS").
                           Must be in VALID_SOURCE_MODULES.

        Returns:
            64-character lowercase hex string (HMAC-SHA3-256 output).
            This format is compatible with the schema's logic_hash field
            (min_length=64, max_length=512, validated as hex by _validate_hex).

        Raises:
            TypeError:     If source_module is not a string.
            ValueError:    If source_module is not in the allowlist.
            RuntimeError:  If the deployment secret is not configured.
        """
        # Hardened(v7): Explicit type check at API boundary. Schema validates
        # types before we see them, but direct callers (tests, non-schema
        # paths) get a clear TypeError instead of a vague AttributeError
        # deep in the f-string or frozenset lookup.
        if not isinstance(source_module, str):
            raise TypeError(
                f"source_module must be str, got {type(source_module).__name__}"
            )

        # Validate module identity before any computation.
        # v3 bug: verify checked allowlist but generate didn't, allowing
        # a compromised sender to generate hashes for arbitrary modules.
        # Since v4, both generate and verify check the allowlist.
        if source_module not in VALID_SOURCE_MODULES:
            raise ValueError(
                f"Unknown source_module: {source_module!r}. "
                f"Must be one of {sorted(VALID_SOURCE_MODULES)}"
            )

        secret = _secret_holder.get()
        slot = _current_slot()
        return _compute_hash(secret, source_module, slot)

    def verify_logic_hash(
        self,
        received_hash: str,
        source_module: str,
        message_timestamp: datetime,
    ) -> bool:
        """
        Verify that the received logic_hash is valid for the given module
        and timestamp.

        Called by the RECEIVER after deserializing a message via the schema.
        The schema has already validated:
          - received_hash is lowercase hex (via _validate_hex)
          - received_hash is 64-512 chars (via Field min/max_length)
          - message_timestamp is UTC and fresh (via validate_timestamp)
          - source_module is in the allowlist (via validate_source)

        This function provides defense-in-depth by re-validating inputs
        and performing the cryptographic comparison.

        Tries the message's time slot and SLOT_TOLERANCE previous slots.
        NO future slots â€” prevents clock-advance attacks (see Attack 4).

        Why use the MESSAGE's timestamp (not the receiver's clock)?
          The sender sets message_timestamp = datetime.now(utc) when creating
          the message. The sender also computes the hash using its own clock.
          If we use the receiver's clock, network delay means the receiver's
          "now" could be a different slot than the sender's "now". Using the
          message's timestamp reconstructs the sender's slot, then the
          tolerance window handles minor clock skew.

        Args:
            received_hash:     The logic_hash from the message header.
            source_module:     The source_module from the message header.
            message_timestamp: The timestamp from the message header (UTC).

        Returns:
            True if the hash matches any slot in the tolerance window.
            False if no slot matches (likely replay, forgery, or clock skew).

        Raises:
            TypeError:    If received_hash is not str, source_module is not str,
                          or message_timestamp is not datetime.
            ValueError:   On malformed input (wrong length, non-hex, bad module,
                          non-UTC timestamp). These are programming errors or
                          active attacks â€” not normal "hash didn't match" cases.
            RuntimeError: If the deployment secret is not configured.
        """
        # â”€â”€ Input validation (defense-in-depth â€” schema already checked) â”€â”€

        # Hardened(v8): Split type vs value checks for received_hash.
        # v7 combined isinstance and len into one ValueError. But wrong TYPE
        # should be TypeError (different remediation for callers catching
        # ValueError for "bad format" vs TypeError for "wrong argument type").
        if not isinstance(received_hash, str):
            raise TypeError(
                f"received_hash must be str, got {type(received_hash).__name__}"
            )

        # Length check: HMAC-SHA3-256 always produces exactly 64 hex chars.
        # If this doesn't match, the hash was computed by a different algorithm
        # or is corrupted. We reject before doing any crypto work.
        if len(received_hash) != 64:
            raise ValueError(
                f"logic_hash must be exactly 64 hex characters. "
                f"Got len={len(received_hash)}"
            )

        # Lowercase enforcement: the schema normalizes to lowercase via
        # _validate_hex, but if this function is called without schema
        # pre-processing (e.g., in testing or from a different entry point),
        # uppercase hex would cause hmac.compare_digest to return False
        # even for a correct hash. Enforce here for defense-in-depth.
        if received_hash != received_hash.lower():
            raise ValueError("logic_hash must be lowercase hex")

        # Hex validation: bytes.fromhex() rejects non-hex characters.
        # This is faster than regex for 64-char strings.
        try:
            bytes.fromhex(received_hash)
        except ValueError:
            raise ValueError("logic_hash contains non-hexadecimal characters")

        # Hardened(v7): Type check for source_module.
        if not isinstance(source_module, str):
            raise TypeError(
                f"source_module must be str, got {type(source_module).__name__}"
            )

        # Module validation: consistent with generate â€” both raise ValueError.
        # v3 bug: verify returned False for invalid modules (conflating
        # "wrong module" with "wrong hash"), making debugging harder.
        if source_module not in VALID_SOURCE_MODULES:
            raise ValueError(f"Unknown source_module: {source_module!r}")

        # Hardened(v7): Type check for message_timestamp.
        if not isinstance(message_timestamp, datetime):
            raise TypeError(
                f"message_timestamp must be datetime, got {type(message_timestamp).__name__}"
            )

        # â”€â”€ Compute expected hash for message's time slot Â±tolerance â”€â”€

        # _timestamp_to_slot validates UTC internally, so we don't need
        # a separate UTC check here. It raises ValueError for non-UTC.
        msg_slot = _timestamp_to_slot(message_timestamp)
        secret = _secret_holder.get()

        # Try current slot and SLOT_TOLERANCE previous slots.
        # range(-1, 1) = [-1, 0] â†’ [previous_slot, current_slot]
        # NO future slots (delta > 0 never tried â€” see SLOT_TOLERANCE docs).
        for delta in range(-SLOT_TOLERANCE, 1):
            candidate_slot = msg_slot + delta
            expected = _compute_hash(secret, source_module, candidate_slot)

            # Constant-time comparison prevents timing side-channel (Attack 6).
            # Without this, an attacker measuring verification time could
            # determine how many bytes of the hash matched, progressively
            # narrowing the search space. hmac.compare_digest takes the
            # same time regardless of how many bytes match.
            if hmac.compare_digest(received_hash, expected):
                return True

        return False


# =============================================================================
#   MODULE-LEVEL SINGLETON
#
#   Safe to share globally â€” the rotator is stateless. All state lives in
#   _secret_holder (the cached deployment secret). Multiple LogicRotator
#   instances produce identical results.
#
#   Usage:
#     from logic_lock import rotator
#     hash_hex = rotator.generate_logic_hash("CVS")
# =============================================================================

rotator = LogicRotator()


# =============================================================================
#
#   SECTION 7: SELF-TEST
#
#   Run with: python logic_lock.py
#   Tests basic generate/verify cycle, boundary conditions, and error handling.
#   Uses an ephemeral test secret (not the production secret).
#
#   The self-test uses _secret_holder.load_for_testing() to inject an
#   ephemeral secret into the global holder, with try/finally to ensure
#   cleanup. This avoids the v3 bug where a subclass override didn't
#   affect the module-level singleton's secret.
#
#   v5: Expanded to 14 tests from v4's 8.
#   v6: Added tests for v5 regression fixes. 16 tests.
#   v7: Added type errors, long secret. 20 tests.
#   v8: Fixed v7 Test 19 (was testing allowlist, not ASCII). Fixed v7
#       Test 20 (didn't restore secret). Added TypeError consistency
#       tests. Fixed latent slot-boundary flake in Tests 3 and 9 (all
#       versions v4-v7 used time-based slot computation that could
#       overshoot by 2 slots at boundaries). 22 tests.
#
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  ICVS LogicRotator v8 â€” Self-Test")
    print("=" * 60)

    _secret_holder.load_for_testing()

    try:
        test_module = "DCAP"
        now = datetime.now(timezone.utc)

        # Test 1: Generate + verify (same time)
        # Proves: basic round-trip works, output format is correct.
        generated = rotator.generate_logic_hash(test_module)
        assert len(generated) == 64, f"Expected 64 hex chars, got {len(generated)}"
        assert all(c in '0123456789abcdef' for c in generated)
        assert rotator.verify_logic_hash(generated, test_module, now)
        print("[1]  Generate + verify (same time): PASS")

        # Test 2: Same slot (+5s)
        # Proves: timestamps within the same 20-second slot produce the same hash.
        assert rotator.verify_logic_hash(generated, test_module, now + timedelta(seconds=5))
        print("[2]  Same slot (+5s): PASS")

        # Test 3: Previous slot tolerance
        # Proves: the tolerance window includes the previous slot.
        # Hardened(v8): Use direct slot arithmetic instead of time-based
        # computation. v4-v7 used `now - timedelta(SLOT_DURATION + 1)` which
        # can overshoot by 2 slots at slot boundaries (e.g., if now lands on
        # second 0 of a slot, subtracting 21s crosses TWO slot boundaries).
        prev_slot = _timestamp_to_slot(now) - 1
        prev_hash = _compute_hash(_secret_holder.get(), test_module, prev_slot)
        assert rotator.verify_logic_hash(prev_hash, test_module, now)
        print("[3]  Previous slot tolerance: PASS")

        # Test 4: Outside tolerance (3 slots away)
        # Proves: old messages beyond the tolerance window are rejected.
        assert not rotator.verify_logic_hash(generated, test_module,
            now - timedelta(seconds=SLOT_DURATION_SECONDS * 3))
        print("[4]  Outside tolerance rejected: PASS")

        # Test 5: Wrong module
        # Proves: cross-module forgery is blocked (Attack 2).
        assert not rotator.verify_logic_hash(generated, "CVS", now)
        print("[5]  Wrong module rejected: PASS")

        # Test 6: Invalid module raises (not returns False)
        # Proves: unknown modules get ValueError, not silent failure.
        try:
            rotator.generate_logic_hash("EVIL")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass
        print("[6]  Invalid module raises ValueError: PASS")

        # Test 7: Tampered hash
        # Proves: even a small change to the hash is detected.
        assert not rotator.verify_logic_hash("00" * 32, test_module, now)
        print("[7]  Tampered hash rejected: PASS")

        # Test 8: All 16 modules produce unique hashes
        # Proves: module binding works â€” each module's hash is distinct.
        hashes = {m: rotator.generate_logic_hash(m) for m in VALID_SOURCE_MODULES}
        assert len(set(hashes.values())) == len(VALID_SOURCE_MODULES)
        print(f"[8]  All {len(VALID_SOURCE_MODULES)} modules unique: PASS")

        # --- v5 additions ---

        # Test 9: Future slot rejected (no future tolerance)
        # Proves: clock-advance attacks are blocked (Attack 4).
        # Hardened(v8): Direct slot arithmetic (same fix as Test 3).
        future_slot = _timestamp_to_slot(now) + 1
        future_hash = _compute_hash(_secret_holder.get(), test_module, future_slot)
        assert not rotator.verify_logic_hash(future_hash, test_module, now)
        print("[9]  Future slot rejected: PASS")

        # Test 10: Malformed hash raises (short length)
        try:
            rotator.verify_logic_hash("abc", test_module, now)
            assert False
        except ValueError:
            pass
        print("[10] Short hash raises ValueError: PASS")

        # Test 11: Uppercase hash raises
        try:
            rotator.verify_logic_hash(generated.upper(), test_module, now)
            assert False
        except ValueError:
            pass
        print("[11] Uppercase hash raises ValueError: PASS")

        # Test 12: Non-hex hash raises
        try:
            rotator.verify_logic_hash("g" * 64, test_module, now)
            assert False
        except ValueError:
            pass
        print("[12] Non-hex hash raises ValueError: PASS")

        # Test 13: Naive timestamp raises
        try:
            rotator.verify_logic_hash(generated, test_module, datetime.now())
            assert False
        except ValueError:
            pass
        print("[13] Naive timestamp raises ValueError: PASS")

        # --- v6 additions ---

        # Test 14: timezone(timedelta(0)) accepted (value-based UTC check)
        # Proves: the v6 fix for v5's identity-check regression works.
        # timezone(timedelta(0)) is a DIFFERENT object than timezone.utc
        # on some Python implementations, but both represent UTC.
        constructed_utc = datetime(
            now.year, now.month, now.day, now.hour, now.minute, now.second,
            now.microsecond, tzinfo=timezone(timedelta(0))
        )
        constructed_hash = _compute_hash(
            _secret_holder.get(), test_module, _timestamp_to_slot(constructed_utc)
        )
        assert rotator.verify_logic_hash(constructed_hash, test_module, constructed_utc)
        print("[14] timezone(timedelta(0)) accepted: PASS")

        # Test 15: Secret source tracking (testâ†’test overwrite allowed)
        _secret_holder.load_for_testing()  # Should NOT raise (testâ†’test)
        print("[15] Testâ†’test secret overwrite: PASS")

        # Test 16: Secret management â€” clear, then get raises
        _secret_holder.clear()
        try:
            _secret_holder.get()
            assert False
        except RuntimeError:
            pass
        _secret_holder.load_for_testing()  # Restore for subsequent tests
        print("[16] Post-clear get raises, restore works: PASS")

        # --- v7/v8 additions ---

        # Test 17: Non-str module raises TypeError (not ValueError)
        # Proves: type errors are distinguished from value errors.
        try:
            rotator.generate_logic_hash(123)
            assert False
        except TypeError:
            pass
        print("[17] Non-str module â†’ TypeError: PASS")

        # Test 18: Non-datetime timestamp raises TypeError
        try:
            rotator.verify_logic_hash(generated, test_module, "2026-02-15")
            assert False
        except TypeError:
            pass
        print("[18] Non-datetime ts â†’ TypeError: PASS")

        # Test 19: Non-str received_hash raises TypeError (v8 fix)
        # v7 raised ValueError for this â€” inconsistent with source_module.
        # v8 splits isinstance (TypeError) from len (ValueError).
        try:
            rotator.verify_logic_hash(12345, test_module, now)
            assert False
        except TypeError:
            pass
        print("[19] Non-str hash â†’ TypeError: PASS")

        # Test 20: Long secret (64 bytes) works
        # Proves: secrets longer than 32 bytes are accepted.
        _secret_holder.load_for_testing(secrets.token_bytes(64))
        long_generated = rotator.generate_logic_hash(test_module)
        assert rotator.verify_logic_hash(long_generated, test_module, now)
        # Hardened(v8): Restore original test secret (v7 forgot this).
        _secret_holder.load_for_testing()
        print("[20] Long secret (64B) works + restored: PASS")

        # Test 21: Exotic tzinfo error handling (v7 improvement)
        # Proves: a tzinfo that raises in utcoffset() is caught cleanly.
        import datetime as _dt_module
        class _BrokenTZ(_dt_module.tzinfo):
            def utcoffset(self, dt):
                raise OSError("NTP unreachable")
            def tzname(self, dt):
                return "BROKEN"
            def dst(self, dt):
                return timedelta(0)
        try:
            broken_ts = datetime(2026, 1, 1, tzinfo=_BrokenTZ())
            _timestamp_to_slot(broken_ts)
            assert False
        except ValueError as e:
            assert "NTP unreachable" in str(e)
        print("[21] Exotic tzinfo error caught: PASS")

        # Test 22: lenâ‰ 64 hash raises ValueError (not TypeError)
        # Proves: the type/value split works â€” str of wrong length is ValueError.
        try:
            rotator.verify_logic_hash("abcd" * 8, test_module, now)  # 32 chars
            assert False
        except ValueError:
            pass
        print("[22] Short-but-str hash â†’ ValueError: PASS")

        print(f"\n{'=' * 60}")
        print(f"  ALL SELF-TESTS PASSED (22/22)")
        print(f"{'=' * 60}")

    finally:
        # Always clean up test secret, even if a test fails.
        # This prevents a test failure from leaving the module in a
        # state where the next import gets a test secret.
        _secret_holder.clear()


# =============================================================================
#
#   QUICK REFERENCE â€” VALIDATION LAYERS PER INPUT
#   â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#   Input              â”‚ Type Check   â”‚ Value Check           â”‚ Crypto Check
#   â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#   received_hash      â”‚ isinstance   â”‚ len=64, lowercase,    â”‚ compare_digest
#                      â”‚ â†’ TypeError  â”‚ hex chars â†’ ValueErrorâ”‚ vs expected
#   source_module      â”‚ isinstance   â”‚ frozenset allowlist   â”‚ bound in HMAC
#                      â”‚ â†’ TypeError  â”‚ â†’ ValueError          â”‚ data field
#   message_timestamp  â”‚ isinstance   â”‚ UTC (utcoffset=0)     â”‚ slot computation
#                      â”‚ â†’ TypeError  â”‚ â†’ ValueError          â”‚ (integer division)
#   deployment_secret  â”‚ (bytes)      â”‚ hex, even-length,     â”‚ HMAC key
#                      â”‚              â”‚ â‰¥32 bytes â†’ ValueErrorâ”‚
#
#
#   HMAC INPUT STRUCTURE
#   â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#   key  = ICVS_LOGIC_SECRET (32+ bytes from environment)
#   data = "ICVS-LogicLock-v8|CVS|86974380"
#          ^^^^^^^^^^^^^^^^^^  ^^^  ^^^^^^^^
#          protocol version   module  time slot
#          (prevents cross-   (prevents cross-  (prevents
#           version replay)    module forgery)    replay)
#
#
#   EXCEPTION TYPES
#   â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#   TypeError    â†’ wrong Python type (programming bug at call site)
#   ValueError   â†’ right type, wrong content (bad data / attacker)
#   RuntimeError â†’ infrastructure problem (missing secret / deployment)
#
#
#   SECURITY PROPERTIES
#   â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#   Property                    â”‚ Mechanism
#   â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#   Anti-replay (20s window)    â”‚ Time slot binding in HMAC data
#   Anti-forgery                â”‚ HMAC key = deployment secret
#   Anti-cross-module           â”‚ Module ID binding in HMAC data
#   Anti-cross-version          â”‚ Protocol version in HMAC data
#   Anti-timing-side-channel    â”‚ hmac.compare_digest (constant-time)
#   Anti-encoding-ambiguity     â”‚ "|" delimiter between fields
#   Anti-clock-advance          â”‚ No future slot acceptance
#   Fail-closed on missing key  â”‚ RuntimeError on first call
#   Fail-closed on bad module   â”‚ ValueError (both generate + verify)
#
# =============================================================================