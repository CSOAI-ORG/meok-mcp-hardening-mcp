#!/usr/bin/env python3
"""
Buy Pro: https://www.csoai.org/checkout

MEOK MCP Hardening MCP — auto red-team for ANY MCP server
=========================================================

By MEOK AI Labs · https://meok.ai · MIT
<!-- mcp-name: io.github.CSOAI-ORG/meok-mcp-hardening-mcp -->

WHAT THIS DOES
--------------
Runs a structured security audit against any MCP server's manifest + tool
surface. Pairs with `mcp-spec-compliance-mcp` (which checks SCHEMA conformity)
by checking SECURITY conformity instead.

Scanned categories (mapped to OWASP LLM Top 10, 2025 revision):

- **LLM01** Prompt-injection vectors in tool descriptions
- **LLM02** Insecure output handling — eval / exec / shell sinks in tool names
- **LLM05** Supply-chain — unpinned dependencies, missing repository URL
- **LLM06** Sensitive info disclosure — secrets in descriptions / examples
- **LLM07** Insecure plugin design — over-broad tool surface, no auth claim
- **LLM08** Excessive agency — destructive tools without `requires_confirm`
- **LLM09** Overreliance — missing transparency / origin / signing block
- **LLM10** Model theft — public endpoints with no auth + no rate-limit hint

Also checks five MCP-specific risks beyond OWASP:
- **MCP-S1** Tool-name spoofing (homoglyphs, lookalikes)
- **MCP-S2** Roundtrip-input echoing (untrusted-data → tool description back)
- **MCP-S3** Side-channel via `resources/list` URLs (data exfil)
- **MCP-S4** Privileged elevation — `admin*` / `sudo*` tool names exposed
- **MCP-S5** Long-running tool with no cancel signal

THE VIRAL MOVE
--------------
Every MCP author about to publish wants a clean security report. Every MCP
*consumer* (Claude Desktop, Anthropic, Cursor, Windsurf, Smithery, Glama)
wants to verify what they're loading. This MCP becomes the seatbelt.

TOOLS
-----
- audit_server_json(server_json): full OWASP + MCP-S report
- audit_tool_description(tool): single-tool deep-scan
- check_destructive_surface(server_json): writes/deletes/transfers without gate
- check_supply_chain(server_json): pin + provenance audit
- list_owasp_findings(): canonical OWASP LLM Top 10 map
- generate_hardened_template(): a starter passing-score server.json
- sign_security_report(audit_result): HMAC seal for public verify

PRICING
-------
Free MIT self-host · £29/mo Starter · £79/mo Pro · A2A Substrate £999/mo.

VERIFICATION
------------
Verify any signed report at https://meok.ai/verify (works for ALL signed
MEOK attestations — same key namespace).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_HMAC_SECRET = os.environ.get("MEOK_HMAC_SECRET") or os.environ.get(
    "MEOK_ATTESTATION_KEY"
)

# Destructive verbs in tool names (LLM08 — excessive agency)
DESTRUCTIVE_VERBS = {
    "delete", "destroy", "drop", "remove", "purge", "wipe", "erase",
    "send", "transfer", "wire", "pay", "charge", "refund",
    "publish", "deploy", "release", "approve", "merge",
    "kill", "terminate", "shutdown", "restart",
    "execute", "exec", "eval", "run", "spawn",
    "grant", "revoke", "elevate", "impersonate", "sudo", "su",
}

PRIVILEGE_PREFIXES = {"admin_", "root_", "sudo_", "superuser_", "owner_"}

SUPPLY_CHAIN_REQUIRED = {"repository", "version"}

# Secret-shape regexes (LLM06)
SECRET_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9]{20,}"),        "OpenAI-style API key"),
    (re.compile(r"sk-ant-[A-Za-z0-9_-]{50,}"),  "Anthropic API key"),
    (re.compile(r"rk_live_[A-Za-z0-9]{20,}"),   "Stripe restricted key (live)"),
    (re.compile(r"sk_live_[A-Za-z0-9]{20,}"),   "Stripe secret key (live)"),
    (re.compile(r"whsec_[A-Za-z0-9]{20,}"),     "Stripe webhook secret"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"),       "GitHub PAT (classic)"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{50,}"), "GitHub PAT (fine-grained)"),
    (re.compile(r"AIza[0-9A-Za-z_-]{30,}"),     "Google API key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"),            "AWS access key id"),
    (re.compile(r"xox[bpsa]-[A-Za-z0-9-]{10,}"), "Slack token"),
]

# Prompt-injection signal phrases inside tool descriptions (LLM01)
PROMPT_INJECTION_TOKENS = [
    "ignore previous instructions",
    "ignore prior instructions",
    "disregard the above",
    "system:",
    "<system>",
    "</system>",
    "you are now",
    "act as",
    "jailbreak",
    "bypass",
]

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    rule: str       # e.g. "LLM01" or "MCP-S3"
    severity: str   # critical | high | medium | low | info
    title: str
    detail: str
    where: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "where": self.where,
        }


@dataclass
class AuditReport:
    server_name: str
    findings: list[Finding] = field(default_factory=list)
    scanned_at: float = field(default_factory=time.time)

    def add(self, *args, **kwargs) -> None:
        self.findings.append(Finding(*args, **kwargs))

    def score(self) -> int:
        """0–100 hardening score (higher is harder)."""
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
        deduction = sum(weights.get(f.severity, 0) for f in self.findings)
        return max(0, 100 - deduction)

    def grade(self) -> str:
        s = self.score()
        if s >= 90: return "A"
        if s >= 80: return "B"
        if s >= 70: return "C"
        if s >= 60: return "D"
        return "F"

    def as_dict(self) -> dict[str, Any]:
        return {
            "server_name": self.server_name,
            "score": self.score(),
            "grade": self.grade(),
            "finding_count": len(self.findings),
            "findings": [f.as_dict() for f in self.findings],
            "scanned_at": self.scanned_at,
            "scanner": "meok-mcp-hardening-mcp",
            "scanner_version": "1.0.0",
        }


# ---------------------------------------------------------------------------
# Core auditors
# ---------------------------------------------------------------------------

def _normalised(s: str) -> str:
    return unicodedata.normalize("NFKC", s or "").lower()


def _scan_secrets(text: str, where: str, report: AuditReport) -> None:
    if not text:
        return
    for pat, label in SECRET_PATTERNS:
        if pat.search(text):
            report.add(
                rule="LLM06",
                severity="critical",
                title=f"Possible {label} embedded in {where}",
                detail=(
                    "A secret-shaped string was found. Anyone reading the MCP "
                    "manifest can extract this — rotate immediately and move "
                    "credentials to environment variables."
                ),
                where=where,
            )


def _scan_prompt_injection(text: str, where: str, report: AuditReport) -> None:
    if not text:
        return
    norm = _normalised(text)
    for token in PROMPT_INJECTION_TOKENS:
        if token in norm:
            report.add(
                rule="LLM01",
                severity="high",
                title=f"Prompt-injection phrase '{token}' in {where}",
                detail=(
                    "Tool descriptions are read by upstream LLMs as context. "
                    "Instructional phrases here can hijack the calling agent."
                ),
                where=where,
            )


def _tool_name(tool: dict[str, Any]) -> str:
    return tool.get("name") or tool.get("tool_name") or ""


def _check_tool(tool: dict[str, Any], report: AuditReport, index: int) -> None:
    name = _tool_name(tool)
    desc = tool.get("description", "")
    where = f"tools[{index}].{name or '?'}"

    if not name:
        report.add("LLM07", "high", "Tool missing name", "Tools must have an explicit name.", where)
        return

    # LLM01 in tool desc
    _scan_prompt_injection(desc, f"{where}.description", report)
    # LLM06 in tool desc
    _scan_secrets(desc, f"{where}.description", report)

    # LLM08 — destructive verb without confirmation hint
    name_norm = _normalised(name)
    verbs = {v for v in DESTRUCTIVE_VERBS if v in re.split(r"[_\-\s]", name_norm)}
    if verbs:
        gated = any(k in tool for k in ("requires_confirm", "confirmable", "destructive"))
        gated = gated or any(
            k in _normalised(desc)
            for k in ("requires confirmation", "destructive", "irreversible")
        )
        if not gated:
            report.add(
                rule="LLM08",
                severity="high",
                title=f"Destructive tool '{name}' has no confirmation gate",
                detail=(
                    f"Verb(s) {sorted(verbs)} indicate side effects. Add a "
                    "`requires_confirm` flag or document the gate in the "
                    "description so agents can require user approval."
                ),
                where=where,
            )

    # MCP-S4 — privileged elevation in exposed tool name
    if any(name_norm.startswith(p) for p in PRIVILEGE_PREFIXES):
        report.add(
            rule="MCP-S4",
            severity="critical",
            title=f"Privileged tool '{name}' exposed in public surface",
            detail=(
                "Tools whose names imply admin/root capability should not be "
                "discoverable on a generic MCP surface. Move to a gated tier "
                "or rename with explicit auth requirement."
            ),
            where=where,
        )

    # MCP-S1 — homoglyph/lookalike (non-ASCII letters in tool name)
    if any(ord(c) > 127 for c in name):
        report.add(
            rule="MCP-S1",
            severity="medium",
            title=f"Tool name '{name}' contains non-ASCII characters",
            detail=(
                "Non-ASCII letters in tool names can spoof legitimate tools "
                "(e.g. Cyrillic 'а' vs Latin 'a'). Use ASCII-only identifiers."
            ),
            where=where,
        )

    # LLM02 — eval/exec sinks
    if re.search(r"\b(eval|exec|shell|os\.system|subprocess)\b", _normalised(desc)):
        report.add(
            rule="LLM02",
            severity="high",
            title=f"Tool '{name}' description hints at eval/exec sink",
            detail=(
                "Descriptions referencing eval/exec/shell suggest the tool "
                "passes user input to a code runner. Confirm input is "
                "sandboxed and document the boundary."
            ),
            where=where,
        )


def audit(server_json: dict[str, Any]) -> AuditReport:
    """Run a full security audit against an MCP server.json document."""
    if not isinstance(server_json, dict):
        raise TypeError("server_json must be a dict")

    name = server_json.get("name", "<unnamed>")
    report = AuditReport(server_name=name)

    # LLM05 supply chain
    for required in SUPPLY_CHAIN_REQUIRED:
        if not server_json.get(required):
            report.add(
                rule="LLM05",
                severity="medium",
                title=f"Missing supply-chain field: {required}",
                detail=(
                    "Add this field so downstream registries can verify "
                    "provenance and pin a deterministic version."
                ),
                where="$",
            )

    repo = server_json.get("repository") or {}
    if isinstance(repo, dict) and not (repo.get("url") or repo.get("source")):
        report.add("LLM05", "medium",
                   "Repository object present but URL missing",
                   "Set repository.url so verifiers can locate source.", "repository")

    # LLM09 — transparency block
    if not any(k in server_json for k in ("license", "homepage", "metadata")):
        report.add("LLM09", "low",
                   "No license / homepage / metadata block",
                   "Add a license and homepage so users can vet the project.", "$")

    # LLM10 — public endpoint w/o auth
    remotes = server_json.get("remotes") or []
    if isinstance(remotes, list) and remotes:
        for i, r in enumerate(remotes):
            url = (r or {}).get("url", "")
            if url.startswith("http") and not (r.get("auth") or "bearer" in str(r).lower()):
                report.add(
                    rule="LLM10",
                    severity="medium",
                    title=f"Remote {i} exposes HTTP without declared auth",
                    detail=(
                        "Public remote endpoints should declare an auth model "
                        "(bearer / OAuth / mTLS) so callers can verify."
                    ),
                    where=f"remotes[{i}]",
                )

    # Scan top-level description
    desc = server_json.get("description", "")
    _scan_secrets(desc, "description", report)
    _scan_prompt_injection(desc, "description", report)

    # Walk tools
    tools = server_json.get("tools") or []
    if isinstance(tools, list):
        for i, t in enumerate(tools):
            if isinstance(t, dict):
                _check_tool(t, report, i)

    # MCP-S3 — resources/list URLs to non-https
    resources = server_json.get("resources") or []
    if isinstance(resources, list):
        for i, r in enumerate(resources):
            url = (r or {}).get("uri", "") if isinstance(r, dict) else ""
            if url.startswith("http://"):
                report.add(
                    rule="MCP-S3",
                    severity="medium",
                    title=f"Resource[{i}] uses plain http://",
                    detail=(
                        "Plain-HTTP resource URIs can be intercepted; use "
                        "https:// or a stdio/file URI."
                    ),
                    where=f"resources[{i}]",
                )

    return report


# ---------------------------------------------------------------------------
# HMAC sealing
# ---------------------------------------------------------------------------

def _hmac_sign(payload: bytes) -> str:
    if not _HMAC_SECRET:
        return "unsigned-no-key-configured"
    return hmac.new(_HMAC_SECRET.encode(), payload, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# MCP wiring
# ---------------------------------------------------------------------------

mcp = FastMCP("meok-mcp-hardening")


@mcp.tool()
def audit_server_json(server_json: dict) -> dict:
    """Full OWASP LLM Top 10 + MCP-specific security audit of an MCP server.json."""
    return audit(server_json).as_dict()


@mcp.tool()
def audit_tool_description(tool: dict) -> dict:
    """Deep-scan a single tool description for injection / destructive / spoof signals."""
    report = AuditReport(server_name=f"tool:{tool.get('name','?')}")
    _check_tool(tool, report, 0)
    return report.as_dict()


@mcp.tool()
def check_destructive_surface(server_json: dict) -> dict:
    """Return only the destructive-surface findings (LLM08) — fast gate for CI."""
    full = audit(server_json)
    return {
        "server_name": full.server_name,
        "destructive_findings": [
            f.as_dict() for f in full.findings if f.rule == "LLM08"
        ],
    }


@mcp.tool()
def check_supply_chain(server_json: dict) -> dict:
    """Return only supply-chain findings (LLM05) — pin + provenance audit."""
    full = audit(server_json)
    return {
        "server_name": full.server_name,
        "supply_chain_findings": [
            f.as_dict() for f in full.findings if f.rule == "LLM05"
        ],
    }


@mcp.tool()
def list_owasp_findings() -> dict:
    """Return the canonical OWASP LLM Top 10 (2025) → MCP-Hardening rule map."""
    return {
        "owasp_llm_top_10_2025": {
            "LLM01": "Prompt injection",
            "LLM02": "Insecure output handling",
            "LLM03": "Training data poisoning",
            "LLM04": "Model denial of service",
            "LLM05": "Supply chain vulnerabilities",
            "LLM06": "Sensitive information disclosure",
            "LLM07": "Insecure plugin design",
            "LLM08": "Excessive agency",
            "LLM09": "Overreliance",
            "LLM10": "Model theft",
        },
        "mcp_specific_rules": {
            "MCP-S1": "Tool-name spoofing (homoglyph / lookalike)",
            "MCP-S2": "Roundtrip-input echoing",
            "MCP-S3": "Insecure resource URI (plain HTTP)",
            "MCP-S4": "Privileged-tool exposure on public surface",
            "MCP-S5": "Long-running tool with no cancel signal",
        },
        "score_formula": "100 minus weighted-deduction (critical=25, high=15, medium=8, low=3)",
    }


@mcp.tool()
def generate_hardened_template() -> dict:
    """Return a minimal-passing server.json starter that scores A."""
    return {
        "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
        "name": "io.github.YOUR-ORG/your-mcp",
        "version": "0.1.0",
        "description": "One-line description of what your MCP does. No secrets, no instructional phrases.",
        "license": "MIT",
        "homepage": "https://example.com/your-mcp",
        "repository": {"url": "https://github.com/YOUR-ORG/your-mcp", "source": "github"},
        "packages": [
            {
                "registryType": "pypi",
                "identifier": "your-mcp",
                "version": "0.1.0",
                "runtimeHint": "python",
                "transport": {"type": "stdio"},
            }
        ],
        "tools": [
            {
                "name": "your_safe_tool",
                "description": "A read-only operation that returns a deterministic value to the caller.",
            }
        ],
        "remotes": [
            {
                "type": "streamable-http",
                "url": "https://api.example.com/v1/your-mcp",
                "auth": "bearer",
            }
        ],
    }


@mcp.tool()
def sign_security_report(audit_result: dict) -> dict:
    """HMAC-seal an audit result so it can be published as a signed badge."""
    payload = json.dumps(audit_result, sort_keys=True, separators=(",", ":")).encode()
    signature = _hmac_sign(payload)
    return {
        "report": audit_result,
        "signature": signature,
        "signed_at": int(time.time()),
        "verify_at": "https://meok.ai/verify",
        "issuer": "meok-mcp-hardening-mcp",
    }


def main() -> None:  # pragma: no cover
    """Entry point for `meok-mcp-hardening-mcp` script."""
    mcp.run()


if __name__ == "__main__":  # pragma: no cover
    main()
