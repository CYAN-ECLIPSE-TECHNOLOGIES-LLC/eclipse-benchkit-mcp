#!/usr/bin/env python3
# Eclipse Benchkit MCP server (spec: SPEC.md).
# Copyright 2026 Cyan Eclipse Technologies LLC - cetech.ai
"""Surfaces are disjoint, selected by ECLIPSE_BENCHKIT_SURFACE
(vendor default, verifier). A verb from the other surface returns
the identical unknown-tool refusal as a nonsense name. No verb
buys, licenses, or activates any internal tool; no house bench
verdict or certification verb exists.

v0.1.1: startup runs the section 7.3 config fence (F-B14) and hard-
exits with CONFIG_FENCE_REFUSED:<class> on a violation. Verifier
verbs require the verifier token (spec 5): pass `verifier_token`
per call, or set BENCHKIT_VERIFIER_TOKEN in the verifier process
to the fixture token in keys/verifier-token.fixture.key. The
verifier nonce is never a tool input for a new draw - it is
generated verifier-side (CSPRNG + verifier secret seed) and
revealed only in the sample manifest; a supplied nonce is honoured
only as a section 3.3 replay key for an already-issued pair."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import benchkit  # noqa: E402

SERVER_NAME = "io.github.CYAN-ECLIPSE-TECHNOLOGIES-LLC/eclipse-benchkit-mcp"
SERVER_VERSION = benchkit.TOOL_VERSION
_STR = {"type": "string"}
_OBJ = {"type": "object"}


def _obj(props, required):
    return {"type": "object", "properties": props,
            "required": required, "additionalProperties": False}


DESCRIPTIONS = {
    "benchkit_run_begin": "Vendor surface: open a scorecard run over a fixture vendor server descriptor (live-URL descriptors refused by the section 7.3 fence).",
    "benchkit_check_record": "Vendor surface: chain one executed check's record with its spot-check hook, as it runs.",
    "benchkit_scorecard_seal": "Vendor surface: seal the scorecard (signature binds head hash, counts and format version) before any sample exists.",
    "benchkit_scorecard_get": "Vendor surface: fetch a sealed scorecard + all run records.",
    "benchkit_export_get": "Vendor surface: EXPORTED_SELF_BENCH or DOWNGRADED_EXPORT for a scorecard.",
    "spotcheck_request": "Verifier surface (token required): verify the seal, generate the verifier nonce verifier-side, draw the commit-then-sample manifest. A supplied verifier_nonce is honoured only as a replay key for an already-issued pair.",
    "spotcheck_run": "Verifier surface (token required): re-run the sampled checks against the fixture vendor server; issues the counter-signed receipt.",
    "spotcheck_receipt_get": "Verifier surface (token required): fetch a spot-check verification receipt by manifest id.",
    "spotcheck_recompute": "Verifier surface (token required): pure recompute of verdict + detection statistic from receipt + scorecard + outcomes; verifies receipt signatures, outcome chain and rerun head.",
    "anomaly_queue_read": "Verifier surface (token required): pre-seal sample attempts, seal defects, replay attempts as violations.",
}
SCHEMAS = {
    "benchkit_run_begin": _obj({"server": _OBJ, "supersedes": _STR}, ["server"]),
    "benchkit_check_record": _obj({"scorecard_id": _STR, "check_id": _STR, "invocation_hash": _STR, "input_hash": _STR, "expected_output_hash": _STR, "observed_output_hash": _STR, "verdict_as_run": _STR, "hook": _OBJ, "determinism_class": _STR, "env_fingerprint": _STR, "ts": _STR}, ["scorecard_id", "check_id"]),
    "benchkit_scorecard_seal": _obj({"scorecard_id": _STR}, ["scorecard_id"]),
    "benchkit_scorecard_get": _obj({"scorecard_id": _STR}, ["scorecard_id"]),
    "benchkit_export_get": _obj({"scorecard_id": _STR}, ["scorecard_id"]),
    "spotcheck_request": _obj({"scorecard_hash": _STR, "scorecard": _OBJ, "verifier_nonce": _STR, "vendor_nonce": _STR, "verifier_token": _STR}, ["scorecard_hash", "scorecard"]),
    "spotcheck_run": _obj({"sample_manifest_id": _STR, "verifier_token": _STR}, ["sample_manifest_id"]),
    "spotcheck_receipt_get": _obj({"sample_manifest_id": _STR, "verifier_token": _STR}, ["sample_manifest_id"]),
    "spotcheck_recompute": _obj({"receipt": _OBJ, "scorecard": _OBJ, "outcomes": {"type": "array", "items": _OBJ}, "verifier_nonce": _STR, "manifest": _OBJ, "verifier_token": _STR}, ["receipt", "scorecard", "outcomes"]),
    "anomaly_queue_read": _obj({"verifier_token": _STR}, []),
}


def surface_tools():
    if os.environ.get("ECLIPSE_BENCHKIT_SURFACE", "vendor") == "verifier":
        return benchkit.VERIFIER_TOOLS
    return benchkit.VENDOR_TOOLS


def startup_fence(env=None):
    """F-B14: returns 'CONFIG_FENCE_REFUSED:<class>' or None."""
    return benchkit.startup_fence(env)


def dispatch(name, args):
    tools = surface_tools()
    if name not in tools:
        return {"refusal": "NO_SUCH_TOOL",
                "detail": "%r is not a tool here." % (name,)}
    if not isinstance(args, dict):
        raise benchkit.ToolError("arguments must be an object")
    return tools[name](args)


def handle(req):
    method = req.get("method")
    rid = req.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME,
                           "version": SERVER_VERSION}}}
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": [
            {"name": n, "description": DESCRIPTIONS[n],
             "inputSchema": SCHEMAS[n]} for n in surface_tools()]}}
    if method == "tools/call":
        params = req.get("params", {})
        try:
            result = dispatch(params.get("name"),
                              params.get("arguments", {}))
            is_err = isinstance(result, dict) and "refusal" in result
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "isError": is_err,
                "content": [{"type": "text",
                             "text": json.dumps(result,
                                                sort_keys=True)}]}}
        except benchkit.ToolError as e:
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "isError": True,
                "content": [{"type": "text", "text": json.dumps(
                    {"error": str(e)}, sort_keys=True)}]}}
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601,
                      "message": "method not found: %s" % method}}


def main():
    fence = startup_fence()
    if fence:
        sys.stderr.write(fence + "\n")
        sys.stderr.flush()
        sys.exit(2)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
