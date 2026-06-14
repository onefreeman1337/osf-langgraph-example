"""
OSF + LangGraph: give your agent verifiable, citable security data.
================================================================================

A complete, runnable example of wiring Open Source Filings (OSF) into a LangGraph
agent. The agent answers questions like "Is CVE-2021-44228 actively exploited?"
by (1) discovering the record via OSF's free MCP `get_catalog` tool and (2)
paying a few cents in USDC over x402 to retrieve it — and every record ships with
a provenance URL to the authoritative U.S. government source (nvd.nist.gov,
cisa.gov) so the agent, or a human auditing it, can verify every field.

WHY THIS MATTERS
    Most agent data access is RAG over scraped text: plausible, but unverifiable.
    For security decisions ("patch this now?") an agent needs ground truth it can
    cite. OSF records carry the source URL so every fact is independently checkable.

ARCHITECTURE (this mirrors how the OSF marketplace actually works)
    - Discovery is FREE and uses standard MCP: the agent calls OSF's `get_catalog`
      tool over the MCP streamable-http transport (initialize -> session ->
      tools/call). A tiny built-in client handles the handshake; swap in your
      preferred MCP client if you already use one.
    - Retrieval is PAID and uses x402: buying a record settles $0.04 in USDC on
      Base mainnet. We keep a small x402 client for that step, since the paid
      handshake is x402-native (not plain MCP).
    - The `osf_security_lookup` tool below ties them together: discover -> pay ->
      return a decision-ready summary + the provenance citation.

--------------------------------------------------------------------------------
SETUP
    pip install langgraph langchain-core langchain-anthropic httpx
    pip install x402 eth-account

    export ANTHROPIC_API_KEY=sk-ant-...       # or swap in any tool-calling LLM
    export OSF_BUYER_PRIVATE_KEY=0x...         # a funded Base wallet (a few $ USDC)

RUN
    python osf_langgraph_example.py "Is CVE-2021-44228 actively exploited?"
--------------------------------------------------------------------------------
"""

import asyncio
import json
import os
import sys
from typing import Annotated, Optional

from typing_extensions import TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition


# ==============================================================================
# OSF endpoints
# ==============================================================================
OSF_API = "https://api.osf-master-server.com"
OSF_MCP_URL = OSF_API + "/mcp"                         # free MCP tools (get_catalog)
OSF_BUY = OSF_API + "/x402/buy/security/{record_id}"   # paid: $0.04 USDC on Base


# ==============================================================================
# THE OSF TOOL  --  this is the part you copy into your own agent
# ==============================================================================
@tool
async def osf_security_lookup(cve_id: str) -> str:
    """Look up verified security intelligence for a CVE from Open Source Filings.

    Returns authoritative vulnerability data — CVSS severity, CISA Known-Exploited
    (actively-exploited) status, and a provenance URL back to the primary U.S.
    government source (nvd.nist.gov / cisa.gov) so every field can be independently
    verified. Use this to make or justify a security decision about a specific CVE
    (patch prioritization, exposure assessment, triage). Data is point-in-time and
    citable, not a guess.

    Args:
        cve_id: a CVE identifier, e.g. "CVE-2021-44228".

    Returns:
        A JSON string with the record's key fields and its provenance URL, or a
        short error string the agent can reason about.
    """
    cve_id = (cve_id or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return f"error: '{cve_id}' is not a valid CVE id (expected like CVE-2021-44228)."

    # 1) DISCOVER via OSF's free MCP get_catalog tool (filters by record_key).
    record_id, prov_hint = await _find_record_id(cve_id)
    if record_id is None:
        return (f"error: no OSF security record found for {cve_id}. "
                f"It may not be in the current catalog window.")

    # 2) BUY the record over x402 ($0.04 USDC on Base). One round trip.
    record = _buy_record(record_id)
    if isinstance(record, str):           # an error message bubbled up
        return record

    # 3) Hand the agent a compact, decision-ready summary + the citation.
    data = record.get("data", {}) if isinstance(record, dict) else {}
    inner = data if isinstance(data, dict) else {}
    cve = inner.get("cve", inner) if isinstance(inner.get("cve"), dict) else inner
    summary = {
        "cve_id": cve_id,
        "data_type": record.get("data_type"),
        "source": record.get("source"),
        "cvss_base_score": _first(inner, cve, "cvss_base_score", "baseScore"),
        "cvss_severity": _first(inner, cve, "cvss_severity", "severity"),
        "description": _first(inner, cve, "description", "short_description"),
        # The whole point: a URL the agent (or its auditor) can independently check.
        "provenance_url": record.get("provenance_url") or prov_hint,
        "_note": "Verifiable at provenance_url — primary government source.",
    }
    return json.dumps(summary, indent=2)


# ------------------------------------------------------------------------------
# DISCOVERY: OSF's free get_catalog over MCP streamable-http.
#
# We use a tiny built-in MCP client that does the exact handshake the protocol
# requires: initialize -> (capture mcp-session-id) -> notifications/initialized
# -> tools/call, carrying the session id on every request. This is dependency-
# free and version-proof. If you already use an MCP client library in your stack
# (e.g. langchain-mcp-adapters, or the official `mcp` package), you can swap this
# out — just ensure it manages the mcp-session-id handshake.
# ------------------------------------------------------------------------------
async def _find_record_id(cve_id: str):
    """Resolve a CVE id -> (record_id, provenance_url) using OSF's free MCP
    get_catalog tool, filtered by record_key. Returns (None, None) if not found."""
    # Try scoped to CISA_KEV first (the actively-exploited signal), then any source.
    for args in ({"source": "CISA_KEV", "record_key": cve_id, "limit": 1},
                 {"record_key": cve_id, "limit": 1}):
        try:
            result = await _mcp_call_tool("get_catalog", args)
            records = _records_from_catalog(result)
            if records:
                r0 = records[0]
                return int(r0["record_id"]), r0.get("provenance_url")
        except Exception as e:
            print(f"[osf] get_catalog lookup note: {e!r}", file=sys.stderr)
    return None, None


async def _mcp_call_tool(tool_name: str, arguments: dict):
    """Minimal MCP streamable-http client: initialize -> initialized -> tools/call,
    carrying the mcp-session-id the server returns. Returns the tool's parsed JSON
    payload. Uses httpx (already a dependency of the x402/langchain stack)."""
    import httpx

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }

    async with httpx.AsyncClient(timeout=30.0) as http:
        # 1) initialize -> the server returns an mcp-session-id header.
        init = await http.post(OSF_MCP_URL, headers=headers, json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "osf-langgraph-example", "version": "1.0"},
            },
        })
        session_id = init.headers.get("mcp-session-id")
        if not session_id:
            raise RuntimeError(f"no mcp-session-id from initialize (HTTP {init.status_code})")

        sess_headers = dict(headers)
        sess_headers["mcp-session-id"] = session_id

        # 2) acknowledge initialization (required before tools/call).
        await http.post(OSF_MCP_URL, headers=sess_headers,
                        json={"jsonrpc": "2.0", "method": "notifications/initialized"})

        # 3) call the tool, carrying the session id.
        resp = await http.post(OSF_MCP_URL, headers=sess_headers, json={
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        })
        body = _parse_jsonrpc_or_sse(resp.text)

    # Unwrap MCP tool result -> the tool's JSON text payload.
    result = body.get("result", body) if isinstance(body, dict) else body
    content = result.get("content") if isinstance(result, dict) else None
    if isinstance(content, list) and content:
        first = content[0]
        text = first.get("text") if isinstance(first, dict) else None
        if text:
            try:
                return json.loads(text)
            except Exception:
                return text
    return result


def _parse_jsonrpc_or_sse(raw: str):
    """Parse a body that is either a JSON object or SSE 'data:' frames."""
    raw = (raw or "").strip()
    if not raw:
        return {}
    if raw.startswith("{"):
        try:
            return json.loads(raw)
        except Exception:
            pass
    last = None
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            chunk = line[len("data:"):].strip()
            if chunk and chunk != "[DONE]":
                last = chunk
    if last:
        try:
            return json.loads(last)
        except Exception:
            return {}
    return {}


def _records_from_catalog(raw) -> list:
    """Pull the records list out of a get_catalog result, tolerant of shape."""
    obj = raw
    if isinstance(raw, str):
        try:
            obj = json.loads(raw)
        except Exception:
            return []
    if isinstance(obj, dict):
        for key in ("catalog", "records", "results"):
            v = obj.get(key)
            if isinstance(v, list):
                return v
    if isinstance(obj, list):
        return obj
    return []


# ------------------------------------------------------------------------------
# RETRIEVAL: paid get_record over x402 (USDC on Base). Kept dependency-light.
# ------------------------------------------------------------------------------
def _buy_record(record_id: int):
    """Pay for one OSF security record over x402 and return the parsed JSON record.
    Returns an error string on failure. Key read from OSF_BUYER_PRIVATE_KEY."""
    key = (os.getenv("OSF_BUYER_PRIVATE_KEY") or "").strip()
    if not key:
        return "error: OSF_BUYER_PRIVATE_KEY not set — cannot pay for the record."
    if not key.startswith("0x"):
        key = "0x" + key

    try:
        from eth_account import Account
        from x402 import x402Client
        from x402.http.clients import x402HttpxClient
        from x402.mechanisms.evm import EthAccountSigner
        from x402.mechanisms.evm.exact.register import register_exact_evm_client
    except Exception as e:
        return f"error: x402 client not installed ({e!r}). pip install x402 eth-account"

    target = OSF_BUY.format(record_id=record_id)
    try:
        account = Account.from_key(key)
        client = x402Client()
        register_exact_evm_client(client, EthAccountSigner(account))

        # Forward the 402's resource + extensions into the payment payload
        # (required for clean settlement against the CDP facilitator).
        _orig = x402Client.create_payment_payload

        async def _cpp(self, payment_required, resource=None, extensions=None):
            if extensions is None:
                extensions = getattr(payment_required, "extensions", None)
            if resource is None:
                resource = getattr(payment_required, "resource", None)
            return await _orig(self, payment_required, resource=resource, extensions=extensions)

        x402Client.create_payment_payload = _cpp

        async def _go():
            async with x402HttpxClient(client, timeout=60.0) as http:
                resp = await http.get(target)
                await resp.aread()
                if not resp.is_success:
                    return f"error: OSF returned HTTP {resp.status_code} for record {record_id}."
                return json.loads(resp.text)

        # We're already inside an async tool; run the buy on the running loop.
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            # Execute synchronously in a fresh loop on a worker thread to avoid
            # nesting issues inside the LangGraph event loop.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                return ex.submit(lambda: asyncio.run(_go())).result()
        return asyncio.run(_go())
    except Exception as e:
        return f"error: x402 purchase failed for record {record_id}: {e!r}"


def _first(*dicts_then_keys):
    """_first(d1, d2, 'k1', 'k2') -> first non-empty d[k] across dicts/keys."""
    dicts = [d for d in dicts_then_keys if isinstance(d, dict)]
    keys = [k for k in dicts_then_keys if isinstance(k, str)]
    for k in keys:
        for d in dicts:
            v = d.get(k)
            if v not in (None, "", []):
                return v
    return None


# ==============================================================================
# STANDARD LANGGRAPH SCAFFOLDING  --  boilerplate, here so it runs end to end
# ==============================================================================
class AgentState(TypedDict):
    messages: Annotated[list, add_messages]


def build_agent():
    from langchain_anthropic import ChatAnthropic
    llm = ChatAnthropic(model="claude-sonnet-4-6", temperature=0)

    tools = [osf_security_lookup]
    llm_with_tools = llm.bind_tools(tools)

    async def agent_node(state: AgentState):
        return {"messages": [await llm_with_tools.ainvoke(state["messages"])]}

    graph = StateGraph(AgentState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", ToolNode(tools))
    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", tools_condition)  # -> "tools" or END
    graph.add_edge("tools", "agent")
    return graph.compile()


SYSTEM_PROMPT = (
    "You are a security triage assistant. When asked about a specific CVE, use the "
    "osf_security_lookup tool to fetch verified, citable data before answering. Base "
    "your recommendation on CISA Known-Exploited status and CVSS severity, and ALWAYS "
    "include the provenance_url so the user can verify the facts at the primary "
    "government source. Be concise and decision-oriented."
)


async def _amain():
    question = " ".join(sys.argv[1:]).strip() or "Is CVE-2021-44228 actively exploited?"
    agent = build_agent()
    print(f"\n>>> {question}\n")
    result = await agent.ainvoke({
        "messages": [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=question)]
    })
    print(result["messages"][-1].content)
    print()


def main():
    asyncio.run(_amain())


if __name__ == "__main__":
    main()
