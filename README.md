# OSF + LangGraph: verifiable security data for your agent

A working example of giving a [LangGraph](https://langchain-ai.github.io/langgraph/) agent access to **verifiable, citable security intelligence** — CVE records, CISA Known-Exploited (actively-exploited) status, and CVSS data — where every record ships with a provenance URL back to the authoritative U.S. government source.

The agent pays per-record in USDC over [x402](https://www.x402.org/) on Base. No account, no API key, no subscription. Records are about **$0.04** each.

```
>>> Is CVE-2020-5847 actively exploited?

Yes — CVE-2020-5847 is actively exploited in the wild.

  CISA Known Exploited (KEV): Yes — confirmed actively exploited
  Source: CISA Known Exploited Vulnerabilities (KEV) Catalog

Recommendation: Patch Immediately. CISA KEV listing is the strongest possible
signal for patch prioritization...

Verify the data yourself: https://nvd.nist.gov/vuln/detail/CVE-2020-5847
```

## Why this exists

Most agent data access is RAG over scraped web text: plausible, but unverifiable. For a security decision — *"should I patch this now?"* — an agent needs ground truth it can **cite**, not a guess that sounds right.

[Open Source Filings (OSF)](https://osf-master-server.com) serves provenance-stamped public-domain government data to agents. Every record returns with the authoritative source URL (nvd.nist.gov, cisa.gov), so the agent — or a human auditing the agent's decision later — can independently verify every field. The citation *is* the product.

## How it works

The example mirrors how the OSF marketplace actually works — two rails:

1. **Discovery is free, over MCP.** The agent calls OSF's `get_catalog` tool (over the [MCP](https://modelcontextprotocol.io/) streamable-http transport) to resolve a CVE id to a record. No payment.
2. **Retrieval is paid, over x402.** Buying the full record settles ~$0.04 in USDC on Base mainnet via the x402 payment handshake.

The `osf_security_lookup` tool ties them together: discover → pay → return a decision-ready summary plus the provenance citation. That tool is the only OSF-specific part — copy it straight into your own graph; everything else is standard LangGraph scaffolding so the example runs end to end.

## Setup

```bash
pip install langgraph langchain-core langchain-anthropic httpx
pip install x402 eth-account

export ANTHROPIC_API_KEY=sk-ant-...      # or swap in any tool-calling LLM
export OSF_BUYER_PRIVATE_KEY=0x...        # a funded Base wallet (a few dollars of USDC)
```

The buyer wallet needs a small USDC balance on Base mainnet to pay for records (each lookup costs about $0.04). The x402 facilitator covers gas.

## Run

```bash
python osf_langgraph_example.py "Is CVE-2021-44228 actively exploited?"
```

Try other CVEs — `CVE-2020-5847`, `CVE-2021-44228`, any CVE in the CISA KEV / NVD catalog.

## Using it in your own agent

The whole integration is the `osf_security_lookup` tool. Drop it into your existing LangGraph (or any tool-calling) agent:

```python
from langchain_core.tools import tool

# ... the osf_security_lookup tool from this repo ...

tools = [osf_security_lookup, your_other_tools]
llm_with_tools = llm.bind_tools(tools)
```

The agent decides when to call it, fetches verified data, and gets a provenance URL it can cite.

## Notes

- **Discovery client.** This example includes a tiny built-in MCP client that handles the streamable-http handshake (`initialize` → session → `tools/call`). If you already use an MCP client in your stack (e.g. `langchain-mcp-adapters` or the official `mcp` package), you can swap it in — just point it at `https://api.osf-master-server.com/mcp`.
- **Production.** The example opens a fresh MCP session per lookup, which is fine for a demo. In production, cache and reuse the session.
- **"Verifiable" means cited, not signed.** Each record carries its authoritative source URL for you to check — that's ground-truth-with-a-citation. (Cryptographically signed receipts are on the OSF roadmap.)

## Data sources

OSF's security vertical covers NVD CVE records (with CVSS), CISA Known Exploited Vulnerabilities, EPSS exploitation-probability scores, GitHub Security Advisories, CWE, and MITRE ATT&CK — all public-domain, pulled from documented official APIs, each with a provenance URL. There are 40+ more sources across compliance, financial, legal, scientific, and geospatial categories. Browse the free catalog at [osf-master-server.com](https://osf-master-server.com) or the discovery manifest at [`/.well-known/x402`](https://api.osf-master-server.com/.well-known/x402).

## License

MIT — use it however you like.
