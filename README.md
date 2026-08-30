# DNS Divergence Classifier

Query a domain across 8 public DoH resolvers simultaneously, compare answers, and classify divergences as benign GeoDNS/CDN routing, stale TTL caching, or suspicious injection — with a plain-English trust score.

## Why This Is Different

**Existing tools:** `dig`/`drill` (single resolver), `dnsviz` (DNSSEC validation), `dnstwist` (typosquatting), public DNS lookup websites (one resolver at a time).

**This tool's unique value:** Runs **parallel DoH queries to 8 diverse resolvers** (Cloudflare, Google, NextDNS, OpenDNS, AdGuard, DNS.SB, LibreDNS, CleanBrowsing), **diffs the answer sets in real time**, and **classifies the divergence cause** — not just "different answers" but *why*: GeoDNS/CDN (benign), stale cache (operational), or sinkhole match (threat). Outputs a **trust score (0–100)** with human-readable reasoning, not raw packet dumps.

## How It Works

1. **Parallel DoH queries** — Sends DNS-over-HTTPS (RFC 8484) POST requests to 8 resolvers concurrently using `aiohttp`.
2. **Response parsing** — Uses `dnslib` to parse wire-format DNS responses into structured records (A, AAAA, CNAME, TXT, MX, NS).
3. **Answer clustering** — Groups resolvers by identical answer sets to count distinct responses.
4. **Classification logic**:
   - **Sinkhole match** → Any answer in RFC 1918 / loopback / blocklist ranges → *Suspicious Injection*
   - **Single answer set** → All resolvers agree → *Consistent*
   - **Multiple sets + major resolver spread** → Likely GeoDNS/CDN → *Benign GeoDNS*
   - **High TTL variance (>1hr)** → Stale cache across resolvers → *Stale TTL*
   - **Otherwise** → Unexplained divergence → *Suspicious Injection*
5. **Trust score** — 100 baseline, penalized per anomaly type; sinkhole = -30 each, extra answer set = -10 to -15, high TTL variance = -10 per hour.

## How To Run

```bash
# Install dependencies
pip install -r requirements.txt

# Single domain (A record)
python dns_divergence.py example.com

# AAAA record
python dns_divergence.py example.com --type AAAA

# Verbose output with per-resolver details
python dns_divergence.py example.com -v

# Batch mode from file (one domain per line)
python dns_divergence.py domains.txt --batch

# JSON output (for scripting)
python dns_divergence.py example.com --json
```

## Example Output

```bash
$ python dns_divergence.py example.com
```

```
┌─────────────────────────────────────────────────────────────────┐
│ Domain: example.com (A)  |  Trust Score: 100/100  |  Consistent │
└─────────────────────────────────────────────────────────────────┘
Summary: Consistent: All resolvers agree on the answer

┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Resolver        ┃ Status     ┃ Answers               ┃ TTL      ┃ Latency    ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━┩
│ Cloudflare      │ ✓ OK       │ 104.20.23.154,        │ 75       │ 485ms      │
│                 │            │ 172.66.147.243        │          │            │
│ Google          │ ✓ OK       │ 104.20.23.154,        │ 227      │ 687ms      │
│                 │            │ 172.66.147.243        │          │            │
│ NextDNS         │ ✓ OK       │ 104.20.23.154,        │ 133      │ 1334ms     │
│                 │            │ 172.66.147.243        │          │            │
│ OpenDNS         │ ✓ OK       │ 104.20.23.154,        │ 203      │ 820ms      │
│                 │            │ 172.66.147.243        │          │            │
│ AdGuard         │ ✓ OK       │ 104.20.23.154,        │ 228      │ 799ms      │
│                 │            │ 172.66.147.243        │          │            │
│ DNS.SB          │ ✓ OK       │ 104.20.23.154,        │ 180      │ 1242ms     │
│                 │            │ 172.66.147.243        │          │            │
│ LibreDNS        │ ✓ OK       │ 104.20.23.154,        │ 117      │ 1069ms     │
│                 │            │ 172.66.147.243        │          │            │
│ CleanBrowsing   │ ✓ OK       │ 104.20.23.154,        │ 238      │ 1181ms     │
│                 │            │ 172.66.147.243        │          │            │
└─────────────────┴────────────┴───────────────────────┴──────────┴────────────┘

Details:
  • ✓ All resolvers returned identical answers
  • Trust score breakdown: {'total_resolvers': 8, 'successful_resolvers': 8, 'unique_answer_sets': 1, 'ttl_variance': 3177.36, 'sinkhole_matches': 0, 'geodns_indicators': 0}
```

```bash
$ python dns_divergence.py google.com
```

```
┌──────────────────────────────────────────────────────────────────┐
│ Domain: google.com (A)  |  Trust Score: 79/100  |  Benign Geodns │
└──────────────────────────────────────────────────────────────────┘
Summary: Benign GeoDNS: 8 regional answer sets (CDN/load balancing)

┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Resolver        ┃ Status     ┃ Answers               ┃ TTL      ┃ Latency    ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━┩
│ Cloudflare      │ ✓ OK       │ 142.250.134.100,      │ 300      │ 272ms      │
│                 │            │ 142.250.134.101,      │          │            │
│                 │            │ 142.250.134.102 ...   │          │            │
│                 │            │ (+3 more)             │          │            │
│ Google          │ ✓ OK       │ 142.250.202.110       │ 72       │ 343ms      │
│ NextDNS         │ ✓ OK       │ 142.250.207.78        │ 299      │ 803ms      │
│ OpenDNS         │ ✓ OK       │ 142.250.201.110       │ 300      │ 396ms      │
│ AdGuard         │ ✓ OK       │ 142.251.37.142        │ 260      │ 392ms      │
│ DNS.SB          │ ✓ OK       │ 142.251.24.100,       │ 152      │ 800ms      │
│                 │            │ 142.251.24.101,       │          │            │
│                 │            │ 142.251.24.102 ...    │          │            │
│                 │            │ (+3 more)             │          │            │
│ LibreDNS        │ ✓ OK       │ 142.251.110.100,      │ 237      │ 565ms      │
│                 │            │ 142.251.110.101,      │          │            │
│                 │            │ 142.251.110.102 ...   │          │            │
│                 │            │ (+3 more)             │          │            │
│ CleanBrowsing   │ ✓ OK       │ 172.217.23.14         │ 57       │ 786ms      │
└─────────────────┴────────────┴───────────────────────┴──────────┴────────────┘

Details:
  • 🌍 8 distinct answer sets detected (likely GeoDNS/CDN)
  •   This is normal for globally distributed services
  • Trust score breakdown: {'total_resolvers': 8, 'successful_resolvers': 8, 'unique_answer_sets': 8, 'ttl_variance': 9145.73, 'sinkhole_matches': 0, 'geodns_indicators': 9}
```

## Tech Stack + Libraries Reused

| Library | Purpose | Why Not Custom |
|---------|---------|----------------|
| `aiohttp` | Async HTTP client for DoH POST requests | Battle-tested, handles connection pooling, timeouts, retries |
| `dnslib` | DNS wire-format parsing (RFC 1035) | Full RFC-compliant parser; writing one is error-prone |
| `pydantic` | Data models + validation | Type-safe configs/results; eliminates boilerplate |
| `rich` | Terminal tables, panels, colors | Professional CLI UX without ANSI escaping by hand |
| `pyyaml` | Config file parsing | Standard, zero-surprise YAML loader |

**The genuinely new piece:** The **classification engine** (`classifier.py`) that takes clustered resolver answers + TTLs + sinkhole ranges and emits a *single* trust score with plain-English reasoning. No existing OSS tool combines multi-resolver DoH querying with divergence *classification* (not just diffing) and a trust score.

## Known Limitations / What's Next

- **No DNSSEC validation** — Answers aren't cryptographically verified; a resolver could lie and we'd trust it. Next: integrate `dnssec` validation per resolver.
- **IPv6-only resolvers not tested** — All 8 resolvers support both A/AAAA; would need AAAA-specific endpoints for v6-only paths.
- **Sinkhole list is static** — Hardcoded RFC 1918 + loopback + common blocklist ranges. Next: pull from `abuse.ch` / `blocklist.de` feeds.
- **No historical baseline** — Single snapshot; can't detect "this domain changed from 1 answer set to 3 yesterday." Next: SQLite cache + trend detection.
- **Rate limiting** — No backoff/retry on 429; some resolvers (NextDNS) rate-limit aggressive parallel queries.
- **EDNS Client Subnet (ECS)** — Not sent; GeoDNS answers may reflect resolver location, not client location. Next: optional ECS support.

---

**License:** MIT — see [LICENSE](LICENSE)