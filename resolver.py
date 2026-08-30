import asyncio
import time
from typing import List, Optional
import aiohttp
import dnslib
from dnslib import DNSRecord, QTYPE, RR, A, AAAA, CNAME, TXT, MX, NS, DNSQuestion
from models import ResolverResult, RecordType
from config import load_config


class DoHResolver:
    def __init__(self, config):
        self.config = config
        self.timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)

    async def query(self, session: aiohttp.ClientSession, resolver: dict, domain: str, record_type: RecordType) -> ResolverResult:
        start_time = time.time()
        resolver_name = resolver["name"]
        resolver_url = resolver["url"]
        resolver_ip = resolver.get("ip", "")

        try:
            qtype_map = {"A": 1, "AAAA": 28, "CNAME": 5, "TXT": 16, "MX": 15, "NS": 2}
            q = DNSRecord(q=DNSQuestion(domain, qtype_map[record_type.value]))
            query_data = q.pack()

            headers = {
                "accept": "application/dns-message",
                "content-type": "application/dns-message",
            }

            async with session.post(resolver_url, data=query_data, headers=headers, timeout=self.timeout) as resp:
                if resp.status != 200:
                    return ResolverResult(
                        resolver_name=resolver_name,
                        resolver_ip=resolver_ip,
                        success=False,
                        error=f"HTTP {resp.status}",
                        latency_ms=(time.time() - start_time) * 1000,
                    )

                response_data = await resp.read()
                latency_ms = (time.time() - start_time) * 1000

                return self._parse_response(resolver_name, resolver_ip, response_data, latency_ms)

        except asyncio.TimeoutError:
            return ResolverResult(
                resolver_name=resolver_name,
                resolver_ip=resolver_ip,
                success=False,
                error="Timeout",
                latency_ms=(time.time() - start_time) * 1000,
            )
        except Exception as e:
            return ResolverResult(
                resolver_name=resolver_name,
                resolver_ip=resolver_ip,
                success=False,
                error=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _parse_response(self, resolver_name: str, resolver_ip: str, data: bytes, latency_ms: float) -> ResolverResult:
        try:
            response = DNSRecord.parse(data)
            answers = []
            ttl = None

            for rr in response.rr:
                if rr.rtype in (QTYPE.A, QTYPE.AAAA):
                    answers.append(str(rr.rdata))
                    if ttl is None:
                        ttl = rr.ttl
                elif rr.rtype == QTYPE.CNAME:
                    answers.append(str(rr.rdata))
                    if ttl is None:
                        ttl = rr.ttl
                elif rr.rtype == QTYPE.TXT:
                    for txt in rr.rdata.data:
                        answers.append(txt.decode() if isinstance(txt, bytes) else str(txt))
                    if ttl is None:
                        ttl = rr.ttl
                elif rr.rtype == QTYPE.MX:
                    answers.append(f"{rr.rdata.preference} {rr.rdata.exchange}")
                    if ttl is None:
                        ttl = rr.ttl
                elif rr.rtype == QTYPE.NS:
                    answers.append(str(rr.rdata))
                    if ttl is None:
                        ttl = rr.ttl

            return ResolverResult(
                resolver_name=resolver_name,
                resolver_ip=resolver_ip,
                success=True,
                answers=sorted(answers),
                ttl=ttl,
                latency_ms=latency_ms,
            )
        except Exception as e:
            return ResolverResult(
                resolver_name=resolver_name,
                resolver_ip=resolver_ip,
                success=False,
                error=f"Parse error: {e}",
                latency_ms=latency_ms,
            )

    async def query_all(self, domain: str, record_type: RecordType) -> List[ResolverResult]:
        connector = aiohttp.TCPConnector(limit=self.config.max_concurrent)
        async with aiohttp.ClientSession(connector=connector, timeout=self.timeout) as session:
            tasks = [
                self.query(session, resolver, domain, record_type)
                for resolver in self.config.resolvers
            ]
            results = await asyncio.gather(*tasks)
            return list(results)


def load_config():
    import yaml
    with open("config.yaml", "r") as f:
        data = yaml.safe_load(f)

    class Config:
        def __init__(self, data):
            self.resolvers = data["resolvers"]
            self.sinkhole_ranges = data["sinkhole_ranges"]
            self.timeout_seconds = data["timeout_seconds"]
            self.max_concurrent = data["max_concurrent"]

    return Config(data)