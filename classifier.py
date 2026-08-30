import ipaddress
from typing import List, Set, Tuple
from collections import Counter
from models import (
    ResolverResult, DomainAnalysis, Classification, 
    RecordType, TrustScoreBreakdown
)
from config import load_config


class DNSClassifier:
    def __init__(self, config=None):
        self.config = config or load_config()
        self.sinkhole_networks = [ipaddress.ip_network(r) for r in self.config.sinkhole_ranges]

    def classify(self, domain: str, record_type: RecordType, results: List[ResolverResult]) -> DomainAnalysis:
        successful = [r for r in results if r.success and r.answers]
        failed = [r for r in results if not r.success]

        if not successful:
            return DomainAnalysis(
                domain=domain,
                record_type=record_type,
                resolver_results=results,
                classification=Classification.ERROR,
                trust_score=0,
                summary="All resolvers failed to respond",
                details=[f"{r.resolver_name}: {r.error}" for r in failed],
            )

        answer_sets = self._group_by_answers(successful)
        unique_answers = len(answer_sets)

        ttl_variance = self._calculate_ttl_variance(successful)
        sinkhole_matches = self._check_sinkholes(successful)
        geodns_confidence = self._check_geodns(answer_sets, successful)

        classification, trust_score, summary, details = self._determine_classification(
            successful, answer_sets, unique_answers, ttl_variance, 
            sinkhole_matches, geodns_confidence, len(results)
        )

        breakdown = TrustScoreBreakdown(
            total_resolvers=len(results),
            successful_resolvers=len(successful),
            unique_answer_sets=unique_answers,
            ttl_variance=ttl_variance,
            sinkhole_matches=sinkhole_matches,
            geodns_indicators=int(geodns_confidence * 10),
        )

        details.append(f"Trust score breakdown: {breakdown.model_dump()}")

        return DomainAnalysis(
            domain=domain,
            record_type=record_type,
            resolver_results=results,
            classification=classification,
            trust_score=trust_score,
            summary=summary,
            details=details,
        )

    def _group_by_answers(self, results: List[ResolverResult]) -> List[List[ResolverResult]]:
        groups = {}
        for r in results:
            key = tuple(r.answers)
            if key not in groups:
                groups[key] = []
            groups[key].append(r)
        return list(groups.values())

    def _calculate_ttl_variance(self, results: List[ResolverResult]) -> float:
        ttls = [r.ttl for r in results if r.ttl is not None]
        if len(ttls) < 2:
            return 0.0
        mean = sum(ttls) / len(ttls)
        variance = sum((t - mean) ** 2 for t in ttls) / len(ttls)
        return variance

    def _check_sinkholes(self, results: List[ResolverResult]) -> int:
        count = 0
        for r in results:
            for answer in r.answers:
                try:
                    ip = ipaddress.ip_address(answer.split()[0] if " " in answer else answer)
                    for network in self.sinkhole_networks:
                        if ip in network:
                            count += 1
                            break
                except ValueError:
                    continue
        return count

    def _is_public_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str.split()[0] if " " in ip_str else ip_str)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip == ipaddress.IPv4Address('0.0.0.0'))
        except ValueError:
            return False

    def _check_geodns(self, answer_sets: List[List[ResolverResult]], successful: List[ResolverResult]) -> float:
        unique_answers = len(answer_sets)
        if unique_answers <= 1:
            return 0.0

        all_public = True
        for group in answer_sets:
            for r in group:
                for ans in r.answers:
                    if not self._is_public_ip(ans):
                        all_public = False

        if not all_public:
            return 0.0

        major_resolvers = {"Cloudflare", "Google", "NextDNS", "OpenDNS", "AdGuard", "DNS.SB", "LibreDNS", "CleanBrowsing"}
        resolver_names = {r.resolver_name for r in successful}
        major_present = len(resolver_names & major_resolvers)

        if unique_answers >= 5 and major_present >= 4:
            return 0.9
        elif unique_answers >= 3 and major_present >= 3:
            return 0.7
        elif unique_answers >= 2 and major_present >= 2:
            return 0.5
        elif unique_answers <= 3 and major_present >= 2:
            return 0.6
        
        return 0.2

    def _determine_classification(
        self, successful: List[ResolverResult], answer_sets: List[List[ResolverResult]],
        unique_answers: int, ttl_variance: float, sinkhole_matches: int,
        geodns_confidence: float, total_resolvers: int
    ) -> Tuple[Classification, int, str, List[str]]:
        details = []

        if sinkhole_matches > 0:
            details.append(f"⚠ {sinkhole_matches} resolver(s) returned sinkhole/private IP addresses")
            return Classification.SUSPICIOUS_INJECTION, max(0, 100 - sinkhole_matches * 30), \
                "Suspicious: Responses match known sinkhole/blocklist ranges", details

        if unique_answers == 1:
            details.append("✓ All resolvers returned identical answers")
            return Classification.CONSISTENT, 100, \
                "Consistent: All resolvers agree on the answer", details

        if geodns_confidence >= 0.7:
            details.append(f"🌍 {unique_answers} distinct answer sets detected (likely GeoDNS/CDN)")
            details.append("  This is normal for globally distributed services")
            score = max(75, 100 - (unique_answers - 1) * 3)
            return Classification.BENIGN_GEODNS, score, \
                f"Benign GeoDNS: {unique_answers} regional answer sets (CDN/load balancing)", details

        if geodns_confidence >= 0.4:
            details.append(f"🌍 {unique_answers} distinct answer sets detected (possible GeoDNS/CDN)")
            details.append("  Multiple answer sets from major resolvers suggest regional routing")
            score = max(60, 90 - (unique_answers - 1) * 5)
            return Classification.BENIGN_GEODNS, score, \
                f"Likely GeoDNS: {unique_answers} answer sets from major resolvers", details

        if ttl_variance > 10000 and unique_answers <= 3:
            details.append(f"⏱ High TTL variance detected ({ttl_variance:.0f}s)")
            details.append("  Resolvers may have stale cached records")
            score = max(50, 80 - int(ttl_variance / 5000) * 10)
            return Classification.STALE_TTL, score, \
                f"Stale TTL: High variance ({ttl_variance:.0f}s) suggests caching issues", details

        details.append(f"⚠ {unique_answers} distinct answer sets with no clear GeoDNS pattern")
        score = max(20, 80 - (unique_answers - 1) * 10)
        return Classification.SUSPICIOUS_INJECTION, score, \
            f"Unclear divergence: {unique_answers} answer sets, possible injection or misconfiguration", details