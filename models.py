from typing import List, Optional
from pydantic import BaseModel, Field
from enum import Enum


class RecordType(str, Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    TXT = "TXT"
    MX = "MX"
    NS = "NS"


class Classification(str, Enum):
    BENIGN_GEODNS = "benign_geodns"
    STALE_TTL = "stale_ttl"
    SUSPICIOUS_INJECTION = "suspicious_injection"
    CONSISTENT = "consistent"
    ERROR = "error"


class ResolverResult(BaseModel):
    resolver_name: str
    resolver_ip: str
    success: bool
    answers: List[str] = Field(default_factory=list)
    ttl: Optional[int] = None
    error: Optional[str] = None
    latency_ms: Optional[float] = None


class DomainAnalysis(BaseModel):
    domain: str
    record_type: RecordType
    resolver_results: List[ResolverResult]
    classification: Classification
    trust_score: int
    summary: str
    details: List[str] = Field(default_factory=list)


class TrustScoreBreakdown(BaseModel):
    total_resolvers: int
    successful_resolvers: int
    unique_answer_sets: int
    ttl_variance: Optional[float] = None
    sinkhole_matches: int
    geodns_indicators: int