import yaml
from dataclasses import dataclass
from typing import List


@dataclass
class Config:
    resolvers: List[dict]
    sinkhole_ranges: List[str]
    timeout_seconds: int
    max_concurrent: int


def load_config(path: str = "config.yaml") -> Config:
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    return Config(**data)