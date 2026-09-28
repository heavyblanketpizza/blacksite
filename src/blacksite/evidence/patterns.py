"""Log template mining with the Drain algorithm.

Collapses millions of lines into a few hundred templates such as
``connect() failed (<NUM>: Connection refused) while connecting to upstream``, so the
model can read the shape of an incident before searching it. This is a compact
implementation of Drain (He et al., ICWS 2017), the algorithm behind logpai/Drain3,
kept in-house because Drain3 has had no release since 2022.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

WILDCARD = "<*>"

_MASKS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<TS>"),
    (re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?![\w.])"), "<IP>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"\b(?=[0-9a-fA-F]*[a-fA-F])(?=[0-9a-fA-F]*\d)[0-9a-fA-F]{12,}\b"), "<HEX>"),
    (re.compile(r"(?<![\w.<])[-+]?\d+(?:\.\d+)?(?![\d>])"), "<NUM>"),
]
_VARIABLE_TOKEN = re.compile(r"\d|<(?:UUID|TS|IP|HEX|NUM)>")
# An access log's status code identifies the event; keep it out of the <NUM> mask.
_HTTP_STATUS = re.compile(r'(HTTP/\d(?:\.\d)?") ([1-5]\d\d)(?= )')
_KEPT = "\x00KEPT\x00"


def mask(message: str) -> str:
    """Replace values that vary between otherwise identical lines."""
    kept: list[str] = []

    def keep(match: re.Match[str]) -> str:
        kept.append(match.group(2))
        return f"{match.group(1)} {_KEPT}"

    message = _HTTP_STATUS.sub(keep, message)
    for pattern, replacement in _MASKS:
        message = pattern.sub(replacement, message)
    for value in kept:
        message = message.replace(_KEPT, value, 1)
    return message


@dataclass
class Cluster:
    tokens: list[str]
    size: int = 0

    @property
    def template(self) -> str:
        return " ".join(self.tokens)


@dataclass
class TemplateMiner:
    """Assigns each message to a template cluster, generalizing clusters as lines arrive."""

    similarity: float = 0.5
    prefix_tokens: int = 1
    clusters: list[Cluster] = field(default_factory=list)
    _leaves: dict[tuple[str, ...], list[int]] = field(default_factory=dict, repr=False)

    def add(self, message: str, group: str = "") -> int:
        """Return the cluster id for ``message``; lines in different groups never share one.

        Blacksite passes the line's severity as ``group`` so that, for example, HTTP 200
        and 502 access-log lines stay separate even though only the status differs.
        """
        tokens = mask(message).split() or ["<EMPTY>"]
        prefix = tuple(WILDCARD if _VARIABLE_TOKEN.search(token) else token for token in tokens[: self.prefix_tokens])
        leaf = self._leaves.setdefault((group, str(len(tokens)), *prefix), [])

        best_id, best_score = -1, (-1.0, -1)
        for cluster_id in leaf:
            score = _similarity(self.clusters[cluster_id].tokens, tokens)
            if score > best_score:
                best_id, best_score = cluster_id, score
        if best_id >= 0 and best_score[0] >= self.similarity:
            cluster = self.clusters[best_id]
            cluster.tokens = [
                known if known == token else WILDCARD for known, token in zip(cluster.tokens, tokens, strict=True)
            ]
            cluster.size += 1
            return best_id

        self.clusters.append(Cluster(tokens=list(tokens), size=1))
        leaf.append(len(self.clusters) - 1)
        return len(self.clusters) - 1


def _similarity(template: list[str], tokens: list[str]) -> tuple[float, int]:
    """Share of positions that match exactly; ties go to the template with more wildcards."""
    matches = wildcards = 0
    for known, token in zip(template, tokens, strict=True):
        if known == WILDCARD:
            wildcards += 1
        elif known == token:
            matches += 1
    return matches / len(template), wildcards
