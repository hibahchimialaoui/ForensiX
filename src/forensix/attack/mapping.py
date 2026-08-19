"""MITRE ATT&CK technique extraction from curated Sigma rules (M4-02).

Techniques are extracted directly from each rule's native tags (SigmaRuleTag,
verified via pySigma), never inferred or guessed. Per SigmaHQ's own
documentation (nuance already noted in docs/sigma_rules.md), this mapping is
at technique level, not procedure level. A rule with no technique tag (only
tactic tags, e.g. attack.execution) yields an empty list - no artificial
mapping is produced.
"""

import re

from sigma.collection import SigmaCollection

from forensix.detection.executor import get_rule_metadata, load_rule_files

_TECHNIQUE_PATTERN = re.compile(r"^t\d{4}(\.\d{3})?$")


def extract_attack_techniques(rule_yaml: str) -> list[str]:
    """Return the ATT&CK technique IDs (e.g. ['T1059.001']) tagged on a rule.

    Only tags matching the technique ID pattern are kept; tactic-only tags
    are intentionally excluded, so an untagged rule returns an empty list
    rather than a fabricated mapping.
    """
    rule_collection = SigmaCollection.from_yaml(rule_yaml)
    rule = rule_collection.rules[0]
    return [
        tag.name.upper()
        for tag in rule.tags
        if tag.namespace == "attack" and _TECHNIQUE_PATTERN.match(tag.name)
    ]


def build_rule_technique_map() -> dict[str, list[str]]:
    """Build {rule_id: [technique_ids]} for every curated rule (M2-02)."""
    mapping: dict[str, list[str]] = {}
    for rule_file in load_rule_files():
        rule_yaml = rule_file.read_text(encoding="utf-8")
        rule_id, _ = get_rule_metadata(rule_yaml)
        mapping[rule_id] = extract_attack_techniques(rule_yaml)
    return mapping
