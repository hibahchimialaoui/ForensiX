"""Tests for MITRE ATT&CK technique extraction (M4-02)."""

from forensix.attack.mapping import build_rule_technique_map, extract_attack_techniques

RULE_WITH_TECHNIQUE = """
title: test
id: 11111111-1111-1111-1111-111111111111
level: high
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 'cmd.exe'
    condition: selection
"""

RULE_WITHOUT_TECHNIQUE = """
title: test
id: 22222222-2222-2222-2222-222222222222
level: medium
tags:
    - attack.command-and-control
    - attack.stealth
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort: 4444
    condition: selection
"""

RULE_WITH_MULTIPLE_TECHNIQUES = """
title: test
id: 33333333-3333-3333-3333-333333333333
level: high
tags:
    - attack.privilege-escalation
    - attack.t1055
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 'test.exe'
    condition: selection
"""


def test_extracts_a_single_technique_and_excludes_tactic_tags():
    techniques = extract_attack_techniques(RULE_WITH_TECHNIQUE)
    assert techniques == ["T1059.001"]


def test_rule_without_technique_tags_returns_empty_list():
    """A rule with only tactic tags must not produce a fabricated mapping."""
    techniques = extract_attack_techniques(RULE_WITHOUT_TECHNIQUE)
    assert techniques == []


def test_rule_with_multiple_techniques_returns_all_of_them():
    techniques = extract_attack_techniques(RULE_WITH_MULTIPLE_TECHNIQUES)
    assert sorted(techniques) == ["T1055", "T1218"]


def test_build_rule_technique_map_covers_all_seven_curated_rules():
    mapping = build_rule_technique_map()
    assert len(mapping) == 7
    # At least one curated rule (net_connection_win_office_uncommon_ports)
    # is known to have no technique tag - verified empirically.
    assert any(techniques == [] for techniques in mapping.values())
    # At least one curated rule has more than one technique tag.
    assert any(len(techniques) > 1 for techniques in mapping.values())
