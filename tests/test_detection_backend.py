"""Tests for the custom pySigma backend targeting the ForensiX Event Store."""

from pathlib import Path

from forensix.detection.backend import compile_rule_to_where_clause

POWERSHELL_RULE = """
title: Suspicious PowerShell process
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 'powershell.exe'
        CommandLine|contains: '-enc'
    condition: selection
"""

NETWORK_RULE = """
title: Network connection to suspicious port
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort: 4444
    condition: selection
"""

# Regression test for a real bug found in M2-02: group_expression was not
# defined, causing NotImplementedError on any rule using a list of values
# (very common in real Sigma rules). The two rules above never exercised
# this path, which is exactly why the bug went unnoticed until real rules
# from rules/sigma/ were tested.
LIST_VALUE_RULE = """
title: Suspicious file extension in Startup folder
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains: 'Startup'
        TargetFilename|endswith:
            - '.bat'
            - '.ps1'
            - '.vbs'
    condition: selection
"""


def test_endswith_and_contains_map_to_like_with_wildcards():
    where_clause = compile_rule_to_where_clause(POWERSHELL_RULE)
    assert '"process_name" LIKE' in where_clause
    assert "'%powershell.exe'" in where_clause
    assert '"process_command_line" LIKE' in where_clause
    assert "'%-enc%'" in where_clause
    assert " AND " in where_clause


def test_field_mapping_translates_sigma_names_to_event_record_columns():
    where_clause = compile_rule_to_where_clause(NETWORK_RULE)
    assert '"network_destination_port"' in where_clause
    # Sigma field name should never leak through into the generated SQL.
    assert "DestinationPort" not in where_clause


def test_list_of_values_compiles_with_grouping_parentheses():
    """Regression test: a rule with a list of values must compile, with the
    OR-ed values wrapped in parentheses (group_expression)."""
    where_clause = compile_rule_to_where_clause(LIST_VALUE_RULE)
    assert '"file_path" LIKE' in where_clause
    assert " OR " in where_clause
    assert "(" in where_clause and ")" in where_clause


def test_all_selected_sigma_rules_compile_without_error():
    """Every rule file curated in M2-02 (rules/sigma/) must compile with our
    backend. This does not guarantee correct execution against real data for
    rules using unmapped fields (see docs/sigma_rules.md compatibility notes)
    - it only guarantees pySigma can convert the rule without raising."""
    rules_dir = Path(__file__).resolve().parent.parent / "rules" / "sigma"
    rule_files = list(rules_dir.glob("*.yml"))
    assert len(rule_files) == 7, f"Expected 7 curated rules, found {len(rule_files)}"

    for rule_file in rule_files:
        rule_yaml = rule_file.read_text(encoding="utf-8")
        where_clause = compile_rule_to_where_clause(rule_yaml)
        assert where_clause, f"{rule_file.name} compiled to an empty clause"
