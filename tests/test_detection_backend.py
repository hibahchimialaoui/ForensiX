"""Tests for the custom pySigma backend targeting the ForensiX Event Store."""

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
