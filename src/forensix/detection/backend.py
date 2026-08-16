"""Custom pySigma backend targeting the ForensiX PostgreSQL Event Store.

pySigma ships official backends for several SIEMs (Splunk, Elastic, CrowdStrike...)
but none for a bespoke schema like ForensiX's EventRecord table, so this module
implements a minimal one by subclassing TextQueryBackend, following the pattern
documented at https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html.

Chain: Sigma rule (YAML) -> pySigma parser -> field mapping pipeline (Sigma
field names -> EventRecord columns) -> ForensixPostgresBackend -> SQL
WHERE-clause fragment, applied via SQLAlchemy text() against EventRecord.

Known limitations (see docs/detection_backend.md for the full list, task 4):
- Field mapping only covers the fields used by the M2-02 rule set; unmapped
  fields pass through unchanged and fail at query time, not at rule-load time.
- EventRecord.event_id is a String column, but Sigma rules typically express
  EventID as a number, which this backend renders as an unquoted numeric
  literal - comparing that against a text column raises a type error in
  PostgreSQL unless cast; must be handled in the execution pipeline (M2-03).
- Only LIKE-style wildcard matching and AND/OR/NOT are exercised by the
  M2-02 rule set; regex, CIDR, and field-to-field comparisons are untested.
"""

from sigma.collection import SigmaCollection
from sigma.conversion.base import TextQueryBackend
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

# Maps Sigma field names (as used in Windows/Sysmon-oriented Sigma rules) to
# ForensiX's flattened EventRecord columns (src/forensix/models/db.py).
FIELD_MAPPING = {
    "Image": "process_name",
    "CommandLine": "process_command_line",
    "ParentProcessId": "process_ppid",
    "ProcessId": "process_pid",
    "TargetFilename": "file_path",
    "DestinationIp": "network_destination_ip",
    "DestinationPort": "network_destination_port",
    "EventID": "event_id",
}


class ForensixPostgresBackend(TextQueryBackend):
    """Convert Sigma rules into SQL WHERE-clause fragments for EventRecord."""

    name = "ForensiX PostgreSQL Event Store backend"
    formats = {"default": "SQL WHERE-clause fragment for EventRecord"}

    and_token = " AND "
    or_token = " OR "
    not_token = "NOT "
    eq_token = " = "

    field_quote = '"'
    field_quote_pattern = None

    str_quote = "'"
    escape_char = "\\"
    wildcard_multi = "%"
    wildcard_single = "_"
    add_escaped = "\\"

    wildcard_match_expression = "{field} LIKE {value}"
    field_null_expression = "{field} IS NULL"
    unbound_value_str_expression = "'{value}'"
    unbound_value_num_expression = "{value}"
    group_expression = "({expr})"


def _build_pipeline() -> ProcessingPipeline:
    """Field-mapping pipeline applied before conversion (Sigma names -> our columns)."""
    return ProcessingPipeline(
        items=[ProcessingItem(transformation=FieldMappingTransformation(FIELD_MAPPING))]
    )


def compile_rule_to_where_clause(rule_yaml: str) -> str:
    """Compile a single Sigma rule (YAML text) into a SQL WHERE-clause fragment."""
    rule_collection = SigmaCollection.from_yaml(rule_yaml)
    backend = ForensixPostgresBackend(processing_pipeline=_build_pipeline())
    queries = backend.convert(rule_collection)
    return queries[0].strip()

