"""
Custom pySigma conversion backend that compiles a parsed SigmaRule directly
into a Python predicate (dict -> bool) instead of a query string for some
external SIEM. This lets us execute real Sigma detection logic (AND/OR/NOT,
wildcards, regex, CIDR, numeric compares, field-exists, etc.) directly
against normalized log dicts in memory, without needing a SIEM backend.
"""
import ipaddress
import re as _re

from sigma.conversion.base import Backend
from sigma.conversion.state import ConversionState
from sigma.conditions import ConditionAND, ConditionOR
from sigma.types import SigmaCompareExpression


def _wildcard_to_regex(value: str) -> _re.Pattern:
    escaped = _re.escape(value)
    escaped = escaped.replace(r"\*", ".*").replace(r"\?", ".")
    return _re.compile(f"^{escaped}$", _re.IGNORECASE)


class PythonPredicateBackend(Backend):
    """Sigma -> Python predicate backend. Each compiled rule is a callable
    accepting a flat dict of log fields and returning True/False."""

    def convert_condition_and(self, cond: ConditionAND, state: ConversionState):
        subs = [self.convert_condition(a, state) for a in cond.args]
        return lambda log: all(s(log) for s in subs)

    def convert_condition_or(self, cond: ConditionOR, state: ConversionState):
        subs = [self.convert_condition(a, state) for a in cond.args]
        return lambda log: any(s(log) for s in subs)

    def convert_condition_not(self, cond, state: ConversionState):
        sub = self.convert_condition(cond.args[0], state)
        return lambda log: not sub(log)

    def convert_condition_field_eq_val_str(self, cond, state):
        field = cond.field
        pattern = _wildcard_to_regex(str(cond.value))
        return lambda log: bool(pattern.match(str(log.get(field, ""))))

    def convert_condition_field_eq_val_str_case_sensitive(self, cond, state):
        field = cond.field
        val = str(cond.value)
        escaped = _re.escape(val).replace(r"\*", ".*").replace(r"\?", ".")
        pattern = _re.compile(f"^{escaped}$")
        return lambda log: bool(pattern.match(str(log.get(field, ""))))

    def convert_condition_field_eq_val_num(self, cond, state):
        field = cond.field
        val = cond.value.number

        def check(log, field=field, val=val):
            v = log.get(field)
            try:
                return float(v) == float(val)
            except (TypeError, ValueError):
                return False

        return check

    def convert_condition_field_eq_val_re(self, cond, state):
        field = cond.field
        pattern = _re.compile(str(cond.value.regexp), _re.IGNORECASE)
        return lambda log: bool(pattern.search(str(log.get(field, ""))))

    def convert_condition_field_eq_val_cidr(self, cond, state):
        field = cond.field
        net = ipaddress.ip_network(cond.value.cidr, strict=False)

        def check(log, field=field, net=net):
            try:
                return ipaddress.ip_address(str(log.get(field, ""))) in net
            except ValueError:
                return False

        return check

    def convert_condition_field_eq_val_bool(self, cond, state):
        field = cond.field
        val = bool(cond.value)
        return lambda log: bool(log.get(field)) == val

    def convert_condition_field_eq_val_null(self, cond, state):
        field = cond.field
        return lambda log: log.get(field) is None

    def convert_condition_field_exists(self, cond, state):
        field = cond.field
        return lambda log: field in log and log.get(field) is not None

    def convert_condition_field_not_exists(self, cond, state):
        field = cond.field
        return lambda log: log.get(field) is None

    def convert_condition_field_compare_op_val(self, cond, state):
        field = cond.field
        op = cond.value.op
        num = cond.value.number.number
        ops = {
            SigmaCompareExpression.CompareOperators.LT: lambda a, b: a < b,
            SigmaCompareExpression.CompareOperators.LTE: lambda a, b: a <= b,
            SigmaCompareExpression.CompareOperators.GT: lambda a, b: a > b,
            SigmaCompareExpression.CompareOperators.GTE: lambda a, b: a >= b,
        }
        fn = ops[op]

        def check(log, field=field, num=num, fn=fn):
            try:
                return fn(float(log.get(field)), float(num))
            except (TypeError, ValueError):
                return False

        return check

    def convert_condition_field_eq_field(self, cond, state):
        field, other = cond.field, cond.value
        return lambda log: log.get(field) == log.get(other)

    def convert_condition_as_in_expression(self, cond, state):
        if isinstance(cond, ConditionOR):
            return self.convert_condition_or(cond, state)
        return self.convert_condition_and(cond, state)

    def convert_condition_val_str(self, cond, state):
        pattern = _wildcard_to_regex(str(cond.value))
        return lambda log: any(pattern.match(str(v)) for v in log.values())

    def convert_condition_val_num(self, cond, state):
        val = cond.value.number

        def check(log, val=val):
            for v in log.values():
                try:
                    if float(v) == float(val):
                        return True
                except (TypeError, ValueError):
                    continue
            return False

        return check

    def convert_condition_val_re(self, cond, state):
        pattern = _re.compile(str(cond.value.regexp), _re.IGNORECASE)
        return lambda log: any(pattern.search(str(v)) for v in log.values())

    # Unsupported by an in-memory engine (no query language / correlation store)
    def convert_condition_field_eq_query_expr(self, cond, state):
        raise NotImplementedError("Query-expression fields are not supported by the in-memory engine")

    def convert_condition_query_expr(self, cond, state):
        raise NotImplementedError("Raw query expressions are not supported by the in-memory engine")

    def convert_condition_field_eq_val_timestamp_part(self, cond, state):
        raise NotImplementedError("Timestamp-part comparisons are not supported by the in-memory engine")

    def convert_correlation_event_count_rule(self, rule, state):
        raise NotImplementedError("Correlation rules are not supported by the in-memory engine")

    convert_correlation_extended_temporal_ordered_rule = convert_correlation_event_count_rule
    convert_correlation_extended_temporal_rule = convert_correlation_event_count_rule
    convert_correlation_temporal_ordered_rule = convert_correlation_event_count_rule
    convert_correlation_temporal_rule = convert_correlation_event_count_rule
    convert_correlation_value_avg_rule = convert_correlation_event_count_rule
    convert_correlation_value_count_rule = convert_correlation_event_count_rule
    convert_correlation_value_median_rule = convert_correlation_event_count_rule
    convert_correlation_value_percentile_rule = convert_correlation_event_count_rule
    convert_correlation_value_sum_rule = convert_correlation_event_count_rule

    def finalize_query(self, rule, query, index, state, output_format):
        return query
