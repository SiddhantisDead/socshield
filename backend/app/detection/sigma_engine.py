import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

from app.detection.backend import PythonPredicateBackend
from app.detection.mitre_mapper import extract_mitre
from app.models.enums import Severity

logger = logging.getLogger(__name__)

_LEVEL_TO_SEVERITY = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "informational": Severity.informational,
}


@dataclass
class CompiledRule:
    rule_id: str
    title: str
    description: str
    severity: Severity
    mitre_id: str
    mitre_technique: str
    logsource_category: str
    predicate: Callable[[dict], bool]


class SigmaEngine:
    def __init__(self, rules_dir: str | Path):
        self.rules_dir = Path(rules_dir)
        self.rules: list[CompiledRule] = []

    def load_rules(self) -> list[str]:
        """Parse every Sigma YAML rule in rules_dir and compile it into a
        Python predicate. Returns a list of load errors (empty on success)."""
        self.rules = []
        errors: list[str] = []
        backend = PythonPredicateBackend()

        for path in sorted(self.rules_dir.glob("*.yml")) + sorted(self.rules_dir.glob("*.yaml")):
            try:
                collection = SigmaCollection.from_yaml(path.read_text())
            except SigmaError as exc:
                errors.append(f"{path.name}: {exc}")
                continue

            for rule in collection.rules:
                try:
                    predicates = backend.convert(SigmaCollection([rule]))
                    predicate = predicates[0]
                except (NotImplementedError, SigmaError) as exc:
                    errors.append(f"{path.name} ({rule.title}): {exc}")
                    continue

                tags = [str(t) for t in rule.tags]
                mitre_id, mitre_technique = extract_mitre(tags)
                level = str(rule.level.name if rule.level else "medium").lower()

                self.rules.append(
                    CompiledRule(
                        rule_id=str(rule.id) if rule.id else path.stem,
                        title=rule.title,
                        description=rule.description or "",
                        severity=_LEVEL_TO_SEVERITY.get(level, Severity.medium),
                        mitre_id=mitre_id,
                        mitre_technique=mitre_technique,
                        logsource_category=(rule.logsource.category or "") if rule.logsource else "",
                        predicate=predicate,
                    )
                )

        logger.info("Loaded %d Sigma rules from %s (%d errors)", len(self.rules), self.rules_dir, len(errors))
        return errors

    def evaluate(self, log_fields: dict) -> list[CompiledRule]:
        matches = []
        for rule in self.rules:
            try:
                if rule.predicate(log_fields):
                    matches.append(rule)
            except Exception:  # a malformed field value shouldn't crash detection
                continue
        return matches


_engine: SigmaEngine | None = None


def get_engine(rules_dir: str | Path) -> SigmaEngine:
    global _engine
    if _engine is None:
        _engine = SigmaEngine(rules_dir)
        _engine.load_rules()
    return _engine


def reload_engine(rules_dir: str | Path) -> list[str]:
    global _engine
    _engine = SigmaEngine(rules_dir)
    return _engine.load_rules()
