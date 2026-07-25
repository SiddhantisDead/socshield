import hashlib
import logging
from pathlib import Path

import yara

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]


class YaraEngine:
    def __init__(self, rules_dir: str | Path):
        self.rules_dir = Path(rules_dir)
        self._compiled = None

    def load_rules(self) -> list[str]:
        errors: list[str] = []
        rule_files = {p.stem: str(p) for p in self.rules_dir.glob("*.yar")}
        rule_files.update({p.stem: str(p) for p in self.rules_dir.glob("*.yara")})
        if not rule_files:
            self._compiled = None
            return errors
        try:
            self._compiled = yara.compile(filepaths=rule_files)
        except yara.Error as exc:
            errors.append(str(exc))
            self._compiled = None
        return errors

    def scan_bytes(self, data: bytes) -> dict:
        sha256 = hashlib.sha256(data).hexdigest()
        matched_rules: list[dict] = []

        if self._compiled is not None:
            try:
                matches = self._compiled.match(data=data)
            except yara.Error as exc:
                logger.warning("YARA scan failed: %s", exc)
                matches = []

            for m in matches:
                meta = dict(m.meta)
                matched_rules.append(
                    {
                        "rule": m.rule,
                        "namespace": m.namespace,
                        "tags": list(m.tags),
                        "severity": str(meta.get("severity", "medium")),
                        "description": str(meta.get("description", "")),
                        "mitre_id": str(meta.get("mitre_id", "")),
                    }
                )

        severity = "informational"
        for match in matched_rules:
            sev = match["severity"].lower()
            if sev in _SEVERITY_ORDER and _SEVERITY_ORDER.index(sev) > _SEVERITY_ORDER.index(severity):
                severity = sev

        return {
            "sha256": sha256,
            "matched_rules": matched_rules,
            "severity": severity.capitalize(),
            "is_malicious": len(matched_rules) > 0,
        }


_engine: YaraEngine | None = None


def get_yara_engine(rules_dir: str | Path) -> YaraEngine:
    global _engine
    if _engine is None:
        _engine = YaraEngine(rules_dir)
        _engine.load_rules()
    return _engine
