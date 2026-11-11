"""
Rule store for custom detection rules.

Manages rules/custom_rules.yaml with:
  * process-wide file locking (msvcrt on Windows, fcntl on POSIX)
  * atomic replacement via temp file + os.replace
  * mtime-based hot reload
  * validation of regex patterns and severity values

Built-in rules live in code (utils.vulnerability_patterns) and are exposed
read-only through this store; only custom rules are persisted to YAML.
"""

import os
import re
import copy
import tempfile
import threading
from contextlib import contextmanager

import yaml

from utils.logger import get_logger

logger = get_logger()

# Portable advisory file locking
try:
    import msvcrt  # Windows

    def _lock_file(fh):
        # Lock 1 byte at the current position; blocks until available.
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)

    def _unlock_file(fh):
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)

except ImportError:  # POSIX
    import fcntl

    def _lock_file(fh):
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)

    def _unlock_file(fh):
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


VALID_SEVERITIES = ("critical", "high", "medium", "low")
VALID_LANGUAGES = ("python", "javascript", "php", "java", "c", "cpp",
                   "go", "ruby", "generic", "common")

# Mapping to the capitalized severities used throughout the scanner/reports.
SEVERITY_DISPLAY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}

DEFAULT_RULES_PATH = os.environ.get(
    "ZEROHUNTAI_RULES_PATH",
    os.path.join("rules", "custom_rules.yaml"),
)


class RuleValidationError(ValueError):
    """Raised when a rule payload fails validation."""


class BuiltinRuleError(PermissionError):
    """Raised when a caller tries to modify or delete a built-in rule."""


def validate_rule_payload(payload):
    """
    Validate a rule payload from the API.

    Returns a normalized rule dict (without id/source/enabled).
    Raises RuleValidationError with a human-readable reason on failure.
    """
    if not isinstance(payload, dict):
        raise RuleValidationError("request body must be a JSON object")

    errors = []

    name = payload.get("name")
    if not name or not isinstance(name, str) or not name.strip():
        errors.append("'name' is required and must be a non-empty string")

    pattern = payload.get("pattern")
    if not pattern or not isinstance(pattern, str):
        errors.append("'pattern' is required and must be a regex string")
    else:
        try:
            re.compile(pattern)
        except re.error as exc:
            errors.append(f"invalid regex pattern: {exc}")

    severity = payload.get("severity")
    if not isinstance(severity, str) or severity.lower() not in VALID_SEVERITIES:
        errors.append(
            f"'severity' is required and must be one of: {', '.join(VALID_SEVERITIES)}"
        )

    language = payload.get("language", "python")
    if not isinstance(language, str) or language.lower() not in VALID_LANGUAGES:
        errors.append(
            f"'language' must be one of: {', '.join(VALID_LANGUAGES)}"
        )

    description = payload.get("description", "")
    if description is not None and not isinstance(description, str):
        errors.append("'description' must be a string")

    if errors:
        raise RuleValidationError("; ".join(errors))

    return {
        "name": name.strip(),
        "pattern": pattern,
        "severity": severity.lower(),
        "language": language.lower(),
        "description": (description or "").strip(),
    }


class RuleStore:
    """Thread-safe store for custom rules backed by a YAML file."""

    def __init__(self, rules_path=DEFAULT_RULES_PATH):
        self.rules_path = rules_path
        # Serializes in-process writers; the file lock additionally guards
        # against other processes (gunicorn workers, CLI runs, ...).
        self._write_lock = threading.RLock()
        self._cache_lock = threading.RLock()
        self._custom_rules = []
        self._mtime = None
        self.reload()

    # ------------------------------------------------------------------ load

    @contextmanager
    def _file_lock(self):
        """
        OS-level lock on a sidecar lock file, shared by every read and write.

        Combined with the in-process _write_lock this guarantees that
        concurrent writers (threads or separate processes) never interleave
        a read-modify-write and corrupt the YAML.
        """
        directory = os.path.dirname(os.path.abspath(self.rules_path))
        os.makedirs(directory, exist_ok=True)
        lock_path = self.rules_path + ".lock"
        # 'a+' guarantees the file exists and has at least one lockable byte;
        # msvcrt.locking cannot lock a zero-length region on Windows.
        with open(lock_path, "a+") as lock_fh:
            lock_fh.seek(0, os.SEEK_END)
            if lock_fh.tell() == 0:
                lock_fh.write("x")
                lock_fh.flush()
            _lock_file(lock_fh)
            try:
                yield
            finally:
                _unlock_file(lock_fh)

    def _read_file_locked(self):
        """Read and parse the YAML file while holding the shared file lock."""
        if not os.path.exists(self.rules_path):
            return []

        with self._file_lock():
            with open(self.rules_path, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)

        return self._parse_yaml(raw)

    def _parse_yaml(self, raw):
        """
        Parse the YAML document into a flat list of custom rule dicts.

        Two shapes are accepted:
          1. {"rules": [ {id, name, pattern, severity, ...}, ... ]} (current)
          2. legacy multi-document AST rules (function_call style) which
             carry no regex 'pattern' — those are skipped, they cannot be
             evaluated by the regex engine.
        Duplicated top-level 'language'/'rules' keys collapse to a single
        rules list under safe_load.
        """
        if not raw:
            return []

        documents = raw if isinstance(raw, list) else [raw]
        rules = []
        seen_ids = set()

        for doc in documents:
            if not isinstance(doc, dict):
                continue
            for entry in doc.get("rules", []) or []:
                if not isinstance(entry, dict):
                    continue
                rule = self._normalize_loaded(entry)
                if rule is None:
                    continue
                if rule["id"] in seen_ids:
                    continue
                seen_ids.add(rule["id"])
                rules.append(rule)

        return rules

    def _normalize_loaded(self, entry):
        """Coerce a persisted rule into the canonical schema, or skip it."""
        rule_id = entry.get("id")
        pattern = entry.get("pattern")
        if not rule_id or not isinstance(pattern, str):
            # Legacy AST-style rule without a regex pattern: not evaluable
            # by the pattern engine, ignore it rather than crashing startup.
            return None

        severity = entry.get("severity", "medium")
        if isinstance(severity, str):
            severity = severity.lower()
        if severity not in VALID_SEVERITIES:
            severity = "medium"

        try:
            re.compile(pattern)
        except re.error:
            logger.warning("Skipping rule %s: invalid regex", rule_id)
            return None

        return {
            "id": str(rule_id),
            "name": str(entry.get("name", rule_id)),
            "pattern": pattern,
            "severity": severity,
            "language": str(entry.get("language", "python")).lower(),
            "description": str(entry.get("description", "")),
            "enabled": bool(entry.get("enabled", True)),
            "source": "custom",
        }

    def reload(self, force=False):
        """Reload rules from disk when the file's mtime has changed."""
        with self._cache_lock:
            try:
                mtime = os.path.getmtime(self.rules_path)
            except OSError:
                mtime = None

            if not force and mtime == self._mtime and self._custom_rules:
                return self._custom_rules

            try:
                rules = self._read_file_locked()
            except yaml.YAMLError as exc:
                logger.error("Failed to parse %s: %s", self.rules_path, exc)
                return self._custom_rules

            self._custom_rules = rules
            self._mtime = mtime
            logger.info("Loaded %d custom rule(s) from %s", len(rules),
                        self.rules_path)
            return self._custom_rules

    # ------------------------------------------------------------- accessors

    def get_custom_rules(self):
        """Return a deep-copied snapshot of custom rules (hot-reload aware)."""
        with self._cache_lock:
            self.reload()
            return copy.deepcopy(self._custom_rules)

    def get_enabled_custom_rules(self):
        """Snapshot of enabled custom rules for a scan."""
        return [r for r in self.get_custom_rules() if r["enabled"]]

    def get_builtin_rules(self):
        """
        Expose the code-defined patterns from utils.vulnerability_patterns
        as read-only rule dicts.
        """
        from utils.vulnerability_patterns import get_vulnerability_patterns

        builtin = []
        for language, patterns in get_vulnerability_patterns().items():
            for index, pattern_info in enumerate(patterns):
                severity = str(
                    pattern_info.get("default_severity", "Medium")
                ).lower()
                # Deterministic, stable across restarts (never use hash(),
                # which is salted per interpreter process).
                builtin.append({
                    "id": f"BUILTIN-{language.upper()}-{index:03d}",
                    "name": pattern_info.get("type", "Built-in rule"),
                    "pattern": pattern_info["pattern"],
                    "severity": severity if severity in VALID_SEVERITIES else "medium",
                    "language": language,
                    "description": pattern_info.get("description", ""),
                    "enabled": True,
                    "source": "builtin",
                })
        return builtin

    def list_rules(self):
        """All rules (builtin first, then custom) for the API."""
        return self.get_builtin_rules() + self.get_custom_rules()

    def find_rule(self, rule_id):
        """Find a rule by id across builtin and custom sets."""
        for rule in self.get_builtin_rules():
            if rule["id"] == rule_id:
                return rule
        for rule in self.get_custom_rules():
            if rule["id"] == rule_id:
                return rule
        return None

    # -------------------------------------------------------------- mutation

    def add_rule(self, payload):
        """Validate and persist a new custom rule. Returns the stored dict."""
        normalized = validate_rule_payload(payload)

        with self._write_lock:
            rules = self._read_file_locked()
            existing_ids = {r["id"] for r in rules}

            rule_id = payload.get("id")
            if rule_id is not None:
                if not isinstance(rule_id, str) or not rule_id.strip():
                    raise RuleValidationError("'id' must be a non-empty string")
                rule_id = rule_id.strip()
            else:
                rule_id = self._generate_id(rules, normalized["name"])

            if rule_id in existing_ids:
                raise RuleValidationError(f"rule id '{rule_id}' already exists")
            if self.find_rule(rule_id) is not None:
                raise RuleValidationError(f"rule id '{rule_id}' already exists")

            rule = {
                "id": rule_id,
                "source": "custom",
                "enabled": bool(payload.get("enabled", True)),
                **normalized,
            }
            rules.append(rule)
            self._write_rules(rules)
            logger.info("Added custom rule %s", rule_id)
            return copy.deepcopy(rule)

    def set_enabled(self, rule_id, enabled):
        """Toggle a custom rule's enabled flag. Built-in rules are protected."""
        if not isinstance(enabled, bool):
            raise RuleValidationError("'enabled' must be a boolean")

        with self._write_lock:
            rules = self._read_file_locked()
            for rule in rules:
                if rule["id"] == rule_id:
                    rule["enabled"] = enabled
                    self._write_rules(rules)
                    logger.info("Rule %s enabled=%s", rule_id, enabled)
                    return copy.deepcopy(rule)

            if self.find_rule(rule_id) is not None:
                raise BuiltinRuleError(
                    f"rule '{rule_id}' is built-in and cannot be modified"
                )
            raise KeyError(rule_id)

    def delete_rule(self, rule_id):
        """Remove a custom rule. Built-in rules are protected."""
        with self._write_lock:
            rules = self._read_file_locked()
            for index, rule in enumerate(rules):
                if rule["id"] == rule_id:
                    removed = rules.pop(index)
                    self._write_rules(rules)
                    logger.info("Deleted custom rule %s", rule_id)
                    return copy.deepcopy(removed)

            if self.find_rule(rule_id) is not None:
                raise BuiltinRuleError(
                    f"rule '{rule_id}' is built-in and cannot be deleted"
                )
            raise KeyError(rule_id)

    # ------------------------------------------------------------- internals

    def _generate_id(self, rules, name):
        slug = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").upper()
        if not slug:
            slug = "CUSTOM"
        base = f"CUSTOM-{slug}"
        candidate = base
        counter = 1
        existing = {r["id"] for r in rules}
        while candidate in existing:
            counter += 1
            candidate = f"{base}-{counter}"
        return candidate

    def _write_rules(self, rules):
        """
        Persist rules atomically:

          1. write to a temp file in the same directory
          2. flush + fsync
          3. os.replace() onto the target (atomic on both Windows and POSIX)

        The whole read-modify-write happens under _write_lock plus the
        OS-level sidecar lock so concurrent writers cannot interleave and
        corrupt the YAML.
        """
        directory = os.path.dirname(os.path.abspath(self.rules_path))
        os.makedirs(directory, exist_ok=True)

        with self._file_lock():
            tmp_fd, tmp_path = tempfile.mkstemp(
                prefix=".custom_rules.", suffix=".tmp", dir=directory
            )
            try:
                with os.fdopen(tmp_fd, "w", encoding="utf-8") as tmp_fh:
                    yaml.safe_dump(
                        {"rules": rules},
                        tmp_fh,
                        default_flow_style=False,
                        allow_unicode=True,
                        sort_keys=False,
                    )
                    tmp_fh.flush()
                    os.fsync(tmp_fh.fileno())
                os.replace(tmp_path, self.rules_path)
            except BaseException:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                raise

        # Refresh the in-process cache immediately.
        with self._cache_lock:
            self._custom_rules = copy.deepcopy(rules)
            try:
                self._mtime = os.path.getmtime(self.rules_path)
            except OSError:
                self._mtime = None


# Process-wide singleton used by both the Flask API and the analyzer.
_store = None
_store_lock = threading.Lock()


def get_rule_store(rules_path=DEFAULT_RULES_PATH):
    """Return the process-wide RuleStore singleton."""
    global _store
    with _store_lock:
        if _store is None:
            _store = RuleStore(rules_path)
        return _store
