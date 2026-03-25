#!/usr/bin/env python3
"""OpenClaw exec secret provider backed by 1Password.

CLI modes
- --path <SECRET_ID>             Print only the final 1Password field reference.
- --path <SECRET_ID> --debug     Print JSON debug information for path resolution.
- --resolve <SECRET_ID>          Print only the resolved secret value.
- --resolve <SECRET_ID> --debug  Print JSON debug information plus the value.
- --resolve                      Read stdin; if it's JSON with `ids`, resolve the whole batch. Otherwise extract a single secret id, or treat stdin as the raw secret id string.

Provider mode
- Reads OpenClaw exec secret provider JSON requests from stdin and returns
  resolved values on stdout.

Design goals
- Avoid full-item reads for resolution.
- Use strict `op item get --fields ... --format json` lookups.
- Prefer custom label lookup for the mapping field named `Mapping`.
- Resolve the final field reference from the filtered field object returned by
  1Password, then use `op read <reference>` for the actual value.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from typing import Any

PROTOCOL_VERSION = 1
OP_BIN = os.environ.get("OPENCLAW_OP_BIN", "/usr/bin/op")
VAULT = os.environ.get("OPENCLAW_OP_VAULT", "OpenClaw")
ALIASES_ITEM = os.environ.get("OPENCLAW_OP_ALIASES_ITEM", "1Password Aliases")
RESOLVER_CACHE_TTL_SECONDS = int(os.environ.get("OPENCLAW_OP_RESOLVER_CACHE_TTL_SECONDS", "300"))
RESOLVER_CACHE_MAX_STALE_SECONDS = int(os.environ.get("OPENCLAW_OP_RESOLVER_CACHE_MAX_STALE_SECONDS", "86400"))
RESOLVER_CACHE_REFRESH_THROTTLE_SECONDS = int(os.environ.get("OPENCLAW_OP_RESOLVER_CACHE_REFRESH_THROTTLE_SECONDS", "30"))

PROFILE_RE = re.compile(
    r"^profiles\.([A-Za-z0-9_-]+):([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$"
)
CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
NON_WORD_RE = re.compile(r"[-_]+")
BUILTIN_FIELD_IDS = {
    "notesPlain",
    "username",
    "password",
    "credential",
    "type",
    "filename",
    "validFrom",
    "expires",
    "hostname",
}


class ResolverError(Exception):
    pass


@dataclass(frozen=True)
class ResolvedTarget:
    secret_id: str
    item_label: str
    selector: str
    type_query: str
    type_reference: str | None
    type_mapping: dict[str, str]
    type_error: str | None
    mapped_field: str
    field_query: str | None
    field_reference: str | None
    cache_state: str | None = None
    cache_age_seconds: int | None = None


class OnePasswordResolver:
    def __init__(self, op_bin: str = OP_BIN, vault: str = VAULT, aliases_item: str = ALIASES_ITEM):
        self.op_bin = op_bin
        self.vault = vault
        self.aliases_item = aliases_item
        self._alias_cache: dict[str, str | None] = {}
        self._aliases_loaded = False
        self._type_cache: dict[str, tuple[dict[str, str], str | None, str | None]] = {}
        self._field_cache: dict[tuple[str, str], dict[str, Any] | None] = {}
        self._cache_path = self._resolve_cache_path()

    @staticmethod
    def _resolve_cache_path() -> str | None:
        explicit = os.environ.get("OPENCLAW_OP_RESOLVER_CACHE_PATH", "").strip()
        if explicit:
            return explicit
        xdg_cache_home = os.environ.get("XDG_CACHE_HOME", "").strip()
        if xdg_cache_home:
            return os.path.join(xdg_cache_home, "openclaw", "1password-resolver-cache.json")
        home = os.environ.get("HOME", "").strip()
        if home:
            return os.path.join(home, ".cache", "openclaw", "1password-resolver-cache.json")
        uid = os.getuid() if hasattr(os, "getuid") else 0
        return os.path.join("/tmp", f"openclaw-1password-resolver-{uid}.json")

    def _load_persistent_cache(self) -> dict[str, Any]:
        if not self._cache_path:
            return {"entries": {}, "aliases": None}
        try:
            with open(self._cache_path, encoding="utf-8") as handle:
                payload = json.load(handle)
            if isinstance(payload, dict):
                if not isinstance(payload.get("entries"), dict):
                    payload["entries"] = {}
                if "aliases" not in payload:
                    payload["aliases"] = None
                return payload
        except FileNotFoundError:
            pass
        except Exception:
            pass
        return {"entries": {}, "aliases": None}

    def _save_persistent_cache(self, payload: dict[str, Any]) -> None:
        if not self._cache_path:
            return
        cache_dir = os.path.dirname(self._cache_path)
        if cache_dir:
            os.makedirs(cache_dir, mode=0o700, exist_ok=True)
        tmp_path = f"{self._cache_path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"))
        os.replace(tmp_path, self._cache_path)
        try:
            os.chmod(self._cache_path, 0o600)
        except OSError:
            pass

    def _serialize_target_for_cache(self, target: ResolvedTarget) -> dict[str, Any]:
        return {
            "secret_id": target.secret_id,
            "item_label": target.item_label,
            "selector": target.selector,
            "type_query": target.type_query,
            "type_reference": target.type_reference,
            "type_mapping": target.type_mapping,
            "type_error": target.type_error,
            "mapped_field": target.mapped_field,
            "field_query": target.field_query,
            "field_reference": target.field_reference,
        }

    def _cache_entry_to_target(self, secret_id: str, entry: dict[str, Any], cache_state: str, cache_age_seconds: int) -> ResolvedTarget | None:
        target = entry.get("target")
        if not isinstance(target, dict):
            return None
        try:
            return ResolvedTarget(
                secret_id=str(target.get("secret_id") or secret_id),
                item_label=str(target["item_label"]),
                selector=str(target["selector"]),
                type_query=str(target.get("type_query") or "label=Mapping"),
                type_reference=target.get("type_reference") if isinstance(target.get("type_reference"), str) else None,
                type_mapping={str(k): str(v) for k, v in dict(target.get("type_mapping") or {}).items()},
                type_error=target.get("type_error") if isinstance(target.get("type_error"), str) else None,
                mapped_field=str(target["mapped_field"]),
                field_query=target.get("field_query") if isinstance(target.get("field_query"), str) else None,
                field_reference=target.get("field_reference") if isinstance(target.get("field_reference"), str) else None,
                cache_state=cache_state,
                cache_age_seconds=cache_age_seconds,
            )
        except Exception:
            return None

    def _get_cached_target(self, secret_id: str) -> ResolvedTarget | None:
        payload = self._load_persistent_cache()
        entries = payload.get("entries") if isinstance(payload, dict) else None
        if not isinstance(entries, dict):
            return None
        entry = entries.get(secret_id)
        if not isinstance(entry, dict):
            return None
        updated_at = entry.get("updated_at")
        if not isinstance(updated_at, (int, float)):
            return None
        age = max(0, int(time.time() - float(updated_at)))
        if age <= RESOLVER_CACHE_TTL_SECONDS:
            return self._cache_entry_to_target(secret_id, entry, "fresh", age)
        if age <= RESOLVER_CACHE_TTL_SECONDS + RESOLVER_CACHE_MAX_STALE_SECONDS:
            return self._cache_entry_to_target(secret_id, entry, "stale", age)
        return None

    def _store_cached_target(self, target: ResolvedTarget) -> None:
        if target.type_error or not target.field_reference:
            return
        payload = self._load_persistent_cache()
        entries = payload.setdefault("entries", {})
        if not isinstance(entries, dict):
            payload["entries"] = {}
            entries = payload["entries"]
        entries[target.secret_id] = {
            "updated_at": int(time.time()),
            "last_refresh_started_at": None,
            "target": self._serialize_target_for_cache(target),
        }
        self._save_persistent_cache(payload)

    def _mark_refresh_started(self, secret_id: str) -> bool:
        payload = self._load_persistent_cache()
        entries = payload.get("entries") if isinstance(payload, dict) else None
        if not isinstance(entries, dict):
            return False
        entry = entries.get(secret_id)
        if not isinstance(entry, dict):
            return False
        now = int(time.time())
        last_refresh_started_at = entry.get("last_refresh_started_at")
        if isinstance(last_refresh_started_at, (int, float)) and now - int(last_refresh_started_at) < RESOLVER_CACHE_REFRESH_THROTTLE_SECONDS:
            return False
        entry["last_refresh_started_at"] = now
        self._save_persistent_cache(payload)
        return True

    def _schedule_background_refresh(self, secret_id: str) -> None:
        if not self._cache_path:
            return
        if not self._mark_refresh_started(secret_id):
            return
        try:
            subprocess.Popen(
                [sys.executable, os.path.abspath(__file__), "--refresh-cache", secret_id],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=os.environ.copy(),
                start_new_session=True,
                close_fds=True,
            )
        except Exception:
            pass

    def _get_cached_aliases(self) -> tuple[dict[str, str] | None, str | None, int | None]:
        payload = self._load_persistent_cache()
        aliases_entry = payload.get("aliases") if isinstance(payload, dict) else None
        if not isinstance(aliases_entry, dict):
            return None, None, None
        updated_at = aliases_entry.get("updated_at")
        values = aliases_entry.get("values")
        if not isinstance(updated_at, (int, float)) or not isinstance(values, dict):
            return None, None, None
        normalized = {str(k): str(v) for k, v in values.items() if isinstance(k, str) and isinstance(v, str)}
        age = max(0, int(time.time() - float(updated_at)))
        if age <= RESOLVER_CACHE_TTL_SECONDS:
            return normalized, "fresh", age
        if age <= RESOLVER_CACHE_TTL_SECONDS + RESOLVER_CACHE_MAX_STALE_SECONDS:
            return normalized, "stale", age
        return None, None, None

    def _store_cached_aliases(self, aliases: dict[str, str]) -> None:
        payload = self._load_persistent_cache()
        payload["aliases"] = {
            "updated_at": int(time.time()),
            "last_refresh_started_at": None,
            "values": aliases,
        }
        self._save_persistent_cache(payload)

    def _mark_alias_refresh_started(self) -> bool:
        payload = self._load_persistent_cache()
        aliases_entry = payload.get("aliases") if isinstance(payload, dict) else None
        if not isinstance(aliases_entry, dict):
            return False
        now = int(time.time())
        last_refresh_started_at = aliases_entry.get("last_refresh_started_at")
        if isinstance(last_refresh_started_at, (int, float)) and now - int(last_refresh_started_at) < RESOLVER_CACHE_REFRESH_THROTTLE_SECONDS:
            return False
        aliases_entry["last_refresh_started_at"] = now
        self._save_persistent_cache(payload)
        return True

    def _schedule_alias_refresh(self) -> None:
        if not self._cache_path:
            return
        if not self._mark_alias_refresh_started():
            return
        try:
            subprocess.Popen(
                [sys.executable, os.path.abspath(__file__), "--refresh-aliases"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=os.environ.copy(),
                start_new_session=True,
                close_fds=True,
            )
        except Exception:
            pass

    def _run_op(self, args: list[str], *, optional: bool = False) -> str | None:
        proc = subprocess.run(
            [self.op_bin, *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            if optional:
                return None
            stderr = (proc.stderr or "").strip()
            stdout = (proc.stdout or "").strip()
            detail = stderr or stdout or f"op exited with code {proc.returncode}"
            raise ResolverError(detail)
        return (proc.stdout or "").strip()

    def _read_op_ref(self, ref: str, *, optional: bool = False) -> str | None:
        return self._run_op(["read", ref], optional=optional)

    @staticmethod
    def _titleize(value: str) -> str:
        spaced = CAMEL_BOUNDARY_RE.sub(" ", value)
        spaced = NON_WORD_RE.sub(" ", spaced)
        words = [word for word in spaced.split() if word]
        if not words:
            return value
        return " ".join(word[:1].upper() + word[1:] for word in words)

    @staticmethod
    def _coerce_field_value(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value.strip()
        return json.dumps(value, separators=(",", ":"))

    @staticmethod
    def _escape_field_selector(value: str) -> str:
        return value.replace("\\", "\\\\").replace(".", "\\.").replace("=", "\\=")

    @staticmethod
    def _split_selector(secret_id: str) -> tuple[list[str], str]:
        parts = secret_id.split(".")
        if len(parts) < 2:
            raise ResolverError(f"unsupported secret id: {secret_id}")
        return parts[:-1], parts[-1]

    def _get_field_object(self, item_label: str, field_query: str, *, optional: bool = False) -> dict[str, Any] | None:
        cache_key = (item_label, field_query)
        if cache_key in self._field_cache:
            return self._field_cache[cache_key]

        raw = self._run_op(
            ["item", "get", "--vault", self.vault, item_label, "--fields", field_query, "--format", "json"],
            optional=optional,
        )
        if raw is None:
            self._field_cache[cache_key] = None
            return None

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ResolverError(
                f"field query '{field_query}' for item '{item_label}' did not return valid JSON: {exc}"
            ) from exc

        if not isinstance(payload, dict):
            raise ResolverError(f"field query '{field_query}' for item '{item_label}' did not return a JSON object")

        selector, _, wanted = field_query.partition("=")
        wanted = wanted.strip()

        def matches_query(field: dict[str, Any]) -> bool:
            if selector == "label":
                name = field.get("label")
            elif selector == "id":
                name = field.get("id")
            elif selector == "title":
                name = field.get("title")
            else:
                name = None
            return isinstance(name, str) and name.strip() == wanted

        field: dict[str, Any] | None = None

        if "fields" in payload:
            fields = payload.get("fields", [])
            if isinstance(fields, list):
                for candidate in fields:
                    if isinstance(candidate, dict) and matches_query(candidate):
                        field = candidate
                        break
                if field is None:
                    for candidate in fields:
                        if isinstance(candidate, dict):
                            field = candidate
                            break
        elif matches_query(payload) or any(key in payload for key in ("reference", "value", "label", "id")):
            field = payload

        if field is None:
            if optional:
                self._field_cache[cache_key] = None
                return None
            raise ResolverError(f"field query '{field_query}' returned no usable field for item '{item_label}'")

        self._field_cache[cache_key] = field
        return field

    def _read_field_value(self, item_label: str, field_query: str, *, optional: bool = False) -> tuple[str | None, str | None]:
        field = self._get_field_object(item_label, field_query, optional=optional)
        if field is None:
            return None, None

        reference = field.get("reference")
        if isinstance(reference, str) and reference.strip():
            value = self._read_op_ref(reference.strip(), optional=True)
            if value not in (None, ""):
                return value, reference.strip()

        value = self._coerce_field_value(field.get("value"))
        if value and value != "REDACTED":
            return value, reference.strip() if isinstance(reference, str) and reference.strip() else None
        if optional:
            return None, reference.strip() if isinstance(reference, str) and reference.strip() else None
        raise ResolverError(f"field query '{field_query}' on item '{item_label}' is empty or unreadable")

    def _load_aliases(self) -> None:
        if self._aliases_loaded:
            return

        cached_aliases, cache_state, _cache_age = self._get_cached_aliases()
        if cached_aliases is not None:
            self._alias_cache = cached_aliases
            self._aliases_loaded = True
            if cache_state == "stale":
                self._schedule_alias_refresh()
            return

        raw = self._run_op(
            ["item", "get", "--vault", self.vault, self.aliases_item, "--format", "json"],
            optional=False,
        )
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ResolverError(f"alias item '{self.aliases_item}' did not return valid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise ResolverError(f"alias item '{self.aliases_item}' did not return a JSON object")
        aliases: dict[str, str] = {}
        fields = payload.get("fields", [])
        if isinstance(fields, list):
            for field in fields:
                if not isinstance(field, dict):
                    continue
                label = field.get("label")
                if not isinstance(label, str) or not label.strip():
                    continue
                value = self._coerce_field_value(field.get("value"))
                if value and value != "REDACTED":
                    aliases[label.strip()] = value
        self._alias_cache = aliases
        self._aliases_loaded = True
        self._store_cached_aliases(aliases)

    def _lookup_alias(self, key: str) -> str | None:
        if not self._aliases_loaded:
            self._load_aliases()
        value = self._alias_cache.get(key)
        return value.strip() if isinstance(value, str) and value.strip() else None

    def _alias_or_default(self, candidates: list[str], fallback: str) -> str:
        for key in candidates:
            value = self._lookup_alias(key)
            if value:
                return value
        return fallback

    def _normalize_segment(self, segment: str, *, scope: str | None = None) -> str:
        fallback = self._titleize(segment)
        candidates: list[str] = []
        if scope:
            candidates.append(f"{scope}.{segment}")
        candidates.append(segment)
        return self._alias_or_default(candidates, fallback)

    def _resolve_target_parts(self, secret_id: str) -> tuple[str, str]:
        profile_match = PROFILE_RE.fullmatch(secret_id)
        if profile_match:
            provider, profile, selector = profile_match.groups()
            provider_label = self._alias_or_default(
                [f"provider.{provider}", provider],
                self._titleize(provider),
            )
            return f"{provider_label} ({profile})", selector

        stem_parts, selector = self._split_selector(secret_id)

        if stem_parts[:2] == ["gateway", "auth"] and len(stem_parts) == 2:
            item_label = self._alias_or_default(["item.gateway.auth", "gateway.auth"], "Gateway Auth")
            return item_label, selector

        if len(stem_parts) >= 4 and stem_parts[:2] == ["plugins", "entries"] and "config" in stem_parts[3:]:
            plugin = stem_parts[2]
            config_index = stem_parts.index("config")
            path_parts = stem_parts[config_index + 1 :]
            item_parts = [self._normalize_segment(plugin, scope="plugin")]
            item_parts.extend(self._normalize_segment(part, scope="path") for part in path_parts)
            return " ".join(part for part in item_parts if part), selector

        if len(stem_parts) >= 3 and stem_parts[:2] == ["skills", "entries"]:
            skill = stem_parts[2]
            extra_parts = stem_parts[3:]
            if extra_parts[:1] == ["config"]:
                extra_parts = extra_parts[1:]
            item_parts = [self._normalize_segment(skill, scope="skill")]
            item_parts.extend(self._normalize_segment(part, scope="path") for part in extra_parts)
            return " ".join(part for part in item_parts if part), selector

        fallback_label = self._alias_or_default(
            [f"item.{'.'.join(stem_parts)}", ".".join(stem_parts)],
            " ".join(self._titleize(part) for part in stem_parts),
        )
        return fallback_label, selector

    @staticmethod
    def _parse_mapping(raw: str | None) -> dict[str, str]:
        if raw is None:
            return {}
        text = raw.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                out: dict[str, str] = {}
                for key, value in parsed.items():
                    if isinstance(key, str) and isinstance(value, str) and key.strip() and value.strip():
                        out[key.strip()] = value.strip()
                return out
        except json.JSONDecodeError:
            pass
        out: dict[str, str] = {}
        normalized = text.replace("\n", ",")
        for chunk in normalized.split(","):
            part = chunk.strip()
            if not part or "=" not in part:
                continue
            key, value = part.split("=", 1)
            key = key.strip()
            value = value.strip()
            if key and value:
                out[key] = value
        return out

    @staticmethod
    def _looks_like_missing_type_error(message: str) -> bool:
        normalized = message.lower()
        markers = [
            "not found",
            "returned no fields",
            "no usable field",
            "no such",
        ]
        return any(marker in normalized for marker in markers)

    def _resolve_type_mapping(self, item_label: str) -> tuple[dict[str, str], str | None, str | None]:
        if item_label in self._type_cache:
            return self._type_cache[item_label]

        type_query = f"label={self._escape_field_selector('Mapping')}"
        try:
            raw, type_reference = self._read_field_value(item_label, type_query, optional=False)
        except ResolverError as exc:
            if self._looks_like_missing_type_error(str(exc)):
                result = ({}, None, None)
                self._type_cache[item_label] = result
                return result
            result = ({}, None, str(exc))
            self._type_cache[item_label] = result
            return result

        mapping = self._parse_mapping(raw)
        result = (mapping, type_reference, None)
        self._type_cache[item_label] = result
        return result

    def _resolve_field_reference(self, item_label: str, mapped_field: str) -> tuple[str | None, str | None]:
        queries = [f"id={mapped_field}"] if mapped_field in BUILTIN_FIELD_IDS else []
        queries.append(f"label={self._escape_field_selector(mapped_field)}")
        if mapped_field not in BUILTIN_FIELD_IDS:
            queries.append(f"id={mapped_field}")

        seen: set[str] = set()
        for query in queries:
            if query in seen:
                continue
            seen.add(query)
            field = self._get_field_object(item_label, query, optional=True)
            if not isinstance(field, dict):
                continue
            reference = field.get("reference")
            if isinstance(reference, str) and reference.strip():
                return query, reference.strip()
        return None, None

    def _resolve_target_live(self, secret_id: str) -> ResolvedTarget:
        item_label, selector = self._resolve_target_parts(secret_id)
        type_mapping, type_reference, type_error = self._resolve_type_mapping(item_label)
        mapped_field = type_mapping.get(selector, selector)
        field_query, field_reference = self._resolve_field_reference(item_label, mapped_field)
        return ResolvedTarget(
            secret_id=secret_id,
            item_label=item_label,
            selector=selector,
            type_query=f"label={self._escape_field_selector('Mapping')}",
            type_reference=type_reference,
            type_mapping=type_mapping,
            type_error=type_error,
            mapped_field=mapped_field,
            field_query=field_query,
            field_reference=field_reference,
            cache_state="miss",
            cache_age_seconds=0,
        )

    def resolve_target(self, secret_id: str) -> ResolvedTarget:
        cached = self._get_cached_target(secret_id)
        if cached is not None:
            if cached.cache_state == "stale":
                self._schedule_background_refresh(secret_id)
            return cached
        target = self._resolve_target_live(secret_id)
        if not target.type_error and target.field_reference:
            self._store_cached_target(target)
        return target

    def _resolve_reference_live(self, secret_id: str) -> ResolvedTarget:
        target = self._resolve_target_live(secret_id)
        if target.type_error:
            raise ResolverError(f"failed to resolve Mapping field: {target.type_error}")
        if not target.field_reference:
            raise ResolverError(
                f"could not resolve final field reference for '{target.mapped_field}' on item '{target.item_label}'"
            )
        self._store_cached_target(target)
        return target

    def resolve_reference(self, secret_id: str) -> ResolvedTarget:
        target = self.resolve_target(secret_id)
        if target.type_error:
            raise ResolverError(f"failed to resolve Mapping field: {target.type_error}")
        if not target.field_reference:
            raise ResolverError(
                f"could not resolve final field reference for '{target.mapped_field}' on item '{target.item_label}'"
            )
        return target

    def resolve_value(self, secret_id: str) -> tuple[ResolvedTarget, str]:
        target = self.resolve_reference(secret_id)
        try:
            value = self._read_op_ref(target.field_reference, optional=False)
        except ResolverError:
            if target.cache_state in {"fresh", "stale"}:
                target = self._resolve_reference_live(secret_id)
                value = self._read_op_ref(target.field_reference, optional=False)
            else:
                raise
        if value in (None, ""):
            raise ResolverError(f"no value resolved for {secret_id}")
        return target, value


def handle_provider_request(resolver: OnePasswordResolver, payload: dict[str, Any]) -> dict[str, Any]:
    ids = payload.get("ids", [])
    if not isinstance(ids, list):
        raise ResolverError("request field 'ids' must be a list")

    values: dict[str, str] = {}
    errors: dict[str, dict[str, str]] = {}

    for secret_id in ids:
        if not isinstance(secret_id, str) or not secret_id.strip():
            errors[str(secret_id)] = {"message": "secret id must be a non-empty string"}
            continue
        try:
            _, value = resolver.resolve_value(secret_id)
            values[secret_id] = value
        except Exception as exc:  # noqa: BLE001
            errors[secret_id] = {"message": str(exc)}

    response: dict[str, Any] = {"protocolVersion": PROTOCOL_VERSION, "values": values}
    if errors:
        response["errors"] = errors
    return response


def _debug_payload(target: ResolvedTarget, *, value: str | None = None) -> dict[str, Any]:
    payload = asdict(target)
    payload["ok"] = True
    if value is not None:
        payload["value"] = value
    return payload


def path_command(resolver: OnePasswordResolver, secret_id: str, debug: bool) -> int:
    try:
        target = resolver.resolve_reference(secret_id)
    except Exception as exc:  # noqa: BLE001
        if debug:
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        else:
            print(str(exc), file=sys.stderr)
        return 1

    if debug:
        print(json.dumps(_debug_payload(target), indent=2))
    else:
        print(target.field_reference)
    return 0


def resolve_command(resolver: OnePasswordResolver, secret_id: str, debug: bool) -> int:
    try:
        target, value = resolver.resolve_value(secret_id)
    except Exception as exc:  # noqa: BLE001
        if debug:
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        else:
            print(str(exc), file=sys.stderr)
        return 1

    if debug:
        print(json.dumps(_debug_payload(target, value=value), indent=2))
    else:
        print(value)
    return 0


def refresh_cache_command(resolver: OnePasswordResolver, secret_ids: list[str]) -> int:
    exit_code = 0
    for secret_id in secret_ids:
        try:
            resolver._resolve_reference_live(secret_id)
        except Exception:
            exit_code = 1
    return exit_code


def refresh_aliases_command(resolver: OnePasswordResolver) -> int:
    try:
        resolver._aliases_loaded = False
        resolver._alias_cache = {}
        resolver._load_aliases()
    except Exception:
        return 1
    return 0


def _parse_stdin_for_resolve(raw: str) -> tuple[str, str | dict[str, Any]]:
    text = raw.strip()
    if not text:
        raise ResolverError("stdin is empty; no secret id provided")

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return "single", text

    if isinstance(payload, str) and payload.strip():
        return "single", payload.strip()

    if isinstance(payload, dict):
        ids = payload.get("ids")
        if isinstance(ids, list):
            normalized_ids = [candidate.strip() for candidate in ids if isinstance(candidate, str) and candidate.strip()]
            if normalized_ids:
                return "batch", {"ids": normalized_ids}
        for key in ("secretId", "id"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return "single", value.strip()
        raise ResolverError("stdin JSON did not contain a usable secret id or ids array")

    return "single", text


def main(argv: list[str]) -> int:
    resolver = OnePasswordResolver()
    debug = "--debug" in argv[1:]
    args = [arg for arg in argv[1:] if arg != "--debug"]

    if len(args) == 2 and args[0] == "--path":
        return path_command(resolver, args[1], debug)

    if len(args) == 2 and args[0] == "--resolve":
        return resolve_command(resolver, args[1], debug)

    if len(args) >= 2 and args[0] == "--refresh-cache":
        return refresh_cache_command(resolver, [arg for arg in args[1:] if arg.strip()])

    if len(args) == 1 and args[0] == "--refresh-aliases":
        return refresh_aliases_command(resolver)

    if len(args) == 1 and args[0] == "--resolve":
        try:
            mode, payload = _parse_stdin_for_resolve(sys.stdin.read())
        except Exception as exc:  # noqa: BLE001
            if debug:
                print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
            else:
                print(str(exc), file=sys.stderr)
            return 1

        if mode == "batch":
            response = handle_provider_request(resolver, payload)
            if debug:
                pretty = {"ok": not bool(response.get("errors")), **response}
                print(json.dumps(pretty, indent=2))
            else:
                print(json.dumps(response, separators=(",", ":")))
            return 0 if not response.get("errors") else 1

        return resolve_command(resolver, str(payload), debug)

    if len(args) != 0:
        print(
            "usage: openclaw_1password_resolver.py [--path SECRET_ID | --resolve [SECRET_ID]] [--debug]",
            file=sys.stderr,
        )
        return 2

    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise ResolverError("stdin payload must be a JSON object")
        response = handle_provider_request(resolver, payload)
        json.dump(response, sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0
    except Exception as exc:  # noqa: BLE001
        json.dump(
            {
                "protocolVersion": PROTOCOL_VERSION,
                "values": {},
                "errors": {"__provider__": {"message": str(exc)}},
            },
            sys.stdout,
            separators=(",", ":"),
        )
        sys.stdout.write("\n")
        return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
