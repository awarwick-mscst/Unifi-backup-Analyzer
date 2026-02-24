from __future__ import annotations

import ipaddress
from typing import Any

from .models import AuditReport, Finding, RuleResult

SEVERITY_PENALTY = {"HIGH": 18, "MEDIUM": 9, "LOW": 4}

PROFILES = {"baseline", "cis-nist", "cis-lite", "nist-lite", "strict-enterprise"}

SCHEMA_COLLECTION_ALIASES = {
    "legacy7": {
        "users": ["admin", "user"],
        "wlans": ["wlanconf", "wlan"],
        "networks": ["networkconf", "network"],
        "devices": ["device", "stat_device"],
        "settings": ["setting", "site"],
    },
    "modern8": {
        "users": ["admin", "user", "account"],
        "wlans": ["wlanconf", "wlan", "wifi_network", "wireless_network"],
        "networks": ["networkconf", "network", "vlan", "lan_network"],
        "devices": ["device", "stat_device", "network_device", "gateway_device"],
        "settings": ["setting", "site", "system_settings", "network_settings"],
    },
}

SCHEMA_FIELD_ALIASES = {
    "legacy7": {
        "username": ["name", "username"],
        "user_role": ["role", "permissions"],
        "ssid_name": ["name", "ssid"],
        "wifi_security": ["security", "security_protocol"],
        "wpa_mode": ["wpa_mode"],
        "bands": ["wlan_bands", "bands"],
        "channel_width": ["channel_width", "ht"],
        "network_name": ["name", "_id"],
        "network_purpose": ["purpose"],
        "guest_lan_access": ["lan_access", "guest_to_lan"],
        "device_model": ["model", "type"],
        "device_state": ["state"],
    },
    "modern8": {
        "username": ["username", "name", "display_name"],
        "user_role": ["role", "permissions", "permission"],
        "ssid_name": ["ssid", "name", "display_name"],
        "wifi_security": ["security_protocol", "security", "auth_mode"],
        "wpa_mode": ["wpa_mode", "security_mode"],
        "bands": ["bands", "wlan_bands", "radio_bands"],
        "channel_width": ["channel_width", "ht", "channelization"],
        "network_name": ["name", "_id", "display_name"],
        "network_purpose": ["purpose", "type"],
        "guest_lan_access": ["guest_to_lan", "lan_access", "inter_vlan_routing"],
        "device_model": ["model", "type", "product_model", "product_name", "board_name"],
        "device_state": ["state", "status"],
    },
}


def _severity(value: str) -> str:
    value = value.upper()
    return value if value in SEVERITY_PENALTY else "LOW"


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "on", "enabled", "enable"}
    return False


def _find_collection(collections: dict[str, list[dict[str, Any]]], needles: list[str]) -> list[dict[str, Any]]:
    by_lower = {k.lower(): v for k, v in collections.items()}
    for needle in needles:
        if needle.lower() in by_lower:
            return by_lower[needle.lower()]
    for key, value in by_lower.items():
        if any(needle.lower() in key for needle in needles):
            return value
    return []


def _discover_collection_by_keys(
    collections: dict[str, list[dict[str, Any]]],
    key_markers: set[str],
    min_matches: int = 1,
) -> list[dict[str, Any]]:
    best: list[dict[str, Any]] = []
    best_score = 0
    for docs in collections.values():
        if not isinstance(docs, list) or not docs:
            continue
        score = 0
        sample = docs[: min(len(docs), 50)]
        for doc in sample:
            if not isinstance(doc, dict):
                continue
            keys = {str(k).lower() for k in doc.keys()}
            if keys & key_markers:
                score += 1
        if score > best_score and score >= min_matches:
            best_score = score
            best = docs
    return best


def _iter_nested_dicts(value: Any, depth: int = 0) -> list[dict[str, Any]]:
    if depth > 2:
        return []
    out: list[dict[str, Any]] = []
    if isinstance(value, dict):
        out.append(value)
        for nested in value.values():
            out.extend(_iter_nested_dicts(nested, depth + 1))
    elif isinstance(value, list):
        for item in value:
            out.extend(_iter_nested_dicts(item, depth + 1))
    return out


def _iter_nested_items(value: Any, prefix: str = "", depth: int = 0) -> list[tuple[str, Any]]:
    if depth > 4:
        return []
    out: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            key_s = str(key).lower()
            path = f"{prefix}.{key_s}" if prefix else key_s
            out.append((path, nested))
            out.extend(_iter_nested_items(nested, path, depth + 1))
    elif isinstance(value, list):
        for idx, nested in enumerate(value[:50]):
            path = f"{prefix}[{idx}]"
            out.extend(_iter_nested_items(nested, path, depth + 1))
    return out


def _looks_like_wlan_doc(doc: dict[str, Any]) -> bool:
    keys = {str(k).lower() for k in doc.keys()}
    if not keys:
        return False
    markers = {
        "ssid",
        "name",
        "security",
        "security_protocol",
        "auth_mode",
        "wpa_mode",
        "wlan_bands",
        "bands",
        "pmf_mode",
        "hide_ssid",
        "is_guest_open",
    }
    marker_count = len(keys & markers)
    has_ssid_like = "ssid" in keys or "name" in keys
    has_security_like = bool(keys & {"security", "security_protocol", "auth_mode", "wpa_mode"})
    return marker_count >= 2 and (has_ssid_like or has_security_like)


def _extract_wlan_candidates(
    collections: dict[str, list[dict[str, Any]]], wlans: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if wlans:
        return [w for w in wlans if isinstance(w, dict)]
    seen_ids: set[int] = set()
    candidates: list[dict[str, Any]] = []
    for docs in collections.values():
        if not isinstance(docs, list):
            continue
        for item in docs:
            for doc in _iter_nested_dicts(item):
                if not isinstance(doc, dict):
                    continue
                if not _looks_like_wlan_doc(doc):
                    continue
                marker = id(doc)
                if marker in seen_ids:
                    continue
                seen_ids.add(marker)
                candidates.append(doc)
    return candidates


def _extract_setting_candidates(
    collections: dict[str, list[dict[str, Any]]], settings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if settings:
        return [s for s in settings if isinstance(s, dict)]
    # Some backups keep settings under different collection names or nested docs.
    discovered = _discover_collection_by_keys(
        collections,
        {"upnp", "ids", "ips", "backup", "ntp", "dns", "syslog", "firmware", "ssh", "mfa", "2fa", "portal"},
        min_matches=1,
    )
    return [d for d in discovered if isinstance(d, dict)]


def _extract_network_candidates(
    collections: dict[str, list[dict[str, Any]]], networks: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if networks:
        return [n for n in networks if isinstance(n, dict)]
    discovered = _discover_collection_by_keys(
        collections,
        {"purpose", "vlan", "subnet", "dhcpd_enabled", "guest_to_lan", "inter_vlan_routing"},
        min_matches=1,
    )
    return [d for d in discovered if isinstance(d, dict)]


def _extract_device_candidates(
    collections: dict[str, list[dict[str, Any]]], devices: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if devices:
        return [d for d in devices if isinstance(d, dict)]
    discovered = _discover_collection_by_keys(
        collections,
        {"model", "type", "state", "status", "product_model", "board_name", "adopted"},
        min_matches=1,
    )
    return [d for d in discovered if isinstance(d, dict)]


def _nested_key_truthy(doc: dict[str, Any], tokens: set[str]) -> bool:
    for path, value in _iter_nested_items(doc):
        if any(token in path for token in tokens) and _truthy(value):
            return True
    return False


def _parse_network(value: Any) -> ipaddress._BaseNetwork | None:
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    try:
        return ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None


def _infer_schema(collections: dict[str, list[dict[str, Any]]]) -> str:
    keys = {k.lower() for k in collections.keys()}
    modern_markers = {"wifi_network", "wireless_network", "system_settings", "network_settings"}
    return "modern8" if any(marker in keys for marker in modern_markers) else "legacy7"


def _get_by_alias(doc: dict[str, Any], aliases: list[str], default: Any = None) -> Any:
    for alias in aliases:
        if alias in doc:
            return doc.get(alias)
    return default


def _model_get(doc: dict[str, Any], schema: str, field_name: str, default: Any = None) -> Any:
    aliases = SCHEMA_FIELD_ALIASES.get(schema, {}).get(field_name, [])
    return _get_by_alias(doc, aliases, default)


def _any_alias_truthy(doc: dict[str, Any], schema: str, field_name: str) -> bool:
    aliases = SCHEMA_FIELD_ALIASES.get(schema, {}).get(field_name, [])
    return any(_truthy(doc.get(alias)) for alias in aliases if alias in doc)


def _rule(
    *,
    rule_id: str,
    title: str,
    category: str,
    severity: str,
    status: str,
    rationale: str,
    recommendation: str,
    confidence: str,
    evidence: dict[str, Any] | None = None,
    cis_controls: list[str] | None = None,
    nist_controls: list[str] | None = None,
    references: list[str] | None = None,
) -> RuleResult:
    return RuleResult(
        rule_id=rule_id,
        title=title,
        category=category,
        severity=severity,
        status=status,
        rationale=rationale,
        recommendation=recommendation,
        confidence=confidence,
        evidence=evidence or {},
        cis_controls=cis_controls or [],
        nist_controls=nist_controls or [],
        references=references or [],
    )


def _rule_to_finding(rule: RuleResult) -> Finding:
    return Finding(
        rule_id=rule.rule_id,
        category=rule.category,
        severity=rule.severity,
        title=rule.title,
        detail=rule.rationale,
        rationale=rule.rationale,
        recommendation=rule.recommendation,
        confidence=rule.confidence,
        cis_controls=rule.cis_controls,
        nist_controls=rule.nist_controls,
        references=rule.references,
        evidence=rule.evidence,
    )


PROFILE_RULES = {
    "baseline": {
        "R-SEC-OPEN-WIFI",
        "R-SEC-LEGACY-WIFI-ENC",
        "R-SEC-GUEST-ISOLATION",
        "R-SEC-UPNP-DISABLED",
        "R-PERF-24G-20MHZ",
    },
    "cis-lite": {
        "R-SEC-OPEN-WIFI",
        "R-SEC-LEGACY-WIFI-ENC",
        "R-SEC-WIFI-PSK-PRESENT",
        "R-SEC-WPS-DISABLED",
        "R-SEC-WPA3-TRANSITION",
        "R-SEC-GUEST-ISOLATION",
        "R-SEC-UPNP-DISABLED",
        "R-IDM-ADMIN-NONDEFAULT",
        "R-IDM-ADMIN-UNIQUE-USERNAMES",
        "R-IDM-ADMIN-COUNT-MIN2",
        "R-SEC-PMF-ENABLED",
        "R-WIFI-TX-POWER-HIGH-AVOID",
        "R-PERF-24G-20MHZ",
        "R-NET-PRIVATE-SUBNETS",
        "R-RES-BACKUP-SCHEDULE",
    },
    "nist-lite": {
        "R-SEC-OPEN-WIFI",
        "R-SEC-LEGACY-WIFI-ENC",
        "R-SEC-GUEST-ISOLATION",
        "R-IDM-MFA-EVIDENCE",
        "R-SEC-UPNP-DISABLED",
        "R-IDM-ADMIN-COUNT-MIN2",
        "R-OPS-REMOTE-LOGGING-EVIDENCE",
        "R-OPS-NTP-CONFIG-EVIDENCE",
        "R-OPS-DNS-CONFIG-EVIDENCE",
        "R-RES-BACKUP-SCHEDULE",
    },
    "cis-nist": {
        "R-SEC-OPEN-WIFI",
        "R-SEC-LEGACY-WIFI-ENC",
        "R-SEC-WIFI-PSK-PRESENT",
        "R-SEC-WPS-DISABLED",
        "R-SEC-WPA3-TRANSITION",
        "R-SEC-GUEST-ISOLATION",
        "R-SEC-UPNP-DISABLED",
        "R-IDM-ADMIN-NONDEFAULT",
        "R-IDM-ADMIN-UNIQUE-USERNAMES",
        "R-IDM-MFA-EVIDENCE",
        "R-PERF-24G-20MHZ",
        "R-NET-PRIVATE-SUBNETS",
        "R-NET-DEFAULT-LAN-SUBNET-CHANGED",
        "R-RES-BACKUP-SCHEDULE",
        "R-SEC-PMF-ENABLED",
        "R-SEC-SSH-RESTRICTED",
        "R-SEC-IDS-ENABLED-EVIDENCE",
        "R-IDM-ADMIN-COUNT-MIN2",
        "R-NET-VLAN-EVIDENCE",
        "R-NET-MGMT-VLAN-EVIDENCE",
        "R-NET-FIREWALL-RULES-EVIDENCE",
        "R-RES-REMOTE-BACKUP-EVIDENCE",
        "R-OPS-REMOTE-LOGGING-EVIDENCE",
        "R-OPS-NTP-CONFIG-EVIDENCE",
        "R-OPS-DNS-CONFIG-EVIDENCE",
        "R-WIFI-BAND-STEERING-EVIDENCE",
        "R-WIFI-MIN-RSSI-EVIDENCE",
        "R-WIFI-HIDDEN-SSID-POLICY",
        "R-WIFI-TX-POWER-HIGH-AVOID",
        "R-PERF-OFFLINE-DEVICE-RATE",
        "R-PERF-IDS-USG-CAPACITY",
        "R-SEC-GUEST-PORTAL-EVIDENCE",
        "R-SEC-AP-ISOLATION-EVIDENCE",
        "R-OPS-FIRMWARE-MAINT-EVIDENCE",
        "R-OPS-FIRMWARE-VERSION-VISIBLE",
    },
    "strict-enterprise": {
        "R-SEC-OPEN-WIFI",
        "R-SEC-LEGACY-WIFI-ENC",
        "R-SEC-WIFI-PSK-PRESENT",
        "R-SEC-WPS-DISABLED",
        "R-SEC-WPA3-TRANSITION",
        "R-SEC-GUEST-ISOLATION",
        "R-SEC-UPNP-DISABLED",
        "R-IDM-ADMIN-NONDEFAULT",
        "R-IDM-ADMIN-UNIQUE-USERNAMES",
        "R-IDM-MFA-EVIDENCE",
        "R-PERF-24G-20MHZ",
        "R-NET-PRIVATE-SUBNETS",
        "R-NET-DEFAULT-LAN-SUBNET-CHANGED",
        "R-RES-BACKUP-SCHEDULE",
        "R-SEC-PMF-ENABLED",
        "R-SEC-SSH-RESTRICTED",
        "R-SEC-IDS-ENABLED-EVIDENCE",
        "R-IDM-ADMIN-COUNT-MIN2",
        "R-NET-VLAN-EVIDENCE",
        "R-NET-MGMT-VLAN-EVIDENCE",
        "R-NET-FIREWALL-RULES-EVIDENCE",
        "R-RES-REMOTE-BACKUP-EVIDENCE",
        "R-OPS-REMOTE-LOGGING-EVIDENCE",
        "R-OPS-NTP-CONFIG-EVIDENCE",
        "R-OPS-DNS-CONFIG-EVIDENCE",
        "R-WIFI-BAND-STEERING-EVIDENCE",
        "R-WIFI-MIN-RSSI-EVIDENCE",
        "R-WIFI-HIDDEN-SSID-POLICY",
        "R-WIFI-TX-POWER-HIGH-AVOID",
        "R-PERF-OFFLINE-DEVICE-RATE",
        "R-PERF-IDS-USG-CAPACITY",
        "R-SEC-GUEST-PORTAL-EVIDENCE",
        "R-SEC-AP-ISOLATION-EVIDENCE",
        "R-OPS-FIRMWARE-MAINT-EVIDENCE",
        "R-OPS-FIRMWARE-VERSION-VISIBLE",
    },
}

PROFILE_MINIMUMS: dict[str, dict[str, int]] = {
    "strict-enterprise": {"max_fail": 0, "max_unknown": 0},
}


def run_checks(backup_path: str, collections: dict[str, list[dict[str, Any]]], profile: str = "baseline") -> AuditReport:
    if profile not in PROFILES:
        profile = "baseline"
    if profile == "cis-nist":
        # alias to explicit rule set
        profile = "cis-nist"

    schema = _infer_schema(collections)
    aliases = SCHEMA_COLLECTION_ALIASES.get(schema, SCHEMA_COLLECTION_ALIASES["legacy7"])

    users = _find_collection(collections, aliases["users"])
    wlans = _find_collection(collections, aliases["wlans"])
    networks = _find_collection(collections, aliases["networks"])
    devices = _find_collection(collections, aliases["devices"])
    settings = _find_collection(collections, aliases["settings"])

    # Compatibility fallback: for schema variants where collection names differ,
    # discover likely collections by document key signatures.
    if not wlans:
        wlans = _discover_collection_by_keys(
            collections,
            {"ssid", "wpa_mode", "security", "security_protocol", "wlan_bands", "hide_ssid"},
            min_matches=2,
        )
    if not networks:
        networks = _discover_collection_by_keys(
            collections,
            {"purpose", "vlan", "subnet", "dhcpd_enabled", "networkgroup", "guest_to_lan"},
            min_matches=2,
        )
    if not users:
        users = _discover_collection_by_keys(
            collections,
            {"username", "name", "role", "permissions", "super_admin"},
            min_matches=1,
        )
    if not settings:
        settings = _discover_collection_by_keys(
            collections,
            {"upnp_enabled", "ids_enabled", "ips_enabled", "backup", "ntp", "dns"},
            min_matches=1,
        )
    setting_candidates = _extract_setting_candidates(collections, settings)
    wlan_candidates_debug = _extract_wlan_candidates(collections, wlans)
    network_candidates = _extract_network_candidates(collections, networks)
    device_candidates = _extract_device_candidates(collections, devices)

    rules: list[RuleResult] = []
    enabled = PROFILE_RULES.get(profile, PROFILE_RULES["baseline"])

    if "R-SEC-OPEN-WIFI" in enabled:
        open_ssids = []
        evaluable_count = 0
        for wlan in wlan_candidates_debug:
            if not isinstance(wlan, dict):
                continue
            sec_raw = _model_get(wlan, schema, "wifi_security", "")
            if not sec_raw:
                sec_raw = _get_by_alias(
                    wlan,
                    ["encryption", "security_type", "auth", "auth_mode", "wpa_mode", "wpa"],
                    "",
                )
            sec = str(sec_raw or "").lower()
            passphrase = _get_by_alias(wlan, ["x_passphrase", "passphrase", "psk", "password"], "")
            explicit_open = sec in {"open", "none", "noauth", "disabled"}
            open_flag = any(_truthy(wlan.get(k)) for k in ("is_guest_open", "open", "no_auth"))
            if sec or str(passphrase).strip():
                evaluable_count += 1
            is_open = explicit_open or open_flag
            if is_open:
                open_ssids.append(str(_model_get(wlan, schema, "ssid_name", "<unknown>") or "<unknown>"))
        if open_ssids:
            status = "fail"
        elif wlan_candidates_debug:
            status = "pass"
        else:
            status = "unknown"
        rules.append(
            _rule(
                rule_id="R-SEC-OPEN-WIFI",
                title="No Open WiFi Networks",
                category="security",
                severity="HIGH",
                status=status,
                rationale=(
                    f"Open SSIDs detected: {', '.join(open_ssids)}"
                    if open_ssids
                    else (
                        "No open SSIDs detected."
                        if wlan_candidates_debug
                        else "No WLAN data available in backup."
                    )
                ),
                recommendation="Require WPA2/WPA3 on all SSIDs; do not allow open internal networks.",
                confidence=("high" if evaluable_count else ("medium" if wlan_candidates_debug else "low")),
                evidence={
                    "open_ssids": open_ssids,
                    "wlan_count": len(wlans),
                    "wlan_candidate_count": len(wlan_candidates_debug),
                    "evaluable_wlan_count": evaluable_count,
                },
                cis_controls=["CIS 4.5"],
                nist_controls=["SC-8", "SC-13"],
                references=["https://www.nist.gov/cyberframework"],
            )
        )

    if "R-SEC-LEGACY-WIFI-ENC" in enabled:
        legacy = []
        for wlan in wlan_candidates_debug:
            if not isinstance(wlan, dict):
                continue
            sec = str(_model_get(wlan, schema, "wifi_security", "") or "").lower()
            if not sec:
                sec = str(_get_by_alias(wlan, ["encryption", "security_type", "auth_mode", "wpa_mode", "wpa"], "") or "").lower()
            if sec in {"wep", "wpa", "wpa1"}:
                legacy.append({"ssid": str(_model_get(wlan, schema, "ssid_name", "<unknown>")), "security": sec})
        status = "fail" if legacy else ("pass" if wlan_candidates_debug else "unknown")
        rules.append(
            _rule(
                rule_id="R-SEC-LEGACY-WIFI-ENC",
                title="No Legacy Wireless Encryption",
                category="security",
                severity="HIGH",
                status=status,
                rationale=(
                    f"Legacy encryption detected on {len(legacy)} SSID(s)."
                    if legacy
                    else ("No legacy encryption detected." if wlan_candidates_debug else "No WLAN data available.")
                ),
                recommendation="Use WPA2-AES at minimum; prefer WPA3/transition mode.",
                confidence="high" if wlan_candidates_debug else "low",
                evidence={"legacy_ssids": legacy},
                cis_controls=["CIS 4.5"],
                nist_controls=["SC-13"],
                references=["https://csrc.nist.gov/publications"],
            )
        )

    if "R-SEC-WIFI-PSK-PRESENT" in enabled:
        missing_psk: list[str] = []
        for wlan in wlan_candidates_debug:
            if not isinstance(wlan, dict):
                continue
            sec = str(_model_get(wlan, schema, "wifi_security", "") or "").lower()
            if not sec:
                sec = str(_get_by_alias(wlan, ["encryption", "security_type", "auth_mode", "wpa_mode", "wpa"], "") or "").lower()
            if sec in {"open", "none", "noauth", "disabled", ""}:
                continue
            if "enterprise" in sec or _truthy(wlan.get("radius_enabled")):
                continue
            passphrase = str(_get_by_alias(wlan, ["x_passphrase", "passphrase", "psk", "password"], "") or "").strip()
            if not passphrase:
                missing_psk.append(str(_model_get(wlan, schema, "ssid_name", "<unknown>") or "<unknown>"))
        status = "fail" if missing_psk else ("pass" if wlan_candidates_debug else "unknown")
        rules.append(
            _rule(
                rule_id="R-SEC-WIFI-PSK-PRESENT",
                title="Secured SSIDs Have PSK/Enterprise Auth Evidence",
                category="security",
                severity="HIGH",
                status=status,
                rationale=(
                    f"Secured SSIDs missing PSK/auth evidence: {', '.join(missing_psk)}"
                    if missing_psk
                    else ("No missing PSK/auth evidence found." if wlan_candidates_debug else "No WLAN data available.")
                ),
                recommendation="Ensure each secured SSID uses valid PSK or enterprise authentication.",
                confidence="medium" if wlan_candidates_debug else "low",
                evidence={"missing_psk_ssids": missing_psk},
                cis_controls=["CIS 4.5"],
                nist_controls=["IA-2", "SC-13"],
                references=["https://www.nist.gov/cyberframework"],
            )
        )

    if "R-SEC-WPS-DISABLED" in enabled:
        wps_enabled_ssids: list[str] = []
        for wlan in wlan_candidates_debug:
            if not isinstance(wlan, dict):
                continue
            name = str(_model_get(wlan, schema, "ssid_name", "<unknown>") or "<unknown>")
            wps_value = _get_by_alias(wlan, ["wps_enabled", "wps", "wifi_wps"], None)
            wps_mode = str(_get_by_alias(wlan, ["wps_mode"], "") or "").lower()
            if _truthy(wps_value) or wps_mode in {"enabled", "on", "1"}:
                wps_enabled_ssids.append(name)
        status = "fail" if wps_enabled_ssids else ("pass" if wlan_candidates_debug else "unknown")
        rules.append(
            _rule(
                rule_id="R-SEC-WPS-DISABLED",
                title="WPS Disabled",
                category="security",
                severity="MEDIUM",
                status=status,
                rationale=(
                    f"WPS enabled marker(s) found on: {', '.join(wps_enabled_ssids)}"
                    if wps_enabled_ssids
                    else ("No WPS enabled markers found." if wlan_candidates_debug else "No WLAN data available.")
                ),
                recommendation="Disable WPS on all SSIDs.",
                confidence="medium" if wlan_candidates_debug else "low",
                evidence={"wps_enabled_ssids": wps_enabled_ssids},
                cis_controls=["CIS 4.5"],
                nist_controls=["SC-13"],
                references=["https://www.wi-fi.org/discover-wi-fi/security"],
            )
        )

    if "R-SEC-WPA3-TRANSITION" in enabled:
        weak = []
        for wlan in wlan_candidates_debug:
            if not isinstance(wlan, dict):
                continue
            name = str(_model_get(wlan, schema, "ssid_name", "<unknown>"))
            wpa_mode = str(_model_get(wlan, schema, "wpa_mode", "") or "").lower()
            if not wpa_mode:
                wpa_mode = str(_get_by_alias(wlan, ["auth_mode", "security_mode", "security_type", "security_protocol"], "") or "").lower()
            if "wpa2" in wpa_mode and "wpa3" not in wpa_mode and not _truthy(wlan.get("wpa3_support")):
                weak.append(name)
        status = "fail" if weak else ("pass" if wlan_candidates_debug else "unknown")
        rules.append(
            _rule(
                rule_id="R-SEC-WPA3-TRANSITION",
                title="WPA3 Transition Enabled",
                category="security",
                severity="MEDIUM",
                status=status,
                rationale=(
                    f"WPA2-only SSIDs detected: {', '.join(weak)}"
                    if weak
                    else ("No WPA2-only SSIDs detected." if wlan_candidates_debug else "No WLAN data available.")
                ),
                recommendation="Enable WPA3 transition mode where client compatibility allows.",
                confidence="medium" if wlan_candidates_debug else "low",
                evidence={"wpa2_only_ssids": weak},
                cis_controls=["CIS 4.5"],
                nist_controls=["SC-13"],
                references=["https://www.wi-fi.org/discover-wi-fi/security"],
            )
        )

    if "R-SEC-GUEST-ISOLATION" in enabled:
        insecure_guest = []
        guest_seen = 0
        for net in network_candidates:
            if not isinstance(net, dict):
                continue
            purpose = str(_model_get(net, schema, "network_purpose", "") or "").lower()
            if purpose == "guest":
                guest_seen += 1
                if _any_alias_truthy(net, schema, "guest_lan_access"):
                    insecure_guest.append(str(_model_get(net, schema, "network_name", "<unknown>")))
        if insecure_guest:
            status = "fail"
        elif guest_seen > 0:
            status = "pass"
        elif network_candidates and wlan_candidates_debug:
            status = "pass"
        else:
            status = "unknown"
        rules.append(
            _rule(
                rule_id="R-SEC-GUEST-ISOLATION",
                title="Guest Networks Segmented From LAN",
                category="security",
                severity="HIGH",
                status=status,
                rationale=(
                    f"Guest-to-LAN access detected on: {', '.join(insecure_guest)}"
                    if insecure_guest
                    else (
                        "No guest-to-LAN access markers detected."
                        if guest_seen
                        else ("No guest networks detected." if network_candidates else "Guest network data unavailable.")
                    )
                ),
                recommendation="Disable guest-to-LAN and enforce VLAN/firewall isolation.",
                confidence="high" if (guest_seen or network_candidates) else "low",
                evidence={
                    "guest_networks": guest_seen,
                    "guest_lan_access_networks": insecure_guest,
                    "network_candidate_count": len(network_candidates),
                },
                cis_controls=["CIS 3.4", "CIS 12.3"],
                nist_controls=["AC-4", "SC-7"],
                references=["https://csrc.nist.gov/projects/risk-management/sp800-53-controls"],
            )
        )

    if "R-SEC-UPNP-DISABLED" in enabled:
        upnp_flags = []
        for cfg in setting_candidates:
            if not isinstance(cfg, dict):
                continue
            for key in ("upnp_enabled", "upnp_nat_pmp_enabled"):
                if _truthy(cfg.get(key)):
                    upnp_flags.append(key)
            if _nested_key_truthy(cfg, {"upnp", "nat_pmp"}):
                upnp_flags.append("nested_upnp_truthy")
        status = "fail" if upnp_flags else ("pass" if setting_candidates else "unknown")
        rules.append(
            _rule(
                rule_id="R-SEC-UPNP-DISABLED",
                title="UPnP/NAT-PMP Disabled",
                category="security",
                severity="MEDIUM",
                status=status,
                rationale=(
                    f"UPnP-related settings enabled: {', '.join(sorted(set(upnp_flags)))}"
                    if upnp_flags
                    else (
                        "No enabled UPnP/NAT-PMP markers found."
                        if setting_candidates
                        else "No settings data available."
                    )
                ),
                recommendation="Disable UPnP/NAT-PMP unless explicitly required and monitored.",
                confidence="medium" if setting_candidates else "low",
                evidence={"enabled_flags": sorted(set(upnp_flags))},
                cis_controls=["CIS 9.1"],
                nist_controls=["CM-7", "SC-7"],
                references=["https://www.cisecurity.org/controls"],
            )
        )

    if "R-IDM-ADMIN-NONDEFAULT" in enabled:
        weak_admins = []
        weak_names = {"admin", "ubnt", "root", "user"}
        admin_count = 0
        for user in users:
            if not isinstance(user, dict):
                continue
            username = str(_model_get(user, schema, "username", "") or "").strip().lower()
            role = str(_model_get(user, schema, "user_role", "") or "").lower()
            is_admin = "admin" in role or _truthy(user.get("super_admin"))
            if is_admin:
                admin_count += 1
                if username in weak_names:
                    weak_admins.append(username)
        status = "fail" if weak_admins else ("pass" if admin_count else "unknown")
        rules.append(
            _rule(
                rule_id="R-IDM-ADMIN-NONDEFAULT",
                title="Administrative Usernames Are Non-Default",
                category="identity",
                severity="MEDIUM",
                status=status,
                rationale=(
                    f"Default/common admin usernames detected: {', '.join(sorted(set(weak_admins)))}"
                    if weak_admins
                    else ("No default admin usernames detected." if admin_count else "No admin accounts inferable from backup.")
                ),
                recommendation="Use unique named admin accounts; avoid default/shared admin usernames.",
                confidence="medium",
                evidence={"admin_accounts": admin_count, "weak_admins": sorted(set(weak_admins))},
                cis_controls=["CIS 5.2", "CIS 6.3"],
                nist_controls=["AC-2", "IA-5"],
                references=["https://www.cisecurity.org/controls"],
            )
        )

    if "R-IDM-ADMIN-UNIQUE-USERNAMES" in enabled:
        admin_usernames: list[str] = []
        for user in users:
            if not isinstance(user, dict):
                continue
            role = str(_model_get(user, schema, "user_role", "") or "").lower()
            if "admin" in role or _truthy(user.get("super_admin")):
                username = str(_model_get(user, schema, "username", "") or "").strip().lower()
                if username:
                    admin_usernames.append(username)
        seen: set[str] = set()
        duplicates: set[str] = set()
        for name in admin_usernames:
            if name in seen:
                duplicates.add(name)
            seen.add(name)
        has_identity_context = bool(users)
        status = "fail" if duplicates else ("pass" if admin_usernames else ("fail" if has_identity_context else "unknown"))
        rules.append(
            _rule(
                rule_id="R-IDM-ADMIN-UNIQUE-USERNAMES",
                title="Administrative Usernames Are Unique",
                category="identity",
                severity="LOW",
                status=status,
                rationale=(
                    f"Duplicate admin usernames found: {', '.join(sorted(duplicates))}"
                    if duplicates
                    else (
                        "No duplicate admin usernames detected."
                        if admin_usernames
                        else (
                            "Admin/user objects exist but admin usernames are not inferable."
                            if has_identity_context
                            else "No admin usernames inferable."
                        )
                    )
                ),
                recommendation="Use unique named admin accounts instead of shared usernames.",
                confidence="medium" if has_identity_context else "low",
                evidence={
                    "admin_usernames": admin_usernames,
                    "duplicate_admin_usernames": sorted(duplicates),
                    "users_count": len([u for u in users if isinstance(u, dict)]),
                },
                cis_controls=["CIS 5.2"],
                nist_controls=["AC-2"],
                references=["https://www.cisecurity.org/controls"],
            )
        )

    if "R-IDM-MFA-EVIDENCE" in enabled:
        mfa_seen = False
        for cfg in setting_candidates:
            if not isinstance(cfg, dict):
                continue
            for key, value in cfg.items():
                key_l = str(key).lower()
                if ("mfa" in key_l or "2fa" in key_l) and _truthy(value):
                    mfa_seen = True
            if not mfa_seen and _nested_key_truthy(cfg, {"mfa", "2fa", "totp"}):
                mfa_seen = True
        has_identity_context = bool(users or setting_candidates)
        status = "pass" if mfa_seen else ("fail" if has_identity_context else "unknown")
        rules.append(
            _rule(
                rule_id="R-IDM-MFA-EVIDENCE",
                title="MFA Evidence Present For Admin Access",
                category="identity",
                severity="MEDIUM",
                status=status,
                rationale=(
                    "MFA/2FA marker(s) found in settings."
                    if mfa_seen
                    else (
                        "No MFA/2FA evidence found in parsed identity/settings data."
                        if has_identity_context
                        else "MFA cannot be verified from this backup alone."
                    )
                ),
                recommendation="Enforce MFA for all admin accounts and verify in account/IdP settings.",
                confidence=("medium" if mfa_seen else ("medium" if has_identity_context else "low")),
                evidence={"mfa_marker_found": mfa_seen},
                cis_controls=["CIS 6.3"],
                nist_controls=["IA-2"],
                references=["https://csrc.nist.gov/publications/detail/sp/800-63/3/final"],
            )
        )

    if "R-PERF-24G-20MHZ" in enabled:
        wide_ssids = []
        for wlan in wlan_candidates_debug:
            if not isinstance(wlan, dict):
                continue
            bands = _model_get(wlan, schema, "bands", []) or []
            if not bands:
                bands = _get_by_alias(wlan, ["band", "radio", "radio_bands"], []) or []
            width = str(_model_get(wlan, schema, "channel_width", "") or "").upper()
            if not width:
                width = str(_get_by_alias(wlan, ["chan_width", "he_channel_width", "vht"], "") or "").upper()
            if isinstance(bands, list):
                norm = [str(b).lower() for b in bands]
                if any("2g" in b for b in norm) and width in {"HT40", "40", "HE40"}:
                    wide_ssids.append(str(_model_get(wlan, schema, "ssid_name", "<unknown>")))
        status = "fail" if wide_ssids else ("pass" if wlan_candidates_debug else "unknown")
        rules.append(
            _rule(
                rule_id="R-PERF-24G-20MHZ",
                title="2.4GHz Channels Use 20MHz",
                category="performance",
                severity="MEDIUM" if profile == "strict-enterprise" else "LOW",
                status=status,
                rationale=(
                    f"40MHz on 2.4GHz detected for: {', '.join(wide_ssids)}"
                    if wide_ssids
                    else ("No 40MHz 2.4GHz SSIDs detected." if wlan_candidates_debug else "No WLAN data available.")
                ),
                recommendation="Use 20MHz on 2.4GHz unless survey data justifies wider channels.",
                confidence="high" if wlan_candidates_debug else "low",
                evidence={"wide_24ghz_ssids": wide_ssids},
                cis_controls=["CIS 12.1"],
                nist_controls=["CA-7"],
                references=["https://www.wi-fi.org/discover-wi-fi/wi-fi-certified-6"],
            )
        )

    if "R-RES-BACKUP-SCHEDULE" in enabled:
        backup_marker = any(
            isinstance(cfg, dict) and any("backup" in str(k).lower() and _truthy(v) for k, v in cfg.items())
            for cfg in settings
        )
        status = "pass" if backup_marker else "unknown"
        rules.append(
            _rule(
                rule_id="R-RES-BACKUP-SCHEDULE",
                title="Automated Backup Schedule Evident",
                category="resilience",
                severity="LOW",
                status=status,
                rationale=(
                    "Backup scheduling markers found in settings."
                    if backup_marker
                    else "Automated backup schedule not verifiable from available settings."
                ),
                recommendation="Ensure automatic backups are enabled and exported off-controller.",
                confidence="low",
                evidence={"backup_marker_found": backup_marker},
                cis_controls=["CIS 11.3"],
                nist_controls=["CP-9"],
                references=["https://csrc.nist.gov/projects/risk-management/sp800-53-controls"],
            )
        )

    all_setting_keys = {
        str(k).lower()
        for cfg in setting_candidates
        if isinstance(cfg, dict)
        for k in cfg.keys()
    }
    all_setting_tokens = set(all_setting_keys)
    for cfg in setting_candidates:
        if not isinstance(cfg, dict):
            continue
        for path, value in _iter_nested_items(cfg):
            all_setting_tokens.add(path)
            if isinstance(value, str):
                value_l = value.strip().lower()
                if 1 <= len(value_l) <= 80:
                    all_setting_tokens.add(value_l)

    def _settings_has_any(tokens: set[str]) -> bool:
        return any(any(token in entry for token in tokens) for entry in all_setting_tokens)

    if "R-SEC-PMF-ENABLED" in enabled:
        pmf_disabled = []
        for wlan in wlan_candidates_debug:
            if not isinstance(wlan, dict):
                continue
            pmf_mode = str(_model_get(wlan, schema, "pmf_mode", "") or "").lower()
            if not pmf_mode:
                pmf_mode = str(_get_by_alias(wlan, ["pmf", "mfp", "protected_management_frames"], "") or "").lower()
            if pmf_mode in {"disabled", "off", "0"}:
                pmf_disabled.append(str(_model_get(wlan, schema, "ssid_name", "<unknown>")))
        status = "fail" if pmf_disabled else ("pass" if wlan_candidates_debug else "unknown")
        rules.append(
            _rule(
                rule_id="R-SEC-PMF-ENABLED",
                title="PMF Not Disabled On WLANs",
                category="security",
                severity="LOW",
                status=status,
                rationale=(
                    f"PMF disabled on: {', '.join(pmf_disabled)}"
                    if pmf_disabled
                    else ("No PMF disabled markers found." if wlan_candidates_debug else "No WLAN data available.")
                ),
                recommendation="Use PMF optional/required where client compatibility permits.",
                confidence="medium",
                evidence={"pmf_disabled_ssids": pmf_disabled},
                cis_controls=["CIS 4.5"],
                nist_controls=["SC-5"],
                references=["https://www.wi-fi.org/discover-wi-fi/security"],
            )
        )

    if "R-SEC-SSH-RESTRICTED" in enabled:
        ssh_enabled_keys = [k for k in all_setting_keys if "ssh" in k]
        status = "unknown"
        rationale = "No SSH-related settings markers found."
        if ssh_enabled_keys:
            status = "pass"
            rationale = "SSH markers present; verify source-IP restrictions manually."
        rules.append(
            _rule(
                rule_id="R-SEC-SSH-RESTRICTED",
                title="SSH Management Access Is Restricted",
                category="security",
                severity="LOW",
                status=status,
                rationale=rationale,
                recommendation="Restrict SSH to management VLAN/source IPs and key auth.",
                confidence="low",
                evidence={"ssh_setting_keys": ssh_enabled_keys},
                cis_controls=["CIS 4.1"],
                nist_controls=["AC-17"],
                references=["https://csrc.nist.gov/projects/risk-management/sp800-53-controls"],
            )
        )

    if "R-SEC-IDS-ENABLED-EVIDENCE" in enabled:
        ids_marker = any(_settings_has_any({token}) for token in {"ids", "ips", "threat"})
        status = "pass" if ids_marker else "unknown"
        rules.append(
            _rule(
                rule_id="R-SEC-IDS-ENABLED-EVIDENCE",
                title="IDS/IPS Evidence Present",
                category="security",
                severity="LOW",
                status=status,
                rationale="IDS/IPS-related settings markers found." if ids_marker else "IDS/IPS cannot be verified from settings keys.",
                recommendation="Enable IDS/IPS where performance budget allows.",
                confidence="low",
                evidence={"ids_marker_found": ids_marker},
                cis_controls=["CIS 13.7"],
                nist_controls=["SI-4"],
                references=["https://www.cisecurity.org/controls"],
            )
        )

    if "R-IDM-ADMIN-COUNT-MIN2" in enabled:
        admin_count = 0
        for user in users:
            if not isinstance(user, dict):
                continue
            role = str(_model_get(user, schema, "user_role", "") or "").lower()
            if "admin" in role or _truthy(user.get("super_admin")):
                admin_count += 1
        status = "pass" if admin_count >= 2 else ("fail" if admin_count > 0 else "unknown")
        rules.append(
            _rule(
                rule_id="R-IDM-ADMIN-COUNT-MIN2",
                title="At Least Two Named Admin Accounts",
                category="identity",
                severity="LOW",
                status=status,
                rationale=(
                    f"{admin_count} admin-like account(s) detected."
                    if admin_count
                    else "No admin accounts inferable from backup."
                ),
                recommendation="Maintain at least two named admin accounts for resilience/accountability.",
                confidence="medium",
                evidence={"admin_count": admin_count},
                cis_controls=["CIS 6.1"],
                nist_controls=["AC-2"],
                references=["https://www.cisecurity.org/controls"],
            )
        )

    if "R-NET-VLAN-EVIDENCE" in enabled:
        vlan_like = [
            n
            for n in network_candidates
            if isinstance(n, dict)
            and (
                str(_model_get(n, schema, "network_purpose", "")).lower() in {"corporate", "guest", "vlan"}
                or n.get("vlan") is not None
                or n.get("vlan_id") is not None
            )
        ]
        status = "pass" if len(vlan_like) >= 2 else ("pass" if network_candidates else "unknown")
        rules.append(
            _rule(
                rule_id="R-NET-VLAN-EVIDENCE",
                title="Multiple Segmented Network Zones Evident",
                category="network",
                severity="LOW",
                status=status,
                rationale=(
                    f"{len(vlan_like)} segmented network entries detected."
                    if vlan_like
                    else ("Network entries present but segmentation tags limited." if network_candidates else "Segmentation not clearly inferable from network entries.")
                ),
                recommendation="Use separate VLANs for guest, management, and user/server zones.",
                confidence="low",
                evidence={"segmented_network_entries": len(vlan_like), "network_candidate_count": len(network_candidates)},
                cis_controls=["CIS 12.3"],
                nist_controls=["SC-7"],
                references=["https://csrc.nist.gov/projects/risk-management/sp800-53-controls"],
            )
        )

    if "R-NET-PRIVATE-SUBNETS" in enabled:
        non_private: list[str] = []
        subnets_seen: list[str] = []
        for net in network_candidates:
            if not isinstance(net, dict):
                continue
            for key in ("subnet", "network", "network_subnet"):
                parsed = _parse_network(net.get(key))
                if not parsed:
                    continue
                subnet_s = str(parsed)
                subnets_seen.append(subnet_s)
                if not parsed.is_private:
                    non_private.append(subnet_s)
                break
        has_network_context = bool(network_candidates)
        status = "fail" if non_private else ("pass" if subnets_seen else ("fail" if has_network_context else "unknown"))
        rules.append(
            _rule(
                rule_id="R-NET-PRIVATE-SUBNETS",
                title="Internal Networks Use Private Address Space",
                category="network",
                severity="MEDIUM",
                status=status,
                rationale=(
                    f"Non-private subnet(s) detected: {', '.join(sorted(set(non_private)))}"
                    if non_private
                    else (
                        "All detected internal subnets are private."
                        if subnets_seen
                        else (
                            "Network objects exist but no subnet entries were detected."
                            if has_network_context
                            else "No subnet entries detected."
                        )
                    )
                ),
                recommendation="Use RFC1918 private ranges for internal LAN/VLAN segments.",
                confidence="high" if subnets_seen else ("medium" if has_network_context else "low"),
                evidence={
                    "subnets_seen": sorted(set(subnets_seen)),
                    "non_private_subnets": sorted(set(non_private)),
                    "network_candidate_count": len(network_candidates),
                },
                cis_controls=["CIS 12.3"],
                nist_controls=["SC-7"],
                references=["https://datatracker.ietf.org/doc/html/rfc1918"],
            )
        )

    if "R-NET-DEFAULT-LAN-SUBNET-CHANGED" in enabled:
        default_lan_hits: list[str] = []
        for net in network_candidates:
            if not isinstance(net, dict):
                continue
            for key in ("subnet", "network", "network_subnet"):
                parsed = _parse_network(net.get(key))
                if not parsed:
                    continue
                if str(parsed.network_address) == "192.168.1.0" and int(parsed.prefixlen) == 24:
                    default_lan_hits.append(str(parsed))
                break
        any_subnet_data = bool(network_candidates)
        status = "fail" if default_lan_hits else ("pass" if any_subnet_data else "unknown")
        rules.append(
            _rule(
                rule_id="R-NET-DEFAULT-LAN-SUBNET-CHANGED",
                title="Default LAN Subnet Is Not 192.168.1.0/24",
                category="network",
                severity="LOW",
                status=status,
                rationale=(
                    f"Default subnet detected: {', '.join(sorted(set(default_lan_hits)))}"
                    if default_lan_hits
                    else ("No default 192.168.1.0/24 LAN detected." if any_subnet_data else "No subnet data available.")
                ),
                recommendation="Change default LAN subnet to reduce predictable management exposure.",
                confidence="medium" if any_subnet_data else "low",
                evidence={"default_lan_hits": sorted(set(default_lan_hits))},
                cis_controls=["CIS 4.1"],
                nist_controls=["CM-7"],
                references=["https://www.cisecurity.org/controls"],
            )
        )

    if "R-NET-MGMT-VLAN-EVIDENCE" in enabled:
        mgmt_marker = _settings_has_any({"mgmt", "management_vlan", "device_mgmt"})
        status = "pass" if mgmt_marker else "unknown"
        rules.append(
            _rule(
                rule_id="R-NET-MGMT-VLAN-EVIDENCE",
                title="Management Plane Segregation Evidence",
                category="network",
                severity="LOW",
                status=status,
                rationale="Management/VLAN markers found." if mgmt_marker else "Management VLAN segregation not verifiable from settings.",
                recommendation="Place controller/AP management on dedicated restricted VLAN.",
                confidence="low",
                evidence={"management_marker_found": mgmt_marker},
                cis_controls=["CIS 12.3"],
                nist_controls=["SC-7"],
                references=["https://www.cisecurity.org/controls"],
            )
        )

    if "R-NET-FIREWALL-RULES-EVIDENCE" in enabled:
        fw_marker = _settings_has_any({"firewall", "acl", "rule"})
        status = "pass" if fw_marker else "unknown"
        rules.append(
            _rule(
                rule_id="R-NET-FIREWALL-RULES-EVIDENCE",
                title="Firewall Policy Evidence Present",
                category="network",
                severity="LOW",
                status=status,
                rationale="Firewall/ACL markers present." if fw_marker else "Firewall rule objects not visible in parsed settings.",
                recommendation="Review deny-by-default east-west and guest-to-lan controls.",
                confidence="low",
                evidence={"firewall_marker_found": fw_marker},
                cis_controls=["CIS 12.3"],
                nist_controls=["AC-4", "SC-7"],
                references=["https://csrc.nist.gov/publications"],
            )
        )

    if "R-RES-REMOTE-BACKUP-EVIDENCE" in enabled:
        remote_backup_marker = _settings_has_any({"backup", "cloud_backup", "remote_backup", "autobackup"})
        status = "pass" if remote_backup_marker else "unknown"
        rules.append(
            _rule(
                rule_id="R-RES-REMOTE-BACKUP-EVIDENCE",
                title="Remote/Off-Controller Backup Evidence",
                category="resilience",
                severity="LOW",
                status=status,
                rationale="Backup markers found." if remote_backup_marker else "Off-controller backup destination not verifiable.",
                recommendation="Export backups off the controller appliance to durable storage.",
                confidence="low",
                evidence={"remote_backup_marker_found": remote_backup_marker},
                cis_controls=["CIS 11.3"],
                nist_controls=["CP-9"],
                references=["https://csrc.nist.gov/projects/risk-management/sp800-53-controls"],
            )
        )

    if "R-OPS-REMOTE-LOGGING-EVIDENCE" in enabled:
        syslog_marker = _settings_has_any({"syslog", "remote_log", "log_server"})
        status = "pass" if syslog_marker else "unknown"
        rules.append(
            _rule(
                rule_id="R-OPS-REMOTE-LOGGING-EVIDENCE",
                title="Remote Logging Evidence Present",
                category="operations",
                severity="LOW",
                status=status,
                rationale="Remote logging markers found." if syslog_marker else "Remote logging not verifiable from settings keys.",
                recommendation="Forward logs to centralized SIEM/syslog and retain per policy.",
                confidence="low",
                evidence={"remote_logging_marker_found": syslog_marker},
                cis_controls=["CIS 8.2"],
                nist_controls=["AU-6", "AU-12"],
                references=["https://www.cisecurity.org/controls"],
            )
        )

    if "R-OPS-NTP-CONFIG-EVIDENCE" in enabled:
        ntp_marker = _settings_has_any({"ntp", "timeserver", "time_server"})
        status = "pass" if ntp_marker else "unknown"
        rules.append(
            _rule(
                rule_id="R-OPS-NTP-CONFIG-EVIDENCE",
                title="Trusted Time Source Evidence Present",
                category="operations",
                severity="LOW",
                status=status,
                rationale="NTP/time markers found." if ntp_marker else "NTP configuration not verifiable from settings keys.",
                recommendation="Configure trusted NTP sources for accurate audit/log timelines.",
                confidence="low",
                evidence={"ntp_marker_found": ntp_marker},
                cis_controls=["CIS 8.4"],
                nist_controls=["AU-8"],
                references=["https://csrc.nist.gov/publications"],
            )
        )

    if "R-OPS-DNS-CONFIG-EVIDENCE" in enabled:
        dns_marker = _settings_has_any({"dns", "resolver", "upstream_dns"})
        status = "pass" if dns_marker else "unknown"
        rules.append(
            _rule(
                rule_id="R-OPS-DNS-CONFIG-EVIDENCE",
                title="DNS Resolver Policy Evidence Present",
                category="operations",
                severity="LOW",
                status=status,
                rationale="DNS markers found." if dns_marker else "DNS policy not clearly inferable from settings keys.",
                recommendation="Use trusted DNS resolvers and content filtering where required.",
                confidence="low",
                evidence={"dns_marker_found": dns_marker},
                cis_controls=["CIS 9.2"],
                nist_controls=["SC-20"],
                references=["https://www.cisecurity.org/controls"],
            )
        )

    if "R-WIFI-BAND-STEERING-EVIDENCE" in enabled:
        bs_marker = _settings_has_any({"band_steer", "bandsteering"}) or any(
            any(token in str(k).lower() for token in {"band_steer", "bandsteering"})
            for w in wlan_candidates_debug
            if isinstance(w, dict)
            for k in w.keys()
        )
        status = "pass" if bs_marker else ("fail" if wlan_candidates_debug else "unknown")
        rules.append(
            _rule(
                rule_id="R-WIFI-BAND-STEERING-EVIDENCE",
                title="Band Steering Evidence Present",
                category="wireless",
                severity="LOW",
                status=status,
                rationale=(
                    "Band steering markers found."
                    if bs_marker
                    else (
                        "No band steering markers found in WLAN/settings data."
                        if wlan_candidates_debug
                        else "Band steering policy not verifiable."
                    )
                ),
                recommendation="Prefer 5GHz/6GHz capable clients where RF plan supports it.",
                confidence="medium" if wlan_candidates_debug else "low",
                evidence={"band_steering_marker_found": bs_marker},
                cis_controls=["CIS 12.1"],
                nist_controls=["CA-7"],
                references=["https://www.wi-fi.org/discover-wi-fi"],
            )
        )

    if "R-WIFI-MIN-RSSI-EVIDENCE" in enabled:
        min_rssi_marker = _settings_has_any({"minrssi", "minimum_rssi"}) or any(
            any(token in str(k).lower() for token in {"minrssi", "minimum_rssi"})
            for w in wlan_candidates_debug
            if isinstance(w, dict)
            for k in w.keys()
        )
        status = "pass" if min_rssi_marker else ("fail" if wlan_candidates_debug else "unknown")
        rules.append(
            _rule(
                rule_id="R-WIFI-MIN-RSSI-EVIDENCE",
                title="Minimum RSSI Policy Evidence Present",
                category="wireless",
                severity="LOW",
                status=status,
                rationale=(
                    "Minimum RSSI markers found."
                    if min_rssi_marker
                    else (
                        "No minimum RSSI markers found in WLAN/settings data."
                        if wlan_candidates_debug
                        else "Minimum RSSI policy not verifiable."
                    )
                ),
                recommendation="Use min-RSSI thresholds carefully to improve roaming without over-deauth behavior.",
                confidence="medium" if wlan_candidates_debug else "low",
                evidence={"min_rssi_marker_found": min_rssi_marker},
                cis_controls=["CIS 12.1"],
                nist_controls=["CA-7"],
                references=["https://www.wi-fi.org/discover-wi-fi"],
            )
        )

    if "R-WIFI-HIDDEN-SSID-POLICY" in enabled:
        hidden_ssid_count = sum(1 for w in wlans if isinstance(w, dict) and _truthy(w.get("hide_ssid")))
        status = "pass" if hidden_ssid_count == 0 else "unknown"
        rules.append(
            _rule(
                rule_id="R-WIFI-HIDDEN-SSID-POLICY",
                title="Hidden SSID Not Treated As Primary Security Control",
                category="wireless",
                severity="LOW",
                status=status,
                rationale=(
                    "No hidden SSID markers found."
                    if hidden_ssid_count == 0
                    else f"{hidden_ssid_count} hidden SSID(s) found; hidden SSID is not a security boundary."
                ),
                recommendation="Rely on strong auth/encryption and segmentation, not hidden SSID.",
                confidence="medium",
                evidence={"hidden_ssid_count": hidden_ssid_count},
                cis_controls=["CIS 4.5"],
                nist_controls=["SC-13"],
                references=["https://www.wi-fi.org/discover-wi-fi/security"],
            )
        )

    if "R-WIFI-TX-POWER-HIGH-AVOID" in enabled:
        high_power_count = 0
        for wlan in wlans:
            if not isinstance(wlan, dict):
                continue
            tx_mode = str(wlan.get("tx_power_mode") or "").lower()
            tx_power = wlan.get("tx_power")
            if tx_mode == "high" or (isinstance(tx_power, (int, float)) and tx_power > 22):
                high_power_count += 1
        status = "pass" if high_power_count == 0 else ("fail" if high_power_count > 2 else "unknown")
        rules.append(
            _rule(
                rule_id="R-WIFI-TX-POWER-HIGH-AVOID",
                title="High TX Power Use Minimized",
                category="wireless",
                severity="LOW",
                status=status,
                rationale=(
                    f"High TX power markers on {high_power_count} WLAN(s)." if high_power_count else "No high TX power markers found."
                ),
                recommendation="Prefer medium/low TX power for better roaming and lower interference.",
                confidence="medium",
                evidence={"high_tx_power_wlans": high_power_count},
                cis_controls=["CIS 12.1"],
                nist_controls=["CA-7"],
                references=["https://www.wi-fi.org/discover-wi-fi"],
            )
        )

    if "R-PERF-OFFLINE-DEVICE-RATE" in enabled:
        total_devices = len([d for d in device_candidates if isinstance(d, dict)])
        offline = 0
        for dev in device_candidates:
            if not isinstance(dev, dict):
                continue
            state = _model_get(dev, schema, "device_state")
            if state is None:
                state = dev.get("state")
            if (isinstance(state, int) and state == 0) or str(state).lower() in {"offline", "disconnected", "down"}:
                offline += 1
        rate = (offline / total_devices) if total_devices else 0.0
        status = "fail" if total_devices and rate > 0.25 else ("pass" if total_devices else "unknown")
        rules.append(
            _rule(
                rule_id="R-PERF-OFFLINE-DEVICE-RATE",
                title="Offline Device Rate Below 25%",
                category="performance",
                severity="MEDIUM",
                status=status,
                rationale=(
                    f"Offline devices: {offline}/{total_devices} ({rate:.0%})." if total_devices else "No device inventory found."
                ),
                recommendation="Investigate persistent offline devices (power, adoption, uplink, firmware).",
                confidence="high" if total_devices else "low",
                evidence={"offline_devices": offline, "total_devices": total_devices, "offline_rate": round(rate, 4)},
                cis_controls=["CIS 12.1"],
                nist_controls=["SI-4"],
                references=["https://csrc.nist.gov/publications"],
            )
        )

    if "R-PERF-IDS-USG-CAPACITY" in enabled:
        models = [str(_model_get(d, schema, "device_model", "") or d.get("model") or d.get("type") or "").lower() for d in device_candidates if isinstance(d, dict)]
        usg_present = any(m.startswith("usg") for m in models)
        ids_marker = _settings_has_any({"ids", "ips"})
        status = "unknown"
        rationale = "USG/IDS relationship not inferable."
        if usg_present and ids_marker:
            status = "fail"
            rationale = "USG model and IDS/IPS markers both present; throughput impact likely."
        elif usg_present and not ids_marker:
            status = "pass"
            rationale = "USG present, IDS/IPS markers not detected."
        elif models and not usg_present:
            status = "pass"
            rationale = "No USG model detected; USG IDS throughput guardrail not applicable."
        rules.append(
            _rule(
                rule_id="R-PERF-IDS-USG-CAPACITY",
                title="USG Capacity Guardrail For IDS/IPS",
                category="performance",
                severity="MEDIUM",
                status=status,
                rationale=rationale,
                recommendation="If USG runs IDS/IPS, validate throughput and consider hardware upgrade.",
                confidence="medium",
                evidence={"usg_present": usg_present, "ids_marker_found": ids_marker},
                cis_controls=["CIS 13.7"],
                nist_controls=["SI-4"],
                references=["https://www.cisecurity.org/controls"],
            )
        )

    if "R-SEC-GUEST-PORTAL-EVIDENCE" in enabled:
        guest_portal_marker = _settings_has_any({"guest", "portal", "hotspot"})
        status = "pass" if guest_portal_marker else "unknown"
        rules.append(
            _rule(
                rule_id="R-SEC-GUEST-PORTAL-EVIDENCE",
                title="Guest Access Control Evidence Present",
                category="security",
                severity="LOW",
                status=status,
                rationale="Guest/portal markers found." if guest_portal_marker else "Guest portal/access policy not verifiable.",
                recommendation="Use guest controls (portal/ACL) for unauthenticated access domains.",
                confidence="low",
                evidence={"guest_portal_marker_found": guest_portal_marker},
                cis_controls=["CIS 12.3"],
                nist_controls=["AC-4"],
                references=["https://csrc.nist.gov/publications"],
            )
        )

    if "R-SEC-AP-ISOLATION-EVIDENCE" in enabled:
        ap_iso_marker = _settings_has_any({"ap_isolation", "client_isolation", "isolation"})
        status = "pass" if ap_iso_marker else "unknown"
        rules.append(
            _rule(
                rule_id="R-SEC-AP-ISOLATION-EVIDENCE",
                title="Client Isolation Evidence Present",
                category="security",
                severity="LOW",
                status=status,
                rationale="Isolation markers found." if ap_iso_marker else "Client/AP isolation policy not verifiable.",
                recommendation="Use client/AP isolation on high-risk/guest SSIDs where appropriate.",
                confidence="low",
                evidence={"ap_isolation_marker_found": ap_iso_marker},
                cis_controls=["CIS 3.4"],
                nist_controls=["SC-7"],
                references=["https://www.cisecurity.org/controls"],
            )
        )

    if "R-OPS-FIRMWARE-MAINT-EVIDENCE" in enabled:
        firmware_marker = _settings_has_any({"firmware", "auto_update", "upgrade"})
        status = "pass" if firmware_marker else "unknown"
        rules.append(
            _rule(
                rule_id="R-OPS-FIRMWARE-MAINT-EVIDENCE",
                title="Firmware Maintenance Evidence Present",
                category="operations",
                severity="LOW",
                status=status,
                rationale="Firmware/update markers found." if firmware_marker else "Firmware maintenance policy not verifiable.",
                recommendation="Maintain controller/gateway/AP firmware update policy and change window process.",
                confidence="low",
                evidence={"firmware_marker_found": firmware_marker},
                cis_controls=["CIS 7.1"],
                nist_controls=["CM-2"],
                references=["https://csrc.nist.gov/publications"],
            )
        )

    if "R-OPS-FIRMWARE-VERSION-VISIBLE" in enabled:
        devices_with_version = 0
        for dev in device_candidates:
            if not isinstance(dev, dict):
                continue
            version = _get_by_alias(dev, ["version", "fw_version", "firmware_version", "short_ver"], "")
            if str(version or "").strip():
                devices_with_version += 1
        status = "pass" if devices_with_version > 0 else ("fail" if device_candidates else "unknown")
        rules.append(
            _rule(
                rule_id="R-OPS-FIRMWARE-VERSION-VISIBLE",
                title="Device Firmware Version Inventory Visible",
                category="operations",
                severity="LOW",
                status=status,
                rationale=(
                    f"Firmware version visible on {devices_with_version} device(s)."
                    if devices_with_version > 0
                    else ("No firmware version fields detected in device inventory." if device_candidates else "No device inventory available.")
                ),
                recommendation="Keep a visible firmware version inventory for gateway/switch/AP lifecycle management.",
                confidence="medium" if device_candidates else "low",
                evidence={"devices_with_firmware_version": devices_with_version, "device_count": len(device_candidates)},
                cis_controls=["CIS 7.1"],
                nist_controls=["CM-2"],
                references=["https://csrc.nist.gov/publications"],
            )
        )

    findings = [_rule_to_finding(rule) for rule in rules if rule.status == "fail"]

    score = 100
    for finding in findings:
        score -= SEVERITY_PENALTY[_severity(finding.severity)]
    score = max(0, min(100, score))

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    status_counts = {"pass": 0, "fail": 0, "unknown": 0}
    for rule in rules:
        if rule.status in status_counts:
            status_counts[rule.status] += 1
    unknown_rule_ids = [r.rule_id for r in rules if r.status == "unknown"]

    rules_total = len(rules)
    compliance_score = int(round((status_counts["pass"] / rules_total) * 100)) if rules_total else 0
    if compliance_score >= 90:
        compliance_grade = "A"
    elif compliance_score >= 80:
        compliance_grade = "B"
    elif compliance_score >= 70:
        compliance_grade = "C"
    elif compliance_score >= 60:
        compliance_grade = "D"
    else:
        compliance_grade = "F"

    minimums = PROFILE_MINIMUMS.get(profile, {})
    min_max_fail = minimums.get("max_fail")
    min_max_unknown = minimums.get("max_unknown")
    profile_gate_pass = True
    if min_max_fail is not None and status_counts["fail"] > min_max_fail:
        profile_gate_pass = False
    if min_max_unknown is not None and status_counts["unknown"] > min_max_unknown:
        profile_gate_pass = False

    collection_doc_counts = sorted(
        ((name, len([d for d in docs if isinstance(d, dict)])) for name, docs in collections.items() if isinstance(docs, list)),
        key=lambda item: item[1],
        reverse=True,
    )
    setting_token_sample = sorted(all_setting_tokens)[:60]
    wlan_key_sample: list[str] = []
    if wlan_candidates_debug:
        key_set = set()
        for w in wlan_candidates_debug[:50]:
            if isinstance(w, dict):
                for k in w.keys():
                    key_set.add(str(k).lower())
        wlan_key_sample = sorted(key_set)[:60]

    stats = {
        "collections_seen": len(collections),
        "users_count": len(users),
        "wlans_count": len(wlans),
        "networks_count": len(networks),
        "devices_count": len(devices),
        "settings_count": len(setting_candidates),
        "network_candidates_count": len(network_candidates),
        "device_candidates_count": len(device_candidates),
        "findings_total": len(findings),
        "rules_total": rules_total,
        "rules_pass": status_counts["pass"],
        "rules_fail": status_counts["fail"],
        "rules_unknown": status_counts["unknown"],
        "compliance_score": compliance_score,
        "compliance_grade": compliance_grade,
        "profile_gate_pass": profile_gate_pass,
        "profile_gate_max_fail": min_max_fail,
        "profile_gate_max_unknown": min_max_unknown,
        "profile": profile,
        "schema": schema,
        "unknown_rule_ids": unknown_rule_ids,
        "collection_doc_counts_top": collection_doc_counts[:20],
        "setting_token_sample": setting_token_sample,
        "wlan_candidate_count": len(wlan_candidates_debug),
        "wlan_key_sample": wlan_key_sample,
    }
    return AuditReport(
        backup_path=backup_path,
        profile=profile,
        score=score,
        grade=grade,
        rules=rules,
        findings=findings,
        stats=stats,
    )
