from __future__ import annotations

from typing import Any

from .models import AuditReport, Finding

SEVERITY_PENALTY = {
    "HIGH": 18,
    "MEDIUM": 9,
    "LOW": 4,
}

PROFILES = {"baseline", "cis-nist"}

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
        "pmf_mode": ["pmf_mode", "pmf"],
        "bands": ["wlan_bands", "bands"],
        "channel_width": ["channel_width", "ht"],
        "tx_power_mode": ["tx_power_mode"],
        "tx_power": ["tx_power"],
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
        "pmf_mode": ["pmf_mode", "pmf", "management_frame_protection"],
        "bands": ["bands", "wlan_bands", "radio_bands"],
        "channel_width": ["channel_width", "ht", "channelization"],
        "tx_power_mode": ["tx_power_mode", "power_mode"],
        "tx_power": ["tx_power", "transmit_power_dbm"],
        "network_name": ["name", "_id", "display_name"],
        "network_purpose": ["purpose", "type"],
        "guest_lan_access": ["guest_to_lan", "lan_access", "inter_vlan_routing"],
        "device_model": ["model", "type", "product_model", "product_name", "board_name"],
        "device_state": ["state", "status"],
    },
}


def _severity(value: str) -> str:
    value = value.upper()
    if value not in SEVERITY_PENALTY:
        return "LOW"
    return value


def _find_collection(collections: dict[str, list[dict[str, Any]]], needles: list[str]) -> list[dict[str, Any]]:
    by_lower = {k.lower(): v for k, v in collections.items()}
    for needle in needles:
        if needle.lower() in by_lower:
            return by_lower[needle.lower()]
    for key, value in by_lower.items():
        if any(needle.lower() in key for needle in needles):
            return value
    return []


def _infer_schema(collections: dict[str, list[dict[str, Any]]]) -> str:
    keys = {k.lower() for k in collections.keys()}
    modern_markers = {"wifi_network", "wireless_network", "system_settings", "network_settings"}
    if any(marker in keys for marker in modern_markers):
        return "modern8"
    return "legacy7"


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


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "on", "enabled", "enable"}
    return False


def _finding(
    *,
    category: str,
    severity: str,
    title: str,
    detail: str,
    recommendation: str,
    evidence: dict[str, Any] | None = None,
    cis_controls: list[str] | None = None,
    nist_controls: list[str] | None = None,
) -> Finding:
    return Finding(
        category=category,
        severity=severity,
        title=title,
        detail=detail,
        recommendation=recommendation,
        evidence=evidence or {},
        cis_controls=cis_controls or [],
        nist_controls=nist_controls or [],
    )


def _detect_platform(
    devices: list[dict[str, Any]], settings: list[dict[str, Any]], schema: str
) -> tuple[str, str, list[str]]:
    models: list[str] = []
    for dev in devices:
        if not isinstance(dev, dict):
            continue
        model = str(_model_get(dev, schema, "device_model", "") or "").strip().lower()
        if model:
            models.append(model)

    joined = " ".join(models)
    cloudkey_gen1_tokens = {"uck", "uc-ck", "uc_ck", "uc-ck-eu"}
    cloudkey_gen2_tokens = {"uck-g2", "uck_g2", "uc-ck-g2", "cloudkey gen2"}
    cloudkey_plus_tokens = {"uckp", "uck-g2-plus", "uc-ck-g2-plus", "cloudkey gen2 plus"}

    if any(token in joined for token in cloudkey_plus_tokens):
        return "cloudkey", "gen2-plus", models
    if any(token in joined for token in cloudkey_gen2_tokens):
        return "cloudkey", "gen2", models
    if any(token in joined for token in cloudkey_gen1_tokens) or "cloudkey" in joined:
        return "cloudkey", "gen1", models

    for cfg in settings:
        if not isinstance(cfg, dict):
            continue
        for key, value in cfg.items():
            key_l = str(key).lower()
            val_l = str(value).lower()
            if "cloudkey" in key_l or "cloud key" in val_l:
                return "cloudkey", "unknown", models

    if any(model.startswith(("udm", "uxg")) for model in models):
        return "udm", "unknown", models
    if any(model.startswith("usg") for model in models):
        return "usg", "unknown", models
    return "unknown", "unknown", models


def run_checks(
    backup_path: str, collections: dict[str, list[dict[str, Any]]], profile: str = "baseline"
) -> AuditReport:
    if profile not in PROFILES:
        profile = "baseline"

    schema = _infer_schema(collections)
    aliases = SCHEMA_COLLECTION_ALIASES.get(schema, SCHEMA_COLLECTION_ALIASES["legacy7"])

    findings: list[Finding] = []

    users = _find_collection(collections, aliases["users"])
    wlans = _find_collection(collections, aliases["wlans"])
    networks = _find_collection(collections, aliases["networks"])
    devices = _find_collection(collections, aliases["devices"])
    settings = _find_collection(collections, aliases["settings"])

    weak_admin_names = {"admin", "ubnt", "root", "user"}
    platform, platform_variant, platform_models = _detect_platform(devices, settings, schema)
    admin_count = 0
    for user in users:
        if not isinstance(user, dict):
            continue
        username = str(_model_get(user, schema, "username", "") or "").strip().lower()
        role = str(_model_get(user, schema, "user_role", "") or "").lower()
        is_admin_like = "admin" in role or _truthy(user.get("super_admin"))
        if is_admin_like:
            admin_count += 1
        if username and username in weak_admin_names and is_admin_like:
            findings.append(
                _finding(
                    category="security",
                    severity="MEDIUM",
                    title="Weak admin username",
                    detail=f"Administrative account uses common username '{username}'.",
                    recommendation="Rename admin accounts to unique non-default names and review all admin identities.",
                    evidence={"username": username},
                    cis_controls=["CIS 5.2", "CIS 6.3"],
                    nist_controls=["AC-2", "IA-5"],
                )
            )

    if profile == "cis-nist" and admin_count < 2:
        findings.append(
            _finding(
                category="security",
                severity="LOW",
                title="Single admin account pattern",
                detail="Only one admin-like account was detected.",
                recommendation="Use separate named admin accounts and avoid shared accounts for accountability.",
                evidence={"admin_accounts": admin_count},
                cis_controls=["CIS 6.1"],
                nist_controls=["AC-2", "AU-12"],
            )
        )

    for wlan in wlans:
        if not isinstance(wlan, dict):
            continue
        name = str(_model_get(wlan, schema, "ssid_name", "<unknown>") or "<unknown>")
        sec = str(_model_get(wlan, schema, "wifi_security", "") or "").lower()
        wpa_mode = str(_model_get(wlan, schema, "wpa_mode", "") or "").lower()
        pmf_mode = str(_model_get(wlan, schema, "pmf_mode", "") or "").lower()

        if sec in {"open", "none"} or _truthy(wlan.get("is_guest_open")):
            findings.append(
                _finding(
                    category="security",
                    severity="HIGH",
                    title="Open wireless network",
                    detail=f'SSID "{name}" appears open (no WPA security).',
                    recommendation="Enable WPA2/WPA3 immediately and isolate unauthenticated access to captive portal-only guest use.",
                    evidence={"ssid": name, "security": sec},
                    cis_controls=["CIS 4.5"],
                    nist_controls=["SC-8", "SC-13"],
                )
            )
        elif sec in {"wep", "wpa", "wpa1"}:
            findings.append(
                _finding(
                    category="security",
                    severity="HIGH",
                    title="Legacy wireless encryption",
                    detail=f'SSID "{name}" uses legacy encryption ({sec}).',
                    recommendation="Migrate this SSID to WPA2-AES at minimum, preferably WPA3 or WPA2/WPA3 transition mode.",
                    evidence={"ssid": name, "security": sec},
                    cis_controls=["CIS 4.5"],
                    nist_controls=["SC-13", "IA-7"],
                )
            )
        elif "wpa2" in wpa_mode and not _truthy(wlan.get("wpa3_support")) and "wpa3" not in wpa_mode:
            findings.append(
                _finding(
                    category="security",
                    severity="MEDIUM",
                    title="WPA3 not enabled",
                    detail=f'SSID "{name}" appears to run WPA2 without WPA3 transition mode.',
                    recommendation="Enable WPA3 transition mode for capable clients, and migrate legacy clients on a phased schedule.",
                    evidence={"ssid": name, "wpa_mode": wpa_mode or sec},
                    cis_controls=["CIS 4.5"],
                    nist_controls=["SC-13"],
                )
            )

        if pmf_mode in {"disabled", "off", "0"}:
            findings.append(
                _finding(
                    category="security",
                    severity="LOW",
                    title="PMF disabled",
                    detail=f'SSID "{name}" has Protected Management Frames disabled.',
                    recommendation="Set PMF to optional or required based on client support to reduce management frame spoofing risks.",
                    evidence={"ssid": name, "pmf_mode": pmf_mode},
                    cis_controls=["CIS 4.5"],
                    nist_controls=["SC-5", "SC-40"],
                )
            )

        bands = _model_get(wlan, schema, "bands", []) or []
        width = str(_model_get(wlan, schema, "channel_width", "") or "").upper()
        if isinstance(bands, list):
            normalized_bands = [str(b).lower() for b in bands]
            if any("2g" in b for b in normalized_bands) and width in {"HT40", "40", "HE40"}:
                findings.append(
                    _finding(
                        category="performance",
                        severity="MEDIUM",
                        title="Wide 2.4GHz channel",
                        detail=f'SSID "{name}" uses 40MHz on 2.4GHz (higher interference risk).',
                        recommendation="Set 2.4GHz radios to 20MHz in dense/noisy environments unless a survey justifies 40MHz.",
                        evidence={"ssid": name, "channel_width": width},
                        cis_controls=["CIS 12.1"],
                        nist_controls=["SI-4", "CA-7"],
                    )
                )

        tx_power_mode = str(_model_get(wlan, schema, "tx_power_mode", "") or "").lower()
        tx_power = _model_get(wlan, schema, "tx_power")
        if tx_power_mode == "high" or (isinstance(tx_power, (int, float)) and tx_power > 22):
            findings.append(
                _finding(
                    category="performance",
                    severity="LOW",
                    title="High transmit power",
                    detail=f'SSID "{name}" appears configured for high TX power.',
                    recommendation="Tune TX power to medium/low where possible to improve roaming and reduce co-channel interference.",
                    evidence={"ssid": name, "tx_power_mode": tx_power_mode, "tx_power": tx_power},
                    cis_controls=["CIS 12.1"],
                    nist_controls=["CA-7"],
                )
            )

    guest_network_count = 0
    guest_isolated_count = 0
    for net in networks:
        if not isinstance(net, dict):
            continue
        name = str(_model_get(net, schema, "network_name", "<unknown>") or "<unknown>")
        purpose = str(_model_get(net, schema, "network_purpose", "") or "").lower()
        if purpose == "guest":
            guest_network_count += 1
            allow_lan = _any_alias_truthy(net, schema, "guest_lan_access")
            if allow_lan:
                findings.append(
                    _finding(
                        category="security",
                        severity="HIGH",
                        title="Guest network can access LAN",
                        detail=f'Guest network "{name}" appears allowed to access LAN resources.',
                        recommendation="Disable guest-to-LAN access and enforce ACL/firewall separation between guest and internal VLANs.",
                        evidence={"network": name},
                        cis_controls=["CIS 3.4", "CIS 12.3"],
                        nist_controls=["AC-4", "SC-7"],
                    )
                )
            else:
                guest_isolated_count += 1

    if profile == "cis-nist" and guest_network_count > 0 and guest_isolated_count == 0:
        findings.append(
            _finding(
                category="security",
                severity="MEDIUM",
                title="Guest segmentation confidence low",
                detail="Guest networks were found but clear isolation markers were not detected in backup fields.",
                recommendation="Validate guest VLAN/firewall isolation manually in UI and gateway firewall policy.",
                evidence={"guest_networks": guest_network_count},
                cis_controls=["CIS 12.3"],
                nist_controls=["AC-4", "SC-7"],
            )
        )

    upnp_any = False
    ssh_any = False
    mfa_marker = False
    for cfg in settings:
        if not isinstance(cfg, dict):
            continue
        for key in ("upnp_enabled", "upnp_nat_pmp_enabled"):
            if _truthy(cfg.get(key)):
                upnp_any = True
                findings.append(
                    _finding(
                        category="security",
                        severity="MEDIUM",
                        title="UPnP enabled",
                        detail=f"{key} is enabled.",
                        recommendation="Disable UPnP/NAT-PMP unless explicitly required and monitored.",
                        evidence={"key": key},
                        cis_controls=["CIS 9.1", "CIS 12.3"],
                        nist_controls=["CM-7", "SC-7"],
                    )
                )
        for key, value in cfg.items():
            key_lower = str(key).lower()
            if "ssh" in key_lower and _truthy(value):
                ssh_any = True
                findings.append(
                    _finding(
                        category="security",
                        severity="LOW",
                        title="SSH exposed in config",
                        detail=f'Configuration flag "{key}" is enabled.',
                        recommendation="Restrict SSH to management VLAN/source IPs and prefer key-based authentication.",
                        evidence={"key": key},
                        cis_controls=["CIS 4.1", "CIS 5.3"],
                        nist_controls=["AC-17", "IA-2"],
                    )
                )
            if ("mfa" in key_lower or "2fa" in key_lower) and _truthy(value):
                mfa_marker = True

    if profile == "cis-nist" and not mfa_marker and users:
        findings.append(
            _finding(
                category="security",
                severity="MEDIUM",
                title="MFA not verifiable from backup",
                detail="No explicit MFA/2FA markers were found in parsed settings.",
                recommendation="Enforce MFA for all UniFi administrative accounts and verify via identity provider/account settings.",
                evidence={"users_count": len(users)},
                cis_controls=["CIS 6.3"],
                nist_controls=["IA-2"],
            )
        )

    offline_devices = 0
    gateway_models: list[str] = []
    for dev in devices:
        if not isinstance(dev, dict):
            continue
        model = str(_model_get(dev, schema, "device_model", "") or "")
        state = _model_get(dev, schema, "device_state")
        if isinstance(state, int) and state == 0:
            offline_devices += 1
        if model:
            gateway_models.append(model.lower())
    if offline_devices > 0:
        findings.append(
            _finding(
                category="performance",
                severity="LOW",
                title="Offline devices in backup",
                detail=f"{offline_devices} device(s) recorded offline at backup time.",
                recommendation="Check adoption state, uplink health, firmware, and PoE budgets for persistently offline devices.",
                evidence={"offline_devices": offline_devices},
                cis_controls=["CIS 12.1"],
                nist_controls=["SI-4", "CA-7"],
            )
        )

    ids_enabled = any(
        _truthy(cfg.get("ips_enabled")) or _truthy(cfg.get("ids_enabled")) for cfg in settings if isinstance(cfg, dict)
    )
    if ids_enabled and any(model.startswith("usg") for model in gateway_models):
        findings.append(
            _finding(
                category="performance",
                severity="MEDIUM",
                title="IDS/IPS on USG hardware",
                detail="IDS/IPS appears enabled on USG-class gateway, which may reduce throughput significantly.",
                recommendation="Measure WAN throughput impact and tune IDS sensitivity or upgrade gateway hardware if bottlenecked.",
                evidence={"gateway_models": gateway_models},
                cis_controls=["CIS 13.7"],
                nist_controls=["SI-4", "SC-5"],
            )
        )

    if profile == "cis-nist" and not upnp_any and not ssh_any and ids_enabled:
        findings.append(
            _finding(
                category="hardening",
                severity="LOW",
                title="Positive hardening indicators",
                detail="UPnP appears disabled and IDS/IPS appears enabled.",
                recommendation="Maintain this posture and confirm gateway rules/logging are reviewed periodically.",
                evidence={"ids_enabled": ids_enabled},
                cis_controls=["CIS 9.1", "CIS 13.7"],
                nist_controls=["CM-7", "SI-4"],
            )
        )

    if platform == "cloudkey":
        cloudkey_gen1 = platform_variant == "gen1"
        if cloudkey_gen1:
            findings.append(
                _finding(
                    category="performance",
                    severity="MEDIUM",
                    title="Cloud Key Gen1 resource constraints",
                    detail="Cloud Key Gen1 model detected, which can be resource-constrained on larger sites.",
                    recommendation="Consider migrating controller role to Cloud Key Gen2+/self-hosted VM if site scale has grown.",
                    evidence={"models": platform_models},
                    cis_controls=["CIS 12.1"],
                    nist_controls=["CA-7", "SI-4"],
                )
            )
        elif platform_variant == "gen2-plus":
            findings.append(
                _finding(
                    category="hardening",
                    severity="LOW",
                    title="Cloud Key Gen2 Plus platform detected",
                    detail="Cloud Key Gen2 Plus markers detected; generally better suited for moderate environments than Gen1.",
                    recommendation="Keep firmware current and monitor storage health if Protect workloads share the same appliance.",
                    evidence={"models": platform_models},
                    cis_controls=["CIS 7.1"],
                    nist_controls=["CM-2"],
                )
            )
        if len(devices) >= 40:
            findings.append(
                _finding(
                    category="performance",
                    severity="MEDIUM",
                    title="Large device count on Cloud Key",
                    detail=f"{len(devices)} devices detected with Cloud Key platform markers.",
                    recommendation="Review controller CPU/RAM usage and consider moving controller to more capable hardware.",
                    evidence={"devices_count": len(devices)},
                    cis_controls=["CIS 12.1"],
                    nist_controls=["CA-7"],
                )
            )

        backup_schedule_marker = any(
            isinstance(cfg, dict)
            and any("backup" in str(k).lower() and _truthy(v) for k, v in cfg.items())
            for cfg in settings
        )
        if profile == "cis-nist" and not backup_schedule_marker:
            findings.append(
                _finding(
                    category="resilience",
                    severity="LOW",
                    title="Automatic backup schedule not verifiable",
                    detail="No explicit enabled backup schedule markers were found in parsed settings.",
                    recommendation="Verify automatic backups are enabled and exported off-controller.",
                    evidence={"platform": platform},
                    cis_controls=["CIS 11.3"],
                    nist_controls=["CP-9"],
                )
            )

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

    stats = {
        "collections_seen": len(collections),
        "users_count": len(users),
        "wlans_count": len(wlans),
        "networks_count": len(networks),
        "devices_count": len(devices),
        "settings_count": len(settings),
        "findings_total": len(findings),
        "profile": profile,
        "schema": schema,
        "platform": platform,
        "platform_variant": platform_variant,
    }
    return AuditReport(
        backup_path=backup_path,
        profile=profile,
        score=score,
        grade=grade,
        findings=findings,
        stats=stats,
    )
