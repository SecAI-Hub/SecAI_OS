"""Tests for M19 — Network Traffic Analysis Protection.

Validates:
- Tor config: MaxCircuitDirtiness, ConnectionPadding
- Search mediator: query timing randomization, query padding
- DNS leak detection script exists and is well-formed
- DNS leak check timer/service exist
- nftables: tightened DNS rules with excess logging
- appliance.yaml has traffic_analysis_protection config
- recipe.yml enables dns-leak-check timer
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch

import yaml

REPO_ROOT = Path(__file__).parent.parent
TORRC_PATH = REPO_ROOT / "files" / "system" / "etc" / "secure-ai" / "tor" / "torrc"
SCRIPTS_DIR = REPO_ROOT / "files" / "system" / "usr" / "libexec" / "secure-ai"
SYSTEMD_DIR = REPO_ROOT / "files" / "system" / "usr" / "lib" / "systemd" / "system"
NFTABLES_PATH = REPO_ROOT / "files" / "system" / "etc" / "nftables" / "secure-ai.nft"
CONFIG_PATH = REPO_ROOT / "files" / "system" / "etc" / "secure-ai" / "config" / "appliance.yaml"
RECIPE_PATH = REPO_ROOT / "recipes" / "recipe.yml"

# Add search-mediator to path for imports
_search_mediator_dir = str(REPO_ROOT / "services" / "search-mediator")
if _search_mediator_dir not in sys.path:
    sys.path.insert(0, _search_mediator_dir)

# Also need services/ for common.audit_chain
_services_root = str(REPO_ROOT / "services")
if _services_root not in sys.path:
    sys.path.insert(0, _services_root)


class TestTorConfig:
    def test_max_circuit_dirtiness_reduced(self):
        content = TORRC_PATH.read_text()
        assert "MaxCircuitDirtiness 30" in content

    def test_connection_padding_enabled(self):
        content = TORRC_PATH.read_text()
        assert "ConnectionPadding 1" in content

    def test_reduced_padding_disabled(self):
        content = TORRC_PATH.read_text()
        assert "ReducedConnectionPadding 0" in content

    def test_isolate_dest_addr(self):
        content = TORRC_PATH.read_text()
        lines = [line.split() for line in content.splitlines() if line.strip() and not line.lstrip().startswith("#")]
        listeners = [line for line in lines if line[0] == "SocksPort"]
        assert len(listeners) == 1
        assert listeners[0][1] == "127.0.0.1:9050"
        assert {"IsolateDestAddr", "IsolateDestPort"} <= set(listeners[0][2:])
        assert not any(line[0] in {"IsolateDestAddr", "IsolateDestPort"} for line in lines)

    def test_safe_logging(self):
        content = TORRC_PATH.read_text()
        assert "SafeLogging 1" in content

    def test_sandbox_enabled(self):
        content = TORRC_PATH.read_text()
        assert "Sandbox 1" in content


class TestQueryPadding:
    def test_pad_short_query(self):
        import app as sm_module
        # A short query should be padded to 256 bytes
        result = sm_module.pad_query("hello world")
        assert len(result.encode("utf-8")) == 256

    def test_pad_medium_query(self):
        import app as sm_module
        # A query > 256 bytes should pad to 512
        query = "a" * 300
        result = sm_module.pad_query(query)
        assert len(result.encode("utf-8")) == 512

    def test_pad_large_query(self):
        import app as sm_module
        # A query > 512 bytes should pad to 1024
        query = "b" * 600
        result = sm_module.pad_query(query)
        assert len(result.encode("utf-8")) == 1024

    def test_pad_exact_bucket(self):
        import app as sm_module
        # Exactly 256 bytes — no extra padding needed
        query = "c" * 256
        result = sm_module.pad_query(query)
        assert len(result.encode("utf-8")) == 256

    def test_pad_over_largest_bucket(self):
        import app as sm_module
        # Over 1024 — returned as-is (no padding possible)
        query = "d" * 2000
        result = sm_module.pad_query(query)
        assert result == query

    def test_pad_preserves_query_content(self):
        import app as sm_module
        query = "test search query"
        result = sm_module.pad_query(query)
        assert result.startswith(query)
        assert result.strip() == query  # padding is whitespace


class TestQueryTimingConstants:
    def test_delay_min_exists(self):
        import app as sm_module
        assert hasattr(sm_module, "QUERY_DELAY_MIN")
        assert sm_module.QUERY_DELAY_MIN >= 0

    def test_delay_max_exists(self):
        import app as sm_module
        assert hasattr(sm_module, "QUERY_DELAY_MAX")
        assert sm_module.QUERY_DELAY_MAX > sm_module.QUERY_DELAY_MIN

    def test_pad_buckets_defined(self):
        import app as sm_module
        assert hasattr(sm_module, "QUERY_PAD_BUCKETS")
        assert sm_module.QUERY_PAD_BUCKETS == [256, 512, 1024]

    def test_random_delay_function_exists(self):
        import app as sm_module
        assert callable(sm_module._random_delay)

    def test_random_delay_sleeps(self):
        import app as sm_module
        with patch.object(sm_module.time, "sleep") as mock_sleep:
            with patch.object(sm_module._privacy_random, "uniform", return_value=1.5):
                delay = sm_module._random_delay()
                mock_sleep.assert_called_once_with(1.5)
                assert delay == 1.5


class TestDNSLeakDetection:
    def test_script_exists(self):
        assert (SCRIPTS_DIR / "check-dns-leak.sh").exists()

    def test_script_executable(self):
        assert os.access(SCRIPTS_DIR / "check-dns-leak.sh", os.X_OK)

    def test_checks_direct_dns(self):
        content = (SCRIPTS_DIR / "check-dns-leak.sh").read_text()
        assert "dig" in content or "nslookup" in content

    def test_no_automatic_tor_probe(self):
        content = (SCRIPTS_DIR / "check-dns-leak.sh").read_text()
        assert "socks5" not in content
        assert "curl " not in content

    def test_live_scope_guard_replaces_rule_grep(self):
        content = (SCRIPTS_DIR / "check-dns-leak.sh").read_text()
        assert "require-maintenance" in content
        assert "nft list ruleset" not in content

    def test_diagnostic_does_not_publish_offline_success(self):
        content = (SCRIPTS_DIR / "check-dns-leak.sh").read_text()
        assert '"dns_leak_detected":None' in content
        assert "maintenance_diagnostic" in content
        assert "dns-leak-check.json" not in content

    def test_selected_search_policy_is_not_runtime_authority(self):
        content = (SCRIPTS_DIR / "check-dns-leak.sh").read_text()
        assert "policy.yaml" not in content
        assert content.index("require-maintenance") < content.index("dig +short")


class TestDNSLeakTimer:
    def test_service_exists(self):
        assert (SYSTEMD_DIR / "secure-ai-dns-leak-check.service").exists()

    def test_timer_exists(self):
        assert (SYSTEMD_DIR / "secure-ai-dns-leak-check.timer").exists()

    def test_timer_interval(self):
        content = (SYSTEMD_DIR / "secure-ai-dns-leak-check.timer").read_text()
        assert "OnUnitActiveSec=60min" in content

    def test_service_is_oneshot(self):
        content = (SYSTEMD_DIR / "secure-ai-dns-leak-check.service").read_text()
        assert "Type=oneshot" in content

    def test_service_has_sandboxing(self):
        content = (SYSTEMD_DIR / "secure-ai-dns-leak-check.service").read_text()
        assert "NoNewPrivileges=yes" in content
        assert "ProtectHome=yes" in content
        assert "LimitCORE=0" in content


class TestNftablesDNS:
    def test_no_implicit_rate_limited_dns_exception(self):
        content = NFTABLES_PATH.read_text()
        assert "dport 53 limit rate" not in content
        assert "flags timeout" in content

    def test_direct_dns_requires_airlock_identity_and_full_scope(self):
        content = NFTABLES_PATH.read_text()
        assert "meta skuid $AIRLOCK_UID udp dport 53 meta nfproto @full accept" in content
        assert "meta skuid $AIRLOCK_UID udp dport 53 meta protocol @full accept" in content

    def test_host_dns_requires_maintenance_scope(self):
        content = NFTABLES_PATH.read_text()
        assert "udp dport { 53, 123 } meta nfproto @maintenance accept" in content
        assert "udp dport { 53, 123 } meta protocol @maintenance accept" in content

    def test_default_policy_drop(self):
        content = NFTABLES_PATH.read_text()
        assert "policy drop" in content


class TestApplianceConfig:
    def test_traffic_analysis_section(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert "traffic_analysis_protection" in config

    def test_query_delay_min(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["traffic_analysis_protection"]["query_delay_min"] == 0.5

    def test_query_delay_max(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["traffic_analysis_protection"]["query_delay_max"] == 3.0

    def test_pad_buckets(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["traffic_analysis_protection"]["query_pad_buckets"] == [256, 512, 1024]

    def test_tor_circuit_dirtiness(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["traffic_analysis_protection"]["tor_max_circuit_dirtiness"] == 30

    def test_tor_padding_enabled(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["traffic_analysis_protection"]["tor_connection_padding"] is True

    def test_dns_check_interval(self):
        config = yaml.safe_load(CONFIG_PATH.read_text())
        assert config["traffic_analysis_protection"]["dns_leak_check_interval"] == 60


class TestRecipeIncludes:
    def test_dns_probe_timer_disabled_by_default(self):
        recipe = yaml.safe_load(RECIPE_PATH.read_text())
        systemd_module = next(m for m in recipe["modules"] if m.get("type") == "systemd")
        enabled = systemd_module["system"]["enabled"]
        assert "secure-ai-dns-leak-check.timer" not in enabled
        assert "secure-ai-dns-leak-check.timer" in systemd_module["system"]["disabled"]
