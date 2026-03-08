"""Tests for M20 — Differential Privacy for Search Queries.

Validates:
- Decoy query list and generation
- Query uniqueness / k-anonymity detection
- Decoy search dispatching
- DP config loading from policy.yaml
- Policy file has differential_privacy section
- Search route integrates DP checks
"""

import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

REPO_ROOT = Path(__file__).parent.parent
POLICY_PATH = REPO_ROOT / "files" / "system" / "etc" / "secure-ai" / "policy" / "policy.yaml"
CONFIG_PATH = REPO_ROOT / "files" / "system" / "etc" / "secure-ai" / "config" / "appliance.yaml"

# Add search-mediator and services/ to path
_search_mediator_dir = str(REPO_ROOT / "services" / "search-mediator")
if _search_mediator_dir not in sys.path:
    sys.path.insert(0, _search_mediator_dir)

_services_root = str(REPO_ROOT / "services")
if _services_root not in sys.path:
    sys.path.insert(0, _services_root)


class TestDecoyQueries:
    def test_decoy_list_exists(self):
        import app as sm
        assert hasattr(sm, "DECOY_QUERIES")
        assert len(sm.DECOY_QUERIES) >= 10

    def test_decoy_list_has_diverse_topics(self):
        import app as sm
        topics = set()
        for q in sm.DECOY_QUERIES:
            topics.add(q.split()[0].lower())
        # Should have at least 8 distinct first-words (diverse topics)
        assert len(topics) >= 8

    def test_generate_decoy_queries_count(self):
        import app as sm
        decoys = sm.generate_decoy_queries(2)
        assert len(decoys) == 2

    def test_generate_decoy_queries_no_duplicates(self):
        import app as sm
        decoys = sm.generate_decoy_queries(5)
        assert len(set(decoys)) == 5

    def test_generate_decoy_queries_capped(self):
        import app as sm
        # Cannot exceed the list size
        decoys = sm.generate_decoy_queries(100)
        assert len(decoys) == len(sm.DECOY_QUERIES)

    def test_generate_decoy_queries_zero(self):
        import app as sm
        decoys = sm.generate_decoy_queries(0)
        assert len(decoys) == 0


class TestQueryUniqueness:
    def test_normal_query_not_unique(self):
        import app as sm
        result = sm.check_query_uniqueness("weather forecast today")
        assert result["unique"] is False
        assert result["matches"] == []

    def test_proper_name_detected(self):
        import app as sm
        result = sm.check_query_uniqueness("treatment for John Smith condition")
        assert result["unique"] is True
        assert any("John Smith" in m for m in result["matches"])

    def test_street_address_detected(self):
        import app as sm
        result = sm.check_query_uniqueness("directions to 123 Main St")
        assert result["unique"] is True

    def test_case_number_detected(self):
        import app as sm
        result = sm.check_query_uniqueness("status of case no 12345")
        assert result["unique"] is True

    def test_rare_disease_detected(self):
        import app as sm
        result = sm.check_query_uniqueness("treatment for rare disease symptoms")
        assert result["unique"] is True

    def test_generic_query_passes(self):
        import app as sm
        result = sm.check_query_uniqueness("how to make pasta")
        assert result["unique"] is False


class TestDecoySearchDispatch:
    def test_send_decoy_search_calls_searxng(self):
        import app as sm
        with patch.object(sm.requests, "get") as mock_get:
            mock_get.return_value = MagicMock(status_code=200)
            sm.send_decoy_search("weather forecast today")
            mock_get.assert_called_once()
            args, kwargs = mock_get.call_args
            assert "search" in args[0]
            assert "weather" in kwargs["params"]["q"]

    def test_send_decoy_search_ignores_errors(self):
        import app as sm
        with patch.object(sm.requests, "get", side_effect=Exception("timeout")):
            # Should not raise
            sm.send_decoy_search("test query")

    def test_run_decoy_searches_sends_correct_count(self):
        import app as sm
        with patch.object(sm, "send_decoy_search") as mock_send:
            with patch.object(sm.time, "sleep"):
                count = sm.run_decoy_searches(3)
                assert count == 3
                assert mock_send.call_count == 3

    def test_run_decoy_searches_zero(self):
        import app as sm
        with patch.object(sm, "send_decoy_search") as mock_send:
            count = sm.run_decoy_searches(0)
            assert count == 0
            mock_send.assert_not_called()


class TestDPConfigLoading:
    def test_load_dp_config_defaults(self):
        import app as sm
        with patch.object(sm, "load_policy", return_value={}):
            config = sm._load_dp_config()
            assert config["enabled"] is True
            assert config["decoy_count"] == 2
            assert config["uniqueness_mode"] == "warn"
            assert config["batch_window"] == 5.0

    def test_load_dp_config_from_policy(self):
        import app as sm
        policy = {
            "search": {
                "differential_privacy": {
                    "enabled": False,
                    "decoy_count": 0,
                    "uniqueness_mode": "auto-block",
                    "batch_window": 10.0,
                }
            }
        }
        with patch.object(sm, "load_policy", return_value=policy):
            config = sm._load_dp_config()
            assert config["enabled"] is False
            assert config["decoy_count"] == 0
            assert config["uniqueness_mode"] == "auto-block"
            assert config["batch_window"] == 10.0


class TestPolicyFile:
    def test_differential_privacy_section_exists(self):
        policy = yaml.safe_load(POLICY_PATH.read_text())
        assert "differential_privacy" in policy["search"]

    def test_dp_enabled(self):
        policy = yaml.safe_load(POLICY_PATH.read_text())
        dp = policy["search"]["differential_privacy"]
        assert dp["enabled"] is True

    def test_dp_decoy_count(self):
        policy = yaml.safe_load(POLICY_PATH.read_text())
        dp = policy["search"]["differential_privacy"]
        assert dp["decoy_count"] == 2

    def test_dp_uniqueness_mode(self):
        policy = yaml.safe_load(POLICY_PATH.read_text())
        dp = policy["search"]["differential_privacy"]
        assert dp["uniqueness_mode"] == "warn"

    def test_dp_batch_window(self):
        policy = yaml.safe_load(POLICY_PATH.read_text())
        dp = policy["search"]["differential_privacy"]
        assert dp["batch_window"] == 5.0


class TestQueryGeneralization:
    def test_medical_keyword_generalizes(self):
        import app as sm
        result = sm.generalize_query("treatment for headaches")
        assert result == "medical conditions"

    def test_legal_keyword_generalizes(self):
        import app as sm
        result = sm.generalize_query("find a lawyer near me")
        assert result == "legal services"

    def test_financial_keyword_generalizes(self):
        import app as sm
        result = sm.generalize_query("how to invest savings")
        assert result == "financial news"

    def test_mental_health_keyword_generalizes(self):
        import app as sm
        result = sm.generalize_query("dealing with anxiety")
        assert result == "mental health"

    def test_generic_query_no_generalization(self):
        import app as sm
        result = sm.generalize_query("best pasta recipes")
        assert result is None

    def test_category_keywords_map_exists(self):
        import app as sm
        assert hasattr(sm, "CATEGORY_KEYWORDS")
        assert len(sm.CATEGORY_KEYWORDS) >= 20


class TestBatchTiming:
    def test_apply_batch_delay_first_call_no_wait(self):
        import app as sm
        # Reset state
        sm._last_batch_time = 0.0
        with patch.object(sm.time, "sleep") as mock_sleep:
            delay = sm.apply_batch_delay(5.0)
            # First call after reset — no wait needed
            mock_sleep.assert_not_called()
            assert delay == 0.0

    def test_apply_batch_delay_waits_within_window(self):
        import app as sm
        sm._last_batch_time = time.time()  # just now
        with patch.object(sm.time, "sleep") as mock_sleep:
            with patch.object(sm.time, "time", side_effect=[
                sm._last_batch_time + 1.0,  # now (1s later)
                sm._last_batch_time + 5.0,  # after sleep
            ]):
                delay = sm.apply_batch_delay(5.0)
                mock_sleep.assert_called_once()
                assert delay > 0

    def test_send_cover_search_calls_decoy(self):
        import app as sm
        with patch.object(sm, "send_decoy_search") as mock_send:
            sm.send_cover_search("medical conditions")
            mock_send.assert_called_once_with("medical conditions")


class TestSearchRouteDP:
    def test_search_includes_decoys_sent(self):
        """The search response should include decoys_sent count."""
        import app as sm
        with sm.app.test_client() as client:
            with patch.object(sm, "_is_search_enabled", return_value=True), \
                 patch.object(sm, "_get_session_mode", return_value="normal"), \
                 patch.object(sm, "_random_delay", return_value=0.1), \
                 patch.object(sm, "run_decoy_searches", return_value=2), \
                 patch.object(sm, "send_cover_search"), \
                 patch.object(sm, "apply_batch_delay", return_value=0.0), \
                 patch.object(sm, "_load_dp_config", return_value={
                     "enabled": True, "decoy_count": 2,
                     "uniqueness_mode": "allow", "batch_window": 5.0,
                 }), \
                 patch.object(sm.requests, "get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = {"results": []}
                mock_get.return_value = mock_resp

                resp = client.post("/v1/search", json={"query": "test search"})
                assert resp.status_code == 200
                data = resp.get_json()
                assert data["decoys_sent"] == 2

    def test_unique_query_blocked_in_auto_block_mode(self):
        import app as sm
        with sm.app.test_client() as client:
            with patch.object(sm, "_is_search_enabled", return_value=True), \
                 patch.object(sm, "_get_session_mode", return_value="normal"), \
                 patch.object(sm, "_load_dp_config", return_value={
                     "enabled": True, "decoy_count": 0,
                     "uniqueness_mode": "auto-block", "batch_window": 5.0,
                 }):
                resp = client.post("/v1/search", json={
                    "query": "treatment for John Smith rare disease"
                })
                assert resp.status_code == 422
                data = resp.get_json()
                assert "unique" in data.get("error", "").lower() or "unique_matches" in data

    def test_unique_query_warns_in_warn_mode(self):
        import app as sm
        with sm.app.test_client() as client:
            with patch.object(sm, "_is_search_enabled", return_value=True), \
                 patch.object(sm, "_get_session_mode", return_value="normal"), \
                 patch.object(sm, "_random_delay", return_value=0.1), \
                 patch.object(sm, "run_decoy_searches", return_value=0), \
                 patch.object(sm, "send_cover_search"), \
                 patch.object(sm, "apply_batch_delay", return_value=0.0), \
                 patch.object(sm, "_load_dp_config", return_value={
                     "enabled": True, "decoy_count": 0,
                     "uniqueness_mode": "warn", "batch_window": 5.0,
                 }), \
                 patch.object(sm.requests, "get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = {"results": []}
                mock_get.return_value = mock_resp

                resp = client.post("/v1/search", json={
                    "query": "treatment for John Smith condition"
                })
                assert resp.status_code == 200
                data = resp.get_json()
                assert "uniqueness_warning" in data

    def test_dp_disabled_skips_checks(self):
        import app as sm
        with sm.app.test_client() as client:
            with patch.object(sm, "_is_search_enabled", return_value=True), \
                 patch.object(sm, "_get_session_mode", return_value="normal"), \
                 patch.object(sm, "_random_delay", return_value=0.1), \
                 patch.object(sm, "_load_dp_config", return_value={
                     "enabled": False, "decoy_count": 0,
                     "uniqueness_mode": "auto-block", "batch_window": 5.0,
                 }), \
                 patch.object(sm, "run_decoy_searches") as mock_decoys, \
                 patch.object(sm.requests, "get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = {"results": []}
                mock_get.return_value = mock_resp

                resp = client.post("/v1/search", json={
                    "query": "treatment for John Smith rare disease"
                })
                # Should succeed because DP is disabled
                assert resp.status_code == 200
                mock_decoys.assert_not_called()

    def test_cover_search_sent_for_sensitive_query(self):
        import app as sm
        with sm.app.test_client() as client:
            with patch.object(sm, "_is_search_enabled", return_value=True), \
                 patch.object(sm, "_get_session_mode", return_value="normal"), \
                 patch.object(sm, "_random_delay", return_value=0.1), \
                 patch.object(sm, "run_decoy_searches", return_value=0), \
                 patch.object(sm, "send_cover_search") as mock_cover, \
                 patch.object(sm, "apply_batch_delay", return_value=0.0), \
                 patch.object(sm, "_load_dp_config", return_value={
                     "enabled": True, "decoy_count": 0,
                     "uniqueness_mode": "allow", "batch_window": 5.0,
                 }), \
                 patch.object(sm.requests, "get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = {"results": []}
                mock_get.return_value = mock_resp

                resp = client.post("/v1/search", json={
                    "query": "treatment for headaches"
                })
                assert resp.status_code == 200
                mock_cover.assert_called_once_with("medical conditions")
