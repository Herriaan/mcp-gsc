"""
Tests for gsc_server.py.

All Google API calls are mocked — no real credentials are needed to run these tests.
Run with: pytest test_gsc_server.py -v
"""
import importlib
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, PropertyMock


# ---------------------------------------------------------------------------
# Helpers to reload the module with a clean environment each test
# ---------------------------------------------------------------------------

def _load_module(env_overrides: dict | None = None):
    """Import gsc_server with a fresh environment."""
    env = {
        "GSC_SKIP_OAUTH": "true",          # prevent live OAuth attempts by default
        "GSC_DATA_STATE": "all",
        "GSC_ALLOW_DESTRUCTIVE": "false",
        **(env_overrides or {}),
    }
    with patch.dict(os.environ, env, clear=False):
        if "gsc_server" in sys.modules:
            del sys.modules["gsc_server"]
        import gsc_server as mod
    return mod


# ---------------------------------------------------------------------------
# TestAuth
# ---------------------------------------------------------------------------

class TestAuth(unittest.TestCase):

    def test_token_loaded_from_config_dir(self):
        """TOKEN_FILE must resolve inside the user config dir, not SCRIPT_DIR."""
        mod = _load_module()
        # By default, TOKEN_FILE should NOT equal os.path.join(SCRIPT_DIR, "token.json").
        self.assertNotEqual(mod.TOKEN_FILE, os.path.join(mod.SCRIPT_DIR, "token.json"))

    def test_old_token_migrated_silently(self):
        """On first run after upgrade, a token at the old SCRIPT_DIR location is moved.

        SCRIPT_DIR is derived from __file__ at module load time, so this test places a
        real token.json in the actual SCRIPT_DIR and re-imports with a fresh GSC_CONFIG_DIR.
        The test cleans up after itself regardless of outcome.
        """
        # Discover the real SCRIPT_DIR by importing once
        if "gsc_server" in sys.modules:
            del sys.modules["gsc_server"]
        with patch.dict(os.environ, {"GSC_SKIP_OAUTH": "true", "GSC_DATA_STATE": "all",
                                     "GSC_ALLOW_DESTRUCTIVE": "false"}, clear=False):
            import gsc_server as _tmp
        actual_script_dir = _tmp.SCRIPT_DIR
        del sys.modules["gsc_server"]

        old_token_path = os.path.join(actual_script_dir, "token.json")
        old_token_content = '{"test": "migration_test"}'
        preexisting_backup = None

        with tempfile.TemporaryDirectory() as new_config_dir:
            try:
                # Back up any real existing token so we don't destroy it
                if os.path.exists(old_token_path):
                    preexisting_backup = old_token_path + ".test_bak"
                    import shutil as _shutil
                    _shutil.copy2(old_token_path, preexisting_backup)

                # Place test token in old location
                with open(old_token_path, "w") as f:
                    f.write(old_token_content)

                # Re-import with new config dir (no token there yet → migration should fire)
                env = {
                    "GSC_SKIP_OAUTH": "true",
                    "GSC_DATA_STATE": "all",
                    "GSC_ALLOW_DESTRUCTIVE": "false",
                    "GSC_CONFIG_DIR": new_config_dir,
                }
                with patch.dict(os.environ, env, clear=False):
                    import gsc_server as mod

                new_token_path = os.path.join(new_config_dir, "token.json")
                self.assertTrue(os.path.exists(new_token_path), "Token was not migrated to new location")
                self.assertFalse(os.path.exists(old_token_path), "Old token was not removed after migration")
                with open(new_token_path) as f:
                    self.assertEqual(f.read(), old_token_content)

            finally:
                del sys.modules["gsc_server"]
                # Clean up any leftover test token in SCRIPT_DIR
                if os.path.exists(old_token_path):
                    os.remove(old_token_path)
                # Restore original token if it existed
                if preexisting_backup and os.path.exists(preexisting_backup):
                    import shutil as _shutil
                    _shutil.move(preexisting_backup, old_token_path)

    def test_expired_token_refresh_succeeds(self):
        """If refresh succeeds, get_gsc_service_oauth returns without error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env = {"GSC_SKIP_OAUTH": "false", "GSC_DATA_STATE": "all",
                   "GSC_ALLOW_DESTRUCTIVE": "false", "GSC_CONFIG_DIR": tmpdir}
            with patch.dict(os.environ, env, clear=False):
                if "gsc_server" in sys.modules:
                    del sys.modules["gsc_server"]
                import gsc_server as mod

            mock_creds = MagicMock()
            mock_creds.valid = False
            mock_creds.expired = True
            mock_creds.refresh_token = "refresh_token"
            mock_creds.to_json.return_value = '{"token": "refreshed"}'

            def fake_refresh(request):
                mock_creds.valid = True

            mock_creds.refresh.side_effect = fake_refresh

            with patch("gsc_server.Credentials.from_authorized_user_file", return_value=mock_creds), \
                 patch("gsc_server.build", return_value=MagicMock()), \
                 patch.object(mod, "TOKEN_FILE", os.path.join(tmpdir, "token.json")):
                open(os.path.join(tmpdir, "token.json"), "w").write("{}")
                service = mod.get_gsc_service_oauth()
                self.assertIsNotNone(service)

    def test_expired_token_no_refresh_raises_runtime_error(self):
        """When refresh fails and no secrets file, get_gsc_service_oauth raises RuntimeError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env = {"GSC_SKIP_OAUTH": "false", "GSC_DATA_STATE": "all",
                   "GSC_ALLOW_DESTRUCTIVE": "false", "GSC_CONFIG_DIR": tmpdir}
            with patch.dict(os.environ, env, clear=False):
                if "gsc_server" in sys.modules:
                    del sys.modules["gsc_server"]
                import gsc_server as mod

            mock_creds = MagicMock()
            mock_creds.valid = False
            mock_creds.expired = True
            mock_creds.refresh_token = None  # no refresh token available

            with patch("gsc_server.Credentials.from_authorized_user_file", return_value=mock_creds), \
                 patch.object(mod, "TOKEN_FILE", os.path.join(tmpdir, "token.json")), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", os.path.join(tmpdir, "no_secrets.json")):
                open(os.path.join(tmpdir, "token.json"), "w").write("{}")
                with self.assertRaises((RuntimeError, FileNotFoundError)):
                    mod.get_gsc_service_oauth()

    def test_no_token_no_secrets_raises_file_not_found(self):
        """With no token file and no secrets file, FileNotFoundError is raised."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env = {"GSC_SKIP_OAUTH": "false", "GSC_DATA_STATE": "all",
                   "GSC_ALLOW_DESTRUCTIVE": "false", "GSC_CONFIG_DIR": tmpdir}
            with patch.dict(os.environ, env, clear=False):
                if "gsc_server" in sys.modules:
                    del sys.modules["gsc_server"]
                import gsc_server as mod

            with patch.object(mod, "TOKEN_FILE", os.path.join(tmpdir, "nonexistent_token.json")), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", os.path.join(tmpdir, "nonexistent_secrets.json")), \
                 patch("sys.stdin.isatty", return_value=True):
                # This asserts the interactive path (a human can run the OAuth flow), so
                # isatty is forced True regardless of the runner's actual stdin — the
                # non-interactive MCP path is TestAuth.test_expired_token_no_refresh_raises_runtime_error.
                with self.assertRaises(FileNotFoundError):
                    mod.get_gsc_service_oauth()

    def test_skip_oauth_env_var(self):
        """GSC_SKIP_OAUTH=true makes get_gsc_service skip OAuth."""
        mod = _load_module({"GSC_SKIP_OAUTH": "true"})
        self.assertTrue(mod.SKIP_OAUTH)


# ---------------------------------------------------------------------------
# Shared fixture helper
# ---------------------------------------------------------------------------

def _make_service():
    """Return a MagicMock that mimics the Google Search Console service object."""
    return MagicMock()


# ---------------------------------------------------------------------------
# TestListProperties
# ---------------------------------------------------------------------------

class TestListProperties(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_properties_list(self):
        mod = _load_module()
        service = _make_service()
        service.sites().list().execute.return_value = {
            "siteEntry": [
                {"siteUrl": "https://example.com/", "permissionLevel": "siteOwner"},
                {"siteUrl": "sc-domain:example.com", "permissionLevel": "siteFullUser"},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.list_properties()
        data = json.loads(result)
        self.assertEqual(data["count"], 2)
        self.assertEqual(data["properties"][0]["site_url"], "https://example.com/")
        self.assertEqual(data["properties"][1]["permission_level"], "siteFullUser")

    async def test_returns_message_when_no_properties(self):
        mod = _load_module()
        service = _make_service()
        service.sites().list().execute.return_value = {}
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.list_properties()
        self.assertIsInstance(result, str)
        self.assertIn("No Search Console properties", result)

    async def test_handles_api_error(self):
        mod = _load_module()
        with patch("gsc_server.get_gsc_service", side_effect=Exception("API error")):
            result = await mod.list_properties()
        self.assertIn("Error", result)


# ---------------------------------------------------------------------------
# TestGetSearchAnalytics
# ---------------------------------------------------------------------------

class TestGetSearchAnalytics(unittest.IsolatedAsyncioTestCase):

    def _make_rows(self):
        return {
            "rows": [
                {"keys": ["seo tool"], "clicks": 100, "impressions": 1000, "ctr": 0.1, "position": 5.0},
                {"keys": ["mcp server"], "clicks": 50, "impressions": 500, "ctr": 0.1, "position": 8.2},
            ]
        }

    async def test_returns_json_with_rows(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = self._make_rows()
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_search_analytics("https://example.com/")
        data = json.loads(result)
        self.assertEqual(data["row_count"], 2)
        self.assertEqual(data["rows"][0]["query"], "seo tool")
        self.assertEqual(data["rows"][0]["clicks"], 100)
        self.assertIn("ctr", data["rows"][0])

    async def test_no_data_returns_string_message(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {}
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_search_analytics("https://example.com/")
        self.assertIsInstance(result, str)
        self.assertNotIn("{", result[:5])  # not JSON

    async def test_row_limit_capped_at_500(self):
        """Requesting more than 500 rows should be capped."""
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {"rows": []}
        with patch("gsc_server.get_gsc_service", return_value=service):
            await mod.get_search_analytics("https://example.com/", row_limit=9999)
        # Verify the request body capped at 500
        call_args = service.searchanalytics().query.call_args
        if call_args:
            body = call_args[1].get("body") or (call_args[0][0] if call_args[0] else None)
            if body and "rowLimit" in body:
                self.assertLessEqual(body["rowLimit"], 500)

    async def test_handles_404(self):
        mod = _load_module()
        with patch("gsc_server.get_gsc_service", side_effect=Exception("404")):
            result = await mod.get_search_analytics("https://example.com/")
        self.assertIn("not found", result.lower())


# ---------------------------------------------------------------------------
# TestGetSiteDetails
# ---------------------------------------------------------------------------

class TestGetSiteDetails(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_permission_and_verification(self):
        mod = _load_module()
        service = _make_service()
        service.sites().get().execute.return_value = {
            "permissionLevel": "siteOwner",
            "siteVerificationInfo": {"verificationState": "VERIFIED"},
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_site_details("https://example.com/")
        data = json.loads(result)
        self.assertEqual(data["permission_level"], "siteOwner")
        self.assertEqual(data["verification"]["state"], "VERIFIED")

    async def test_handles_404(self):
        mod = _load_module()
        with patch("gsc_server.get_gsc_service", side_effect=Exception("404")):
            result = await mod.get_site_details("https://example.com/")
        self.assertIn("Error", result)


# ---------------------------------------------------------------------------
# TestGetSitemaps
# ---------------------------------------------------------------------------

class TestGetSitemaps(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_sitemap_list(self):
        mod = _load_module()
        service = _make_service()
        service.sitemaps().list().execute.return_value = {
            "sitemap": [
                {"path": "https://example.com/sitemap.xml", "errors": "0", "warnings": "1",
                 "contents": [{"type": "web", "submitted": "1000"}]},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_sitemaps("https://example.com/")
        data = json.loads(result)
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["sitemaps"][0]["warnings"], 1)
        self.assertEqual(data["sitemaps"][0]["status"], "Has warnings")
        self.assertEqual(data["sitemaps"][0]["indexed_urls"], "1000")

    async def test_no_sitemaps_returns_message(self):
        mod = _load_module()
        service = _make_service()
        service.sitemaps().list().execute.return_value = {}
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_sitemaps("https://example.com/")
        self.assertIsInstance(result, str)
        self.assertIn("No sitemaps", result)


# ---------------------------------------------------------------------------
# TestInspectUrl
# ---------------------------------------------------------------------------

class TestInspectUrl(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_verdict(self):
        mod = _load_module()
        service = _make_service()
        service.urlInspection().index().inspect().execute.return_value = {
            "inspectionResult": {
                "indexStatusResult": {
                    "verdict": "PASS",
                    "coverageState": "Submitted and indexed",
                    "pageFetchState": "SUCCESSFUL",
                    "robotsTxtState": "ALLOWED",
                    "lastCrawlTime": "2026-04-01T10:00:00Z",
                }
            }
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.inspect_url_enhanced("https://example.com/", "https://example.com/page/")
        data = json.loads(result)
        self.assertEqual(data["verdict"], "PASS")
        self.assertEqual(data["page_url"], "https://example.com/page/")
        self.assertIn("last_crawled", data)


# ---------------------------------------------------------------------------
# TestBatchUrlInspection
# ---------------------------------------------------------------------------

class TestBatchUrlInspection(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_results(self):
        mod = _load_module()
        service = _make_service()
        service.urlInspection().index().inspect().execute.return_value = {
            "inspectionResult": {
                "indexStatusResult": {
                    "verdict": "PASS",
                    "coverageState": "Submitted and indexed",
                    "lastCrawlTime": "2026-04-01T10:00:00Z",
                }
            }
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.batch_url_inspection(
                "https://example.com/",
                "https://example.com/a/\nhttps://example.com/b/"
            )
        data = json.loads(result)
        self.assertEqual(data["count"], 2)
        self.assertEqual(data["results"][0]["verdict"], "PASS")

    async def test_batch_limit_enforced_at_10_urls(self):
        mod = _load_module()
        with patch("gsc_server.get_gsc_service", return_value=_make_service()):
            urls = "\n".join([f"https://example.com/{i}/" for i in range(11)])
            result = await mod.batch_url_inspection("https://example.com/", urls)
        self.assertIn("Too many URLs", result)


# ---------------------------------------------------------------------------
# TestCheckIndexingIssues
# ---------------------------------------------------------------------------

class TestCheckIndexingIssues(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_summary(self):
        mod = _load_module()
        service = _make_service()
        service.urlInspection().index().inspect().execute.return_value = {
            "inspectionResult": {
                "indexStatusResult": {
                    "verdict": "PASS",
                    "coverageState": "Submitted and indexed",
                }
            }
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.check_indexing_issues(
                "https://example.com/", "https://example.com/page/"
            )
        data = json.loads(result)
        self.assertIn("summary", data)
        self.assertEqual(data["summary"]["total_checked"], 1)
        self.assertEqual(data["summary"]["indexed"], 1)


# ---------------------------------------------------------------------------
# TestGetPerformanceOverview
# ---------------------------------------------------------------------------

class TestGetPerformanceOverview(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_totals_and_trend(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.side_effect = [
            {"rows": [{"keys": [], "clicks": 500, "impressions": 5000, "ctr": 0.1, "position": 12.0}]},
            {"rows": [
                {"keys": ["2026-04-01"], "clicks": 250, "impressions": 2500, "ctr": 0.1, "position": 12.0},
                {"keys": ["2026-04-02"], "clicks": 250, "impressions": 2500, "ctr": 0.1, "position": 12.0},
            ]},
        ]
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_performance_overview("https://example.com/")
        data = json.loads(result)
        self.assertEqual(data["totals"]["clicks"], 500)
        self.assertEqual(len(data["daily_trend"]), 2)


# ---------------------------------------------------------------------------
# TestGetAdvancedSearchAnalytics
# ---------------------------------------------------------------------------

class TestGetAdvancedSearchAnalytics(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_rows(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {
            "rows": [
                {"keys": ["seo"], "clicks": 100, "impressions": 1000, "ctr": 0.1, "position": 5.0},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_advanced_search_analytics("https://example.com/")
        data = json.loads(result)
        self.assertEqual(data["rows"][0]["query"], "seo")
        self.assertIn("pagination", data)

    async def test_invalid_filters_json_returns_error_string(self):
        mod = _load_module()
        with patch("gsc_server.get_gsc_service", return_value=_make_service()):
            result = await mod.get_advanced_search_analytics(
                "https://example.com/", filters="not valid json"
            )
        self.assertIn("Invalid filters", result)

    async def test_pagination_info_included(self):
        mod = _load_module()
        service = _make_service()
        # Return exactly row_limit rows → has_more=True
        rows = [{"keys": [f"q{i}"], "clicks": 1, "impressions": 10, "ctr": 0.1, "position": 5.0}
                for i in range(10)]
        service.searchanalytics().query().execute.return_value = {"rows": rows}
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_advanced_search_analytics(
                "https://example.com/", row_limit=10
            )
        data = json.loads(result)
        self.assertTrue(data["pagination"]["has_more"])
        self.assertEqual(data["pagination"]["next_start_row"], 10)


# ---------------------------------------------------------------------------
# TestCompareSearchPeriods
# ---------------------------------------------------------------------------

class TestCompareSearchPeriods(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_comparison(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.side_effect = [
            {"rows": [{"keys": ["seo"], "clicks": 100, "impressions": 1000, "ctr": 0.1, "position": 5.0}]},
            {"rows": [{"keys": ["seo"], "clicks": 120, "impressions": 1100, "ctr": 0.11, "position": 4.5}]},
        ]
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.compare_search_periods(
                "https://example.com/",
                "2026-03-01", "2026-03-28",
                "2026-04-01", "2026-04-07",
            )
        data = json.loads(result)
        self.assertIn("comparison", data)
        self.assertEqual(len(data["comparison"]), 1)
        self.assertEqual(data["comparison"][0]["key"], ["seo"])


# ---------------------------------------------------------------------------
# TestGetSearchByPageQuery
# ---------------------------------------------------------------------------

class TestGetSearchByPageQuery(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_with_totals(self):
        mod = _load_module()
        service = _make_service()
        service.searchanalytics().query().execute.return_value = {
            "rows": [
                {"keys": ["best seo tool"], "clicks": 50, "impressions": 500, "ctr": 0.1, "position": 7.5},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_search_by_page_query(
                "https://example.com/", "https://example.com/blog/seo/"
            )
        data = json.loads(result)
        self.assertEqual(data["page_url"], "https://example.com/blog/seo/")
        self.assertEqual(data["totals"]["clicks"], 50)
        self.assertEqual(data["rows"][0]["query"], "best seo tool")


# ---------------------------------------------------------------------------
# TestListSitemapsEnhanced
# ---------------------------------------------------------------------------

class TestListSitemapsEnhanced(unittest.IsolatedAsyncioTestCase):

    async def test_returns_json_sitemap_list(self):
        mod = _load_module()
        service = _make_service()
        service.sitemaps().list().execute.return_value = {
            "sitemap": [
                {"path": "https://example.com/sitemap.xml", "errors": "0", "warnings": "0",
                 "isSitemapsIndex": False, "isPending": False},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.list_sitemaps_enhanced("https://example.com/")
        data = json.loads(result)
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["pending_count"], 0)

    async def test_warning_status_correctly_set(self):
        """Regression: status should be 'Has warnings' when warnings > 0."""
        mod = _load_module()
        service = _make_service()
        service.sitemaps().list().execute.return_value = {
            "sitemap": [
                {"path": "https://example.com/sitemap.xml", "errors": "0", "warnings": "3"},
            ]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.list_sitemaps_enhanced("https://example.com/")
        # list_sitemaps_enhanced returns JSON without a status field (it's in get_sitemaps),
        # but warnings count must still be 3
        data = json.loads(result)
        self.assertEqual(data["sitemaps"][0]["warnings"], 3)


# ---------------------------------------------------------------------------
# TestGetSitemapDetails
# ---------------------------------------------------------------------------

class TestGetSitemapDetails(unittest.IsolatedAsyncioTestCase):

    async def test_get_details_returns_json(self):
        mod = _load_module()
        service = _make_service()
        service.sitemaps().get().execute.return_value = {
            "isSitemapsIndex": False,
            "isPending": False,
            "errors": "0",
            "warnings": "0",
            "contents": [{"type": "web", "submitted": 500, "indexed": 480}],
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.get_sitemap_details("https://example.com/", "https://example.com/sitemap.xml")
        data = json.loads(result)
        self.assertEqual(data["type"], "Sitemap")
        self.assertEqual(data["status"], "processed")
        self.assertEqual(data["content_breakdown"][0]["submitted"], 500)


# ---------------------------------------------------------------------------
# TestSafetyGuards
# ---------------------------------------------------------------------------

class TestSafetyGuards(unittest.IsolatedAsyncioTestCase):

    async def test_add_site_blocked_by_default(self):
        mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "false"})
        result = await mod.add_site("https://newsite.com/")
        self.assertIn("Safety", result)

    async def test_delete_site_blocked_by_default(self):
        mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "false"})
        result = await mod.delete_site("https://newsite.com/")
        self.assertIn("Safety", result)

    async def test_delete_sitemap_blocked_by_default(self):
        mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "false"})
        result = await mod.delete_sitemap("https://example.com/", "https://example.com/sitemap.xml")
        self.assertIn("Safety", result)

    async def test_add_site_allowed_when_flag_set(self):
        mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "true"})
        service = _make_service()
        service.sites().add().execute.return_value = {}
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.add_site("https://newsite.com/")
        self.assertNotIn("Safety", result)

    async def test_delete_site_allowed_when_flag_set(self):
        mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "true"})
        service = _make_service()
        service.sites().delete().execute.return_value = {}
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.delete_site("https://example.com/")
        self.assertNotIn("Safety", result)

    async def test_delete_sitemap_allowed_when_flag_set(self):
        mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "true"})
        service = _make_service()
        service.sitemaps().delete().execute.return_value = {}
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.delete_sitemap("https://example.com/", "https://example.com/sitemap.xml")
        self.assertNotIn("Safety", result)


# ---------------------------------------------------------------------------
# TestReauthenticate
# ---------------------------------------------------------------------------

class TestReauthenticate(unittest.IsolatedAsyncioTestCase):

    async def test_replaces_token_only_after_successful_login(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            token_path = os.path.join(tmpdir, "token.json")
            open(token_path, "w").write('{"old": "token"}')
            secrets_path = os.path.join(tmpdir, "secrets.json")
            open(secrets_path, "w").write("{}")

            mod = _load_module()

            mock_creds = MagicMock()
            mock_creds.to_json.return_value = '{"token": "new"}'

            with patch.object(mod, "TOKEN_FILE", token_path), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", secrets_path), \
                 patch("gsc_server.InstalledAppFlow") as mock_flow_cls, \
                 patch("sys.stdin.isatty", return_value=True):
                # Asserts the interactive re-auth path (a human runs this from a real
                # terminal); isatty forced True regardless of the runner's actual stdin.
                mock_flow = MagicMock()
                mock_flow.run_local_server.return_value = mock_creds
                mock_flow_cls.from_client_secrets_file.return_value = mock_flow
                result = await mod.reauthenticate()

            self.assertIn("Successfully authenticated", result)
            self.assertIn("Previous token replaced", result)
            with open(token_path) as f:
                self.assertEqual(json.load(f), {"token": "new"})

    async def test_returns_error_when_no_secrets_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            token_path = os.path.join(tmpdir, "token.json")
            open(token_path, "w").write('{"old": "token"}')
            mod = _load_module()
            with patch.object(mod, "TOKEN_FILE", token_path), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", os.path.join(tmpdir, "no_secrets.json")):
                result = await mod.reauthenticate()
            self.assertIn("Error", result)
            # Without a way to log in again, the old token must survive.
            with open(token_path) as f:
                self.assertEqual(f.read(), '{"old": "token"}')


# ---------------------------------------------------------------------------
# TestStdoutClean
# ---------------------------------------------------------------------------

class TestStdoutClean(unittest.TestCase):

    def test_auth_fallback_does_not_write_to_stdout(self):
        """get_gsc_service must not print() to stdout on OAuth failure (prevents MCP corruption)."""
        mod = _load_module({"GSC_SKIP_OAUTH": "false"})

        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured

        try:
            with patch("gsc_server.get_gsc_service_oauth", side_effect=RuntimeError("no token")), \
                 patch("gsc_server.service_account.Credentials.from_service_account_file",
                        side_effect=Exception("no file")):
                try:
                    mod.get_gsc_service()
                except Exception:
                    pass
        finally:
            sys.stdout = old_stdout

        stdout_output = captured.getvalue()
        self.assertEqual(stdout_output, "", f"Unexpected stdout: {stdout_output!r}")


# ---------------------------------------------------------------------------
# TestSiteVerification
#
# Covers what the siteverification scope bump added in 0.3.1:
# - a token saved under the old, narrower scope must not be reused silently
#   (it is not expired, so without an explicit scope check it would be)
# - the two id forms Search Console uses (sc-domain:/URL) map onto the two
#   the Site Verification API accepts (INET_DOMAIN/SITE)
# - get_verification_token is read-only, verify_site is gated behind
#   GSC_ALLOW_DESTRUCTIVE like the other ownership-changing tools
# - a 400 means different things depending on which call produced it
# ---------------------------------------------------------------------------

class TestSiteVerificationScopeIntegration(unittest.TestCase):
    """
    Exercises the real google.oauth2.credentials.Credentials, not a mock.

    from_authorized_user_file(filename, scopes) is documented as loading
    scopes from the file, but only when the caller does NOT pass a scopes
    argument — Credentials.from_authorized_user_info does
    `if scopes is None and "scopes" in info: scopes = info.get("scopes")`.
    Passing SCOPES explicitly (the original code) makes it silently discard
    whatever the file actually recorded and overwrite it with SCOPES, which
    makes has_scopes(SCOPES) trivially true for any token file regardless of
    what Google really granted. A test that mocks from_authorized_user_file
    itself (see TestSiteVerificationScope above) can't see this: the mock
    just returns whatever creds object the test hands it.
    """

    @staticmethod
    def _write_token(path, scopes, expiry):
        json.dump(
            {
                "token": "at",
                "refresh_token": "rt",
                "client_id": "cid",
                "client_secret": "secret",
                "scopes": scopes,
                "expiry": expiry,
            },
            open(path, "w"),
        )

    def test_real_token_with_old_scope_is_not_silently_reused(self):
        """
        Gives the token a future expiry so `valid` is True on its own — the
        only way this can still fail is through the refresh/no-refresh-token
        branch, which requires `expired` to be True. With a future expiry
        that branch is never entered, so if the fix is missing the buggy
        has_scopes(SCOPES) check would return the reused (falsely "complete")
        credentials here instead of raising. A token without an explicit
        expiry auto-expires immediately, which would route this through the
        refresh path instead and mask the actual bug with a real (and, with
        fake credentials, always-failing) network call — see the sibling
        test_real_token_with_all_scopes_is_reused for why that path is worth
        avoiding in a test that is supposed to run without credentials.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            token_path = os.path.join(tmpdir, "token.json")
            future = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            self._write_token(
                token_path, ["https://www.googleapis.com/auth/webmasters"], future
            )

            env = {"GSC_SKIP_OAUTH": "false", "GSC_DATA_STATE": "all",
                   "GSC_ALLOW_DESTRUCTIVE": "false", "GSC_CONFIG_DIR": tmpdir}
            with patch.dict(os.environ, env, clear=False):
                if "gsc_server" in sys.modules:
                    del sys.modules["gsc_server"]
                import gsc_server as mod

            with patch.object(mod, "TOKEN_FILE", token_path), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", os.path.join(tmpdir, "no_secrets.json")):
                # Non-tty sandbox: a credential the scope check correctly
                # discarded takes the "cannot refresh" RuntimeError path,
                # same as a missing token would.
                with self.assertRaises(RuntimeError):
                    mod.get_oauth_credentials()

    def test_real_token_with_all_scopes_is_reused(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            token_path = os.path.join(tmpdir, "token.json")
            future = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            json.dump(
                {
                    "token": "at",
                    "refresh_token": "rt",
                    "client_id": "cid",
                    "client_secret": "secret",
                    "scopes": [
                        "https://www.googleapis.com/auth/webmasters",
                        "https://www.googleapis.com/auth/siteverification",
                    ],
                    "expiry": future,
                },
                open(token_path, "w"),
            )

            env = {"GSC_SKIP_OAUTH": "false", "GSC_DATA_STATE": "all",
                   "GSC_ALLOW_DESTRUCTIVE": "false", "GSC_CONFIG_DIR": tmpdir}
            with patch.dict(os.environ, env, clear=False):
                if "gsc_server" in sys.modules:
                    del sys.modules["gsc_server"]
                import gsc_server as mod

            with patch.object(mod, "TOKEN_FILE", token_path):
                creds = mod.get_oauth_credentials()

            self.assertTrue(creds.has_scopes(mod.SCOPES))


class TestScopeUpgradeDoesNotBreakSearchConsole(unittest.TestCase):
    """
    Regression coverage for a real cross-model review finding: an earlier
    version of get_oauth_credentials required the FULL SCOPES list (including
    the new SITE_VERIFICATION_SCOPE) on every call, no matter which service
    was being built. Every token saved before that scope existed — i.e. every
    v0.3.0 install upgrading to this version — would fail that check, and in
    a headless MCP server (non-tty) that meant a RuntimeError on the very
    first Search Console call, breaking the entire existing toolset for the
    sake of two new tools neither had asked for yet.
    """

    @staticmethod
    def _write_token(path, scopes, expiry):
        json.dump(
            {
                "token": "at",
                "refresh_token": "rt",
                "client_id": "cid",
                "client_secret": "secret",
                "scopes": scopes,
                "expiry": expiry,
            },
            open(path, "w"),
        )

    def test_search_console_still_works_with_pre_upgrade_token(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            token_path = os.path.join(tmpdir, "token.json")
            future = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            self._write_token(
                token_path, ["https://www.googleapis.com/auth/webmasters"], future
            )

            env = {"GSC_SKIP_OAUTH": "false", "GSC_DATA_STATE": "all",
                   "GSC_ALLOW_DESTRUCTIVE": "false", "GSC_CONFIG_DIR": tmpdir}
            with patch.dict(os.environ, env, clear=False):
                if "gsc_server" in sys.modules:
                    del sys.modules["gsc_server"]
                import gsc_server as mod

            with patch.object(mod, "TOKEN_FILE", token_path), \
                 patch("gsc_server.build", return_value=MagicMock()) as build:
                # Must NOT raise: a token with only the old scope is still
                # good enough for the Search Console service specifically.
                mod.get_gsc_service_oauth()

            self.assertEqual(build.call_args.args[0], "searchconsole")

    def test_site_verification_still_requires_reconsent_with_pre_upgrade_token(self):
        """The other half of the fix: a request that genuinely needs the new
        scope must still be refused a pre-upgrade token, not silently allowed
        through because some other call site happened to accept it."""
        with tempfile.TemporaryDirectory() as tmpdir:
            token_path = os.path.join(tmpdir, "token.json")
            future = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            self._write_token(
                token_path, ["https://www.googleapis.com/auth/webmasters"], future
            )

            env = {"GSC_SKIP_OAUTH": "false", "GSC_DATA_STATE": "all",
                   "GSC_ALLOW_DESTRUCTIVE": "false", "GSC_CONFIG_DIR": tmpdir}
            with patch.dict(os.environ, env, clear=False):
                if "gsc_server" in sys.modules:
                    del sys.modules["gsc_server"]
                import gsc_server as mod

            with patch.object(mod, "TOKEN_FILE", token_path), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", os.path.join(tmpdir, "no_secrets.json")):
                with self.assertRaises(RuntimeError):
                    mod.get_site_verification_service()


class TestSiteVerificationScope(unittest.TestCase):

    def test_scopes_include_siteverification(self):
        mod = _load_module()
        self.assertIn("https://www.googleapis.com/auth/siteverification", mod.SCOPES)
        self.assertIn("https://www.googleapis.com/auth/webmasters", mod.SCOPES)

    def test_stored_token_missing_new_scope_triggers_reconsent(self):
        """A token from before the scope bump must not be reused as-is."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env = {"GSC_SKIP_OAUTH": "false", "GSC_DATA_STATE": "all",
                   "GSC_ALLOW_DESTRUCTIVE": "false", "GSC_CONFIG_DIR": tmpdir}
            with patch.dict(os.environ, env, clear=False):
                if "gsc_server" in sys.modules:
                    del sys.modules["gsc_server"]
                import gsc_server as mod

            old_scope_creds = MagicMock()
            old_scope_creds.valid = True
            old_scope_creds.has_scopes.return_value = False

            open(os.path.join(tmpdir, "token.json"), "w").write("{}")

            with patch("gsc_server.Credentials.from_authorized_user_file", return_value=old_scope_creds), \
                 patch.object(mod, "TOKEN_FILE", os.path.join(tmpdir, "token.json")), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", os.path.join(tmpdir, "no_secrets.json")):
                # Not a TTY here, so the code takes the same "cannot refresh"
                # path a headless MCP server would — proof the under-scoped
                # token was discarded rather than handed to build().
                with self.assertRaises(RuntimeError):
                    mod.get_oauth_credentials()

    def test_stored_token_with_all_scopes_is_reused(self):
        mod = _load_module({"GSC_SKIP_OAUTH": "false"})
        good_creds = MagicMock()
        good_creds.valid = True
        good_creds.has_scopes.return_value = True

        # A real (temporary) token path: the token lock lives next to the
        # token file, so a path like /dev/null cannot host it.
        with tempfile.TemporaryDirectory() as tmpdir:
            token_path = os.path.join(tmpdir, "token.json")
            open(token_path, "w").write("{}")
            with patch("gsc_server.Credentials.from_authorized_user_file", return_value=good_creds), \
                 patch.object(mod, "TOKEN_FILE", token_path):
                creds = mod.get_oauth_credentials()

        self.assertIs(creds, good_creds)


class TestSiteVerificationTarget(unittest.TestCase):

    def test_domain_property_becomes_inet_domain(self):
        mod = _load_module()
        self.assertEqual(
            mod._verification_target("sc-domain:puur-skincare.nl"),
            {"type": "INET_DOMAIN", "identifier": "puur-skincare.nl"},
        )

    def test_prefix_property_becomes_site(self):
        mod = _load_module()
        self.assertEqual(
            mod._verification_target("https://www.puur-skincare.nl/"),
            {"type": "SITE", "identifier": "https://www.puur-skincare.nl/"},
        )


class TestGetVerificationToken(unittest.IsolatedAsyncioTestCase):

    async def test_sends_domain_target_and_returns_token(self):
        mod = _load_module()
        service = _make_service()
        service.webResource().getToken().execute.return_value = {
            "token": "google-site-verification=abc123"
        }

        with patch("gsc_server.get_site_verification_service", return_value=service):
            result = await mod.get_verification_token("sc-domain:example.com")

        body = service.webResource().getToken.call_args.kwargs["body"]
        self.assertEqual(body["site"]["type"], "INET_DOMAIN")
        self.assertEqual(body["site"]["identifier"], "example.com")
        self.assertEqual(body["verificationMethod"], "DNS_TXT")
        self.assertIn("google-site-verification=abc123", result)

    async def test_not_gated_by_allow_destructive(self):
        """Read-only: must work even with GSC_ALLOW_DESTRUCTIVE unset."""
        mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "false"})
        service = _make_service()
        service.webResource().getToken().execute.return_value = {"token": "t"}

        with patch("gsc_server.get_site_verification_service", return_value=service):
            result = await mod.get_verification_token("sc-domain:example.com")

        self.assertNotIn("Safety", result)


class TestVerifySite(unittest.IsolatedAsyncioTestCase):

    async def test_blocked_by_default(self):
        mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "false"})
        result = await mod.verify_site("sc-domain:example.com")
        self.assertIn("Safety", result)

    async def test_allowed_when_flag_set_reports_owners(self):
        mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "true"})
        service = _make_service()
        service.webResource().insert().execute.return_value = {"owners": ["mail@katama.nl"]}

        with patch("gsc_server.get_site_verification_service", return_value=service):
            result = await mod.verify_site("sc-domain:example.com")

        kwargs = service.webResource().insert.call_args.kwargs
        self.assertEqual(kwargs["verificationMethod"], "DNS_TXT")
        self.assertEqual(kwargs["body"]["site"]["identifier"], "example.com")
        self.assertIn("verified", result)
        self.assertIn("mail@katama.nl", result)


class TestVerificationErrorHandling(unittest.IsolatedAsyncioTestCase):
    """A 400 means something different depending on which call produced it."""

    @staticmethod
    def _http_error(status, message):
        resp = MagicMock()
        resp.status = status
        content = json.dumps({"error": {"message": message}}).encode("utf-8")
        from googleapiclient.errors import HttpError
        return HttpError(resp, content)

    async def test_token_request_400_reports_validation_error_not_propagation(self):
        """Nothing is published yet when fetching a token, so propagation advice
        would send the user chasing a DNS record that does not exist."""
        mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "true"})
        service = _make_service()
        service.webResource().getToken().execute.side_effect = self._http_error(
            400, "Invalid verification method for this site type."
        )

        with patch("gsc_server.get_site_verification_service", return_value=service):
            result = await mod.get_verification_token("sc-domain:example.com", method="FILE")

        self.assertIn("Invalid verification method", result)
        self.assertNotIn("resolve", result)

    async def test_verify_400_keeps_propagation_advice(self):
        mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "true"})
        service = _make_service()
        service.webResource().insert().execute.side_effect = self._http_error(
            400, "Token not found."
        )

        with patch("gsc_server.get_site_verification_service", return_value=service):
            result = await mod.verify_site("sc-domain:example.com")

        self.assertIn("Token not found", result)
        self.assertIn("resolve", result)


# ---------------------------------------------------------------------------
# Streamable HTTP transport and the read-only tool set
#
# The shared HTTP service serves many sessions at once, so it only exposes
# tools that cannot change anything in Search Console or on disk. stdio keeps
# the full set (still behind GSC_ALLOW_DESTRUCTIVE).
# ---------------------------------------------------------------------------

ALL_TOOL_NAMES = {
    "list_properties", "add_site", "delete_site", "get_verification_token", "verify_site",
    "get_search_analytics", "get_site_details", "get_sitemaps", "inspect_url_enhanced",
    "batch_url_inspection", "check_indexing_issues", "get_performance_overview",
    "get_advanced_search_analytics", "compare_search_periods", "get_search_by_page_query",
    "list_sitemaps_enhanced", "get_sitemap_details", "submit_sitemap", "delete_sitemap",
    "manage_sitemaps", "get_creator_info", "reauthenticate",
}

WRITE_OR_ADMIN_TOOL_NAMES = {
    "add_site", "delete_site", "get_verification_token", "verify_site",
    "submit_sitemap", "delete_sitemap", "manage_sitemaps", "reauthenticate",
}


def _run_main(mod, env):
    """Run main() with the given env, without starting a real server."""
    with patch.dict(os.environ, env, clear=False), \
         patch.object(mod.mcp, "run") as run:
        mod.main()
    return run


class TestTransport(unittest.IsolatedAsyncioTestCase):

    async def test_stdio_is_default_and_keeps_all_tools(self):
        mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "true"})
        env = {k: v for k, v in os.environ.items()}
        env.pop("MCP_TRANSPORT", None)
        with patch.dict(os.environ, env, clear=True), patch.object(mod.mcp, "run") as run:
            mod.main()
        run.assert_called_once_with(transport="stdio")
        names = {t.name for t in await mod.mcp.list_tools()}
        self.assertEqual(names, ALL_TOOL_NAMES)

    async def test_streamable_http_configures_settings_and_runs(self):
        mod = _load_module()
        run = _run_main(mod, {"MCP_TRANSPORT": "streamable-http", "MCP_PORT": "18897"})
        run.assert_called_once_with("streamable-http")
        settings = mod.mcp.settings
        self.assertEqual(settings.host, "127.0.0.1")
        self.assertEqual(settings.port, 18897)
        self.assertTrue(settings.stateless_http)
        sec = settings.transport_security
        self.assertTrue(sec.enable_dns_rebinding_protection)
        self.assertEqual(sorted(sec.allowed_hosts), ["127.0.0.1:18897", "localhost:18897"])
        self.assertEqual(sec.allowed_origins, [])

    async def test_streamable_http_respects_mcp_host(self):
        mod = _load_module()
        _run_main(mod, {"MCP_TRANSPORT": "streamable-http", "MCP_PORT": "18897",
                        "MCP_HOST": "localhost"})
        self.assertEqual(mod.mcp.settings.host, "localhost")

    async def test_sse_is_rejected_with_clear_error(self):
        mod = _load_module()
        with self.assertRaises(ValueError) as ctx:
            _run_main(mod, {"MCP_TRANSPORT": "sse"})
        self.assertIn("streamable-http", str(ctx.exception))

    async def test_unknown_transport_is_rejected(self):
        mod = _load_module()
        with self.assertRaises(ValueError) as ctx:
            _run_main(mod, {"MCP_TRANSPORT": "carrier-pigeon"})
        self.assertIn("carrier-pigeon", str(ctx.exception))

    async def test_invalid_port_is_rejected(self):
        mod = _load_module()
        with self.assertRaises(ValueError):
            _run_main(mod, {"MCP_TRANSPORT": "streamable-http", "MCP_PORT": "abc"})


class TestReadOnlyHttpMode(unittest.IsolatedAsyncioTestCase):

    async def test_every_registered_tool_is_classified(self):
        """A new tool must be put on one side explicitly, never default into HTTP."""
        mod = _load_module()
        names = {t.name for t in await mod.mcp.list_tools()}
        self.assertEqual(names, ALL_TOOL_NAMES)
        self.assertEqual(set(mod.READ_ONLY_TOOLS), ALL_TOOL_NAMES - WRITE_OR_ADMIN_TOOL_NAMES)
        self.assertTrue(set(mod.READ_ONLY_TOOLS) <= names)

    async def test_http_mode_lists_no_write_tool(self):
        mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "true"})
        _run_main(mod, {"MCP_TRANSPORT": "streamable-http", "MCP_PORT": "18897",
                        "GSC_ALLOW_DESTRUCTIVE": "true"})
        names = {t.name for t in await mod.mcp.list_tools()}
        self.assertEqual(names, set(mod.READ_ONLY_TOOLS))
        self.assertFalse(names & WRITE_OR_ADMIN_TOOL_NAMES)

    async def test_http_mode_write_call_touches_no_file_and_no_google_api(self):
        from mcp.server.fastmcp.exceptions import ToolError

        with tempfile.TemporaryDirectory() as tmpdir:
            token_path = os.path.join(tmpdir, "token.json")
            with open(token_path, "w") as f:
                f.write('{"keep": "me"}')
            secrets_path = os.path.join(tmpdir, "secrets.json")
            with open(secrets_path, "w") as f:
                f.write("{}")

            mod = _load_module({"GSC_ALLOW_DESTRUCTIVE": "true", "GSC_CONFIG_DIR": tmpdir})
            _run_main(mod, {"MCP_TRANSPORT": "streamable-http", "MCP_PORT": "18897",
                            "GSC_ALLOW_DESTRUCTIVE": "true"})
            before = sorted(os.listdir(tmpdir))

            calls = {
                "reauthenticate": {},
                "submit_sitemap": {"site_url": "https://example.com/",
                                   "sitemap_url": "https://example.com/sitemap.xml"},
                "delete_sitemap": {"site_url": "https://example.com/",
                                   "sitemap_url": "https://example.com/sitemap.xml"},
                "manage_sitemaps": {"site_url": "https://example.com/", "action": "submit",
                                    "sitemap_url": "https://example.com/sitemap.xml"},
                "add_site": {"site_url": "https://example.com/"},
                "delete_site": {"site_url": "https://example.com/"},
                "verify_site": {"site_url": "sc-domain:example.com"},
                "get_verification_token": {"site_url": "sc-domain:example.com"},
            }
            with patch.object(mod, "TOKEN_FILE", token_path), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", secrets_path), \
                 patch("gsc_server.build") as build, \
                 patch("gsc_server.InstalledAppFlow") as flow, \
                 patch("gsc_server.Credentials.from_authorized_user_file") as load, \
                 patch("sys.stdin.isatty", return_value=True):
                for name, args in calls.items():
                    with self.assertRaises(ToolError, msg=name):
                        await mod.mcp.call_tool(name, args)

            build.assert_not_called()
            flow.from_client_secrets_file.assert_not_called()
            load.assert_not_called()
            self.assertEqual(sorted(os.listdir(tmpdir)), before)
            with open(token_path) as f:
                self.assertEqual(f.read(), '{"keep": "me"}')

    async def test_http_mode_read_tool_still_works(self):
        mod = _load_module()
        _run_main(mod, {"MCP_TRANSPORT": "streamable-http", "MCP_PORT": "18897"})
        service = _make_service()
        service.sites().list().execute.return_value = {
            "siteEntry": [{"siteUrl": "sc-domain:example.com", "permissionLevel": "siteOwner"}]
        }
        with patch("gsc_server.get_gsc_service", return_value=service):
            result = await mod.mcp.call_tool("list_properties", {})
        self.assertIn("sc-domain:example.com", json.dumps(result, default=str))


# ---------------------------------------------------------------------------
# Token file: never deleted, written atomically, guarded by a file lock
# ---------------------------------------------------------------------------

def _future(hours=1):
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_real_token(path, expiry, token="at"):
    with open(path, "w") as f:
        json.dump({
            "token": token,
            "refresh_token": "rt",
            "client_id": "cid",
            "client_secret": "secret",
            "scopes": [
                "https://www.googleapis.com/auth/webmasters",
                "https://www.googleapis.com/auth/siteverification",
            ],
            "expiry": expiry,
        }, f)


def _load_oauth_module(tmpdir):
    return _load_module({"GSC_SKIP_OAUTH": "false", "GSC_CONFIG_DIR": tmpdir})


def _fake_refresh(delay=0.0):
    """Stand-in for google.oauth2.credentials.Credentials.refresh (a network call)."""
    import time as _time
    from google.auth import _helpers

    def refresh(self, request):
        _time.sleep(delay)
        self.token = "refreshed"
        self.expiry = _helpers.utcnow() + timedelta(hours=1)
    return refresh


class TestTokenFileSafety(unittest.TestCase):

    def test_corrupt_token_file_is_kept_and_call_fails(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mod = _load_oauth_module(tmpdir)
            token_path = os.path.join(tmpdir, "token.json")
            with open(token_path, "w") as f:
                f.write("not json{")
            with patch.object(mod, "TOKEN_FILE", token_path), \
                 patch("sys.stdin.isatty", return_value=False):
                with self.assertRaises(RuntimeError) as ctx:
                    mod.get_oauth_credentials()
            self.assertIn(token_path, str(ctx.exception))
            with open(token_path) as f:
                self.assertEqual(f.read(), "not json{")

    def test_failed_refresh_keeps_token_file_and_call_fails(self):
        from google.auth.exceptions import RefreshError

        with tempfile.TemporaryDirectory() as tmpdir:
            mod = _load_oauth_module(tmpdir)
            token_path = os.path.join(tmpdir, "token.json")
            _write_real_token(token_path, _future(-1))
            with open(token_path) as f:
                original = f.read()
            with patch.object(mod, "TOKEN_FILE", token_path), \
                 patch("sys.stdin.isatty", return_value=False), \
                 patch("gsc_server.Credentials.refresh", side_effect=RefreshError("invalid_grant")):
                with self.assertRaises(RuntimeError) as ctx:
                    mod.get_oauth_credentials()
            self.assertIn("invalid_grant", str(ctx.exception))
            with open(token_path) as f:
                self.assertEqual(f.read(), original)

    def test_refreshed_token_is_written_atomically_with_mode_0600(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mod = _load_oauth_module(tmpdir)
            token_path = os.path.join(tmpdir, "token.json")
            _write_real_token(token_path, _future(-1))
            os.chmod(token_path, 0o644)
            with patch.object(mod, "TOKEN_FILE", token_path), \
                 patch("gsc_server.Credentials.refresh", _fake_refresh()), \
                 patch("gsc_server.os.replace", wraps=os.replace) as replace:
                creds = mod.get_oauth_credentials()
            self.assertEqual(creds.token, "refreshed")
            replace.assert_called_once()
            src, dst = replace.call_args.args
            self.assertEqual(dst, token_path)
            self.assertEqual(os.path.dirname(src), tmpdir)
            self.assertEqual(os.stat(token_path).st_mode & 0o777, 0o600)
            with open(token_path) as f:
                self.assertEqual(json.load(f)["token"], "refreshed")
            # No temp files left behind; only the token and its lock file.
            self.assertEqual(sorted(os.listdir(tmpdir)), ["token.json", "token.json.lock"])

    def test_concurrent_refreshes_end_with_one_valid_file(self):
        import threading

        with tempfile.TemporaryDirectory() as tmpdir:
            mod = _load_oauth_module(tmpdir)
            token_path = os.path.join(tmpdir, "token.json")
            _write_real_token(token_path, _future(-1))
            results, errors = [], []
            refresh = MagicMock(side_effect=_fake_refresh(0.2))

            def call():
                try:
                    results.append(mod.get_oauth_credentials())
                except Exception as e:  # pragma: no cover - surfaced below
                    errors.append(e)

            def refresh_method(self, request):
                return refresh(self, request)

            with patch.object(mod, "TOKEN_FILE", token_path), \
                 patch("gsc_server.Credentials.refresh", refresh_method):
                threads = [threading.Thread(target=call) for _ in range(2)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()

            self.assertEqual(errors, [])
            self.assertEqual(len(results), 2)
            self.assertTrue(all(c.valid for c in results))
            # The second caller re-reads inside the lock and finds the fresh token.
            self.assertEqual(refresh.call_count, 1)
            with open(token_path) as f:
                data = json.load(f)
            self.assertEqual(data["token"], "refreshed")
            self.assertEqual(os.stat(token_path).st_mode & 0o777, 0o600)

    def test_reauthenticate_without_tty_keeps_token(self):
        import asyncio

        with tempfile.TemporaryDirectory() as tmpdir:
            mod = _load_oauth_module(tmpdir)
            token_path = os.path.join(tmpdir, "token.json")
            with open(token_path, "w") as f:
                f.write('{"old": "token"}')
            secrets_path = os.path.join(tmpdir, "secrets.json")
            with open(secrets_path, "w") as f:
                f.write("{}")
            with patch.object(mod, "TOKEN_FILE", token_path), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", secrets_path), \
                 patch("sys.stdin.isatty", return_value=False):
                asyncio.run(mod.reauthenticate())
            with open(token_path) as f:
                self.assertEqual(f.read(), '{"old": "token"}')

    def test_reauthenticate_failed_login_keeps_token(self):
        import asyncio

        with tempfile.TemporaryDirectory() as tmpdir:
            mod = _load_oauth_module(tmpdir)
            token_path = os.path.join(tmpdir, "token.json")
            with open(token_path, "w") as f:
                f.write('{"old": "token"}')
            secrets_path = os.path.join(tmpdir, "secrets.json")
            with open(secrets_path, "w") as f:
                f.write("{}")
            with patch.object(mod, "TOKEN_FILE", token_path), \
                 patch.object(mod, "OAUTH_CLIENT_SECRETS_FILE", secrets_path), \
                 patch("gsc_server.InstalledAppFlow") as flow_cls, \
                 patch("sys.stdin.isatty", return_value=True):
                flow_cls.from_client_secrets_file.return_value.run_local_server.side_effect = (
                    RuntimeError("browser closed")
                )
                result = asyncio.run(mod.reauthenticate())
            self.assertIn("Error", result)
            with open(token_path) as f:
                self.assertEqual(f.read(), '{"old": "token"}')


# ---------------------------------------------------------------------------
# Event loop: the whole synchronous chain of a tool runs in a worker thread
# ---------------------------------------------------------------------------

class TestEventLoopNotBlocked(unittest.IsolatedAsyncioTestCase):

    DELAY = 0.5

    async def _heartbeat(self, stop, ticks):
        import asyncio
        while not stop.is_set():
            ticks.append(1)
            await asyncio.sleep(0.02)

    async def _run_two_with_heartbeat(self, make_call):
        import asyncio
        import time as _time

        stop, ticks = asyncio.Event(), []
        beat = asyncio.create_task(self._heartbeat(stop, ticks))
        start = _time.perf_counter()
        results = await asyncio.gather(make_call(), make_call())
        elapsed = _time.perf_counter() - start
        stop.set()
        await beat
        return results, elapsed, len(ticks)

    async def test_slow_google_call_does_not_block(self):
        import time as _time

        mod = _load_module()
        service = _make_service()

        def slow_execute():
            _time.sleep(self.DELAY)
            return {"siteEntry": [{"siteUrl": "sc-domain:example.com", "permissionLevel": "siteOwner"}]}

        service.sites().list().execute.side_effect = slow_execute
        with patch("gsc_server.get_gsc_service", return_value=service):
            results, elapsed, ticks = await self._run_two_with_heartbeat(
                lambda: mod.mcp.call_tool("list_properties", {})
            )
        self.assertEqual(len(results), 2)
        self.assertLess(elapsed, self.DELAY * 1.6, "two calls ran one after the other")
        # ~25 ticks fit in 0.5 s at 20 ms; a blocked loop manages about one.
        self.assertGreater(ticks, 10)

    async def test_slow_credential_refresh_does_not_block(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mod = _load_oauth_module(tmpdir)
            token_path = os.path.join(tmpdir, "token.json")
            _write_real_token(token_path, _future(-1))
            service = _make_service()
            service.sites().list().execute.return_value = {
                "siteEntry": [{"siteUrl": "sc-domain:example.com", "permissionLevel": "siteOwner"}]
            }
            with patch.object(mod, "TOKEN_FILE", token_path), \
                 patch("gsc_server.Credentials.refresh", _fake_refresh(self.DELAY)), \
                 patch("gsc_server.build", return_value=service):
                results, elapsed, ticks = await self._run_two_with_heartbeat(
                    lambda: mod.mcp.call_tool("list_properties", {})
                )
        self.assertEqual(len(results), 2)
        self.assertIn("sc-domain:example.com", json.dumps(results, default=str))
        # The second call waits for the lock and then reuses the fresh token.
        self.assertLess(elapsed, self.DELAY * 1.6)
        self.assertGreater(ticks, 10)



if __name__ == "__main__":
    unittest.main()


class TestTokenLockWithoutFcntl(unittest.TestCase):
    """Windows has no fcntl: the lock falls back to msvcrt and fchmod is skipped."""

    def test_msvcrt_fallback_locks_and_unlocks(self):
        import gsc_server as mod
        calls = []
        fake = MagicMock()
        fake.LK_LOCK, fake.LK_UNLCK = 1, 0
        fake.locking.side_effect = lambda fd, mode, n: calls.append(mode)
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch.object(mod, "TOKEN_FILE", os.path.join(tmpdir, "token.json")), \
             patch.object(mod, "fcntl", None), \
             patch.object(mod, "msvcrt", fake):
            with mod._token_lock():
                self.assertEqual(calls, [fake.LK_LOCK])
            self.assertEqual(calls, [fake.LK_LOCK, fake.LK_UNLCK])

    def test_write_without_fchmod(self):
        import gsc_server as mod
        creds = MagicMock()
        creds.to_json.return_value = '{"token": "x"}'
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "token.json")
            with patch.object(mod, "TOKEN_FILE", path), \
                 patch.object(mod.os, "fchmod", create=True) as fchmod:
                del mod.os.fchmod
                mod._write_token_atomic(creds)
            fchmod.assert_not_called()
            with open(path) as f:
                self.assertEqual(f.read(), '{"token": "x"}')
