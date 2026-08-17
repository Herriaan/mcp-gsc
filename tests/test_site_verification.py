"""Tests for the Site Verification support added in 0.2.2.

These cover the two things the scope bump actually has to guarantee:

1. A token.json saved under the old, narrower scope must not be used silently.
   It stays "valid" (it is not expired), so without an explicit scope check the
   server would happily call the Site Verification API with a credential that
   cannot do it, and the user would see an opaque 403.
2. The verification calls must go to the siteVerification API, not to
   searchconsole.

Only external dependencies are mocked: the Google client library entry points
(build, Credentials, InstalledAppFlow) and the filesystem token. The functions
under test are the real ones.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import gsc_server

    IMPORT_ERROR = None
except ImportError as exc:  # pragma: no cover - depends on the interpreter used
    gsc_server = None
    IMPORT_ERROR = exc

# The server's dependencies live in the project venv, so an interpreter without
# them cannot exercise these tests. Skipping per class rather than per module
# keeps them collectable: a module-level skip collects nothing at all, which
# pytest reports as exit code 5 and any test gate reads as a failure.
#   .venv/bin/python -m unittest discover -s tests
requires_gsc_server = unittest.skipIf(
    gsc_server is None, f"gsc_server dependencies unavailable: {IMPORT_ERROR}"
)


class FakeCreds:
    """Stand-in for google.oauth2.credentials.Credentials."""

    def __init__(self, scopes, valid=True, expired=False, refresh_token="r"):
        self.scopes = scopes
        self.valid = valid
        self.expired = expired
        self.refresh_token = refresh_token

    def has_scopes(self, scopes):
        return set(scopes).issubset(set(self.scopes))

    def to_json(self):
        return '{"fake": true}'


@requires_gsc_server
class ScopeRequirementTests(unittest.TestCase):
    def test_scopes_include_siteverification(self):
        self.assertIn(
            "https://www.googleapis.com/auth/siteverification", gsc_server.SCOPES
        )
        self.assertIn("https://www.googleapis.com/auth/webmasters", gsc_server.SCOPES)

    def test_stored_token_missing_new_scope_triggers_reconsent(self):
        """A token from before the scope bump must force a fresh OAuth flow."""
        old_scope_creds = FakeCreds(
            scopes=["https://www.googleapis.com/auth/webmasters"], valid=True
        )
        fresh_creds = FakeCreds(scopes=list(gsc_server.SCOPES), valid=True)

        flow = mock.Mock()
        flow.run_local_server.return_value = fresh_creds

        with mock.patch.object(gsc_server.os.path, "exists", return_value=True), \
             mock.patch.object(
                 gsc_server.Credentials,
                 "from_authorized_user_file",
                 return_value=old_scope_creds,
             ), \
             mock.patch.object(
                 gsc_server.InstalledAppFlow,
                 "from_client_secrets_file",
                 return_value=flow,
             ), \
             mock.patch("builtins.open", mock.mock_open()):
            creds = gsc_server.get_oauth_credentials()

        flow.run_local_server.assert_called_once()
        self.assertIs(creds, fresh_creds)

    def test_stored_token_with_all_scopes_is_reused(self):
        """A token that already carries both scopes must not trigger a new flow."""
        good_creds = FakeCreds(scopes=list(gsc_server.SCOPES), valid=True)

        flow = mock.Mock()

        with mock.patch.object(gsc_server.os.path, "exists", return_value=True), \
             mock.patch.object(
                 gsc_server.Credentials,
                 "from_authorized_user_file",
                 return_value=good_creds,
             ), \
             mock.patch.object(
                 gsc_server.InstalledAppFlow,
                 "from_client_secrets_file",
                 return_value=flow,
             ):
            creds = gsc_server.get_oauth_credentials()

        flow.run_local_server.assert_not_called()
        self.assertIs(creds, good_creds)


@requires_gsc_server
class SiteVerificationServiceTests(unittest.TestCase):
    def test_builds_siteverification_api(self):
        creds = FakeCreds(scopes=list(gsc_server.SCOPES))

        with mock.patch.object(
            gsc_server, "get_oauth_credentials", return_value=creds
        ), mock.patch.object(gsc_server, "build") as build:
            gsc_server.get_site_verification_service()

        build.assert_called_once()
        args, kwargs = build.call_args
        self.assertEqual(args[0], "siteVerification")
        self.assertEqual(args[1], "v1")
        self.assertIs(kwargs["credentials"], creds)


@requires_gsc_server
class VerificationTargetTests(unittest.TestCase):
    """The two id forms Search Console uses must map onto the two the
    Site Verification API accepts."""

    def test_domain_property_becomes_inet_domain(self):
        self.assertEqual(
            gsc_server._verification_target("sc-domain:puur-skincare.nl"),
            {"type": "INET_DOMAIN", "identifier": "puur-skincare.nl"},
        )

    def test_prefix_property_becomes_site(self):
        self.assertEqual(
            gsc_server._verification_target("https://www.puur-skincare.nl/"),
            {"type": "SITE", "identifier": "https://www.puur-skincare.nl/"},
        )

    def test_domain_prefix_is_stripped_only_once(self):
        """A host that itself contains the literal prefix must survive intact."""
        self.assertEqual(
            gsc_server._verification_target("sc-domain:sc-domain.example.com"),
            {"type": "INET_DOMAIN", "identifier": "sc-domain.example.com"},
        )


@requires_gsc_server
class VerificationCallTests(unittest.IsolatedAsyncioTestCase):
    async def test_get_verification_token_sends_domain_target(self):
        service = mock.Mock()
        service.webResource.return_value.getToken.return_value.execute.return_value = {
            "token": "google-site-verification=abc123"
        }

        with mock.patch.object(
            gsc_server, "get_site_verification_service", return_value=service
        ):
            result = await gsc_server.get_verification_token("sc-domain:example.com")

        body = service.webResource.return_value.getToken.call_args.kwargs["body"]
        self.assertEqual(body["site"]["type"], "INET_DOMAIN")
        self.assertEqual(body["site"]["identifier"], "example.com")
        self.assertEqual(body["verificationMethod"], "DNS_TXT")
        self.assertIn("google-site-verification=abc123", result)

    async def test_verify_site_passes_method_and_reports_owners(self):
        service = mock.Mock()
        service.webResource.return_value.insert.return_value.execute.return_value = {
            "owners": ["mail@katama.nl"]
        }

        with mock.patch.object(
            gsc_server, "get_site_verification_service", return_value=service
        ):
            result = await gsc_server.verify_site("sc-domain:example.com")

        kwargs = service.webResource.return_value.insert.call_args.kwargs
        self.assertEqual(kwargs["verificationMethod"], "DNS_TXT")
        self.assertEqual(kwargs["body"]["site"]["identifier"], "example.com")
        self.assertIn("verified", result)
        self.assertIn("mail@katama.nl", result)


if __name__ == "__main__":
    unittest.main()
