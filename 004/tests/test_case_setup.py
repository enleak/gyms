"""Case setup contracts using authored fixtures, without the upstream corpus."""

import copy
import unittest
from unittest.mock import patch

from gymctl import tracecat
from gym_plugin import alert, reconcile


CALLER_ROLE = "arn:aws:iam::111111111111:role/example-reader"


def event(*, condition=None, error=None, principal=CALLER_ROLE, role_name="groundlink-example"):
    statement = {
        "Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": principal},
    }
    if condition is not None:
        statement["Condition"] = condition
    record = {
        "eventSource": "iam.amazonaws.com", "eventName": "UpdateAssumeRolePolicy",
        "recipientAccountId": "111111111111",
        "userIdentity": {"sessionContext": {"sessionIssuer": {"arn": CALLER_ROLE}}},
        "requestParameters": {"roleName": role_name, "policyDocument": {"Statement": [statement]}},
    }
    if error:
        record["errorCode"] = error
    return record


def desired_case():
    payload = {key: f"fixture-{key}" for key in reconcile.REFERENCE_KEYS}
    payload.update(gym_id="004", alert_id="fixture-alert", source_ordinal=1)
    return {
        "summary": "Authored test alert", "description": "Authored test description",
        "status": "new", "priority": "high", "severity": "medium", "payload": payload,
    }


class Response:
    content = b"{}"

    def __init__(self, payload, status=200):
        self.payload = payload
        self.status_code = status

    def json(self):
        return copy.deepcopy(self.payload)


class CaseClient:
    """Small HTTP contract fixture with real cursor-shaped page responses."""

    def __init__(self, pages=None):
        self.pages = copy.deepcopy(pages or [[]])
        self.writes = []

    def request(self, method, url, *, params=None, json=None):
        base = "/workspaces/workspace-fixture/cases"
        if method == "GET" and url == base:
            index = int((params or {}).get("cursor", "0"))
            more = index + 1 < len(self.pages)
            return Response({
                "items": self.pages[index], "has_more": more,
                "next_cursor": str(index + 1) if more else None,
            })
        if method == "GET" and url.startswith(base + "/"):
            case_id = url.rsplit("/", 1)[-1]
            return Response(next(row for page in self.pages for row in page if row["id"] == case_id))
        if method == "POST" and url == base:
            self.writes.append((method, copy.deepcopy(json)))
            case = {**copy.deepcopy(json), "id": "created-case"}
            self.pages[-1].append(case)
            return Response(case, 201)
        raise AssertionError(f"unexpected API mutation or request: {method} {url}")


class AlertRuleTests(unittest.TestCase):
    def test_groundlink_update_explicitly_trusting_calling_role(self):
        self.assertEqual(alert.caller_role_trust(event()), [CALLER_ROLE])

    def test_failed_conditioned_or_other_principal_updates_are_not_selected(self):
        for record in (
            event(error="AccessDenied"),
            event(condition={"StringEquals": {"sts:ExternalId": "example"}}),
            event(principal="arn:aws:iam::222222222222:root"),
            event(principal="arn:aws:iam::111111111111:role/example"),
            event(principal="arn:aws:iam::111111111111:root"),
            event(role_name="other-example"),
        ):
            with self.subTest(record=record):
                self.assertEqual(alert.caller_role_trust(record), [])


class CaseSetupTests(unittest.TestCase):
    def setUp(self):
        self.desired = desired_case()
        self.source = patch.object(reconcile, "source_case", return_value=self.desired)
        self.source.start()
        self.addCleanup(self.source.stop)

    def test_create_once_and_preserve_edited_case_and_notes(self):
        client = CaseClient()
        first = reconcile.reconcile_case(client, "workspace-fixture")
        stored = client.pages[0][0]
        stored.update(description="Analyst investigation", status="in_progress")
        stored["comments"] = [{"content": "Analyst evidence note"}]
        stored["payload"]["analyst_extension"] = "retained"
        before = copy.deepcopy(stored)
        second = reconcile.reconcile_case(client, "workspace-fixture")
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(second, before)
        self.assertEqual(stored, before)
        self.assertEqual(len(client.writes), 1)

    def test_existing_case_on_later_page_prevents_duplicate_creation(self):
        managed = {**self.desired, "id": "older-case"}
        client = CaseClient([[{"id": "unrelated", "payload": {"gym_id": "002"}}], [managed]])
        self.assertEqual(reconcile.reconcile_case(client, "workspace-fixture")["id"], "older-case")
        self.assertEqual(client.writes, [])

    def test_duplicate_managed_cases_fail_before_mutation(self):
        client = CaseClient([[{**self.desired, "id": "one"}, {**self.desired, "id": "two"}]])
        with self.assertRaisesRegex(tracecat.TracecatError, "expected one Gym 004 case"):
            reconcile.reconcile_case(client, "workspace-fixture")
        self.assertEqual(client.writes, [])

    def test_changed_evidence_reference_is_reported_without_overwriting_case(self):
        managed = {**copy.deepcopy(self.desired), "id": "existing-case"}
        managed["payload"]["source_sha256"] = "changed"
        client = CaseClient([[managed]])
        with self.assertRaisesRegex(tracecat.TracecatError, "source_sha256"):
            reconcile.reconcile_case(client, "workspace-fixture")
        self.assertEqual(client.pages[0][0], managed)
        self.assertEqual(client.writes, [])

    def test_unrelated_case_is_preserved_when_creating_managed_case(self):
        unrelated = {"id": "unrelated", "payload": {"gym_id": "002"}, "description": "Keep me"}
        client = CaseClient([[unrelated]])
        reconcile.reconcile_case(client, "workspace-fixture")
        self.assertEqual(client.pages[0][0], unrelated)
        self.assertEqual(len(client.writes), 1)


if __name__ == "__main__":
    unittest.main()
