import csv
import io

from fastapi.testclient import TestClient


def csrf(client: TestClient) -> str:
    value = client.cookies.get("kenai_csrf")
    assert value
    return value


def test_audit_filters_and_csv_export_exclude_metadata(
    authenticated_client: TestClient,
) -> None:
    client = authenticated_client
    client.post(
        "/users",
        data={
            "csrf_token": csrf(client),
            "slug": "audit-user",
            "display_name": "Audit user",
            "comment": "",
        },
    )

    page = client.get("/audit?action=user.create&outcome=success")
    assert page.status_code == 200
    assert "user.create" in page.text

    exported = client.get("/audit/export.csv?action=user.create&outcome=success")
    assert exported.status_code == 200
    assert exported.headers["cache-control"] == "no-store"
    rows = list(csv.DictReader(io.StringIO(exported.content.decode("utf-8-sig"))))
    assert len(rows) == 1
    assert rows[0]["action"] == "user.create"
    assert "metadata" not in rows[0]
    assert rows[0]["user"] == "audit-user"
