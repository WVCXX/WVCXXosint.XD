import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import httpx
import dns.resolver
from fastapi import WebSocketDisconnect
from fastapi.testclient import TestClient
import main
from modules.blackbird import check_blackbird
from modules.email_infrastructure import check_email_infrastructure
from modules.github_commits import check_github_commits
from modules.google_account import check_google_account
from modules.whatsmyname import check_whatsmyname as check_whatsmyname_package
from modules.whatsmyname import classify_site_response


class FakeWebSocket:
    def __init__(self):
        self.sent: list[dict] = []

    async def send_json(self, data: dict) -> None:
        self.sent.append(data)


class WebSocketOriginTests(unittest.TestCase):
    def test_tools_catalog_marks_unimplemented_sources_as_not_configured(self):
        with TestClient(main.app) as client:
            response = client.get("/api/tools")
        self.assertEqual(response.status_code, 200)
        tools = {tool["id"]: tool for tool in response.json()["tools"]}
        self.assertEqual(tools["google-metadata"]["status"], "not_configured")
        self.assertEqual(tools["blackbird"]["status"], "not_configured")
        self.assertEqual(tools["wayback"]["status"], "available")
        self.assertEqual(tools["whatsmyname"]["status"], "available")
        self.assertEqual(tools["organization-registers"]["status"], "available")

    def test_api_key_settings_store_secrets_locally_without_returning_them(self):
        secret = "test-github-token"
        with tempfile.TemporaryDirectory() as directory:
            settings_path = Path(directory) / "settings.json"
            with (
                patch("modules.config.SETTINGS_PATH", settings_path),
                patch.dict(os.environ, {"GITHUB_TOKEN": ""}),
                TestClient(main.app, client=("127.0.0.1", 8000)) as client,
            ):
                headers = {"Origin": "http://localhost:5173"}
                response = client.put(
                    "/api/settings/keys/github",
                    json={"value": secret},
                    headers=headers,
                )
                self.assertEqual(response.status_code, 200)
                self.assertNotIn(secret, response.text)
                self.assertEqual(settings_path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(main.get_api_key("github"), secret)

                status = client.get("/api/settings/keys", headers=headers)
                self.assertEqual(status.status_code, 200)
                self.assertNotIn(secret, status.text)
                github = next(key for key in status.json()["keys"] if key["provider"] == "github")
                self.assertEqual(github, {
                    "provider": "github",
                    "configured": True,
                    "source": "application",
                    "adapter_implemented": True,
                })
                providers = {key["provider"] for key in status.json()["keys"]}
                self.assertEqual(providers, {
                    "github", "hibp", "shodan", "virustotal", "abuseipdb",
                    "censys_id", "censys_secret", "urlscan", "search",
                })

                deleted = client.delete("/api/settings/keys/github", headers=headers)
                self.assertEqual(deleted.status_code, 200)
                self.assertEqual(settings_path.read_text(encoding="utf-8"), "{}")
                self.assertEqual(main.get_api_key("github"), "")

                forbidden_origin = client.get(
                    "/api/settings/keys",
                    headers={"Origin": "https://untrusted.example"},
                )
                self.assertEqual(forbidden_origin.status_code, 403)

    def test_api_key_settings_reject_remote_clients(self):
        with TestClient(main.app, client=("192.0.2.10", 8000)) as client:
            response = client.get(
                "/api/settings/keys",
                headers={"Origin": "http://localhost:5173"},
            )
        self.assertEqual(response.status_code, 403)

    def test_catalog_separates_saved_key_from_unimplemented_adapter(self):
        with tempfile.TemporaryDirectory() as directory:
            settings_path = Path(directory) / "settings.json"
            with patch("modules.config.SETTINGS_PATH", settings_path):
                main.set_api_key("virustotal", "test-virustotal-token")
                with TestClient(main.app) as client:
                    tools = {tool["id"]: tool for tool in client.get("/api/tools").json()["tools"]}
        virustotal = tools["virustotal"]
        self.assertEqual(virustotal["status"], "not_configured")
        self.assertTrue(virustotal["api_key_configured"])
        self.assertFalse(virustotal["adapter_implemented"])

    def test_query_validation_rejects_private_targets_and_nonstandard_ports(self):
        self.assertEqual(main._validate_query("127.0.0.1", "ip")[1], "Разрешены только публичные IP-адреса")
        self.assertIsNotNone(main._validate_query("http://127.0.0.1/", "url")[1])
        self.assertIsNotNone(main._validate_query("https://example.com:8443/", "url")[1])
        self.assertEqual(main._validate_query("https://example.com/path", "url"), ("example.com", None))

    def test_hibp_without_key_is_not_configured_and_makes_no_request(self):
        with patch("main.get_api_key", return_value=""), patch("main.httpx.AsyncClient") as client:
            result = asyncio.run(main.check_hibp("person@example.com"))
        self.assertEqual(result["status"], "not_configured")
        client.assert_not_called()

    def test_certificate_transparency_obeys_selected_depth(self):
        requested = []

        def return_certificates(request):
            requested.append(str(request.url))
            return httpx.Response(200, json=[
                {"name_value": "www.example.com"},
                {"name_value": "api.internal.example.com"},
                {"name_value": "*.example.com"},
                {"name_value": "unrelated.test"},
            ], request=request)

        transport = httpx.MockTransport(return_certificates)
        actual_async_client = httpx.AsyncClient

        def async_client_factory(*args, **kwargs):
            return actual_async_client(*args, transport=transport, **kwargs)

        with patch("main.httpx.AsyncClient", side_effect=async_client_factory):
            direct = asyncio.run(main.check_certificate_transparency("example.com", 1))
            nested = asyncio.run(main.check_certificate_transparency("example.com", 2))
        self.assertIn("www.example.com", direct["fields"][0]["value"])
        self.assertNotIn("api.internal.example.com", direct["fields"][0]["value"])
        self.assertIn("api.internal.example.com", nested["fields"][0]["value"])
        self.assertEqual(len(requested), 2)

    def test_ip_rdap_does_not_follow_redirects_to_private_hosts(self):
        requested = []

        def redirect_to_private_host(request):
            requested.append(str(request.url))
            return httpx.Response(
                302,
                headers={"Location": "https://127.0.0.1/admin"},
                request=request,
            )

        transport = httpx.MockTransport(redirect_to_private_host)
        actual_async_client = httpx.AsyncClient

        def async_client_factory(*args, **kwargs):
            return actual_async_client(*args, transport=transport, **kwargs)

        with (
            patch("main.resolve_public_addresses", new_callable=AsyncMock, return_value=["93.184.216.34"]),
            patch("main.httpx.AsyncClient", side_effect=async_client_factory),
            patch("main.check_shodan", new_callable=AsyncMock, return_value={"title": "Shodan", "status": "not_configured", "fields": []}),
        ):
            results = asyncio.run(main.get_ip_nodes("8.8.8.8"))
        self.assertEqual(len(requested), 1)
        self.assertEqual(results[0]["status"], "error")

    def test_stream_adds_normalized_result_metadata(self):
        websocket = FakeWebSocket()
        asyncio.run(main._stream_checks(
            websocket,
            [("GitHub", asyncio.sleep(0, result={
                "title": "GitHub profile",
                "status": "completed",
                "fields": [],
            }))],
            "octocat",
        ))
        result = next(message["data"] for message in websocket.sent if message["type"] == "node")
        self.assertEqual(result["query"], "octocat")
        self.assertEqual(result["entity_type"], "OSINT Module")
        self.assertEqual(result["state"], "completed")
        self.assertIsNotNone(result["id"])
        self.assertIsNotNone(result["received_at"])

    def test_rejects_untrusted_origin_before_starting_scan(self):
        with patch("main.get_domain_nodes", new_callable=AsyncMock) as get_domain_nodes:
            with TestClient(main.app) as client:
                with self.assertRaises(WebSocketDisconnect):
                    with client.websocket_connect(
                        "/ws/scan", headers={"origin": "https://attacker.example"}
                    ):
                        pass
            get_domain_nodes.assert_not_awaited()
    def test_accepts_configured_frontend_origin(self):
        with patch("main.get_domain_checks", new_callable=AsyncMock, return_value=[]):
            with TestClient(main.app) as client:
                with client.websocket_connect(
                    "/ws/scan", headers={"origin": "http://127.0.0.1:5173"}
                ) as websocket:
                    websocket.send_json({"query": "example.com"})
                    self.assertEqual(websocket.receive_json()["type"], "root")
                    self.assertEqual(websocket.receive_json()["type"], "done")
    def test_formatted_phone_number_is_scanned_as_phone(self):
        with (
            patch("main.check_username", new_callable=AsyncMock, return_value={}),
            patch("main.check_github_commits", new_callable=AsyncMock, return_value={}),
            TestClient(main.app) as client,
        ):
            with client.websocket_connect("/ws/scan") as websocket:
                websocket.send_json({"query": "+1 (415) 555-2671"})
                root = websocket.receive_json()
                message = websocket.receive_json()
                while message["type"] in ("progress", "loading"):
                    message = websocket.receive_json()
                done = websocket.receive_json()
                while done["type"] in ("progress", "loading"):
                    done = websocket.receive_json()

        self.assertEqual(root["data"]["input_type"], "phone")
        self.assertEqual(message["data"]["title"], "Информация о телефоне")
        self.assertEqual(done["type"], "done")

    def test_explicit_username_type_does_not_become_a_domain(self):
        with (
            patch("main.check_username", new_callable=AsyncMock, return_value={"title": "GitHub profile", "status": "no_results", "fields": []}),
            patch("main.check_github_commits", new_callable=AsyncMock, return_value={"title": "Email в GitHub-коммитах", "status": "no_results", "fields": []}),
            TestClient(main.app) as client,
        ):
            with client.websocket_connect("/ws/scan") as websocket:
                websocket.send_json({"query": "alice.smith", "query_type": "username"})
                root = websocket.receive_json()
                self.assertEqual(root["data"]["input_type"], "username")
                while websocket.receive_json()["type"] != "done":
                    pass

    def test_depth_is_rejected_for_query_types_that_do_not_support_it(self):
        with TestClient(main.app) as client:
            with client.websocket_connect("/ws/scan") as websocket:
                websocket.send_json({"query": "+1 415 555 2671", "query_type": "phone", "depth": 2})
                self.assertIn("поддерживается только", websocket.receive_json()["error"])
    def test_domain_fetch_does_not_follow_redirects(self):
        requested_urls = []
        requests = []

        async def resolve_public_domain(name, record_type):
            if record_type == "A":
                return [SimpleNamespace(address="93.184.216.34")]
            if record_type in ("AAAA", "MX", "NS", "TXT"):
                raise dns.resolver.NoAnswer
            raise AssertionError(f"Unexpected DNS query: {name} {record_type}")

        def redirect_to_private_service(request):
            requested_urls.append(str(request.url))
            requests.append(request)
            return httpx.Response(
                302,
                headers={"Location": "http://127.0.0.1:9999/admin"},
                request=request,
            )
        transport = httpx.MockTransport(redirect_to_private_service)
        actual_async_client = httpx.AsyncClient
        def async_client_factory(*args, **kwargs):
            return actual_async_client(*args, transport=transport, **kwargs)
        with (
            patch(
                "main.dns.asyncresolver.resolve",
                new_callable=AsyncMock,
                side_effect=resolve_public_domain,
            ),
            patch("main.run_theharvester", new_callable=AsyncMock, return_value={}),
            patch("main.check_whois", new_callable=AsyncMock, return_value={}),
            patch("main.check_shodan", new_callable=AsyncMock, return_value={"title": "Shodan", "status": "not_configured", "fields": []}),
            patch("main.check_wayback", new_callable=AsyncMock, return_value={}),
            patch("main.httpx.AsyncClient", side_effect=async_client_factory),
        ):
            nodes = asyncio.run(main.get_domain_nodes("example.com"))
        self.assertEqual(requested_urls, ["https://93.184.216.34/"])
        self.assertEqual(requests[0].headers["host"], "example.com")
        self.assertEqual(requests[0].extensions["sni_hostname"], "example.com")
        website = next(node for node in nodes if node.get("title") == "Веб-сайт")
        self.assertEqual(website["fields"][0]["value"], "302")

    def test_rejects_url_authority_path_before_dns_or_http(self):
        with (
            patch(
                "main.dns.asyncresolver.resolve",
                new_callable=AsyncMock,
            ) as resolve,
            patch("main.httpx.AsyncClient") as async_client,
        ):
            nodes = asyncio.run(main.get_domain_nodes("127.0.0.1:8443/admin"))

        self.assertEqual(nodes[0]["status"], "error")
        resolve.assert_not_awaited()
        async_client.assert_not_called()

    def test_private_dns_answer_never_reaches_http_or_shodan(self):
        async def resolve_private_domain(name, record_type):
            if record_type == "A":
                return [SimpleNamespace(address="127.0.0.1")]
            if record_type in ("AAAA", "MX", "NS", "TXT"):
                raise dns.resolver.NoAnswer
            raise AssertionError(f"Unexpected DNS query: {name} {record_type}")

        with (
            patch(
                "main.dns.asyncresolver.resolve",
                new_callable=AsyncMock,
                side_effect=resolve_private_domain,
            ),
            patch("main.httpx.AsyncClient") as async_client,
            patch("main.check_shodan", new_callable=AsyncMock) as check_shodan,
            patch("main.run_theharvester", new_callable=AsyncMock, return_value={}),
            patch("main.check_whois", new_callable=AsyncMock, return_value={}),
            patch("main.check_wayback", new_callable=AsyncMock, return_value={}),
        ):
            nodes = asyncio.run(main.get_domain_nodes("example.com"))

        async_client.assert_not_called()
        check_shodan.assert_not_awaited()
        website = next(node for node in nodes if node.get("title") == "Веб-сайт")
        self.assertIn("публичного IP", website["fields"][0]["value"])
    def test_email_infrastructure_checks_mx_spf_and_dmarc_asynchronously(self):
        records = {
            ( "example.com", "MX"): [
                SimpleNamespace(exchange="mx.google.com."),
            ],
            ("example.com", "TXT"): [
                SimpleNamespace(strings=[b"v=spf1 include:_spf.google.com ~all"]),
            ],
            ("_dmarc.example.com", "TXT"): [
                SimpleNamespace(strings=[b"v=DMARC1; p=reject"]),
            ],
        }
        async def resolve(name, record_type):
            return records[(name, record_type)]
        with patch(
            "modules.email_infrastructure.dns.asyncresolver.resolve",
            new_callable=AsyncMock,
            side_effect=resolve,
        ) as resolver:
            result = asyncio.run(check_email_infrastructure("analyst@example.com"))
        self.assertEqual(result["title"], "SMTP & Домен")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(resolver.await_count, 3)
        self.assertEqual(result["fields"][0]["value"], "Google")
        self.assertEqual(result["fields"][2]["value"], "MX-записи найдены")
        self.assertIn("SPF: настроен", result["fields"][3]["value"])
        self.assertIn("DMARC: настроен", result["fields"][3]["value"])
    def test_email_infrastructure_rejects_invalid_domain_without_dns(self):
        with patch(
            "modules.email_infrastructure.dns.asyncresolver.resolve",
            new_callable=AsyncMock,
        ) as resolver:
            result = asyncio.run(check_email_infrastructure("user@example.com/path"))
        self.assertEqual(result["status"], "error")
        resolver.assert_not_awaited()
    def test_email_infrastructure_rejects_invalid_local_part_without_dns(self):
        for email in ("@example.com", "user name@example.com"):
            with self.subTest(email=email), patch(
                "modules.email_infrastructure.dns.asyncresolver.resolve",
                new_callable=AsyncMock,
                return_value=[],
            ) as resolver:
                result = asyncio.run(check_email_infrastructure(email))
            self.assertEqual(result["status"], "error")
            resolver.assert_not_awaited()
    def test_blackbird_is_reported_as_not_configured(self):
        result = asyncio.run(check_blackbird("person@example.com"))
        self.assertEqual(result["status"], "not_configured")
        self.assertEqual(len(result["fields"]), 1)
        self.assertIn("не установлен", result["fields"][0]["value"])
    def test_google_adapter_does_not_infer_an_account(self):
        result = asyncio.run(check_google_account("person@gmail.com"))
        self.assertEqual(result["status"], "not_configured")
        self.assertIn("не предполагается", result["fields"][0]["value"])
    def test_github_commit_search_uses_public_api_with_authorization(self):
        requests = []
        def return_commits(request):
            requests.append(request)
            return httpx.Response(
                200,
                json={
                    "items": [
                        {"commit": {"author": {"email": "public@example.com"}}},
                        {"commit": {"author": {"email": "public@example.com"}}},
                    ]
                },
                request=request,
            )
        transport = httpx.MockTransport(return_commits)
        actual_async_client = httpx.AsyncClient
        def async_client_factory(*args, **kwargs):
            return actual_async_client(*args, transport=transport, **kwargs)
        with patch(
            "modules.github_commits.httpx.AsyncClient",
            side_effect=async_client_factory,
        ), patch(
            "modules.github_commits.get_api_key",
            return_value="test-token",
        ):
            result = asyncio.run(check_github_commits("octocat"))
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["fields"][0]["value"], "1")
        self.assertIn("author%3Aoctocat", str(requests[0].url))
        self.assertEqual(requests[0].headers["authorization"], "Bearer test-token")
    def test_email_websocket_streams_new_checks_and_existing_results(self):
        fake_results = {
            "email_infra": {"title": "SMTP & Домен", "status": "ok", "fields": []},
            "github": {"title": "Email в GitHub-коммитах", "status": "info", "fields": []},
            "hibp": {"title": "Утечки (HIBP)", "status": "ok", "fields": []},
            "pgp": {"title": "PGP Ключ", "status": "info", "fields": []},
            "gravatar": {"title": "Gravatar", "status": "info", "fields": []},
        }
        patches = [
            patch("main.check_email_infrastructure", new_callable=AsyncMock, return_value=fake_results["email_infra"]),
            patch("main.check_github_commits", new_callable=AsyncMock, return_value=fake_results["github"]),
            patch("main.check_hibp", new_callable=AsyncMock, return_value=fake_results["hibp"]),
            patch("main.check_pgp", new_callable=AsyncMock, return_value=fake_results["pgp"]),
            patch("main._gravatar_result", new_callable=AsyncMock, return_value=fake_results["gravatar"]),
            patch("main.get_domain_checks", new_callable=AsyncMock, return_value=[]),
        ]
        with TestClient(main.app) as client:
            with patches[0], patches[1] as github, patches[2], patches[3], patches[4], patches[5]:
                with client.websocket_connect("/ws/scan") as websocket:
                    websocket.send_json({"query": "person@example.com"})
                    self.assertEqual(websocket.receive_json()["type"], "root")
                    received = []
                    while True:
                        message = websocket.receive_json()
                        if message["type"] == "done":
                            break
                        if message["type"] == "node":
                            received.append(message["data"]["title"])
                self.assertEqual(len(received), 5)
                github.assert_awaited_once_with("person@example.com")
    def test_scan_streams_results_in_completion_order(self):
        websocket = FakeWebSocket()
        async def delayed_result(title, delay):
            await asyncio.sleep(delay)
            return {"title": title, "status": "info", "fields": []}
        asyncio.run(
            main._stream_checks(
                websocket,
                [
                    ("slow", "profiles", delayed_result("slow", 0.03)),
                    ("fast", "profiles", delayed_result("fast", 0.001)),
                ],
                "",
            )
        )
        titles = [
            message["data"]["title"]
            for message in websocket.sent
            if message["type"] == "node"
        ]
        self.assertEqual(titles, ["fast", "slow"])

    def test_websocket_retry_runs_only_selected_check_titles(self):
        async def result(title):
            return {"title": title, "status": "completed", "fields": []}

        checks = [
            ("keep", "profiles", result("keep")),
            ("retry", "profiles", result("retry")),
        ]
        with TestClient(main.app) as client:
            with patch("main._compose_checks", new_callable=AsyncMock, return_value=checks):
                with client.websocket_connect("/ws/scan") as websocket:
                    websocket.send_json({
                        "query": "octocat",
                        "query_type": "username",
                        "retry_titles": ["retry"],
                    })
                    messages = []
                    while True:
                        message = websocket.receive_json()
                        messages.append(message)
                        if message["type"] == "done":
                            break

        loading_titles = [message["data"]["title"] for message in messages if message["type"] == "loading"]
        nodes = [message["data"] for message in messages if message["type"] == "node"]
        self.assertEqual(loading_titles, ["retry"])
        self.assertEqual([node["check_title"] for node in nodes], ["retry"])
    def test_loading_placeholders_are_streamed_before_results(self):
        websocket = FakeWebSocket()
        async def delayed_result(title, delay):
            await asyncio.sleep(delay)
            return {"title": title, "status": "info", "fields": []}
        asyncio.run(
            main._stream_checks(
                websocket,
                [("slow", "profiles", delayed_result("slow", 0.03))],
                "octocat",
            )
        )
        kinds = [message["type"] for message in websocket.sent]
        self.assertEqual(kinds[0], "loading")
        self.assertEqual(kinds.count("loading"), 1)
        for message in websocket.sent:
            if message["type"] == "node":
                self.assertEqual(message["data"]["state"], "partial")
                self.assertEqual(message["data"]["category"], "profiles")
                self.assertIsNotNone(message["data"]["confidence"])
                self.assertEqual(message["data"]["check_id"], websocket.sent[0]["data"]["check_id"])
    def test_whatsmyname_classifies_by_code_and_body_marker(self):
        self.assertEqual(
            classify_site_response({"e_code": 200, "e_string": "FOUND!"}, 200, "it was FOUND! here"),
            "confirmed",
        )
        self.assertEqual(classify_site_response({"e_code": 200}, 200, "anything"), "possible")
        self.assertEqual(classify_site_response({"e_code": 200, "e_string": "found"}, 404, ""), "absent")
        self.assertEqual(classify_site_response({"e_code": 200, "e_string": "found"}, 301, ""), "inconclusive")
    def test_whatsmyname_probe_uses_dataset_with_body_markers(self):
        dataset = {
            "sites": [
                {"name": "Site A", "uri_check": "https://sitea.example/{account}", "method": "GET", "e_code": 200, "e_string": "welcome"},
                {"name": "Site B", "uri_check": "https://siteb.example/{account}", "method": "GET", "e_code": 200},
            ]
        }

        def handler(request):
            host = request.url.host
            if host == "raw.githubusercontent.com":
                requested.append(str(request.url))
                return httpx.Response(200, json=dataset, request=request)
            if host == "sitea.example":
                return httpx.Response(200, text="welcome to profile", request=request)
            if host == "siteb.example":
                return httpx.Response(404, text="", request=request)
            raise AssertionError(f"Unexpected host: {host}")

        requested = []
        transport = httpx.MockTransport(handler)
        actual_async_client = httpx.AsyncClient

        def async_client_factory(*args, **kwargs):
            return actual_async_client(*args, transport=transport, **kwargs)

        with (
            patch("modules.whatsmyname.httpx.AsyncClient", side_effect=async_client_factory),
            patch("modules.whatsmyname._cache", {"loaded_at": 0.0, "dataset": []}),
        ):
            result = asyncio.run(check_whatsmyname_package("octocat"))
        self.assertEqual(result["status"], "completed")
        labels = [field["label"] for field in result["fields"]]
        self.assertIn("Ссылки", labels)
        confirmed = next(field for field in result["fields"] if field["label"] == "Подтверждено")
        self.assertIn("Site A", confirmed["value"])
    def test_exif_endpoint_reports_not_configured_without_binary(self):
        with patch("modules.exiftool.shutil.which", return_value=None):
            with TestClient(main.app) as client:
                response = client.post("/api/exif", content=b"test", headers={"x-file-name": "photo.jpg"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "not_configured")
    def test_watch_crud_roundtrip_and_detectable_diff(self):
        diff = main._diff_nodes(
            [
                {"title": "MX Записи", "state": "completed"},
                {"title": "WHOIS Домена", "state": "completed"},
            ],
            [
                {"title": "MX Записи", "state": "failed"},
                {"title": "DNS Записи", "state": "completed"},
            ],
        )
        self.assertEqual(diff["added"], ["DNS Записи"])
        self.assertEqual(diff["removed"], ["WHOIS Домена"])
        self.assertEqual(diff["changed"], [{"title": "MX Записи", "from": "completed", "to": "failed"}])
        with TestClient(main.app) as client:
            created = client.post("/api/watch", json={"query": "example.com", "query_type": "domain", "depth": 1, "interval_minutes": 5})
            self.assertEqual(created.status_code, 200, created.text)
            watch_id = created.json()["id"]
            watches = client.get("/api/watch").json()["watches"]
            self.assertIn(watch_id, [item["id"] for item in watches])
            deleted = client.delete(f"/api/watch/{watch_id}")
            self.assertEqual(deleted.json()["deleted"], True)
    def test_organization_scan_runs_public_registry_checks(self):
        with (
            patch("main.check_wikidata_organization", new_callable=AsyncMock, return_value={"title": "Организации (Wikidata)", "status": "completed", "fields": []}),
            patch("main.check_github_organization", new_callable=AsyncMock, return_value={"title": "Организация GitHub", "status": "no_results", "fields": []}),
            TestClient(main.app) as client,
        ):
            with client.websocket_connect("/ws/scan") as websocket:
                websocket.send_json({"query": "Yandex", "query_type": "organization", "depth": 1})
                titles = []
                while True:
                    message = websocket.receive_json()
                    if message["type"] == "node":
                        titles.append(message["data"]["title"])
                    elif message["type"] == "done":
                        break
        self.assertIn("Организации (Wikidata)", titles)
        self.assertIn("Организация GitHub", titles)
if __name__ == "__main__":
    unittest.main()
