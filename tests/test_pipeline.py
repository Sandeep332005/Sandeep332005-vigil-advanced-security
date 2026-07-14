import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
import json
import io
from typing import Any
from api.main import RequestHandler

class MockSocket:
    def __init__(self) -> None:
        pass

def simulate_request(method: str, path: str, body: dict = None) -> tuple[int, dict]:
    req_body = json.dumps(body).encode("utf-8") if body else b""
    rfile = io.BytesIO(req_body)
    wfile = io.BytesIO()
    
    class SilentRequestHandler(RequestHandler):
        def __init__(self) -> None:
            self.rfile = rfile
            self.wfile = wfile
            self.path = path
            self.requestline = f"{method} {path} HTTP/1.1"
            self.command = method
            self.request_version = "HTTP/1.1"
            self.protocol_version = "HTTP/1.1"
            self.close_connection = True
            
            from http.client import HTTPMessage
            self.headers = HTTPMessage()
            self.headers.add_header("Content-Length", str(len(req_body)))
            self.headers.add_header("Content-Type", "application/json")
            
        def log_message(self, format: str, *args: Any) -> None:
            pass
            
    handler = SilentRequestHandler()
    
    if method == "GET":
        handler.do_GET()
    elif method == "POST":
        handler.do_POST()
        
    wfile.seek(0)
    res_bytes = wfile.read()
    
    parts = res_bytes.split(b"\r\n\r\n", 1)
    headers_part = parts[0]
    body_part = parts[1] if len(parts) > 1 else b""
    
    status_line = headers_part.split(b"\r\n")[0].decode("utf-8")
    status = int(status_line.split(" ")[1])
    
    return status, json.loads(body_part.decode("utf-8"))

class EndToEndTests(unittest.TestCase):
    def test_health_check(self) -> None:
        status, res = simulate_request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(res["status"], "ok")

    def test_honeytoken_breach_detection(self) -> None:
        status1, reg = simulate_request("POST", "/honeytoken/register", {
            "asset_id": "vault:decoy:key",
            "metadata": {"severity": "critical", "description": "Decoy test key"}
        })
        self.assertEqual(status1, 200)
        self.assertEqual(reg["status"], "registered")

        event = {
            "event_id": "evt-ht-1",
            "timestamp": "2026-07-14T10:00:00Z",
            "actor_id": "attacker-1",
            "actor_type": "contractor",
            "session_id": "sess-ht",
            "source_system": "wazuh",
            "asset_id": "vault:decoy:key",
            "asset_criticality": 3,
            "action": "read_secret",
            "privilege_level": 2,
            "resource_id": "vault:decoy:key",
            "resource_sensitivity": 4,
            "raw_event_ref": "ref-1",
            "auth_context": {},
            "network_context": {},
            "change_window_context": {}
        }
        status2, res = simulate_request("POST", "/risk/score-event", event)
        self.assertEqual(status2, 200)
        self.assertEqual(res["user_risk_score"], 100.0)
        self.assertEqual(res["recommended_action"], "block")
        self.assertIn("honeytoken_breach", res["reasons"])

    def test_xai_explanations(self) -> None:
        event = {
            "event_id": "evt-xai-1",
            "timestamp": "2026-07-14T10:00:00Z",
            "actor_id": "user-xai",
            "actor_type": "employee",
            "session_id": "sess-xai",
            "source_system": "ssh",
            "asset_id": "host-1",
            "asset_criticality": 4,
            "action": "login",
            "privilege_level": 3,
            "resource_id": "shell",
            "resource_sensitivity": 3,
            "raw_event_ref": "ref-xai",
            "auth_context": {"failed_attempts": 0},
            "network_context": {},
            "change_window_context": {}
        }
        status, res = simulate_request("POST", "/risk/score-event", event)
        self.assertEqual(status, 200)
        self.assertIn("xai_explanation", res)
        explanation = res["xai_explanation"]
        self.assertIn("factors", explanation)
        self.assertTrue(len(explanation["factors"]) > 0)
        contribs = [f["contribution"] for f in explanation["factors"]]
        self.assertEqual(contribs, sorted(contribs, reverse=True))

    def test_behavioral_twin_prediction(self) -> None:
        e1 = {
            "event_id": "twin-1",
            "timestamp": "2026-07-14T10:00:00Z",
            "actor_id": "twin-user",
            "actor_type": "employee",
            "session_id": "sess-twin",
            "source_system": "web",
            "asset_id": "portal",
            "asset_criticality": 1,
            "action": "login",
            "privilege_level": 1,
            "resource_id": "home",
            "resource_sensitivity": 1,
            "raw_event_ref": "ref",
            "auth_context": {},
            "network_context": {},
            "change_window_context": {}
        }
        simulate_request("POST", "/risk/score-event", e1)
        
        e2 = dict(e1, event_id="twin-2", action="view_profile")
        simulate_request("POST", "/risk/score-event", e2)

        e2b = dict(e1, event_id="twin-2b", action="login")
        simulate_request("POST", "/risk/score-event", e2b)
        
        status, preds = simulate_request("GET", "/twin/predict?actor_id=twin-user")
        self.assertEqual(status, 200)
        self.assertIn("view_profile", preds["predictions"])
        
        e3 = dict(e1, event_id="twin-3", action="sudo")
        status3, res = simulate_request("POST", "/risk/score-event", e3)
        self.assertEqual(status3, 200)
        self.assertTrue(res["behavioral_deviation"] > 0.5)

    def test_trust_decay(self) -> None:
        event = {
            "event_id": "evt-decay-1",
            "timestamp": "2026-07-14T10:00:00Z",
            "actor_id": "decay-user",
            "actor_type": "employee",
            "session_id": "sess-decay",
            "source_system": "wazuh",
            "asset_id": "asset-1",
            "asset_criticality": 1,
            "action": "read",
            "privilege_level": 1,
            "resource_id": "res-1",
            "resource_sensitivity": 1,
            "raw_event_ref": "ref",
            "auth_context": {},
            "network_context": {},
            "change_window_context": {}
        }
        status1, res1 = simulate_request("POST", "/risk/score-event", event)
        self.assertEqual(status1, 200)
        self.assertEqual(res1["trust_score"], 1.0)
        
        status2, inspect = simulate_request("GET", "/trust/inspect?actor_id=decay-user")
        self.assertEqual(status2, 200)
        self.assertIn("trust_score", inspect)

    def test_ledger_verification(self) -> None:
        status1, entries = simulate_request("GET", "/ledger/entries")
        self.assertEqual(status1, 200)
        self.assertTrue(len(entries) > 0)
        
        status2, v = simulate_request("GET", "/ledger/verify")
        self.assertEqual(status2, 200)
        self.assertTrue(v["valid"])

    def test_qpc_vault_rotation(self) -> None:
        status, eval_rot = simulate_request("GET", "/qpc/vault-eval?actor_id=decay-user")
        self.assertEqual(status, 200)
        self.assertIn("compliance_status", eval_rot)
        self.assertIn("recommend_rotation", eval_rot)

if __name__ == "__main__":
    unittest.main()
