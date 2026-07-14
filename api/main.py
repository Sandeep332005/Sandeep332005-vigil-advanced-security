import json
import os
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta, timezone

from analytics.risk_engine import score_event
from decisioning.policy_engine import evaluate_access, TrustSession
from secrets_crypto.qpc_signer import sign_artifact, HashChainedLedger
from secrets_crypto.qpc_vault import KeyRotationPolicy
from detections.honeytoken import honeytoken_registry
from analytics.xai_explainer import RiskExplainer
from analytics.behavioral_twin import BehavioralTwin
from shared.models import AccessEvaluationRequest, EvidenceSignRequest, NormalizedEvent, EvidenceSignResponse

# Platform State
ledger = HashChainedLedger()
behavioral_twin = BehavioralTwin()
key_rotation_policy = KeyRotationPolicy()
xai_explainer = RiskExplainer()
sessions = {}


def _route_matches(path: str, *candidates: str) -> bool:
    return path in candidates

class RequestHandler(BaseHTTPRequestHandler):
    def _json_response(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8"))

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        
        if _route_matches(path, "/health", "/api/health"):
            self._json_response(200, {"status": "ok"})
            return
            
        if _route_matches(path, "/honeytoken/list", "/api/honeytokens"):
            self._json_response(200, honeytoken_registry.decoys)
            return

        if _route_matches(path, "/honeytoken/alerts", "/api/honeytokens/alerts"):
            self._json_response(200, honeytoken_registry.get_alerts())
            return
            
        if _route_matches(path, "/trust/inspect", "/api/trust/inspect"):
            qs = parse_qs(parsed.query)
            actor_id = qs.get("actor_id", ["anonymous"])[0]
            if actor_id not in sessions:
                sessions[actor_id] = TrustSession(actor_id)
            session = sessions[actor_id]
            self._json_response(200, {
                "actor_id": actor_id,
                "trust_score": round(session.current_trust(), 3),
                "multiplier": session.suspicious_multiplier,
                "last_activity": session.last_activity_at.isoformat()
            })
            return

        if path.startswith("/api/trust/") and path.endswith("/forecast"):
            parts = path.strip("/").split("/")
            session_id = parts[2] if len(parts) >= 4 else "anonymous"
            qs = parse_qs(parsed.query)
            minutes = int(qs.get("minutes", ["60"])[0])
            if session_id not in sessions:
                sessions[session_id] = TrustSession(session_id)
            session = sessions[session_id]
            forecast = []
            for minute in range(0, minutes + 1, 5):
                future = datetime.now(timezone.utc) + timedelta(minutes=minute)
                forecast.append({"minute": minute, "trust": round(session.current_trust(future), 4)})
            self._json_response(200, {"session_id": session_id, "forecast": forecast})
            return
            
        if _route_matches(path, "/ledger/verify", "/api/ledger/verify"):
            self._json_response(200, ledger.verify_ledger())
            return
            
        if _route_matches(path, "/qpc/vault-eval", "/api/qpc/vault-eval"):
            qs = parse_qs(parsed.query)
            actor_id = qs.get("actor_id", ["anonymous"])[0]
            self._json_response(200, key_rotation_policy.evaluate_rotation(actor_id))
            return
            
        if _route_matches(path, "/twin/predict", "/api/twin/predict"):
            qs = parse_qs(parsed.query)
            actor_id = qs.get("actor_id", ["anonymous"])[0]
            recent_actions = qs.get("recent_actions", [])
            recent_actions = recent_actions[0].split(",") if recent_actions else None
            actual_action = qs.get("actual_action", [""])[0]
            predictions = behavioral_twin.predict_next(actor_id, recent_actions)
            self._json_response(200, {
                "actor_id": actor_id,
                "predictions": predictions,
                "deviation_score": behavioral_twin.deviation_score(actor_id, actual_action, recent_actions) if actual_action else 0.0,
            })
            return
            
        if _route_matches(path, "/ledger/entries", "/api/ledger/entries"):
            self._json_response(200, ledger.chain)
            return

        # Serve frontend React static build files
        frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "dist")
        if os.path.exists(frontend_dir):
            rel_path = path.lstrip("/")
            if not rel_path or rel_path == "":
                rel_path = "index.html"
            target_file = os.path.join(frontend_dir, rel_path)
            
            # Fallback to sandeep-vigil workspace if file is not found (for local verification)
            if not os.path.exists(target_file) or os.path.isdir(target_file):
                fallback_dir = "/Users/sachi/sandeep-vigil/temp_visualizations/frontend/dist"
                fallback_file = os.path.join(fallback_dir, rel_path)
                if os.path.exists(fallback_file) and os.path.isfile(fallback_file):
                    target_file = fallback_file
            
            # Fallback to index.html for React SPA Router
            if not os.path.exists(target_file) or os.path.isdir(target_file):
                target_file = os.path.join(frontend_dir, "index.html")

            if os.path.abspath(target_file).startswith(os.path.abspath(frontend_dir)) and os.path.exists(target_file) and os.path.isfile(target_file):
                mime_types = {
                    ".html": "text/html",
                    ".css": "text/css",
                    ".js": "application/javascript",
                    ".png": "image/png",
                    ".jpg": "image/jpeg",
                    ".svg": "image/svg+xml",
                    ".ico": "image/x-icon"
                }
                _, ext = os.path.splitext(target_file)
                content_type = mime_types.get(ext.lower(), "application/octet-stream")
                
                try:
                    with open(target_file, "rb") as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(content)))
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(content)
                    return
                except Exception as e:
                    self._json_response(500, {"error": str(e)})
                    return
                    
        self._json_response(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        payload = self._read_json()

        if _route_matches(path, "/risk/score-event", "/api/risk/score-event"):
            try:
                event = NormalizedEvent.from_dict(payload)
            except Exception as e:
                self._json_response(400, {"error": f"Invalid event schema: {str(e)}"})
                return

            actor_id = event.actor_id
            if actor_id not in sessions:
                sessions[actor_id] = TrustSession(actor_id)
            session = sessions[actor_id]
            trust_score = session.current_trust()

            ht_hit = honeytoken_registry.check_access(event.asset_id, event.actor_id)
            twin_dev = behavioral_twin.deviation_score(actor_id, event.action)
            behavioral_twin.observe(actor_id, event.action)

            base_risk_res = score_event(event)
            risk_score = base_risk_res.user_risk_score
            reasons = list(base_risk_res.reasons)

            if ht_hit:
                risk_score = 100.0
                reasons.append("honeytoken_breach")
            elif twin_dev > 0.0:
                risk_score = min(100.0, risk_score + (twin_dev * 25.0))
                if twin_dev >= 0.5:
                    reasons.append("behavioral_twin_dev")

            from analytics.features import extract_features
            features = extract_features(event)
            if ht_hit:
                features["honeytoken_breach"] = 1.0
            if twin_dev > 0.0:
                features["behavioral_twin_dev"] = twin_dev

            xai_res = xai_explainer.explain(features, reasons, risk_score)
            session.record_activity(is_suspicious=(risk_score >= 35))
            
            key_rotation_policy.record_usage(actor_id)
            eval_rotation = key_rotation_policy.evaluate_rotation(actor_id)
            keys_rotated = False
            if eval_rotation["mandatory_rotation"] or risk_score >= 60:
                key_rotation_policy.rotate_key(actor_id)
                keys_rotated = True

            sig_req = EvidenceSignRequest(
                artifact_id=event.event_id,
                artifact_hash=hashlib.sha256(json.dumps(event.to_dict(), sort_keys=True).encode("utf-8")).hexdigest(),
                artifact_type="telemetry_event",
                classification="restricted" if risk_score < 60 else "highly_restricted",
                signer="platform_risk_engine"
            )
            sig_res = sign_artifact(sig_req)
            extra_data = {
                "event": event.to_dict(),
                "risk": {
                    "risk_score": risk_score,
                    "is_anomaly": risk_score >= 35
                },
                "decision": base_risk_res.recommended_action.value if not ht_hit else "block",
                "signature": {
                    "classical_sig": sig_res.classical_signature,
                    "classical_pub": "ecdsa_pubkey",
                    "lamport_sig": sig_res.pq_signature,
                    "lamport_pub": "dilithium_pubkey",
                    "metadata": {
                        "risk_score": risk_score,
                        "decision": base_risk_res.recommended_action.value if not ht_hit else "block",
                        "trust_score": round(trust_score, 3),
                        "keys_rotated": keys_rotated,
                        "xai_explanation": xai_res.get("factors", [])
                    }
                }
            }
            ledger_entry = ledger.append(event.event_id, sig_req.artifact_hash, sig_res, extra_data)

            response = {
                "user_risk_score": risk_score,
                "session_risk_score": risk_score,
                "reasons": reasons,
                "recommended_action": base_risk_res.recommended_action.value if not ht_hit else "block",
                "trust_score": round(trust_score, 3),
                "behavioral_deviation": twin_dev,
                "keys_rotated": keys_rotated,
                "xai_explanation": xai_res,
                "ledger_entry": ledger_entry
            }
            self._json_response(200, response)
            return

        if _route_matches(path, "/access/evaluate", "/api/access/evaluate"):
            request = AccessEvaluationRequest.from_dict(payload)
            actor_id = request.actor_id
            
            if actor_id not in sessions:
                sessions[actor_id] = TrustSession(actor_id)
            session = sessions[actor_id]
            
            twin_dev = behavioral_twin.deviation_score(actor_id, request.requested_action)
            ht_hit = honeytoken_registry.check_access(request.resource_id, actor_id) is not None
            
            enriched = AccessEvaluationRequest(
                actor_id=request.actor_id,
                session_id=request.session_id,
                resource_id=request.resource_id,
                requested_action=request.requested_action,
                current_risk_score=request.current_risk_score,
                trust_decay_score=session.current_trust(),
                honeytoken_hit=ht_hit,
                behavioral_twin_deviation=twin_dev
            )
            self._json_response(200, evaluate_access(enriched).to_dict())
            return

        if _route_matches(path, "/evidence/sign", "/api/evidence/sign"):
            request = EvidenceSignRequest.from_dict(payload)
            sig_res = sign_artifact(request)
            ledger_entry = ledger.append(request.artifact_id, request.artifact_hash, sig_res)
            self._json_response(200, {
                **sig_res.to_dict(),
                "ledger_entry": ledger_entry
            })
            return

        if _route_matches(path, "/honeytoken/register", "/api/honeytoken/register"):
            asset_id = payload.get("asset_id")
            metadata = payload.get("metadata", {})
            if not asset_id:
                self._json_response(400, {"error": "Missing asset_id"})
                return
            honeytoken_registry.register_decoy(asset_id, metadata)
            self._json_response(200, {"status": "registered", "asset_id": asset_id})
            return

        if _route_matches(path, "/honeytoken/check", "/api/honeytoken/check"):
            asset_id = payload.get("asset_id")
            actor_id = payload.get("actor_id", "anonymous")
            if not asset_id:
                self._json_response(400, {"error": "Missing asset_id"})
                return
            hit = honeytoken_registry.check_access(asset_id, actor_id)
            self._json_response(200, hit or {"hit": False})
            return

        if _route_matches(path, "/api/evaluate"):
            session_id = payload.get("session_id", "demo-session")
            risk_score = float(payload.get("risk_score", 0.0))
            contributing_features = payload.get("contributing_features", {})
            explanation_payload = xai_explainer.explain(contributing_features, list(contributing_features.keys()), risk_score)
            actor_id = payload.get("event", {}).get("user", session_id)
            if actor_id not in sessions:
                sessions[actor_id] = TrustSession(actor_id)
            session = sessions[actor_id]
            trust_score = round(session.current_trust(), 4)
            honeytoken_alert = None
            event = payload.get("event", {})
            check_asset = event.get("credential") or event.get("resource_id") or event.get("asset_id")
            if check_asset:
                honeytoken_alert = honeytoken_registry.check_access(check_asset, actor_id)

            access_request = AccessEvaluationRequest(
                actor_id=actor_id,
                session_id=session_id,
                resource_id=check_asset or "resource",
                requested_action=event.get("action", "evaluate"),
                current_risk_score=100.0 if honeytoken_alert else risk_score * 100.0,
                trust_decay_score=trust_score,
                honeytoken_hit=honeytoken_alert is not None,
                behavioral_twin_deviation=0.0,
            )
            decision = evaluate_access(access_request).to_dict()
            session.record_activity(is_suspicious=decision["decision"] != "allow")
            decision["current_trust"] = trust_score
            decision["effective_score"] = round(trust_score * (1.0 - min(access_request.current_risk_score / 100.0, 1.0)), 4)
            decision["risk_score"] = risk_score
            decision["explanation"] = explanation_payload["factors"]
            if honeytoken_alert:
                decision["honeytoken_alert"] = honeytoken_alert
            if key_rotation_policy.should_rotate(actor_id, trust_score):
                new_key = key_rotation_policy.rotate(actor_id)
                decision["key_rotated"] = True
                decision["new_key_id"] = new_key["key_id"]
            else:
                decision["key_rotated"] = False

            artifact_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
            sig_req = EvidenceSignRequest(
                artifact_id=session_id,
                artifact_hash=artifact_hash,
                artifact_type="session_evaluation",
                classification="restricted",
                signer="policy_engine",
            )
            sig_res = sign_artifact(sig_req)
            ledger.append(session_id, artifact_hash, sig_res, {"evaluation": decision})
            self._json_response(200, decision)
            return

        if _route_matches(path, "/api/twin/train"):
            actor_id = payload["user_id"]
            actions = payload.get("actions", [])
            behavioral_twin.train(actor_id, actions)
            self._json_response(200, {"status": "trained", "user": actor_id, "actions_processed": len(actions)})
            return

        if path == "/verify":
            record = payload.get("record", {})
            signature_bundle = payload.get("signature_bundle", {})
            classical_sig = signature_bundle.get("classical_sig")
            pq_sig = signature_bundle.get("lamport_sig")
            
            record_str = json.dumps(record, sort_keys=True)
            artifact_hash = hashlib.sha256(record_str.encode("utf-8")).hexdigest()
            
            from secrets_crypto.qpc_signer import verify_signature
            ok = verify_signature(artifact_hash, classical_sig, pq_sig)
            self._json_response(200, {"verified": ok})
            return

        self._json_response(404, {"error": "not_found"})

def run() -> None:
    server = HTTPServer(("127.0.0.1", 8000), RequestHandler)
    print("Serving Unified Insider Threat Platform on http://127.0.0.1:8000")
    server.serve_forever()

if __name__ == "__main__":
    run()
