import React, { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  KeyRound,
  Lock,
  ShieldAlert,
  XCircle
} from "lucide-react";

const API_BASE = window.location.origin;

const tabs = [
  { id: "dashboard", label: "Dashboard", icon: Activity },
  { id: "xai", label: "XAI", icon: ShieldAlert },
  { id: "trust", label: "Trust", icon: KeyRound },
  { id: "ledger", label: "Ledger", icon: Lock },
  { id: "honeytoken", label: "Honeytokens", icon: AlertTriangle }
];

const cardStyle = {
  background: "rgba(15, 23, 42, 0.82)",
  border: "1px solid rgba(148, 163, 184, 0.18)",
  borderRadius: "18px",
  padding: "20px",
  boxShadow: "0 18px 40px rgba(2, 6, 23, 0.28)"
};

function App() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [evalResult, setEvalResult] = useState(null);
  const [trustForecast, setTrustForecast] = useState([]);
  const [ledgerStatus, setLedgerStatus] = useState(null);
  const [ledgerEntries, setLedgerEntries] = useState([]);
  const [honeyAlerts, setHoneyAlerts] = useState([]);

  async function runEvaluation(triggerHoneytoken = false) {
    const payload = {
      session_id: triggerHoneytoken ? "attacker-session" : "demo-session-001",
      risk_score: triggerHoneytoken ? 0 : 0.35,
      contributing_features: triggerHoneytoken
        ? {}
        : {
            geo_anomaly: 0.25,
            auth_failures: 0.15,
            time_anomaly: 0.1,
            trust_decay: 0.3
          },
      event: triggerHoneytoken
        ? { user: "unknown", credential: "vault:secret:admin_backup", action: "read_secret" }
        : { user: "jdoe", resource_id: "normal_resource", action: "login" }
    };

    const response = await fetch(`${API_BASE}/api/evaluate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await response.json();
    setEvalResult(data);

    const trust = await fetch(`${API_BASE}/api/trust/${payload.session_id}/forecast?minutes=60`);
    const trustData = await trust.json();
    setTrustForecast(trustData.forecast || []);

    const verify = await fetch(`${API_BASE}/api/ledger/verify`);
    setLedgerStatus(await verify.json());

    const entries = await fetch(`${API_BASE}/api/ledger/entries`);
    setLedgerEntries(await entries.json());

    const alerts = await fetch(`${API_BASE}/api/honeytokens/alerts`);
    setHoneyAlerts(await alerts.json());
  }

  useEffect(() => {
    runEvaluation(false).catch(() => {});
  }, []);

  return (
    <div className="app-shell">
      <div className="hero">
        <p className="eyebrow">Banking Security Operations</p>
        <h1>VIGIL Advanced Security Platform</h1>
        <p className="subtitle">
          Behavioral risk scoring, trust decay, honeytoken tripwires, and tamper-evident evidence protection in one workspace.
        </p>
      </div>

      <div className="tab-row">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              className={activeTab === tab.id ? "tab active" : "tab"}
              onClick={() => setActiveTab(tab.id)}
            >
              <Icon size={16} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {activeTab === "dashboard" && (
        <div className="grid-two">
          <section style={cardStyle}>
            <h2>Live Evaluation</h2>
            <p>Run a normal session or trigger a honeytoken breach to see trust, policy, and key rotation behavior.</p>
            <div className="button-row">
              <button className="primary" onClick={() => runEvaluation(false)}>Run Normal Demo</button>
              <button className="danger" onClick={() => runEvaluation(true)}>Trigger Honeytoken</button>
            </div>
            {evalResult && (
              <div className="result-stack">
                <div className="metric">
                  <span>Decision</span>
                  <strong>{String(evalResult.decision || evalResult.recommended_action).toUpperCase()}</strong>
                </div>
                <div className="metric">
                  <span>Trust</span>
                  <strong>{evalResult.current_trust ?? evalResult.trust_score}</strong>
                </div>
                <div className="metric">
                  <span>Effective Score</span>
                  <strong>{evalResult.effective_score ?? evalResult.user_risk_score}</strong>
                </div>
                {evalResult.key_rotated && (
                  <div className="badge info">Key rotated: {evalResult.new_key_id}</div>
                )}
                {evalResult.honeytoken_alert && (
                  <div className="badge critical">{evalResult.honeytoken_alert.justification || evalResult.honeytoken_alert.message}</div>
                )}
              </div>
            )}
          </section>

          <section style={cardStyle}>
            <h2>Latest Ledger Status</h2>
            {ledgerStatus ? (
              <div className="status-row">
                {ledgerStatus.valid ? <CheckCircle2 color="#4ade80" /> : <XCircle color="#f87171" />}
                <div>
                  <strong>{ledgerStatus.valid ? "Ledger valid" : "Ledger broken"}</strong>
                  <p>
                    {ledgerStatus.valid
                      ? `${ledgerStatus.entries_verified ?? ledgerEntries.length} entries verified`
                      : `Break at ${ledgerStatus.break_at}`}
                  </p>
                </div>
              </div>
            ) : (
              <p>Loading ledger status...</p>
            )}
            <div className="mini-list">
              {ledgerEntries.slice(-3).reverse().map((entry) => (
                <div key={`${entry.index}-${entry.artifact_id}`} className="mini-item">
                  <span>#{entry.index}</span>
                  <span>{entry.artifact_id || entry.record?.session || "artifact"}</span>
                </div>
              ))}
            </div>
          </section>
        </div>
      )}

      {activeTab === "xai" && (
        <section style={cardStyle}>
          <h2>XAI Risk Breakdown</h2>
          {evalResult?.explanation?.length ? (
            <>
              <ResponsiveContainer width="100%" height={320}>
                <BarChart data={evalResult.explanation}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="factor" stroke="#94a3b8" />
                  <YAxis stroke="#94a3b8" />
                  <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />
                  <Bar dataKey="contribution" fill="#38bdf8" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
              <div className="detail-list">
                {evalResult.explanation.map((item) => (
                  <div key={item.factor} className="detail-item">
                    <strong>{item.factor}</strong>
                    <span>{item.description} Contribution: {item.contribution}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <p>Run an evaluation to generate the XAI breakdown.</p>
          )}
        </section>
      )}

      {activeTab === "trust" && (
        <section style={cardStyle}>
          <h2>Trust Decay Forecast</h2>
          <ResponsiveContainer width="100%" height={340}>
            <LineChart data={trustForecast}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="minute" stroke="#94a3b8" />
              <YAxis domain={[0, 1]} stroke="#94a3b8" />
              <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />
              <Line type="monotone" dataKey="trust" stroke="#f59e0b" strokeWidth={3} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </section>
      )}

      {activeTab === "ledger" && (
        <section style={cardStyle}>
          <h2>Chained Ledger Verification</h2>
          <div className="status-row">
            {ledgerStatus?.valid ? <CheckCircle2 color="#4ade80" /> : <XCircle color="#f87171" />}
            <div>
              <strong>{ledgerStatus?.valid ? "Cryptographic continuity intact" : "Chain verification failed"}</strong>
              <p>{ledgerStatus?.reason || ledgerStatus?.details || "Latest verification result"}</p>
            </div>
          </div>
          <div className="detail-list">
            {ledgerEntries.slice().reverse().map((entry) => (
              <div key={`${entry.index}-${entry.current_hash}`} className="detail-item">
                <strong>Entry {entry.index}</strong>
                <span>{entry.current_hash}</span>
              </div>
            ))}
          </div>
        </section>
      )}

      {activeTab === "honeytoken" && (
        <section style={cardStyle}>
          <h2>Honeytoken Alerts</h2>
          {honeyAlerts.length ? (
            <div className="detail-list">
              {honeyAlerts.map((alert, index) => (
                <div key={`${alert.asset_id}-${index}`} className="detail-item critical-item">
                  <strong>{alert.asset_id}</strong>
                  <span>{alert.justification || alert.message}</span>
                </div>
              ))}
            </div>
          ) : (
            <p>No honeytoken alerts yet. Trigger the simulation from the dashboard.</p>
          )}
        </section>
      )}
    </div>
  );
}

export default App;
