import { useEffect, useState } from "react";
import "./App.css";

const API = "http://127.0.0.1:8000";

function App() {
  const [stats, setStats] = useState({
    active_flows: 0,
    applications: 0,
    source_ips: 0,
    blocked_flows: 0,
    total_packets: 0,
    total_bytes: 0,
    detected_domains: 0,
  });

  const [traffic, setTraffic] = useState([]);
  const [applications, setApplications] = useState([]);
  const [protocols, setProtocols] = useState([]);
  const [domains, setDomains] = useState([]);
  const [blocked, setBlocked] = useState([]);

  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("All");

  // Page navigation
  const [activePage, setActivePage] = useState("Dashboard");

  // Security rules
  const [rules, setRules] = useState([
    {
      id: 1,
      type: "IP",
      value: "192.168.1.50",
      action: "BLOCK",
      status: "Active",
    },
  ]);

  const [ruleType, setRuleType] = useState("IP");
  const [ruleValue, setRuleValue] = useState("");

  const loadData = async () => {
    try {
      const [
        statsRes,
        trafficRes,
        appsRes,
        protocolsRes,
        domainsRes,
        blockedRes,
      ] = await Promise.all([
        fetch(`${API}/stats`),
        fetch(`${API}/traffic`),
        fetch(`${API}/applications`),
        fetch(`${API}/protocols`),
        fetch(`${API}/domains`),
        fetch(`${API}/blocked`),
      ]);

      setStats(await statsRes.json());

      const trafficData = await trafficRes.json();
      setTraffic(trafficData.traffic || []);

      setApplications(await appsRes.json());
      setProtocols(await protocolsRes.json());
      setDomains(await domainsRes.json());
      setBlocked(await blockedRes.json());
    } catch (error) {
      console.error("Backend connection error:", error);
    }
  };

  useEffect(() => {
    loadData();

    const interval = setInterval(loadData, 5000);

    return () => clearInterval(interval);
  }, []);

  const filteredTraffic = traffic.filter((row) => {
    const matchesSearch =
      search === "" ||
      Object.values(row)
        .join(" ")
        .toLowerCase()
        .includes(search.toLowerCase());

    const matchesStatus =
      status === "All" ||
      (status === "Blocked" && row.blocked === "Yes") ||
      (status === "Allowed" && row.blocked === "No");

    return matchesSearch && matchesStatus;
  });

  const formatBytes = (bytes) => {
    if (!bytes) return "0 B";

    if (bytes < 1024) {
      return `${bytes} B`;
    }

    if (bytes < 1024 * 1024) {
      return `${(bytes / 1024).toFixed(1)} KB`;
    }

    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  // Add security rule
  const addRule = () => {
    const value = ruleValue.trim();

    if (!value) {
      alert("Please enter a value.");
      return;
    }

    const newRule = {
      id: Date.now(),
      type: ruleType,
      value: value,
      action: "BLOCK",
      status: "Active",
    };

    setRules((prev) => [...prev, newRule]);
    setRuleValue("");
  };

  // Delete security rule
  const deleteRule = (id) => {
    setRules((prev) => prev.filter((rule) => rule.id !== id));
  };

  // Toggle rule
  const toggleRule = (id) => {
    setRules((prev) =>
      prev.map((rule) =>
        rule.id === id
          ? {
              ...rule,
              status: rule.status === "Active" ? "Disabled" : "Active",
            }
          : rule
      )
    );
  };

  // ---------------- SECURITY RULES PAGE ----------------

  const SecurityRulesPage = () => {
    return (
      <div>
        <header className="header">
          <div>
            <h1>Security Rules</h1>
            <p>
              Manage IP, domain and application blocking rules
            </p>
          </div>

          <div className="live-badge">
            <span></span>
            LIVE
          </div>
        </header>

        {/* Add Rule */}
        <section className="panel" style={{ marginBottom: "24px" }}>
          <div className="panel-header">
            <div>
              <h3>🛡 Create Security Rule</h3>
              <span>
                Add a rule to block unwanted network traffic
              </span>
            </div>
          </div>

          <div
            style={{
              display: "flex",
              gap: "12px",
              alignItems: "center",
              flexWrap: "wrap",
              padding: "20px 0",
            }}
          >
            <select
              value={ruleType}
              onChange={(e) => setRuleType(e.target.value)}
              style={{
                padding: "12px",
                borderRadius: "8px",
                background: "#111827",
                color: "white",
                border: "1px solid #334155",
                minWidth: "140px",
              }}
            >
              <option value="IP">IP Address</option>
              <option value="DOMAIN">Domain</option>
              <option value="APPLICATION">Application</option>
              <option value="PORT">Port</option>
            </select>

            <input
              type="text"
              placeholder={
                ruleType === "IP"
                  ? "e.g. 192.168.1.50"
                  : ruleType === "DOMAIN"
                  ? "e.g. youtube.com"
                  : ruleType === "APPLICATION"
                  ? "e.g. YouTube"
                  : "e.g. 443"
              }
              value={ruleValue}
              onChange={(e) => setRuleValue(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  addRule();
                }
              }}
              style={{
                flex: 1,
                minWidth: "250px",
                padding: "12px",
                borderRadius: "8px",
                background: "#111827",
                color: "white",
                border: "1px solid #334155",
              }}
            />

            <button
              onClick={addRule}
              style={{
                padding: "12px 22px",
                borderRadius: "8px",
                border: "none",
                background: "#2563eb",
                color: "white",
                fontWeight: "600",
                cursor: "pointer",
              }}
            >
              + Add Rule
            </button>
          </div>
        </section>

        {/* Security Status */}
        <section className="stats-grid">
          <div className="stat-card">
            <div className="stat-icon blue">🛡</div>

            <div>
              <p>Total Rules</p>
              <h2>{rules.length}</h2>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon purple">✓</div>

            <div>
              <p>Active Rules</p>
              <h2>
                {rules.filter((rule) => rule.status === "Active").length}
              </h2>
            </div>
          </div>

          <div className="stat-card danger-card">
            <div className="stat-icon red">⚠</div>

            <div>
              <p>Blocked Flows</p>
              <h2>{stats.blocked_flows}</h2>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon cyan">●</div>

            <div>
              <p>Engine Status</p>
              <h2 style={{ color: "#22c55e" }}>ONLINE</h2>
            </div>
          </div>
        </section>

        {/* Rules Table */}
        <section className="panel" style={{ marginTop: "24px" }}>
          <div className="panel-header">
            <div>
              <h3>🚨 Active Security Rules</h3>
              <span>
                Rules configured for network traffic filtering
              </span>
            </div>
          </div>

          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Value</th>
                  <th>Action</th>
                  <th>Status</th>
                  <th>Controls</th>
                </tr>
              </thead>

              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id}>
                    <td>
                      <span className="protocol-tag">
                        {rule.type}
                      </span>
                    </td>

                    <td>{rule.value}</td>

                    <td>
                      <span className="blocked">
                        {rule.action}
                      </span>
                    </td>

                    <td>
                      {rule.status === "Active" ? (
                        <span className="allowed">ACTIVE</span>
                      ) : (
                        <span className="blocked">DISABLED</span>
                      )}
                    </td>

                    <td>
                      <div
                        style={{
                          display: "flex",
                          gap: "8px",
                        }}
                      >
                        <button
                          onClick={() => toggleRule(rule.id)}
                          style={{
                            padding: "7px 12px",
                            borderRadius: "6px",
                            border: "1px solid #334155",
                            background: "#111827",
                            color: "white",
                            cursor: "pointer",
                          }}
                        >
                          {rule.status === "Active"
                            ? "Disable"
                            : "Enable"}
                        </button>

                        <button
                          onClick={() => deleteRule(rule.id)}
                          style={{
                            padding: "7px 12px",
                            borderRadius: "6px",
                            border: "1px solid #7f1d1d",
                            background: "#450a0a",
                            color: "#fca5a5",
                            cursor: "pointer",
                          }}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {rules.length === 0 && (
              <div className="empty">
                No security rules configured.
              </div>
            )}
          </div>
        </section>

        {/* Existing blocked traffic */}
        <section className="panel" style={{ marginTop: "24px" }}>
          <div className="panel-header">
            <div>
              <h3>🚨 Recent Blocked Traffic</h3>
              <span>
                Traffic currently reported as blocked by the DPI engine
              </span>
            </div>
          </div>

          {blocked.length > 0 ? (
            <div className="alerts">
              {blocked.slice(0, 10).map((row, index) => (
                <div className="alert" key={index}>
                  <div className="alert-icon">⚠</div>

                  <div>
                    <strong>Blocked Traffic Detected</strong>

                    <p>
                      {row.src_ip}
                      {" → "}
                      {row.dst_ip}
                      {" • "}
                      {row.application}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="safe-message">
              ✓ No blocked traffic detected
            </div>
          )}
        </section>
      </div>
    );
  };

  // ---------------- DASHBOARD PAGE ----------------

  const DashboardPage = () => {
    return (
      <>
        <header className="header">
          <div>
            <h1>Security Dashboard</h1>

            <p>
              Deep Packet Inspection & Network Traffic Analysis
            </p>
          </div>

          <div className="live-badge">
            <span></span>
            LIVE
          </div>
        </header>

        {/* KPI CARDS */}
        <section className="stats-grid">
          <div className="stat-card">
            <div className="stat-icon blue">◉</div>

            <div>
              <p>Active Flows</p>
              <h2>{stats.active_flows}</h2>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon purple">◈</div>

            <div>
              <p>Applications</p>
              <h2>{stats.applications}</h2>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon cyan">◎</div>

            <div>
              <p>Source IPs</p>
              <h2>{stats.source_ips}</h2>
            </div>
          </div>

          <div className="stat-card danger-card">
            <div className="stat-icon red">⚠</div>

            <div>
              <p>Blocked Flows</p>
              <h2>{stats.blocked_flows}</h2>
            </div>
          </div>
        </section>

        {/* SECONDARY STATS */}
        <section className="mini-stats">
          <div>
            <span>Total Packets</span>

            <strong>
              {stats.total_packets.toLocaleString()}
            </strong>
          </div>

          <div>
            <span>Total Data</span>

            <strong>
              {formatBytes(stats.total_bytes)}
            </strong>
          </div>

          <div>
            <span>Detected Domains</span>

            <strong>{stats.detected_domains}</strong>
          </div>

          <div>
            <span>Engine Status</span>

            <strong className="online">
              ● ONLINE
            </strong>
          </div>
        </section>

        {/* CHARTS */}
        <section className="dashboard-grid">
          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Application Distribution</h3>
                <span>Detected network applications</span>
              </div>
            </div>

            <div className="bars">
              {applications.slice(0, 7).map((item) => {
                const max =
                  applications.length > 0
                    ? applications[0].flows
                    : 1;

                const width = Math.max(
                  5,
                  (item.flows / max) * 100
                );

                return (
                  <div
                    className="bar-row"
                    key={item.application}
                  >
                    <div className="bar-label">
                      {item.application}
                    </div>

                    <div className="bar-container">
                      <div
                        className="bar"
                        style={{
                          width: `${width}%`,
                        }}
                      ></div>
                    </div>

                    <div className="bar-value">
                      {item.flows}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Protocol Distribution</h3>
                <span>Network protocol breakdown</span>
              </div>
            </div>

            <div className="protocol-list">
              {protocols.map((item) => (
                <div
                  className="protocol-row"
                  key={item.protocol}
                >
                  <div>
                    <strong>{item.protocol}</strong>
                  </div>

                  <div className="protocol-bar">
                    <div
                      style={{
                        width: `${Math.min(
                          100,
                          item.flows * 10
                        )}%`,
                      }}
                    ></div>
                  </div>

                  <span>{item.flows}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* DOMAINS */}
        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>🌐 Top Detected Domains</h3>

              <span>
                Most frequently detected destinations
              </span>
            </div>
          </div>

          <div className="domain-grid">
            {domains.map((item, index) => (
              <div
                className="domain-card"
                key={item.domain}
              >
                <div className="domain-number">
                  #{index + 1}
                </div>

                <div className="domain-name">
                  {item.domain}
                </div>

                <div className="domain-count">
                  {item.flows} flows
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* TRAFFIC */}
        <section className="panel">
          <div className="panel-header traffic-header">
            <div>
              <h3>📡 Network Traffic</h3>

              <span>
                Real-time packet flow monitoring
              </span>
            </div>

            <div className="traffic-controls">
              <input
                type="text"
                placeholder="Search IP, domain, app..."
                value={search}
                onChange={(e) =>
                  setSearch(e.target.value)
                }
              />

              <select
                value={status}
                onChange={(e) =>
                  setStatus(e.target.value)
                }
              >
                <option>All</option>
                <option>Allowed</option>
                <option>Blocked</option>
              </select>
            </div>
          </div>

          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Protocol</th>
                  <th>Application</th>
                  <th>Domain</th>
                  <th>Packets</th>
                  <th>Data</th>
                  <th>Status</th>
                </tr>
              </thead>

              <tbody>
                {filteredTraffic
                  .slice(0, 50)
                  .map((row, index) => (
                    <tr key={index}>
                      <td>
                        {row.src_ip}:{row.src_port}
                      </td>

                      <td>
                        {row.dst_ip}:{row.dst_port}
                      </td>

                      <td>
                        <span className="protocol-tag">
                          {row.protocol}
                        </span>
                      </td>

                      <td>{row.application}</td>

                      <td className="domain-cell">
                        {row.domain || "—"}
                      </td>

                      <td>{row.packets}</td>

                      <td>
                        {formatBytes(row.bytes)}
                      </td>

                      <td>
                        {row.blocked === "Yes" ? (
                          <span className="blocked">
                            BLOCKED
                          </span>
                        ) : (
                          <span className="allowed">
                            ALLOWED
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>

            {filteredTraffic.length === 0 && (
              <div className="empty">
                No traffic found.
              </div>
            )}
          </div>
        </section>

        {/* SECURITY ALERTS */}
        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>🚨 Security Alerts</h3>

              <span>
                Blocked network traffic
              </span>
            </div>
          </div>

          {blocked.length > 0 ? (
            <div className="alerts">
              {blocked.slice(0, 10).map(
                (row, index) => (
                  <div
                    className="alert"
                    key={index}
                  >
                    <div className="alert-icon">
                      ⚠
                    </div>

                    <div>
                      <strong>
                        Blocked Traffic Detected
                      </strong>

                      <p>
                        {row.src_ip}
                        {" → "}
                        {row.dst_ip}
                        {" • "}
                        {row.application}
                      </p>
                    </div>
                  </div>
                )
              )}
            </div>
          ) : (
            <div className="safe-message">
              ✓ No blocked traffic detected
            </div>
          )}
        </section>
      </>
    );
  };

  return (
    <div className="app">
      {/* SIDEBAR */}
      <aside className="sidebar">
        <div className="logo">
          <div className="logo-icon">🔐</div>

          <div>
            <h2>DPI Security</h2>
            <span>Network Intelligence</span>
          </div>
        </div>

        <nav>
          <div
            className={`nav-item ${
              activePage === "Dashboard" ? "active" : ""
            }`}
            onClick={() => setActivePage("Dashboard")}
            style={{ cursor: "pointer" }}
          >
            <span>▣</span>
            Dashboard
          </div>

          <div
            className={`nav-item ${
              activePage === "Live Traffic"
                ? "active"
                : ""
            }`}
            onClick={() => setActivePage("Live Traffic")}
            style={{ cursor: "pointer" }}
          >
            <span>◉</span>
            Live Traffic
          </div>

          <div
            className={`nav-item ${
              activePage === "Analytics"
                ? "active"
                : ""
            }`}
            onClick={() => setActivePage("Analytics")}
            style={{ cursor: "pointer" }}
          >
            <span>◈</span>
            Analytics
          </div>

          <div
            className={`nav-item ${
              activePage === "Security Rules"
                ? "active"
                : ""
            }`}
            onClick={() =>
              setActivePage("Security Rules")
            }
            style={{ cursor: "pointer" }}
          >
            <span>🛡</span>
            Security Rules
          </div>

          <div
            className={`nav-item ${
              activePage === "Alerts" ? "active" : ""
            }`}
            onClick={() => setActivePage("Alerts")}
            style={{ cursor: "pointer" }}
          >
            <span>⚠</span>
            Alerts
          </div>

          <div
            className={`nav-item ${
              activePage === "Settings"
                ? "active"
                : ""
            }`}
            onClick={() => setActivePage("Settings")}
            style={{ cursor: "pointer" }}
          >
            <span>⚙</span>
            Settings
          </div>
        </nav>

        <div className="sidebar-status">
          <div className="status-dot"></div>

          <div>
            <strong>Engine Online</strong>
            <small>Live monitoring active</small>
          </div>
        </div>
      </aside>

      {/* MAIN CONTENT */}
      <main className="main">
        {activePage === "Security Rules" ? (
          <SecurityRulesPage />
        ) : activePage === "Dashboard" ? (
          <DashboardPage />
        ) : (
          <>
            <header className="header">
              <div>
                <h1>{activePage}</h1>
                <p>
                  DPI Security Center
                </p>
              </div>

              <div className="live-badge">
                <span></span>
                LIVE
              </div>
            </header>

            <section className="panel">
              <div className="safe-message">
                This section is ready for the next dashboard feature.
              </div>
            </section>
          </>
        )}

        <footer>
          <span>🔐 DPI Security Center</span>

          <span>
            C++ DPI Engine • FastAPI • React
          </span>

          <span>Auto refresh: 5 seconds</span>
        </footer>
      </main>
    </div>
  );
}

export default App;