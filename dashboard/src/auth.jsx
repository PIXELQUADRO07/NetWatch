// auth.jsx – NetWatch frontend authentication
import { createContext, useContext, useState, useCallback, useEffect } from "react";

const API = import.meta.env.VITE_API_BASE || "http://localhost:5000/api";

export const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token,    setToken]    = useState(() => localStorage.getItem("nw_token"));
  const [user,     setUser]     = useState(() => localStorage.getItem("nw_user"));
  const [authEnabled, setAuthEnabled] = useState(true);
  const [checked,  setChecked]  = useState(false);

  // Check if auth is enabled at all
  useEffect(() => {
    fetch(`${API}/status`)
      .then(r => r.json())
      .then(d => {
        if (d.auth_enabled === false) {
          setAuthEnabled(false);
          setToken("no-auth");
          setUser("anonymous");
        }
        setChecked(true);
      })
      .catch(() => setChecked(true));
  }, []);

  const login = useCallback(async (username, password) => {
    const res = await fetch(`${API}/auth/login`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Login failed");
    setToken(data.token);
    setUser(data.username);
    localStorage.setItem("nw_token", data.token);
    localStorage.setItem("nw_user",  data.username);
    return data;
  }, []);

  const logout = useCallback(() => {
    setToken(null);
    setUser(null);
    localStorage.removeItem("nw_token");
    localStorage.removeItem("nw_user");
  }, []);

  // Auto-refresh token before expiry (every 20h)
  useEffect(() => {
    if (!token || token === "no-auth") return;
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${API}/auth/refresh`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.ok) {
          const data = await res.json();
          setToken(data.token);
          localStorage.setItem("nw_token", data.token);
        } else {
          logout();
        }
      } catch {
        // network error — don't log out
      }
    }, 20 * 60 * 60 * 1000);
    return () => clearInterval(interval);
  }, [token, logout]);

  const authedFetch = useCallback(async (url, options = {}) => {
    const headers = { ...(options.headers || {}) };
    if (token && token !== "no-auth") {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const res = await fetch(url, { ...options, headers });
    if (res.status === 401) {
      logout();
      throw new Error("Session expired");
    }
    return res;
  }, [token, logout]);

  return (
    <AuthContext.Provider value={{ token, user, login, logout, authedFetch, authEnabled, checked }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

// ─── Login screen ─────────────────────────────────────────────────────────────

const T = {
  bg: "#05080f", s1: "#0a0f1e", s2: "#0f1628",
  border: "#1c2a42", cyan: "#00e5ff", text: "#e2e8f0", muted: "#475569",
  red: "#ef4444", green: "#10b981",
  mono: "'JetBrains Mono','Fira Code',monospace",
  sans: "'Space Grotesk','Segoe UI',sans-serif",
};

export function LoginScreen({ t }) {
  const { login } = useAuth();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState("");

  const handleLogin = async (e) => {
    e?.preventDefault();
    setLoading(true);
    setError("");
    try {
      await login(username, password);
    } catch (err) {
      setError(t("auth.error"));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      display: "flex", alignItems: "center", justifyContent: "center",
      height: "100vh", background: T.bg, fontFamily: T.sans,
    }}>
      <div style={{
        background: T.s1, border: `1px solid ${T.border}`, borderRadius: 16,
        padding: "40px 48px", width: 380, boxShadow: `0 0 40px ${T.cyan}18`,
      }}>
        {/* Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 32 }}>
          <div style={{
            width: 36, height: 36, border: `2px solid ${T.cyan}`, borderRadius: 8,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 18, color: T.cyan, fontWeight: 800,
          }}>⬡</div>
          <div>
            <div style={{ fontSize: 18, fontWeight: 800, color: T.text, letterSpacing: -0.5 }}>NetWatch</div>
            <div style={{ fontSize: 10, color: T.muted, letterSpacing: 1.5, textTransform: "uppercase" }}>Network Monitor</div>
          </div>
        </div>

        <div style={{ marginBottom: 16 }}>
          <label style={{ display: "block", fontSize: 10, color: T.muted, letterSpacing: 1.5,
                          textTransform: "uppercase", marginBottom: 6 }}>
            {t("auth.username")}
          </label>
          <input
            value={username} onChange={e => setUsername(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleLogin()}
            style={{ width: "100%", background: T.s2, border: `1px solid ${T.border}`,
                     borderRadius: 8, padding: "10px 14px", color: T.text,
                     fontFamily: T.mono, fontSize: 13, outline: "none", boxSizing: "border-box" }}
            autoFocus
          />
        </div>
        <div style={{ marginBottom: 24 }}>
          <label style={{ display: "block", fontSize: 10, color: T.muted, letterSpacing: 1.5,
                          textTransform: "uppercase", marginBottom: 6 }}>
            {t("auth.password")}
          </label>
          <input
            type="password" value={password} onChange={e => setPassword(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleLogin()}
            style={{ width: "100%", background: T.s2, border: `1px solid ${T.border}`,
                     borderRadius: 8, padding: "10px 14px", color: T.text,
                     fontFamily: T.mono, fontSize: 13, outline: "none", boxSizing: "border-box" }}
          />
        </div>

        {error && (
          <div style={{ background: T.red + "18", border: `1px solid ${T.red}44`,
                        borderRadius: 8, padding: "10px 14px", color: T.red,
                        fontSize: 12, marginBottom: 16, fontFamily: T.mono }}>
            {error}
          </div>
        )}

        <button
          onClick={handleLogin} disabled={loading || !username || !password}
          style={{
            width: "100%", padding: "12px", border: `1px solid ${T.cyan}44`,
            borderRadius: 8, background: loading ? T.s2 : T.cyan + "18",
            color: loading ? T.muted : T.cyan, fontFamily: T.sans, fontSize: 13,
            fontWeight: 700, cursor: loading ? "not-allowed" : "pointer", letterSpacing: 0.5,
          }}
        >
          {loading ? t("auth.logging") : t("auth.login")}
        </button>
      </div>
    </div>
  );
}
