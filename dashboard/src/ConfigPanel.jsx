// ConfigPanel.jsx – NetWatch runtime configuration panel
import { useState, useEffect } from "react";
import { useAuth } from "./auth.jsx";
import { useI18n } from "./i18n.jsx";

const API = import.meta.env.VITE_API_BASE || "http://localhost:5000/api";

const T = {
  s1: "#0a0f1e", s2: "#0f1628", s3: "#141d35",
  border: "#1c2a42", border2: "#243350",
  cyan: "#00e5ff", green: "#10b981", amber: "#fbbf24", red: "#ef4444", muted: "#475569",
  text: "#e2e8f0",
  mono: "'JetBrains Mono','Fira Code',monospace",
  sans: "'Space Grotesk','Segoe UI',sans-serif",
};

const Card  = ({children, style={}}) => <div style={{background:T.s1,border:`1px solid ${T.border}`,borderRadius:12,padding:"16px 18px",...style}}>{children}</div>;
const Label = ({children}) => <div style={{fontSize:10,color:T.muted,letterSpacing:1.5,textTransform:"uppercase",marginBottom:6}}>{children}</div>;
const Field = ({children}) => <div style={{marginBottom:18}}>{children}</div>;
const Inp   = ({value,onChange,type="text",min,max,step}) => (
  <input type={type} value={value} onChange={e=>onChange(e.target.value)}
    min={min} max={max} step={step}
    style={{width:"100%",background:T.s2,border:`1px solid ${T.border}`,borderRadius:8,
            padding:"10px 14px",color:T.text,fontFamily:T.mono,fontSize:13,outline:"none",
            boxSizing:"border-box"}}/>
);

export default function ConfigPanel() {
  const { authedFetch } = useAuth();
  const { t, lang, changeLang } = useI18n();
  const [cfg,     setCfg]    = useState(null);
  const [saved,   setSaved]  = useState(false);
  const [loading, setLoading]= useState(true);
  const [error,   setError]  = useState("");

  // Local editable state
  const [bpsThreshold,   setBps]    = useState(5000000);
  const [flowsThreshold, setFlows]  = useState(300);
  const [cooldown,       setCooldown]= useState(30);
  const [geoip,          setGeoip]  = useState(true);
  const [suspPorts,      setSusp]   = useState("[6667, 4444, 1337, 31337, 9001]");
  const [pruneDays,      setPrune]  = useState(7);
  const [rateLimit,      setRate]   = useState(300);
  const [darkMode,       setDark]   = useState(true);
  // Beaconing
  const [beaconMaxVar,   setBeaconVar]  = useState(4.0);
  const [beaconMinConns, setBeaconConns]= useState(6);
  // Baseline Z-score
  const [baselineZ,      setBaselineZ]  = useState(3.0);
  const [baselineMin,    setBaselineMin]= useState(30);
  const [pwCurrent,      setPwCur]  = useState("");
  const [pwNew,          setPwNew]  = useState("");
  const [pwMsg,          setPwMsg]  = useState("");

  useEffect(() => {
    authedFetch(`${API}/config`)
      .then(r => r.json())
      .then(d => {
        setCfg(d);
        setBps(d.alert_threshold_bps    ?? 5000000);
        setFlows(d.alert_threshold_flows ?? 300);
        setCooldown(d.alert_cooldown_sec ?? 30);
        setGeoip(d.geoip_enabled         ?? true);
        setSusp(JSON.stringify(d.suspicious_ports ?? []));
        setPrune(d.prune_keep_days       ?? 7);
        setRate(d.rate_limit_max         ?? 300);
        setDark(d.dark_mode              ?? true);
        setBeaconVar(d.beacon_max_variance   ?? 4.0);
        setBeaconConns(d.beacon_min_conns    ?? 6);
        setBaselineZ(d.baseline_z_thresh     ?? 3.0);
        setBaselineMin(d.baseline_min_samples?? 30);
        setLoading(false);
      })
      .catch(e => { setError(e.message); setLoading(false); });
  }, [authedFetch]);

  const save = async () => {
    setError("");
    let parsedPorts;
    try { parsedPorts = JSON.parse(suspPorts); }
    catch { setError("Porte sospette: JSON non valido"); return; }

    try {
      const res = await authedFetch(`${API}/config`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          alert_threshold_bps:   Number(bpsThreshold),
          alert_threshold_flows: Number(flowsThreshold),
          alert_cooldown_sec:    Number(cooldown),
          geoip_enabled:         geoip,
          suspicious_ports:      parsedPorts,
          prune_keep_days:       Number(pruneDays),
          rate_limit_max:        Number(rateLimit),
          dark_mode:             darkMode,
          language:              lang,
          beacon_max_variance:   Number(beaconMaxVar),
          beacon_min_conns:      Number(beaconMinConns),
          baseline_z_thresh:     Number(baselineZ),
          baseline_min_samples:  Number(baselineMin),
        }),
      });
      if (!res.ok) throw new Error("Save failed");
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } catch (e) {
      setError(e.message);
    }
  };

  const changePassword = async () => {
    setPwMsg("");
    try {
      const res = await authedFetch(`${API}/auth/change-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ current_password: pwCurrent, new_password: pwNew }),
      });
      const d = await res.json();
      if (!res.ok) throw new Error(d.error);
      setPwMsg("Password changed successfully ✓");
      setPwCur(""); setPwNew("");
    } catch (e) {
      setPwMsg(`Errore: ${e.message}`);
    }
  };

  if (loading) return (
    <div style={{display:"flex",alignItems:"center",justifyContent:"center",height:200,
                 color:T.muted,fontFamily:T.mono,fontSize:13}}>{t("general.loading")}</div>
  );

  return (
    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,animation:"fadeIn .3s ease"}}>
      {/* ── Alert thresholds ── */}
      <Card>
        <div style={{fontSize:12,fontWeight:700,letterSpacing:1.5,textTransform:"uppercase",
                     color:T.muted,marginBottom:16}}>Anomaly Detection</div>

        <Field><Label>{t("config.alert_bps")}</Label>
          <Inp value={bpsThreshold} onChange={setBps} type="number" min={1000} step={100000}/>
          <div style={{fontSize:10,color:T.muted,marginTop:4,fontFamily:T.mono}}>
            Current: {(bpsThreshold/1e6).toFixed(1)} MB/s
          </div>
        </Field>

        <Field><Label>{t("config.alert_flows")}</Label>
          <Inp value={flowsThreshold} onChange={setFlows} type="number" min={10}/>
        </Field>

        <Field><Label>{t("config.cooldown")}</Label>
          <Inp value={cooldown} onChange={setCooldown} type="number" min={5} max={3600}/>
        </Field>

        <Field><Label>{t("config.susp_ports")}</Label>
          <textarea value={suspPorts} onChange={e=>setSusp(e.target.value)}
            style={{width:"100%",height:70,background:T.s2,border:`1px solid ${T.border}`,
                    borderRadius:8,padding:"10px 14px",color:T.text,fontFamily:T.mono,
                    fontSize:12,outline:"none",resize:"vertical",boxSizing:"border-box"}}/>
        </Field>
      </Card>

      {/* ── System ── */}
      <Card>
        <div style={{fontSize:12,fontWeight:700,letterSpacing:1.5,textTransform:"uppercase",
                     color:T.muted,marginBottom:16}}>Sistema</div>

        <Field>
          <Label>{t("config.geoip")}</Label>
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <div onClick={()=>setGeoip(!geoip)} style={{
              width:44,height:24,borderRadius:12,background:geoip?T.cyan+"44":T.s3,
              border:`1px solid ${geoip?T.cyan:T.border}`,cursor:"pointer",position:"relative",
              transition:"all .2s",
            }}>
              <div style={{position:"absolute",top:3,left:geoip?22:3,width:16,height:16,
                           borderRadius:"50%",background:geoip?T.cyan:T.muted,transition:"left .2s"}}/>
            </div>
            <span style={{fontSize:12,color:geoip?T.green:T.muted,fontFamily:T.mono}}>
              {geoip?"Enabled":"Disabled"}
            </span>
          </div>
        </Field>

        <Field><Label>{t("config.prune_days")}</Label>
          <Inp value={pruneDays} onChange={setPrune} type="number" min={1} max={365}/>
        </Field>

        <Field><Label>{t("config.rate_limit")}</Label>
          <Inp value={rateLimit} onChange={setRate} type="number" min={10} max={10000}/>
        </Field>

        <Field>
          <Label>{t("config.language")}</Label>
          <select value={lang} onChange={e=>changeLang(e.target.value)}
            style={{width:"100%",background:T.s2,border:`1px solid ${T.border}`,borderRadius:8,
                    padding:"10px 14px",color:T.text,fontFamily:T.mono,fontSize:13,outline:"none"}}>
            <option value="it">Italiano 🇮🇹</option>
            <option value="en">English 🇬🇧</option>
          </select>
        </Field>

        {error && (
          <div style={{color:T.red,fontSize:12,fontFamily:T.mono,marginBottom:12,
                       background:T.red+"18",borderRadius:8,padding:"8px 12px"}}>
            {error}
          </div>
        )}

        <button onClick={save} style={{
          width:"100%",padding:"11px",border:`1px solid ${saved?T.green:T.cyan}44`,
          borderRadius:8,background:saved?T.green+"18":T.cyan+"0a",
          color:saved?T.green:T.cyan,fontFamily:T.sans,fontSize:13,
          fontWeight:700,cursor:"pointer",letterSpacing:.5,transition:"all .2s",
        }}>
          {saved ? t("config.saved") : t("config.save")}
        </button>
      </Card>

      {/* ── Change Password ── */}
      <Card style={{gridColumn:"1 / -1"}}>
        <div style={{fontSize:12,fontWeight:700,letterSpacing:1.5,textTransform:"uppercase",
                     color:T.muted,marginBottom:16}}>{t("auth.change_pw")}</div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr auto",gap:12,alignItems:"end"}}>
          <Field style={{marginBottom:0}}>
            <Label>Password attuale</Label>
            <input type="password" value={pwCurrent} onChange={e=>setPwCur(e.target.value)}
              style={{width:"100%",background:T.s2,border:`1px solid ${T.border}`,borderRadius:8,
                      padding:"10px 14px",color:T.text,fontFamily:T.mono,fontSize:13,outline:"none",
                      boxSizing:"border-box"}}/>
          </Field>
          <Field style={{marginBottom:0}}>
            <Label>Nuova password (min 8 car.)</Label>
            <input type="password" value={pwNew} onChange={e=>setPwNew(e.target.value)}
              style={{width:"100%",background:T.s2,border:`1px solid ${T.border}`,borderRadius:8,
                      padding:"10px 14px",color:T.text,fontFamily:T.mono,fontSize:13,outline:"none",
                      boxSizing:"border-box"}}/>
          </Field>
          <button onClick={changePassword}
            disabled={!pwCurrent || pwNew.length < 8}
            style={{padding:"10px 20px",border:`1px solid ${T.amber}44`,borderRadius:8,
                    background:T.amber+"0a",color:T.amber,fontFamily:T.sans,fontSize:12,
                    fontWeight:700,cursor:"pointer",whiteSpace:"nowrap"}}>
            Cambia
          </button>
        </div>
        {pwMsg && (
          <div style={{marginTop:10,fontSize:12,fontFamily:T.mono,
                       color:pwMsg.includes("Errore")?T.red:T.green}}>
            {pwMsg}
          </div>
        )}
      </Card>
    </div>
  );
}
