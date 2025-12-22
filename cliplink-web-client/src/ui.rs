use leptos::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Clip {
    pub id: String,
    pub title: String,
    pub preview: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum ConnectOutcome {
    Ok { clips: Vec<Clip> },
    Err { message: String },
}

#[server(Connect, "/api")]
pub async fn connect(
    host: String,
    port: u16,
    pub_rsa_key: String,
) -> Result<ConnectOutcome, ServerFnError> {
    println!("### then this");
    if host.trim().is_empty() {
        return Ok(ConnectOutcome::Err {
            message: "Host is required.".to_string(),
        });
    }
    if pub_rsa_key.trim().is_empty() {
        return Ok(ConnectOutcome::Err {
            message: "Public RSA key is required.".to_string(),
        });
    }

    // Replace this with your real backend connect + fetch.
    // Keep it returning ConnectOutcome::{Ok, Err} so the UI can branch.
    let _ = (host, port, pub_rsa_key);

    Ok(ConnectOutcome::Ok {
        clips: vec![
            Clip {
                id: "1".to_string(),
                title: "Alpha".to_string(),
                preview: "First clipboard entry".to_string(),
            },
            Clip {
                id: "2".to_string(),
                title: "Beta".to_string(),
                preview: "Second clipboard entry".to_string(),
            },
        ],
    })
}

#[component]
pub fn App() -> impl IntoView {
    view! {
        <CyberpunkStyles/>
        <div class="scanlines noise">
            <div class="container">
                <ConnectPage/>
            </div>
        </div>
    }
}

#[component]
fn ConnectPage() -> impl IntoView {
    let (host, set_host) = signal(String::new());
    let (port, set_port) = signal(6166);
    let (pub_rsa_key, set_pub_rsa_key) = signal(String::new());

    // Leptos 0.8: ServerAction is the “server fn action” wrapper.
    let connect_action = ServerAction::<Connect>::new();
    let pending = connect_action.pending();
    let value = connect_action.value(); // Signal<Option<Result<ConnectOutcome, ServerFnError>>>

    view! {
        <div class="panel">
            <div style="display:flex; justify-content:space-between; align-items:center; gap:12px;">
                <div>
                    <div class="glitch" data-text="Neon Relay">"Neon Relay"</div>
                    <div style="margin-top:6px; color:var(--muted); letter-spacing:.06em;">
                        "Connect, sync clipboards, move fast."
                    </div>
                </div>
                <span class="badge">"SSR"</span>
            </div>

            <form
                style="margin-top:16px;"
                on:submit=move |ev| {
                    ev.prevent_default();
                println!("### happening");
                    connect_action.dispatch(Connect {
                        host: host.get(),
                        port: port.get(),
                        pub_rsa_key: pub_rsa_key.get(),
                    });
                }
            >
                <div class="row grid2">
                    <div>
                        <label>"Host"</label>
                        <input
                            class="input"
                            placeholder="127.0.0.1"
                            prop:value=host
                            on:input=move |e| set_host.set(event_target_value(&e))
                        />
                    </div>

                    <div>
                        <label>"Port"</label>
                        <input
                            class="input"
                            type="number"
                            placeholder="443"
                            prop:value=move || port.get().to_string()
                            on:input=move |e| {
                                if let Ok(p) = event_target_value(&e).parse::<u16>() {
                                    set_port.set(p);
                                }
                            }
                        />
                    </div>
                </div>

                <div style="margin-top:10px;">
                    <label>"Public RSA key"</label>
                    <textarea
                        class="textarea"
                        placeholder="-----BEGIN PUBLIC KEY-----"
                        prop:value=pub_rsa_key
                        on:input=move |e| set_pub_rsa_key.set(event_target_value(&e))
                    />
                </div>

                <div style="margin-top:12px; display:flex; gap:10px; align-items:center;">
                    <button class="btn" type="submit" disabled=move || pending.get()>
                        {move || if pending.get() { "Connecting..." } else { "Connect" }}
                    </button>
                    <span style="color:var(--muted); font-size:12px; letter-spacing:.10em;">
                        "Neon handshake pending."
                    </span>
                </div>
            </form>

            <div style="margin-top:16px;">
                {move || {
                    match value.get() {
                        None => view! { <div></div> }.into_any(),

                        Some(Err(e)) => view! {
                            <div class="alert">
                                <div class="glitch" data-text="Error">"Error"</div>
                                <div style="margin-top:6px; color:var(--muted);">
                                    {format!("Server function failed: {e}")}
                                </div>
                            </div>
                        }.into_any(),

                        Some(Ok(ConnectOutcome::Err { message })) => view! {
                            <div class="alert">
                                <div class="glitch" data-text="Handshake Failed">"Handshake Failed"</div>
                                <div style="margin-top:6px; color:var(--muted);">
                                    {message}
                                </div>
                            </div>
                        }.into_any(),

                        Some(Ok(ConnectOutcome::Ok { clips })) => view! {
                            <div class="panel" style="margin-top:14px;">
                                <div class="glitch" data-text="Clipboards">"Clipboards"</div>
                                <div style="margin-top:10px; display:grid; gap:10px;">
                                    {clips.into_iter().map(|c| view! {
                                        <div class="panel" style="padding:12px; border-radius:14px;">
                                            <div style="display:flex; justify-content:space-between; align-items:center;">
                                                <div style="font-weight:700; letter-spacing:.08em;">
                                                    {c.title}
                                                </div>
                                                <span class="badge">{c.id}</span>
                                            </div>
                                            <div style="margin-top:6px; color:var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;">
                                                {c.preview}
                                            </div>
                                        </div>
                                    }).collect_view()}
                                </div>
                            </div>
                        }.into_any(),
                    }
                }}
            </div>
        </div>
    }
}

#[component]
fn CyberpunkStyles() -> impl IntoView {
    view! {
        <style>{r#"
:root {
  --bg0: #05040a;
  --bg1: #08061a;
  --neon1: #00f5ff;
  --neon2: #ff2bd6;
  --neon3: #b8ff00;
  --text: #e7e7ff;
  --muted: rgba(231,231,255,.65);
  --panel: rgba(10, 8, 25, .55);
  --panel2: rgba(10, 8, 25, .35);
  --line: rgba(0,245,255,.25);
}

* { box-sizing: border-box; }
html, body { height: 100%; margin: 0; }
body {
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Arial;
  color: var(--text);
  background:
    radial-gradient(1200px 700px at 15% 10%, rgba(255,43,214,.18), transparent 60%),
    radial-gradient(1000px 600px at 85% 30%, rgba(0,245,255,.16), transparent 55%),
    radial-gradient(900px 700px at 55% 90%, rgba(184,255,0,.10), transparent 60%),
    linear-gradient(180deg, var(--bg0), var(--bg1));
  overflow-x: hidden;
}

.scanlines::before {
  content: '';
  position: fixed; inset: 0;
  background: repeating-linear-gradient(
    to bottom,
    rgba(255,255,255,.03),
    rgba(255,255,255,.03) 1px,
    transparent 1px,
    transparent 3px
  );
  pointer-events: none;
  mix-blend-mode: overlay;
  opacity: .25;
}

.noise::after {
  content: '';
  position: fixed; inset: -50px;
  background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="120" height="120"><filter id="n"><feTurbulence type="fractalNoise" baseFrequency=".9" numOctaves="2" stitchTiles="stitch"/></filter><rect width="120" height="120" filter="url(%23n)" opacity=".35"/></svg>');
  background-size: 180px 180px;
  pointer-events: none;
  mix-blend-mode: soft-light;
  opacity: .15;
  animation: drift 9s linear infinite;
}

@keyframes drift {
  0% { transform: translate3d(0,0,0); }
  100% { transform: translate3d(120px,60px,0); }
}

.container {
  max-width: 980px;
  margin: 0 auto;
  padding: 28px 18px 64px;
}

.panel {
  border: 1px solid var(--line);
  background: linear-gradient(180deg, var(--panel), var(--panel2));
  box-shadow:
    0 0 0 1px rgba(255,43,214,.10) inset,
    0 0 28px rgba(0,245,255,.12),
    0 0 54px rgba(255,43,214,.10);
  border-radius: 18px;
  padding: 18px;
  backdrop-filter: blur(10px);
}

.row { display: grid; gap: 12px; }
.grid2 { grid-template-columns: 1fr 160px; }
@media (max-width: 680px) { .grid2 { grid-template-columns: 1fr; } }

label {
  display: block;
  font-size: 12px;
  letter-spacing: .18em;
  text-transform: uppercase;
  color: var(--muted);
  margin: 8px 0 6px;
}

.input, .textarea {
  width: 100%;
  padding: 12px 12px;
  border-radius: 12px;
  border: 1px solid rgba(0,245,255,.22);
  background: rgba(0,0,0,.25);
  color: var(--text);
  outline: none;
  box-shadow: 0 0 0 1px rgba(255,43,214,.10) inset;
}

.textarea { min-height: 160px; resize: vertical; }

.input:focus, .textarea:focus {
  border-color: rgba(0,245,255,.55);
  box-shadow:
    0 0 0 2px rgba(0,245,255,.18),
    0 0 30px rgba(0,245,255,.18);
}

.btn {
  cursor: pointer;
  border: 1px solid rgba(255,43,214,.38);
  background: linear-gradient(90deg, rgba(255,43,214,.18), rgba(0,245,255,.18));
  color: var(--text);
  padding: 12px 14px;
  border-radius: 14px;
  letter-spacing: .12em;
  text-transform: uppercase;
  font-weight: 650;
  box-shadow:
    0 0 18px rgba(255,43,214,.12),
    0 0 28px rgba(0,245,255,.10);
}

.btn:disabled {
  opacity: .55;
  cursor: not-allowed;
  filter: grayscale(.2);
}

.badge {
  display: inline-block;
  padding: 6px 10px;
  border: 1px solid rgba(184,255,0,.35);
  border-radius: 999px;
  font-size: 12px;
  letter-spacing: .12em;
  color: rgba(184,255,0,.95);
  background: rgba(184,255,0,.07);
}

.alert {
  margin-top: 14px;
  border-radius: 14px;
  padding: 12px 12px;
  border: 1px solid rgba(255,80,80,.35);
  background: rgba(255,80,80,.08);
  box-shadow: 0 0 20px rgba(255,80,80,.10);
}

.glitch {
  position: relative;
  display: inline-block;
  font-weight: 800;
  letter-spacing: .12em;
  text-transform: uppercase;
  text-shadow:
    0 0 16px rgba(0,245,255,.22),
    0 0 22px rgba(255,43,214,.14);
}

.glitch::before, .glitch::after {
  content: attr(data-text);
  position: absolute;
  left: 0; top: 0;
  width: 100%;
  overflow: hidden;
  opacity: .8;
}

.glitch::before {
  transform: translate(1px, 0);
  color: rgba(0,245,255,.85);
  clip-path: inset(0 0 65% 0);
  animation: glitch1 2.3s infinite linear alternate-reverse;
}

.glitch::after {
  transform: translate(-1px, 0);
  color: rgba(255,43,214,.85);
  clip-path: inset(62% 0 0 0);
  animation: glitch2 1.9s infinite linear alternate-reverse;
}

@keyframes glitch1 {
  0% { clip-path: inset(0 0 65% 0); transform: translate(1px,0); }
  20% { clip-path: inset(10% 0 55% 0); transform: translate(2px,-1px); }
  40% { clip-path: inset(3% 0 70% 0); transform: translate(-1px,1px); }
  60% { clip-path: inset(18% 0 48% 0); transform: translate(3px,0); }
  80% { clip-path: inset(5% 0 75% 0); transform: translate(1px,-1px); }
  100% { clip-path: inset(12% 0 58% 0); transform: translate(-2px,1px); }
}

@keyframes glitch2 {
  0% { clip-path: inset(62% 0 0 0); transform: translate(-1px,0); }
  25% { clip-path: inset(72% 0 0 0); transform: translate(-3px,1px); }
  50% { clip-path: inset(58% 0 0 0); transform: translate(2px,-1px); }
  75% { clip-path: inset(80% 0 0 0); transform: translate(-2px,0); }
  100% { clip-path: inset(66% 0 0 0); transform: translate(3px,1px); }
}
        "#}</style>
    }
}
