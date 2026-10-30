"use strict";

const TOKEN = new URLSearchParams(location.search).get("t") || "";
const $ = (id) => document.getElementById(id);
let state = {};
let pendingUserId = null;
let pendingConnect = null; // {name, password, code} awaiting fingerprint confirmation

async function api(path, body) {
  const r = await fetch("/api/" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Token": TOKEN },
    body: JSON.stringify(body || {}),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

function toast(msg, kind) {
  const t = $("toast");
  t.textContent = kind === "err" ? msg + "  (click to dismiss)" : msg;
  t.className = "toast " + (kind || "ok");
  clearTimeout(toast.timer);
  // Errors stay until clicked so they can't be missed.
  if (kind !== "err") toast.timer = setTimeout(() => t.classList.add("hidden"), 4000);
}
$("toast").addEventListener("click", () => $("toast").classList.add("hidden"));

async function run(btn, fn) {
  if (btn) btn.disabled = true;
  try { await fn(); } catch (e) { toast(e.message, "err"); }
  finally { if (btn) btn.disabled = false; }
}

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const k of kids) e.append(k);
  return e;
}

// ---------- tabs ----------
document.querySelectorAll(".tab").forEach((b) =>
  b.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === b));
    document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("hidden", p.id !== "tab-" + b.dataset.tab));
    if (b.dataset.tab === "log") refresh();
  })
);

// Header badge: "standard user ▾" opens a menu to restart elevated.
function setAdminMenu(open) {
  $("admin-menu").classList.toggle("hidden", !open);
  $("admin-pill").setAttribute("aria-expanded", String(open));
}
$("admin-pill").addEventListener("click", (e) => {
  e.stopPropagation();
  if (!state.elevated) setAdminMenu($("admin-menu").classList.contains("hidden"));
});
document.addEventListener("click", (e) => { if (!e.target.closest(".pill-menu")) setAdminMenu(false); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") setAdminMenu(false); });
$("admin-elevate").addEventListener("click", (e) =>
  run(e.target, async () => { setAdminMenu(false); await api("elevate"); toast("Reopening as administrator…"); })
);

document.querySelectorAll(".elevate").forEach((b) =>
  b.addEventListener("click", () => run(b, async () => { await api("elevate"); toast("Reopening as administrator…"); }))
);

// ---------- state ----------
async function refresh() {
  try { state = await api("state"); } catch (e) { toast(e.message, "err"); return; }
  render();
}

function render() {
  const s = state;
  $("svc-pill").textContent = "service: " + s.service;
  $("svc-pill").className = "pill " + (s.service === "running" ? "good" : s.service === "not installed" ? "" : "bad");
  $("admin-pill").textContent = s.elevated ? "administrator" : "standard user ▾";
  $("admin-pill").className = "pill pill-btn " + (s.elevated ? "good" : "");
  $("admin-pill").disabled = s.elevated;
  document.querySelectorAll(".needs-admin").forEach((e) => e.classList.toggle("hidden", s.elevated));
  document.querySelectorAll(".admin-only-block").forEach((e) => e.classList.toggle("hidden", !s.elevated));
  document.querySelectorAll(".admin-only").forEach((e) => (e.disabled = !s.elevated));

  const r = s.rdp;
  $("rdp-status").innerHTML = "";
  $("rdp-status").append(
    "Remote Desktop is ", el("b", { class: r.enabled ? "good-text" : "bad-text" }, r.enabled ? "enabled" : "disabled"),
    ` on port ${r.port}. Network Level Authentication: `, el("b", {}, r.nla ? "on" : "off"), "."
  );
  $("rdp-enable").classList.toggle("hidden", r.enabled && r.nla);
  document.querySelectorAll(".rdp-port").forEach((e) => (e.textContent = r.port));
  $("svc-status").textContent = s.service;
  $("lan-ips").textContent = (s.lan_ips || []).join(" or ") || "(this PC's LAN IP)";
  if (s.fingerprint) $("fingerprint").textContent = s.fingerprint;

  if (s.settings && !renderedSettings) {
    renderedSettings = true;
    const st = s.settings;
    $("s-port").value = st.listen_port || "";
    $("s-sources").value = st.allowed_sources || "";
    $("s-maxfail").value = st.max_failures;
    $("s-ban").value = st.ban_minutes;
    $("s-maxsess").value = st.max_sessions;
    $("s-idle").value = st.idle_timeout_minutes;
    $("s-block").checked = st.block_direct_rdp;
  }
  document.querySelectorAll(".gate-port").forEach((e) => (e.textContent = (s.settings && s.settings.listen_port) || "?"));
  renderPublicIP(s);

  renderUsers();
  renderProfiles();
  if (s.log !== undefined) {
    const log = $("log");
    const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 20;
    log.textContent = s.log || "(no activity yet)";
    if (atBottom) log.scrollTop = log.scrollHeight;
  }
}
let renderedSettings = false;

// ---------- public IP ----------
let lastPublicIP = "";
function publicAddr() {
  const port = state.settings && state.settings.listen_port;
  return lastPublicIP && port ? `${lastPublicIP}:${port}` : lastPublicIP;
}
function renderPublicIP(s) {
  const ip = s.public_ip || "";
  const ago = s.public_ip_checked ? Math.round((Date.now() / 1000 - s.public_ip_checked) / 60) : null;
  if (ip && lastPublicIP && ip !== lastPublicIP) toast(`Public IP changed to ${ip} - update your saved computers.`);
  lastPublicIP = ip;
  $("ip-pill").textContent = "public IP: " + (ip || (s.public_ip_error ? "unavailable" : "…"));
  $("ip-pill").className = "pill pill-btn" + (ip ? " good" : "");
  $("public-addr").textContent = ip ? publicAddr() : s.public_ip_error ? "(couldn't look it up)" : "looking up…";
  $("ip-note").textContent =
    (s.public_ip_error && !ip ? `Lookup failed: ${s.public_ip_error}. ` : "") +
    (ago !== null ? `Checked ${ago < 1 ? "just now" : ago + " min ago"}; refreshes every 5 minutes. ` : "") +
    "Home internet addresses can change; if it does, edit the address in your saved computers.";
}
async function copyAddr(text) {
  if (!text) return;
  try { await navigator.clipboard.writeText(text); toast("Copied " + text); }
  catch { toast("Couldn't copy - select the text instead", "err"); }
}
$("ip-pill").addEventListener("click", () => copyAddr(publicAddr()));
$("ip-copy").addEventListener("click", () => copyAddr(publicAddr()));
$("ip-refresh").addEventListener("click", (e) =>
  run(e.target, async () => {
    await api("publicip/refresh");
    await new Promise((r) => setTimeout(r, 1500));
    await refresh();
  })
);

// ---------- server settings ----------
$("s-randport").addEventListener("click", () => {
  const a = new Uint32Array(1);
  crypto.getRandomValues(a);
  $("s-port").value = 20000 + (a[0] % 40000); // 20000-59999, clear of common service ports
});

$("s-save").addEventListener("click", (e) =>
  run(e.target, async () => {
    const r = await api("server/settings", {
      listen_port: +$("s-port").value,
      allowed_sources: $("s-sources").value,
      max_failures: +$("s-maxfail").value,
      ban_minutes: +$("s-ban").value,
      max_sessions: +$("s-maxsess").value,
      idle_timeout_minutes: +$("s-idle").value,
      block_direct_rdp: $("s-block").checked,
    });
    toast(r.note || "Saved.");
    await refresh();
  })
);

$("rdp-enable").addEventListener("click", (e) => run(e.target, async () => { await api("rdp/enable"); toast("Remote Desktop enabled."); await refresh(); }));

const svcAction = (id, path, msg, confirmMsg) =>
  $(id).addEventListener("click", (e) =>
    run(e.target, async () => {
      if (confirmMsg && !confirm(confirmMsg)) return;
      await api(path);
      toast(msg);
      await refresh();
    })
  );
svcAction("svc-install", "service/install", "Service installed and started.");
svcAction("svc-restart", "service/restart", "Service restarted.");
svcAction("svc-stop", "service/stop", "Service stopped.");
svcAction("svc-uninstall", "service/uninstall", "Service removed.", "Remove the SecuRDP service and its firewall rules? Your users and settings are kept.");

// ---------- users ----------
function renderUsers() {
  const box = $("users");
  box.innerHTML = "";
  const users = state.users || [];
  if (!users.length) {
    box.append(el("p", { class: "muted" }, "No users yet. Add one to be able to log in."));
    return;
  }
  for (const u of users) {
    box.append(
      el("div", { class: "card row-between" },
        el("div", {}, el("b", {}, u.username), " ", el("span", { class: "pill " + (u.enabled ? "good" : "bad") }, u.enabled ? "enabled" : "disabled")),
        el("div", { class: "actions tight" },
          el("button", { onclick: (e) => run(e.target, async () => { await api("users/toggle", { username: u.username }); await refresh(); }) }, u.enabled ? "Disable" : "Enable"),
          el("button", { onclick: () => startWizard(u.username) }, "Reset password / authenticator"),
          el("button", { class: "danger", onclick: (e) => run(e.target, async () => {
            if (!confirm(`Delete user ${u.username}?`)) return;
            await api("users/delete", { username: u.username });
            await refresh();
          }) }, "Delete")
        )
      )
    );
  }
}

// Live feedback mirroring the server-side rules in internal/auth/password.go.
const COMMON_USERS = ["admin", "administrator", "root", "user", "guest", "test", "rdp", "remote", "support", "owner", "pi", "ubuntu", "default"];

function setState(node, ok, text) {
  node.textContent = text;
  node.classList.toggle("ok", ok === true);
  node.classList.toggle("bad", ok === false);
}

function checkUserForm() {
  const u = $("uw-user").value.trim();
  const pw = $("uw-pass").value;
  const pw2 = $("uw-pass2").value;

  let userOk = null, userMsg = "5-32 characters: letters, digits, . _ -";
  if (u) {
    if (u.length < 5 || u.length > 32) { userOk = false; userMsg = `${u.length} characters - needs 5 to 32`; }
    else if (!/^[\p{L}\p{N}._-]+$/u.test(u)) { userOk = false; userMsg = "Only letters, digits, . _ - allowed"; }
    else if (COMMON_USERS.includes(u.toLowerCase())) { userOk = false; userMsg = "Too common - attackers try this first"; }
    else { userOk = true; userMsg = "Looks good"; }
  }
  setState($("uw-user-hint"), userOk, userMsg);

  const len = [...pw].length;
  const classes = [
    [/\p{Ll}/u.test(pw), "lowercase"],
    [/\p{Lu}/u.test(pw), "uppercase"],
    [/\p{N}/u.test(pw), "digit"],
    [/[^\p{L}\p{N}]/u.test(pw), "symbol"],
  ];
  const have = classes.filter((c) => c[0]).length;
  const lenOk = len >= 14;
  const clsOk = have >= 3;
  const notUser = !(u && pw.toLowerCase().includes(u.toLowerCase()));
  const touched = pw.length > 0;
  setState($("r-len"), touched ? lenOk : null, `At least 14 characters (${len}/14)`);
  setState($("r-classes"), touched ? clsOk : null,
    `3 of 4 types: ` + classes.map((c) => (c[0] ? c[1].toUpperCase() : c[1])).join(", ") + ` (${have}/3)`);
  setState($("r-user"), touched && u ? notUser : null, "Doesn't contain the username");

  let matchOk = null, matchMsg = "";
  if (pw2) {
    matchOk = pw === pw2;
    matchMsg = matchOk ? "Passwords match" : "Passwords don't match";
  }
  setState($("uw-match"), matchOk, matchMsg);
  $("uw-pass2").classList.toggle("ok", matchOk === true);
  $("uw-pass2").classList.toggle("bad", matchOk === false);
  const pwOk = lenOk && clsOk && notUser;
  $("uw-pass").classList.toggle("ok", touched && pwOk);
  $("uw-pass").classList.toggle("bad", touched && !pwOk);

  $("uw-next").disabled = !(userOk && pwOk && matchOk);
}
["uw-user", "uw-pass", "uw-pass2"].forEach((id) => $(id).addEventListener("input", checkUserForm));
$("uw-show").addEventListener("change", () => {
  const t = $("uw-show").checked ? "text" : "password";
  $("uw-pass").type = $("uw-pass2").type = t;
});

function startWizard(username) {
  $("user-wizard").classList.remove("hidden");
  $("uw-step1").classList.remove("hidden");
  $("uw-step2").classList.add("hidden");
  $("uw-user").value = username || "";
  $("uw-user").readOnly = !!username;
  $("uw-pass").value = $("uw-pass2").value = $("uw-code").value = "";
  $("uw-show").checked = false;
  $("uw-pass").type = $("uw-pass2").type = "password";
  pendingUserId = null;
  checkUserForm();
  (username ? $("uw-pass") : $("uw-user")).focus();
}
function closeWizard() {
  $("user-wizard").classList.add("hidden");
  $("uw-qr").removeAttribute("src");
  $("uw-secret").textContent = "";
  pendingUserId = null;
}
$("add-user").addEventListener("click", () => startWizard(""));
document.querySelectorAll(".uw-cancel").forEach((b) => b.addEventListener("click", closeWizard));

$("uw-next").addEventListener("click", (e) =>
  run(e.target, async () => {
    const r = await api("users/begin", { username: $("uw-user").value.trim(), password: $("uw-pass").value, confirm: $("uw-pass2").value });
    pendingUserId = r.id;
    $("uw-qr").src = r.qr;
    $("uw-secret").textContent = r.secret;
    $("uw-pass").value = $("uw-pass2").value = "";
    $("uw-step1").classList.add("hidden");
    $("uw-step2").classList.remove("hidden");
    $("uw-code").focus();
  })
);

$("uw-confirm").addEventListener("click", (e) =>
  run(e.target, async () => {
    await api("users/confirm", { id: pendingUserId, code: $("uw-code").value.trim() });
    closeWizard();
    toast("User saved. Google Authenticator is linked.");
    await refresh();
  })
);
$("uw-code").addEventListener("keydown", (e) => { if (e.key === "Enter") $("uw-confirm").click(); });

// ---------- profiles ----------
let profilesSig = "";
function renderProfiles() {
  // Only rebuild when something changed, so a half-typed password isn't wiped by the poll.
  const sig = JSON.stringify([state.profiles, state.connected]);
  if (sig === profilesSig) return;
  profilesSig = sig;
  const box = $("profiles");
  const open = box.querySelector(".login-form:not(.hidden)");
  const openName = open && open.dataset.name;
  box.innerHTML = "";
  const profiles = state.profiles || [];
  if (!profiles.length) box.append(el("p", { class: "muted" }, "No saved computers yet. Click \"Add computer\"."));
  for (const p of profiles) {
    const local = (state.connected || {})[p.name];
    const pw = el("input", { type: "password", placeholder: "Gate password", autocomplete: "off" });
    const code = el("input", { inputmode: "numeric", maxlength: "6", placeholder: "Authenticator code" });
    const go = el("button", { class: "primary" }, "Connect");
    const form = el("div", { class: "login-form inline" + (openName === p.name ? "" : " hidden") }, pw, code, go);
    form.dataset.name = p.name;
    const doConnect = () => run(go, async () => {
      await connect(p.name, pw.value, code.value.trim(), "");
      pw.value = code.value = "";
    });
    go.addEventListener("click", doConnect);
    code.addEventListener("keydown", (e) => { if (e.key === "Enter") doConnect(); });
    pw.addEventListener("keydown", (e) => { if (e.key === "Enter") code.focus(); });

    box.append(
      el("div", { class: "card" },
        el("div", { class: "row-between" },
          el("div", {},
            el("b", {}, p.name), " ",
            local ? el("span", { class: "pill good" }, "connected") : "",
            el("div", { class: "muted small" }, `${p.host}:${p.port} · gate user ${p.username}` + (p.rdp_username ? ` · Windows user ${p.rdp_username}` : "") + (p.host_fingerprint ? " · identity verified" : " · not yet verified"))
          ),
          el("div", { class: "actions tight" },
            local
              ? el("button", { class: "danger", onclick: (e) => run(e.target, async () => { await api("disconnect", { name: p.name }); await refresh(); }) }, "Disconnect")
              : el("button", { class: "primary", onclick: () => { form.classList.toggle("hidden"); pw.focus(); } }, "Connect…"),
            el("button", { onclick: () => editProfile(p) }, "Edit"),
            el("button", { class: "danger", onclick: (e) => run(e.target, async () => {
              if (!confirm(`Delete ${p.name}?`)) return;
              await api("profiles/delete", { name: p.name });
              await refresh();
            }) }, "Delete")
          )
        ),
        local ? el("div", { class: "muted small" }, `Tunnel open at ${local}. Close Remote Desktop to end the session.`) : form
      )
    );
  }
}

async function connect(name, password, code, trust) {
  const r = await api("connect", { name, password, code, trust_fingerprint: trust });
  if (r.status === "verify_host") {
    pendingConnect = { name, password, code };
    $("fp-value").textContent = r.fingerprint;
    $("fp-modal").classList.remove("hidden");
    return;
  }
  toast("Connected. Remote Desktop is opening…");
  await refresh();
}

$("fp-yes").addEventListener("click", (e) =>
  run(e.target, async () => {
    $("fp-modal").classList.add("hidden");
    const p = pendingConnect;
    pendingConnect = null;
    await connect(p.name, p.password, p.code, $("fp-value").textContent);
  })
);
$("fp-no").addEventListener("click", () => { pendingConnect = null; $("fp-modal").classList.add("hidden"); });

function editProfile(p) {
  $("profile-form").classList.remove("hidden");
  $("pf-title").textContent = p ? "Edit " + p.name : "Add computer";
  $("pf-original").value = p ? p.name : "";
  $("pf-name").value = p ? p.name : "";
  $("pf-host").value = p ? p.host : "";
  $("pf-port").value = p ? p.port : "";
  $("pf-user").value = p ? p.username : "";
  $("pf-rdpuser").value = p ? p.rdp_username || "" : "";
  $("pf-full").checked = p ? p.rdp_fullscreen : false;
  $("pf-name").focus();
}
$("add-profile").addEventListener("click", () => editProfile(null));
$("pf-cancel").addEventListener("click", () => $("profile-form").classList.add("hidden"));
$("pf-save").addEventListener("click", (e) =>
  run(e.target, async () => {
    await api("profiles/save", {
      original: $("pf-original").value,
      profile: {
        name: $("pf-name").value, host: $("pf-host").value, port: +$("pf-port").value,
        username: $("pf-user").value, rdp_username: $("pf-rdpuser").value, rdp_fullscreen: $("pf-full").checked,
      },
    });
    $("profile-form").classList.add("hidden");
    toast("Saved.");
    await refresh();
  })
);

$("log-refresh").addEventListener("click", refresh);

refresh();
setInterval(() => { if (!document.hidden) refresh(); }, 4000);
