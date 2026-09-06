/* Ghostdrop desktop UI — vanilla JS + fetch, no framework. */
"use strict";
const $ = (id) => document.getElementById(id);
const state = { file: null, lastDrop: null };

async function api(path, opts) {
  const r = await fetch(path, opts);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || ("HTTP " + r.status));
  return body;
}

async function init() {
  const settings = await api("/api/settings").catch(() => ({}));
  $("ver").textContent = settings.version ? ("v" + settings.version) : "";
  if (settings.demo || settings.simulated) $("demo-banner").classList.remove("hidden");
  setGhost(!!settings.ghost_mode);
  if (!localStorage.getItem("gd_onboarded")) $("onboarding").classList.remove("hidden");
  $("onboard-done").onclick = () => { localStorage.setItem("gd_onboarded", "1"); $("onboarding").classList.add("hidden"); };
  $("onboard-open").onclick = () => $("onboarding").classList.toggle("hidden");
  $("ghost-toggle").onclick = async () => {
    const cur = $("ghost-banner").classList.contains("hidden");
    const res = await api("/api/settings/ghost", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ghost: cur }),
    });
    setGhost(!!res.ghost_mode);
  };

  const dz = $("dropzone"), fi = $("file-input");
  ["dragover", "dragenter"].forEach((e) => dz.addEventListener(e, (ev) => { ev.preventDefault(); dz.classList.add("over"); }));
  ["dragleave", "drop"].forEach((e) => dz.addEventListener(e, (ev) => { ev.preventDefault(); dz.classList.remove("over"); }));
  dz.addEventListener("drop", (ev) => setFile(ev.dataTransfer.files[0]));
  dz.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") fi.click(); });
  fi.addEventListener("change", () => setFile(fi.files[0]));

  $("quickdrop").addEventListener("submit", onCreate);
  $("copy-link").onclick = () => copyKind("link");
  $("copy-token").onclick = () => copyKind("token");
  $("show-qr").onclick = toggleQR;
  $("open-details").onclick = openDetails;

  const es = new EventSource("/api/events");
  es.addEventListener("progress", onProgress);
  es.addEventListener("complete", refresh);
  es.addEventListener("created", refresh);
  es.addEventListener("revoked", refresh);
  es.addEventListener("accepted", refresh);
  es.addEventListener("declined", refresh);
  await refresh();
}

function setGhost(on) {
  $("ghost-toggle").textContent = on ? "GHOST: ON" : "GHOST: OFF";
  $("ghost-banner").classList.toggle("hidden", !on);
}

function setFile(f) {
  state.file = f || null;
  $("file-name").textContent = f ? (f.name + " (" + f.size + " bytes)") : "No file selected";
}

async function onCreate(ev) {
  ev.preventDefault();
  const btn = $("create-btn");
  btn.disabled = true;
  try {
    const body = await api("/api/drops", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        recipient: $("f-recipient").value.trim(),
        mode: $("f-mode").value,
        expire_hours: parseFloat($("f-expiry").value) || 24,
        size_bytes: state.file ? state.file.size : 0,
      }),
    });
    state.lastDrop = body;
    $("created").classList.remove("hidden");
    $("created-id").textContent = body.id + " · " + body.url;
    $("created-note").textContent = body.note || "";
    $("qr-img").classList.add("hidden");
    $("details").classList.add("hidden");
    if (state.file) await uploadFile(body.id, state.file);
    await refresh();
    if (location.hash.startsWith("#/drop/")) location.hash = "";
  } catch (e) {
    alert("Create failed: " + e.message);
  } finally {
    btn.disabled = false;
  }
}

function uploadFile(id, file) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    const fd = new FormData();
    fd.append("file", file, file.name);
    $("upload-progress").classList.remove("hidden");
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) $("upload-bar").style.width = ((e.loaded / e.total) * 100).toFixed(1) + "%";
    };
    xhr.onload = () => {
      $("upload-bar").style.width = "100%";
      xhr.status < 300 ? resolve() : reject(new Error("upload HTTP " + xhr.status));
    };
    xhr.onerror = () => reject(new Error("upload failed"));
    xhr.open("POST", "/api/drops/" + encodeURIComponent(id) + "/upload");
    xhr.send(fd);
  });
}

function onProgress(e) {
  try {
    const d = JSON.parse(e.data);
    if (d.total > 0) {
      $("upload-progress").classList.remove("hidden");
      $("upload-bar").style.width = ((d.done / d.total) * 100).toFixed(1) + "%";
    }
  } catch (_) { /* ignore */ }
}

async function copyKind(kind) {
  if (!state.lastDrop) return;
  const res = await api("/api/drops/" + encodeURIComponent(state.lastDrop.id) + "/clipboard?kind=" + kind, { method: "POST" });
  const text = kind === "link" ? state.lastDrop.url : res.value;
  try { await navigator.clipboard.writeText(text); } catch (_) {
    const ta = document.createElement("textarea");
    ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand("copy"); ta.remove();
  }
  $("created-note").textContent = res.note || "Copied.";
}

function toggleQR() {
  if (!state.lastDrop) return;
  const img = $("qr-img");
  if (img.classList.contains("hidden")) {
    img.src = "/api/drops/" + encodeURIComponent(state.lastDrop.id) + "/qr";
    img.classList.remove("hidden");
  } else img.classList.add("hidden");
}

async function openDetails() {
  if (!state.lastDrop) return;
  const res = await api("/api/drops/" + encodeURIComponent(state.lastDrop.id));
  const pre = $("details");
  pre.textContent = JSON.stringify(res.drop, null, 2);
  pre.classList.remove("hidden");
}

function row(d) {
  const el = document.createElement("div");
  el.className = "drop-row";
  const badge = d.signed ? '<span class="badge signed">SIGNED ✓</span>' : '<span class="badge invalid">INVALID</span>';
  el.innerHTML = '<span class="id"></span>' + badge + '<span class="muted"></span>';
  el.children[0].textContent = d.id;
  el.children[2].textContent = (d.mode || "") + " · " + (d.size_bytes || 0) + "B";
  if (d.status === "incoming") {
    const ok = document.createElement("button"); ok.className = "btn"; ok.textContent = "ACCEPT";
    ok.onclick = async () => { await api("/api/drops/" + encodeURIComponent(d.id) + "/accept", { method: "POST" }); await refresh(); };
    const no = document.createElement("button"); no.className = "btn"; no.textContent = "DECLINE";
    no.onclick = async () => { await api("/api/drops/" + encodeURIComponent(d.id) + "/decline", { method: "POST" }); await refresh(); };
    el.appendChild(ok); el.appendChild(no);
  }
  return el;
}

async function refresh() {
  const res = await api("/api/drops").catch(() => ({ drops: [] }));
  const drops = res.drops || [];
  const put = (id, items) => {
    const box = $(id); box.innerHTML = "";
    if (!items.length) { box.innerHTML = '<p class="muted">None.</p>'; return; }
    items.forEach((d) => box.appendChild(row(d)));
  };
  put("incoming", drops.filter((d) => d.status === "incoming"));
  put("list-outgoing", drops.filter((d) => d.status === "outgoing"));
  put("list-verified", drops.filter((d) => d.status === "verified"));
  put("list-expired", drops.filter((d) => d.status === "expired"));
}

document.addEventListener("DOMContentLoaded", init);
