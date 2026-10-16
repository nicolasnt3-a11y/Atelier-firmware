"use strict";

// ==========================================================================
// Petits utilitaires

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const main = $("#main");

function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

async function api(method, url, body) {
  const opts = { method, headers: { "X-Atelier": "1" } };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch("/api/" + url, opts);
  } catch {
    throw new Error("L'Atelier ne répond plus. Il a peut-être été fermé : relance-le depuis son raccourci.");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Erreur ${res.status}`);
  return data;
}

let toastTimer;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 7000);
}

function confirmBox(title, text, okLabel) {
  return new Promise(resolve => {
    const d = document.createElement("dialog");
    d.setAttribute("aria-labelledby", "dlg-title");
    d.innerHTML = `<h2 id="dlg-title">${esc(title)}</h2><p>${esc(text)}</p>
      <div class="row" style="justify-content:flex-end">
        <button value="no" autofocus>Annuler</button>
        <button value="yes" class="primary">${esc(okLabel)}</button></div>`;
    document.body.append(d);
    d.addEventListener("click", e => { if (e.target.value) d.close(e.target.value); });
    d.addEventListener("close", () => { resolve(d.returnValue === "yes"); d.remove(); });
    d.showModal();
  });
}

const fmtSize = n => {
  if (n == null) return "";
  const u = ["octets", "Ko", "Mo", "Go"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toLocaleString("fr-FR", { maximumFractionDigits: i ? 1 : 0 })} ${u[i]}`;
};
const fmtDate = iso => iso ? new Date(iso).toLocaleString("fr-FR", { dateStyle: "long", timeStyle: "short" }) : "";
const fmtDay = iso => iso ? new Date(iso).toLocaleDateString("fr-FR", { dateStyle: "long" }) : "";
const plural = (n, one, many) => `${n.toLocaleString("fr-FR")} ${n > 1 ? many : one}`;
const hex = n => "0x" + Number(n || 0).toString(16);

// Les chemins de mithril commencent par le dossier d'extraction de moria
// (« 0x2ae934-squashfs/etc/shadow ») : on n'en garde que la partie parlante.
function prettyPath(p) {
  const m = /^(?:0x[0-9a-f]+-[^/]+\/)+(.*)$/i.exec(p || "");
  return m ? "/" + m[1] : p || "";
}

function setTitle(t) { document.title = t ? `${t} · Atelier Firmware` : "Atelier Firmware"; }

function focusMain() { main.focus({ preventScroll: true }); window.scrollTo(0, 0); }

// ==========================================================================
// État global et session

let STATUS = null;
let pollTimer = null;

async function refreshStatus() {
  try { STATUS = await api("GET", "status"); } catch (e) { STATUS = null; }
  renderBanner();
  return STATUS;
}

function renderBanner() {
  const b = $("#banner");
  if (!STATUS) {
    b.innerHTML = notice("error", "⚠", "L'Atelier ne répond pas.", "Ferme cet onglet et relance l'Atelier depuis son raccourci.");
  } else if (!STATUS.wsl) {
    b.innerHTML = notice("error", "⚠", "Ubuntu (WSL) ne démarre pas.",
      `Les outils ont besoin d'Ubuntu pour fonctionner. <a href="#/outils">Voir les détails</a>.`);
  } else if (!STATUS.ready) {
    b.innerHTML = notice("warn", "🔧", "Les outils ne sont pas encore installés.",
      `<a href="#/outils">Aller dans « Outils »</a> et cliquer sur « Installer ». Il n'y a qu'à attendre.`);
  } else if (!STATUS.db) {
    b.innerHTML = notice("warn", "📚", "La base des failles connues n'est pas téléchargée.",
      `Sans elle, l'Atelier ne peut pas dire quelles failles touchent le firmware. <a href="#/outils">La télécharger</a>.`);
  } else {
    b.innerHTML = "";
  }
}

function notice(kind, icon, title, html = "") {
  return `<div class="notice ${kind}"><span class="icon" aria-hidden="true">${icon}</span>
    <div><strong>${esc(title)}</strong>${html ? `<p>${html}</p>` : ""}</div></div>`;
}

// Tant que la page est ouverte, elle signale sa présence au serveur ;
// quand on la ferme, le serveur s'arrête tout seul au bout de 3 minutes.
setInterval(() => api("POST", "ping").catch(() => {}), 20000);

// ==========================================================================
// Routage

const routes = [
  [/^#?\/?$/, renderHome, "home"],
  [/^#\/historique$/, renderHistory, "history"],
  [/^#\/outils$/, renderTools, "tools"],
  [/^#\/aide$/, renderHelp, "help"],
  [/^#\/tache\/(\w+)$/, renderJob, null],
  [/^#\/rapport\/([\w.-]+)(?:\/(\w+))?$/, renderReport, "history"],
];

async function route() {
  clearTimeout(pollTimer);
  const hash = location.hash || "#/";
  for (const [re, fn, nav] of routes) {
    const m = re.exec(hash);
    if (!m) continue;
    $$("[data-nav]").forEach(a => {
      if (a.dataset.nav === nav) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    try {
      await fn(...m.slice(1));
    } catch (e) {
      main.innerHTML = notice("error", "⚠", "Impossible d'afficher cette page.", esc(e.message));
    }
    return;
  }
  location.hash = "#/";
}

window.addEventListener("hashchange", () => { route().then(focusMain); });

// ==========================================================================
// Accueil : choisir un firmware

async function renderHome() {
  setTitle("");
  const ready = STATUS?.ready !== false;   // inconnu = on laisse essayer
  main.innerHTML = `
    <h1>Analyser un firmware</h1>
    <p class="lead">Dépose le fichier du logiciel interne d'un appareil (box, caméra, objet connecté…).
      L'Atelier l'ouvre, regarde ce qu'il contient et te dit, en clair, ce qui pose problème.</p>

    <section class="drop" id="drop" aria-labelledby="drop-title">
      <div class="big-icon" aria-hidden="true">📦</div>
      <h2 id="drop-title">Glisse ton fichier ici</h2>
      <p class="muted">Formats courants : .bin, .img, .trx, .chk, .fw… Le fichier ne quitte pas ton ordinateur.</p>
      <p class="or">ou</p>
      <button class="primary big" id="pick" ${ready ? "" : "disabled"}>📂 Choisir un fichier…</button>
      <div id="upload-status" role="status" aria-live="polite" class="small muted" style="margin-top:1rem"></div>
    </section>

    <details class="more card">
      <summary>Options</summary>
      <div class="stack" style="margin-top:1rem">
        <label class="check"><input type="checkbox" id="deep" checked>
          <span><strong>Analyse approfondie</strong> (1 à 3 minutes de plus)<br>
          <span class="muted">Carte de la puce, processeur utilisé, adresse de chargement du code et catalogue des messages
            (erreurs, versions, journaux). Très utile pour les firmwares qui ne sont pas du Linux, comme ceux des calculateurs automobiles.</span></span></label>
        <label class="check"><input type="checkbox" id="broad">
          <span><strong>Reconnaissance élargie</strong><br>
          <span class="muted">Moria cherche environ 2 500 types de fichiers en plus. Plus lent ; utile si l'analyse normale ne reconnaît rien.</span></span></label>
        <div>
          <label for="path">Ou colle le chemin complet du fichier</label>
          <div class="row" style="margin-top:.4rem">
            <input type="text" id="path" placeholder="C:\\Users\\…\\Downloads\\firmware.bin" style="flex:1;min-width:240px">
            <button id="go-path" ${ready ? "" : "disabled"}>Analyser</button>
          </div>
        </div>
      </div>
    </details>

    <h2 style="margin-top:2rem">Comment ça marche</h2>
    <div class="steps-explain">
      <div class="card"><h3><span class="num">1</span>Moria ouvre le colis</h3>
        <p>Un firmware est comme un colis fermé. Moria reconnaît ce qu'il y a dedans (système, noyau, archives) et en sort tous les fichiers.</p></div>
      <div class="card"><h3><span class="num">2</span>Mithril inspecte le contenu</h3>
        <p>Mithril fouille ces fichiers : mots de passe oubliés, logiciels et versions, failles connues, clés faibles, licences.</p></div>
      <div class="card"><h3><span class="num">3</span>Tu lis le rapport</h3>
        <p>Un résumé en clair, du plus grave au moins grave, avec pour chaque point une explication et le détail technique si besoin.</p></div>
    </div>
    <div id="recent"></div>`;

  const deep = () => ({ deep: $("#deep").checked, broad: $("#broad").checked });
  $("#pick").onclick = async () => {
    $("#pick").disabled = true;
    try {
      const { path } = await api("POST", "pick");
      if (path) await startAnalysis(path, deep());
    } catch (e) { toast(e.message); }
    finally { const b = $("#pick"); if (b) b.disabled = STATUS?.ready === false; }
  };
  $("#go-path").onclick = () => startAnalysis($("#path").value, deep());
  $("#path").addEventListener("keydown", e => { if (e.key === "Enter") startAnalysis($("#path").value, deep()); });
  setupDrop(deep);

  const list = await api("GET", "analyses").catch(() => []);
  if (list.length) {
    $("#recent").innerHTML = `<h2 style="margin-top:2rem">Analyses récentes</h2>
      <div class="card">${historyList(list.slice(0, 5))}</div>
      ${list.length > 5 ? `<p><a href="#/historique">Voir les ${list.length} analyses</a></p>` : ""}`;
  }
}

function setupDrop(deep) {
  const zone = $("#drop");
  ["dragenter", "dragover"].forEach(ev => zone.addEventListener(ev, e => {
    e.preventDefault(); zone.classList.add("over");
  }));
  ["dragleave", "drop"].forEach(ev => zone.addEventListener(ev, () => zone.classList.remove("over")));
  zone.addEventListener("drop", e => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (!file) return;
    if (STATUS?.ready === false) { toast("Les outils ne sont pas encore installés : va dans « Outils »."); return; }
    uploadThenAnalyze(file, deep());
  });
}

// Le navigateur ne donne pas le chemin d'un fichier glissé : on en envoie
// une copie à l'Atelier (qui tourne sur ce PC), rangée dans Documents.
function uploadThenAnalyze(file, deep) {
  const st = $("#upload-status");
  const xhr = new XMLHttpRequest();
  xhr.open("PUT", "/api/upload?name=" + encodeURIComponent(file.name));
  xhr.setRequestHeader("X-Atelier", "1");
  xhr.upload.onprogress = e => {
    if (e.lengthComputable) st.textContent = `Copie de « ${file.name} » : ${Math.round(e.loaded / e.total * 100)} %`;
  };
  xhr.onload = () => {
    let data = {};
    try { data = JSON.parse(xhr.responseText); } catch {}
    if (xhr.status !== 200) { st.textContent = ""; toast(data.error || "La copie du fichier a échoué."); return; }
    st.textContent = "Fichier reçu, démarrage de l'analyse…";
    startAnalysis(data.path, deep);
  };
  xhr.onerror = () => toast("La copie du fichier a échoué.");
  st.textContent = `Copie de « ${file.name} »…`;
  xhr.send(file);
}

async function startAnalysis(path, opts) {
  path = (path || "").trim();
  if (!path) { toast("Indique d'abord un fichier."); return; }
  try {
    const job = await api("POST", "analyze", { path, ...opts });
    location.hash = `#/tache/${job.id}`;
  } catch (e) { toast(e.message); }
}

// ==========================================================================
// Suivi d'une tâche (analyse, installation, mise à jour)

async function renderJob(id, keepLogOpen = false) {
  let job;
  try { job = await api("GET", `jobs/${id}`); }
  catch {
    main.innerHTML = notice("warn", "ℹ", "Cette opération n'est plus suivie.",
      `L'Atelier a peut-être été redémarré. <a href="#/historique">Voir mes analyses</a>.`);
    return;
  }
  if (location.hash !== `#/tache/${id}`) return;

  if (job.state === "done" && (job.kind === "analyze" || job.kind === "deep" || job.kind === "ghidra")) {
    location.replace(`#/rapport/${job.result.analysis}${job.kind === "analyze" ? "" : "/approfondie"}`);
    return;
  }
  // En cas d'échec, le rapport partiel reste consultable.
  const next = job.result?.analysis ? `#/rapport/${job.result.analysis}` : job.kind === "analyze" ? "#/" : "#/outils";

  const logOpen = keepLogOpen || $("#joblog")?.open;
  const logScrolled = $("#joblog .log");
  const atBottom = !logScrolled || logScrolled.scrollHeight - logScrolled.scrollTop - logScrolled.clientHeight < 30;
  setTitle(job.title);

  const icon = { done: "✓", error: "✕", running: "" };
  const stateLabel = { done: "terminé", error: "échec", running: "en cours" };
  main.innerHTML = `
    <h1>${esc(job.title)}</h1>
    ${job.state === "running" ? `<p class="lead">Ça peut prendre de quelques secondes à plusieurs minutes selon la taille du fichier. Tu peux laisser cette page ouverte.</p>` : ""}
    <div class="card">
      <ol class="progress-list" aria-label="Étapes">
        ${job.steps.map(s => `<li data-state="${s.state}"><span class="dot" aria-hidden="true">${icon[s.state]}</span>
          <span>${esc(s.label)} <span class="visually-hidden">(${stateLabel[s.state]})</span></span></li>`).join("")}
      </ol>
      <p class="muted small" aria-live="off">Temps écoulé : ${job.elapsed} s</p>
    </div>
    <div id="job-end" role="status" aria-live="polite">
      ${job.state === "error" ? notice("error", "⚠", "L'opération n'a pas abouti.", esc(job.error)) : ""}
      ${job.state === "done" ? notice("ok", "✓", "Terminé !", jobDoneText(job)) : ""}
    </div>
    ${job.state !== "running" ? `<p><a class="btn primary" href="${next}">Continuer</a></p>` : ""}
    <details class="more" id="joblog" ${logOpen || job.state === "error" ? "open" : ""}>
      <summary>Détails techniques</summary>
      <div class="log" tabindex="0" aria-label="Journal technique">${esc(job.log.join("\n"))}</div>
    </details>`;

  const log = $("#joblog .log");
  if (atBottom) log.scrollTop = log.scrollHeight;

  if (job.state === "running") {
    pollTimer = setTimeout(() => renderJob(id), 1000);
  } else {
    refreshStatus();
  }
}

function jobDoneText(job) {
  if (job.kind === "update-tools") {
    const u = job.result?.updated || [];
    return u.length ? `Mis à jour et recompilé : ${esc(u.join(" et "))}.` : "Tout était déjà à jour, rien à faire.";
  }
  if (job.kind === "setup") return "Les outils sont installés et prêts. Tu peux analyser ton premier firmware.";
  if (job.kind === "setup-ghidra") return "Ghidra est installé. Tu peux lancer la rétro-ingénierie depuis l'onglet « Analyse approfondie » d'un rapport.";
  if (job.kind === "update-db") return "La base des failles connues est à jour.";
  if (job.kind === "deep") return "L'analyse approfondie est prête.";
  if (job.kind === "ghidra") return "La rétro-ingénierie est terminée : ouvre l'onglet « Analyse approfondie » pour lire le code.";
  return "";
}

// ==========================================================================
// Historique

function historyList(list) {
  return `<ul class="history">${list.map(m => `
    <li><a href="#/rapport/${esc(m.id)}">
      <span aria-hidden="true">${m.state === "done" ? "📄" : m.state === "error" ? "⚠️" : "⏳"}</span>
      <span style="flex:1;min-width:200px"><span class="name">${esc(m.name)}</span><br>
        <span class="small muted">${esc(fmtDate(m.date))} · ${esc(fmtSize(m.size))}</span></span>
      <span class="small muted">${m.state === "error" ? "Analyse échouée" : m.state === "running" ? "En cours ou interrompue" : ""}</span>
    </a></li>`).join("")}</ul>`;
}

async function renderHistory() {
  setTitle("Mes analyses");
  const list = await api("GET", "analyses");
  main.innerHTML = `<h1>Mes analyses</h1>
    <p class="lead">Chaque analyse est conservée dans ton dossier <strong>Documents › Atelier Firmware</strong>.</p>
    ${list.length ? `<div class="card">${historyList(list)}</div>`
      : `<div class="card empty"><div class="big-icon" aria-hidden="true">🗂️</div><p>Aucune analyse pour l'instant.</p>
         <a class="btn primary" href="#/">Analyser un firmware</a></div>`}`;
}

// ==========================================================================
// Rapport

const SEV = [
  [9, "crit", "Critique"], [7, "high", "Élevée"], [4, "med", "Moyenne"], [0.1, "low", "Faible"],
];
function sevOf(score) {
  if (score == null) return ["none", "Non évaluée"];
  for (const [min, cls, label] of SEV) if (score >= min) return [cls, label];
  return ["none", "Aucune"];
}
function sevBadge(score) {
  const [cls, label] = sevOf(score);
  return `<span class="badge ${cls}">${label}${score != null ? ` · ${score}` : ""}</span>`;
}
const isHighSignal = c => c.kev || (c.cvss_score ?? 0) >= 9 || ((c.cvss_score ?? 0) >= 7 && (c.epss ?? 0) >= 0.10);

const BAD_BOOT = new Set(["fit-unsigned", "fit-signature-not-enforced", "avb-unsigned", "avb-test-key",
  "avb-verification-disabled", "avb-hashtree-disabled", "uefi-secureboot-off", "uefi-setup-mode", "uefi-test-key",
  "uefi-test-platform-key", "uefi-dbx-empty", "uboot-console-interruptible", "uboot-env-weak-password", "uboot-env-secret"]);
const GOOD_BOOT = new Set(["fit-signed", "avb-signed", "uefi-secureboot-on", "avb-dm-verity"]);
const CRIT_SECRET = new Set(["empty-password", "private-key", "der-private-key", "aws-access-key-id", "github-token",
  "github-fine-grained-pat", "gitlab-pat", "stripe-key", "openai-key", "anthropic-key", "slack-token"]);

// Clés réellement exploitables (partie secrète publique ou calculable). Les
// autres constats de mithril (« clé RSA invalide ») sont souvent des fichiers
// qui ne sont pas des clés RSA, par exemple des paramètres Diffie-Hellman.
const STRONG_KEY = new Set(["leaked-key", "roca-key", "shared-prime", "rsa-tiny-modulus", "rsa-weak-modulus"]);
const PRIVATE_KEY = new Set(["private-key", "der-private-key"]);
// Bibliothèque partagée (.so, .so.1.2, .dll, .a) : les clés qu'elle contient
// sont souvent les clés d'exemple de la bibliothèque (mbedTLS, wolfSSL…).
const isLibrary = p => /\.(so(\.\d+)*|dll|a)$/i.test(p || "");

function describe(dict, f) {
  const d = TXT[dict][f.type];
  return {
    title: d?.t || f.description || f.type,
    advice: d?.a || "",
    original: d ? f.description : "",
  };
}

// Regroupe des constats identiques (même fichier, même nature) pour ne pas
// afficher dix fois la même ligne.
function groupBy(list, keyOf) {
  const m = new Map();
  for (const f of list) {
    const k = keyOf(f);
    if (!m.has(k)) m.set(k, { ...f, items: [] });
    m.get(k).items.push(f);
  }
  return [...m.values()];
}

function secretTitle(g) {
  const n = g.items.length;
  if (PRIVATE_KEY.has(g.type)) return n > 1 ? `${n} clés privées` : "Clé privée";
  const t = describe("secrets", g).title;
  return n > 1 ? `${t} (×${n})` : `${t}${g.label && g.label !== g.path ? ` (« ${g.label} »)` : ""}`;
}

function secretLevel(g) {
  if (PRIVATE_KEY.has(g.type) && isLibrary(g.path)) return 2;
  return CRIT_SECRET.has(g.type) || g.confidence_tier === "validated" ? 3 : 2;
}

// Regroupe les constats du plus grave au moins grave, pour l'onglet « L'essentiel ».
function analyse(r) {
  const secrets = r.secrets || [], notable = r.notable || [], cves = [...(r.cves || [])];
  const keys = r.key_weakness || [];
  const kernel = r.kernel_cves || [];
  const kApplicable = kernel.filter(k => k.state === "applicable" || k.applicable);
  const kPossible = kernel.filter(k => k.state === "undetermined" && !k.applicable);
  cves.sort((a, b) => (b.kev ? 1 : 0) - (a.kev ? 1 : 0) || (b.cvss_score ?? -1) - (a.cvss_score ?? -1));

  const secretGroups = groupBy(secrets, s => `${s.path}|${PRIVATE_KEY.has(s.type) ? "private-key" : s.type}`);
  const bootGroups = groupBy(r.boot_security || [], b => `${b.type}|${b.label}`);
  const notableGroups = groupBy(notable, n => `${n.type}|${n.path}`);
  const strongKeys = keys.filter(k => STRONG_KEY.has(k.type));
  const oddKeys = keys.filter(k => !STRONG_KEY.has(k.type));

  const items = [];
  for (const g of secretGroups) {
    const lib = PRIVATE_KEY.has(g.type) && isLibrary(g.path);
    items.push({ level: secretLevel(g), tab: "secrets",
      text: secretTitle(g) + (lib ? " intégrées à une bibliothèque (souvent des clés d'exemple, à vérifier)" : ""),
      where: prettyPath(g.path) });
  }
  for (const k of strongKeys) {
    items.push({ level: 3, tab: "demarrage", text: describe("keys", k).title, where: prettyPath(k.path) });
  }
  // Une ligne par logiciel et par gravité, plutôt qu'une ligne par faille.
  const cveLevel = c => c.kev || c.cvss_score >= 9 ? 3 : 2;
  for (const g of groupBy(cves.filter(isHighSignal), c => `${c.component}|${cveLevel(c)}`)) {
    const n = g.items.length, lvl = cveLevel(g), kev = g.items.filter(c => c.kev).length;
    const what = lvl >= 3 ? (n > 1 ? "failles critiques" : "faille critique") : (n > 1 ? "failles importantes" : "faille importante");
    items.push({ level: lvl, tab: "failles",
      text: `${g.component.replace("@", " ")} : ${n} ${what}${kev ? ` (dont ${kev} exploitée${kev > 1 ? "s" : ""} activement)` : ""}`,
      where: g.items.slice(0, 3).map(c => c.cve).join(", ") + (n > 3 ? "…" : "") });
  }
  for (const k of kApplicable) {
    items.push({ level: 3, tab: "failles", text: `Faille du noyau Linux ${k.cve}`, where: k.impact || "" });
  }
  if (kPossible.length) {
    const kev = kPossible.filter(k => k.kev).length;
    items.push({ level: 2, tab: "failles",
      text: `Noyau Linux ${r.kernel_version || ""} : ${plural(kPossible.length, "faille grave possible", "failles graves possibles")}, non confirmée${kPossible.length > 1 ? "s" : ""}` +
        (kev ? ` (dont ${kev} exploitée${kev > 1 ? "s" : ""} activement)` : ""),
      where: "" });
  }
  for (const b of bootGroups.filter(b => BAD_BOOT.has(b.type))) {
    items.push({ level: 2, tab: "demarrage", text: describe("boot", b).title, where: b.label || prettyPath(b.path) });
  }
  const otherCves = cves.filter(c => !isHighSignal(c));
  if (otherCves.length) {
    items.push({ level: 1, tab: "failles", text: `${plural(otherCves.length, "autre faille connue", "autres failles connues")}, de gravité plus modérée`, where: "" });
  }
  for (const k of oddKeys) {
    items.push({ level: 1, tab: "demarrage", text: `${describe("keys", k).title} (probable fausse alerte, à vérifier)`, where: prettyPath(k.path) });
  }
  for (const n of notableGroups) {
    items.push({ level: 1, tab: "secrets", text: describe("notable", n).title, where: prettyPath(n.path) });
  }
  items.sort((a, b) => b.level - a.level);
  const worst = items[0]?.level || 0;
  return { secrets, secretGroups, notable, notableGroups, cves, kApplicable, kPossible,
           keys, strongKeys, oddKeys, bootGroups, items, worst };
}

async function renderReport(id, tab) {
  const data = await api("GET", `analyses/${encodeURIComponent(id)}`);
  const meta = data.meta || {}, mor = data.moria || {}, r = data.mithril;
  setTitle(meta.name);

  if (!r) {
    main.innerHTML = `<h1>${esc(meta.name)}</h1>
      ${notice("error", "⚠", "Cette analyse n'a pas abouti.",
        "Le fichier n'a peut-être pas pu être lu. Tu peux relancer une analyse depuis l'accueil, ou supprimer celle-ci.")}
      <div class="row"><a class="btn primary" href="#/">Nouvelle analyse</a>
      <button class="danger" id="del">Supprimer</button></div>`;
    $("#del").onclick = () => deleteAnalysis(meta);
    return;
  }

  const a = analyse(r);
  const comps = r.components || [];
  const licenses = r.licenses || [];
  const findings = mor.findings || [];
  const extracted = mor.extraction?.extracted || [];
  const deep = data.deep;
  const ghidra = data.ghidra;
  // Moria n'a rien reconnu de solide (seulement des signatures peu sûres) : rien n'a été
  // extrait, donc « aucun problème » ne voudrait rien dire.
  const weakId = findings.length > 0 && findings.every(f => (f.confidence ?? 0) < 50);
  const undecoded = !extracted.length && (r.file_count || 0) <= 1;
  if (weakId) {
    a.items.push({ level: 1, tab: "contenu", where: "",
      text: `Identification incertaine : « ${findings.map(f => f.type).join(", ")} » reconnu avec peu de certitude, probablement à tort` });
  }

  const verdict = undecoded && a.worst < 3
    ? { cls: "warn", icon: "❔", title: "Contenu non décodé",
        text: "Moria n'a pas su ouvrir ce fichier, donc Mithril n'a presque rien pu inspecter : l'absence de problème ne veut rien dire ici. " +
              "L'onglet « Analyse approfondie » montre ce qu'il contient (processeur, messages, carte de la puce)." }
    : a.worst >= 3
    ? { cls: "crit", icon: "🔴", title: "Des problèmes sérieux ont été trouvés",
        text: "Au moins un point critique : un accès trop facile, un secret exposé ou une faille connue grave. Les détails sont ci-dessous, du plus grave au moins grave." }
    : a.worst === 2
    ? { cls: "warn", icon: "🟠", title: "Quelques points à surveiller",
        text: "Rien de dramatique en apparence, mais certains points méritent d'être regardés." }
    : a.worst === 1
    ? { cls: "ok", icon: "🟢", title: "Rien d'alarmant",
        text: "Seulement des points mineurs ou informatifs." }
    : { cls: "ok", icon: "🟢", title: "Aucun problème détecté",
        text: "Les outils n'ont rien trouvé d'anormal. Cela ne garantit pas l'absence totale de problème, seulement qu'aucun problème connu n'a été repéré." };

  const tabs = [
    ["essentiel", "L'essentiel", null],
    ["secrets", "Secrets et accès", a.secretGroups.length + a.notableGroups.length],
    ["failles", "Failles connues", a.cves.length + a.kApplicable.length + a.kPossible.length],
    ["logiciels", "Logiciels", comps.length],
    ["contenu", "Contenu du fichier", findings.length],
    ["demarrage", "Démarrage et clés", a.bootGroups.length + a.keys.length],
    ["licences", "Licences", licenses.length],
    ["approfondie", "Analyse approfondie", null],
    ["fichiers", "Fichiers et exports", null],
  ];
  const current = tabs.some(t => t[0] === tab) ? tab : "essentiel";

  const tile = (n, label, target, level) =>
    `<button class="tile ${level}" data-goto="${target}"><span class="n">${n.toLocaleString("fr-FR")}</span><span class="l">${label}</span></button>`;
  const secretsLevel = a.secretGroups.some(g => secretLevel(g) >= 3) ? "alert" : a.secrets.length ? "watch" : "fine";
  const hs = a.cves.filter(isHighSignal).length;
  const kernelTotal = a.kApplicable.length + a.kPossible.length;

  main.innerHTML = `
    <div class="report-head">
      <div style="flex:1;min-width:260px">
        <p class="small muted" style="margin:0"><a href="#/historique">Mes analyses</a> ›</p>
        <h1>${esc(meta.name)}</h1>
        <p class="muted small">${esc(fmtDate(meta.date))} · ${esc(fmtSize(meta.size))}
          ${mor.assessment ? ` · reconnu comme : <strong>${esc(mor.assessment)}</strong>${weakId ? " (peu fiable)" : ""}` : ""}</p>
      </div>
      <div class="row no-print">
        <button id="print">🖨️ Imprimer</button>
        ${meta.extracted ? `<button id="open-extract">📁 Voir les fichiers extraits</button>` : ""}
      </div>
    </div>

    <section class="verdict ${verdict.cls}" aria-labelledby="verdict-title">
      <span class="emblem" aria-hidden="true">${verdict.icon}</span>
      <div><h2 id="verdict-title">${verdict.title}</h2><p>${verdict.text}</p></div>
    </section>

    ${!meta.cve_db ? notice("warn", "📚", "La recherche de failles connues n'a pas été faite.",
      `La base des failles n'était pas téléchargée au moment de l'analyse. <a href="#/outils">La télécharger</a>, puis relance l'analyse.`) : ""}

    <div class="tiles">
      ${tile(a.secrets.length, "secrets trouvés", "secrets", secretsLevel)}
      ${tile(a.cves.length, `failles dans les logiciels${hs ? ` (dont ${hs} importante${hs > 1 ? "s" : ""})` : ""}`, "failles",
        hs ? "alert" : a.cves.length ? "watch" : "fine")}
      ${kernelTotal ? tile(kernelTotal, `failles du noyau ${a.kApplicable.length ? "qui s'appliquent" : "possibles, non confirmées"}`, "failles",
        a.kApplicable.length ? "alert" : "watch") : ""}
      ${tile(comps.length, "logiciels identifiés", "logiciels", "")}
      ${tile(a.strongKeys.length, "clés faibles", "demarrage", a.strongKeys.length ? "alert" : a.oddKeys.length ? "watch" : "fine")}
      ${tile(a.notableGroups.length, "fichiers sensibles", "secrets", a.notable.length ? "watch" : "fine")}
      ${tile(r.file_count || 0, "fichiers examinés", "contenu", "")}
    </div>

    <div role="tablist" aria-label="Sections du rapport">
      ${tabs.map(([k, label, n]) => `<button role="tab" id="tab-${k}" aria-controls="panel-${k}"
        aria-selected="${k === current}" tabindex="${k === current ? 0 : -1}" data-tab="${k}">${label}${n != null ? `<span class="count">${n}</span>` : ""}</button>`).join("")}
    </div>
    ${tabs.map(([k]) => `<section role="tabpanel" id="panel-${k}" aria-labelledby="tab-${k}" tabindex="0" ${k === current ? "" : "hidden"}></section>`).join("")}`;

  $("#panel-essentiel").innerHTML = panelEssentials(a);
  $("#panel-secrets").innerHTML = panelSecrets(a);
  $("#panel-failles").innerHTML = panelCves(a, r);
  $("#panel-logiciels").innerHTML = panelComponents(comps, a.cves);
  $("#panel-contenu").innerHTML = panelContent(mor, findings, extracted, meta);
  $("#panel-demarrage").innerHTML = panelBoot(a);
  $("#panel-licences").innerHTML = panelLicenses(licenses);
  $("#panel-approfondie").innerHTML = panelDeep(meta, deep, mor, ghidra);
  $("#panel-fichiers").innerHTML = panelFiles(meta, r, deep, ghidra);

  setupTabs(id);
  setupCveFilters();
  setupComponentFilter();
  setupDeep(meta, deep);
  setupGhidra(meta, deep, ghidra);

  $("#print").onclick = () => window.print();
  $("#open-extract")?.addEventListener("click", () => api("POST", "open", { id, what: "extract" }).catch(e => toast(e.message)));
  $("#open-report").onclick = () => api("POST", "open", { id, what: "report" }).catch(e => toast(e.message));
  $("#del").onclick = () => deleteAnalysis(meta);
  $$("[data-goto]").forEach(b => b.onclick = () => selectTab(b.dataset.goto, true));
}

function setupTabs(id) {
  const tabs = $$('[role="tab"]');
  tabs.forEach((t, i) => {
    t.onclick = () => selectTab(t.dataset.tab, false);
    t.onkeydown = e => {
      const k = { ArrowRight: 1, ArrowLeft: -1, Home: -Infinity, End: Infinity }[e.key];
      if (k === undefined) return;
      e.preventDefault();
      const j = k === -Infinity ? 0 : k === Infinity ? tabs.length - 1 : (i + k + tabs.length) % tabs.length;
      selectTab(tabs[j].dataset.tab, false);
      tabs[j].focus();
    };
  });
  window.selectTab = (name, scroll) => {
    tabs.forEach(t => {
      const on = t.dataset.tab === name;
      t.setAttribute("aria-selected", on);
      t.tabIndex = on ? 0 : -1;
      $("#panel-" + t.dataset.tab).hidden = !on;
    });
    history.replaceState(null, "", `#/rapport/${id}/${name}`);
    if (scroll) { $('[role="tablist"]').scrollIntoView({ behavior: "smooth" }); $("#tab-" + name).focus(); }
  };
}

function explain(html) { return `<div class="explain">${html}</div>`; }
function emptyState(icon, text) { return `<div class="card empty"><div class="big-icon" aria-hidden="true">${icon}</div><p>${text}</p></div>`; }

function panelEssentials(a) {
  if (!a.items.length) {
    return emptyState("✅", "Aucun point à signaler. Les autres onglets donnent le détail de ce qui a été examiné.");
  }
  const lvl = { 3: ["crit", "Critique"], 2: ["high", "À surveiller"], 1: ["info", "Pour info"] };
  return `${explain("<p>Voici ce qui a été trouvé, <strong>du plus grave au moins grave</strong>. Clique sur un point pour voir l'explication complète.</p>")}
    <div class="table-wrap"><table>
      <caption class="visually-hidden">Points trouvés par ordre de gravité</caption>
      <thead><tr><th scope="col">Gravité</th><th scope="col">Constat</th><th scope="col">Où</th></tr></thead>
      <tbody>${a.items.slice(0, 40).map(it => `<tr>
        <td><span class="badge ${lvl[it.level][0]}">${lvl[it.level][1]}</span></td>
        <td><button class="link" data-goto="${it.tab}">${esc(it.text)}</button></td>
        <td class="mono small">${esc(it.where)}</td></tr>`).join("")}</tbody>
    </table></div>
    ${a.items.length > 40 ? `<p class="muted small">… et ${a.items.length - 40} autres points dans les onglets.</p>` : ""}`;
}

// Une carte par constat, ou par groupe de constats identiques (f.items).
function findingCard(f, dict, badge, opts = {}) {
  const d = describe(dict, f);
  const items = f.items || [f];
  const labels = groupBy(items.filter(i => i.label && i.label !== i.path), i => i.label);
  const places = [...new Set(items.map(i => prettyPath(i.path)))];
  return `<article class="finding">
    <h3>${badge}${esc(opts.title || d.title)}</h3>
    ${opts.note ? `<p class="advice">${opts.note}</p>` : ""}
    ${d.advice ? `<p class="advice">${esc(d.advice)}</p>` : ""}
    <dl>
      <dt>Fichier${places.length > 1 ? "s" : ""}</dt><dd class="mono">${places.map(esc).join("<br>")}</dd>
      ${labels.length ? `<dt>Détail</dt><dd class="mono">${labels.map(l =>
        esc(l.label) + (l.items.length > 1 ? ` <span class="muted">(×${l.items.length})</span>` : "")).join("<br>")}</dd>` : ""}
      <dt>Indice</dt><dd>${esc(f.evidence)}</dd>
      <dt>Fiabilité</dt><dd>${esc(TXT.confidenceTier[f.confidence_tier] || f.confidence_tier)} (${f.confidence} %)</dd>
      ${d.original ? `<dt>Description d'origine</dt><dd lang="en">${esc(d.original)}</dd>` : ""}
    </dl></article>`;
}

function panelSecrets(a) {
  let html = explain(`<p>Un <strong>secret</strong> est un mot de passe, une clé ou un jeton d'accès laissé dans le firmware.
    Comme le même firmware est installé sur des milliers d'appareils, un secret trouvé ici est souvent valable sur <em>tous</em> ces appareils.</p>
    <p>La « fiabilité » indique à quel point l'outil est sûr : <em>Vérifié</em> signifie qu'il a pu le contrôler (par exemple, une clé bien formée), <em>Ressemblance</em> que ça en a seulement l'air.</p>`);
  html += `<h2>Secrets trouvés (${a.secrets.length})</h2>`;
  html += a.secretGroups.length
    ? a.secretGroups.map(g => {
        const lib = PRIVATE_KEY.has(g.type) && isLibrary(g.path);
        const level = secretLevel(g);
        return findingCard(g, "secrets",
          `<span class="badge ${level >= 3 ? "crit" : "high"}">${level >= 3 ? "Secret" : "À vérifier"}</span>`,
          { title: secretTitle(g),
            note: lib ? `Ces clés sont <strong>intégrées à une bibliothèque de programmes</strong>. Les bibliothèques de chiffrement
              (mbedTLS, wolfSSL…) embarquent souvent des <strong>clés d'exemple publiques</strong>, qui ne servent qu'aux tests.
              C'est probablement le cas ici : ce n'est grave que si l'appareil s'en sert vraiment.` : "" });
      }).join("")
    : emptyState("🔒", "Aucun mot de passe ni clé secrète trouvé dans le contenu des fichiers.");
  html += `<h2 style="margin-top:1.5rem">Fichiers sensibles (${a.notableGroups.length})</h2>
    <p class="muted">Des fichiers repérés par leur nom, qui contiennent souvent des informations sensibles. Ce n'est pas forcément un problème : à vérifier.</p>`;
  html += a.notableGroups.length
    ? a.notableGroups.map(n => findingCard(n, "notable", `<span class="badge info">À vérifier</span>`)).join("")
    : emptyState("📄", "Aucun fichier sensible repéré.");
  return html;
}

function panelCves(a, r) {
  const scan = r.component_cve_scan;
  let html = explain(`<p>Une <strong>faille connue</strong> (ou CVE) est un défaut de sécurité déjà publié. L'Atelier compare les versions des logiciels
    trouvés avec une base de failles. La <strong>gravité</strong> va de Faible à Critique ; la <strong>probabilité d'exploitation</strong>
    estime les chances que des attaquants s'en servent. Une faille marquée <strong>« exploitée activement »</strong> est à traiter en priorité.</p>
    <p class="small muted">Une version peut être signalée vulnérable alors que le fabricant a corrigé le problème sans changer le numéro : ces résultats sont des pistes, pas des certitudes.</p>`);

  if (!a.cves.length) {
    html += emptyState("🛡️", r.cves ? "Aucune faille connue ne correspond aux logiciels trouvés." :
      "La recherche de failles n'a pas été faite pour cette analyse.");
  } else html += `<div class="filterbar">
      <label class="check"><input type="checkbox" id="cve-important"> <span>Seulement les plus préoccupantes${scan ? ` (${a.cves.filter(isHighSignal).length})` : ""}</span></label>
    </div>
    <div class="table-wrap"><table id="cve-table">
      <caption>Failles connues dans les logiciels (${a.cves.length})</caption>
      <thead><tr><th scope="col">Faille</th><th scope="col">Logiciel</th><th scope="col">Gravité</th>
        <th scope="col" class="num">Probabilité d'exploitation</th><th scope="col">Remarque</th></tr></thead>
      <tbody>${a.cves.map(c => `<tr data-important="${isHighSignal(c)}">
        <td><a href="https://nvd.nist.gov/vuln/detail/${esc(c.cve)}" target="_blank" rel="noopener">${esc(c.cve)}<span class="visually-hidden"> (ouvre le site NVD)</span></a>
          ${c.kev ? `<br><span class="badge crit">Exploitée activement</span>` : ""}</td>
        <td>${esc(c.component.replace("@", " "))}</td>
        <td>${sevBadge(c.cvss_score)}</td>
        <td class="num">${c.epss != null ? (c.epss * 100).toLocaleString("fr-FR", { maximumFractionDigits: 1 }) + " %" : "—"}</td>
        <td class="small">${c.basis?.includes("verify") ? "Correspondance incertaine, à vérifier" : c.basis?.startsWith("osv") ? "Version exacte" : "Plage de versions touchées"}
          ${c.summary ? `<br><span class="muted" lang="en">${esc(c.summary)}</span>` : ""}</td>
      </tr>`).join("")}</tbody>
    </table></div>`;

  if (r.kernel_version || a.kApplicable.length || a.kPossible.length) {
    const scanK = r.kernel_cve_scan || {};
    const kRows = [...a.kApplicable, ...a.kPossible];
    html += `<h2 style="margin-top:1.5rem">Noyau Linux ${esc(r.kernel_version || "")}</h2>
      <p class="muted">Le noyau est le cœur du système. Mithril vérifie une liste choisie de failles du noyau parmi les plus utilisées par les attaquants
      (pas toutes les failles existantes). Pour savoir si une faille s'applique vraiment, il faut connaître les <strong>réglages</strong> avec lesquels
      le noyau a été construit ; quand ils ne sont pas dans le firmware, la faille est marquée <strong>« possible »</strong>.</p>`;
    if (!kRows.length) {
      html += `<p>Aucune des failles surveillées ne touche cette version du noyau${scanK.ruled_out ? ` (${scanK.ruled_out} écartée${scanK.ruled_out > 1 ? "s" : ""} grâce aux réglages du noyau)` : ""}.</p>`;
    } else {
      if (!a.kApplicable.length) {
        html += notice("warn", "ℹ", `${plural(a.kPossible.length, "faille grave touche", "failles graves touchent")} peut-être ce noyau.`,
          "Sa version est concernée, mais ses réglages sont inconnus : impossible de confirmer ou d'écarter ces failles. Plus un noyau est ancien, plus il est probable que certaines s'appliquent.");
      }
      html += `<div class="table-wrap"><table><caption class="visually-hidden">Failles du noyau</caption>
        <thead><tr><th scope="col">Faille</th><th scope="col">Statut</th><th scope="col">Effet</th><th scope="col">Détail</th></tr></thead>
        <tbody>${kRows.map(k => `<tr><td><a href="https://nvd.nist.gov/vuln/detail/${esc(k.cve)}" target="_blank" rel="noopener">${esc(k.cve)}</a>
          ${k.kev ? `<br><span class="badge crit">Exploitée activement</span>` : ""}</td>
          <td>${k.state === "applicable" || k.applicable ? `<span class="badge crit">S'applique</span>` : `<span class="badge med">Possible</span>`}</td>
          <td lang="en">${esc(k.impact)}</td><td class="small">${/config unknown/i.test(k.reason || "") ? "Réglages du noyau inconnus"
            : `<span lang="en">${esc(k.reason || k.note)}</span>`}</td></tr>`).join("")}</tbody></table></div>`;
    }
  }
  return html;
}

function setupCveFilters() {
  const box = $("#cve-important");
  if (!box) return;
  box.onchange = () => $$("#cve-table tbody tr").forEach(tr => tr.hidden = box.checked && tr.dataset.important !== "true");
}

function panelComponents(comps, cves) {
  if (!comps.length) return emptyState("🧩", "Aucun logiciel identifié.");
  const byComp = {};
  for (const c of cves) byComp[c.component] = (byComp[c.component] || 0) + 1;
  const rows = [...comps].sort((x, y) => (byComp[`${y.name}@${y.version}`] || 0) - (byComp[`${x.name}@${x.version}`] || 0) || x.name.localeCompare(y.name));
  return `${explain(`<p>La liste des logiciels présents dans le firmware, avec leur version. On appelle ça un <strong>inventaire logiciel</strong> (ou SBOM).
      C'est grâce à elle que l'Atelier retrouve les failles connues. Tu peux la télécharger dans l'onglet « Fichiers et exports ».</p>`)}
    <div class="filterbar"><label for="comp-filter" class="visually-hidden">Rechercher un logiciel</label>
      <input type="search" id="comp-filter" placeholder="Rechercher un logiciel…">
      <span class="muted small" id="comp-count" aria-live="polite">${plural(comps.length, "logiciel", "logiciels")}</span></div>
    <div class="table-wrap"><table id="comp-table">
      <caption class="visually-hidden">Logiciels identifiés</caption>
      <thead><tr><th scope="col">Logiciel</th><th scope="col">Version</th><th scope="col" class="num">Failles</th>
        <th scope="col">Trouvé grâce à</th><th scope="col">Emplacement</th></tr></thead>
      <tbody>${rows.map(c => {
        const n = byComp[`${c.name}@${c.version}`] || 0;
        return `<tr><td><strong>${esc(c.name)}</strong></td><td class="mono">${esc(c.version)}</td>
          <td class="num">${n ? `<span class="badge high">${n}</span>` : `<span class="muted">0</span>`}</td>
          <td class="small">${esc(TXT.sources[c.source] || c.source)}</td>
          <td class="mono small">${esc(prettyPath(c.origin_path))}</td></tr>`;
      }).join("")}</tbody></table></div>`;
}

function setupComponentFilter() {
  const input = $("#comp-filter");
  if (!input) return;
  input.oninput = () => {
    const q = input.value.trim().toLowerCase();
    let n = 0;
    $$("#comp-table tbody tr").forEach(tr => {
      const show = !q || tr.textContent.toLowerCase().includes(q);
      tr.hidden = !show;
      if (show) n++;
    });
    $("#comp-count").textContent = plural(n, "logiciel", "logiciels");
  };
}

function panelContent(mor, findings, extracted, meta) {
  let html = explain(`<p>Ce que <strong>Moria</strong> a reconnu à l'intérieur du fichier. Un firmware est souvent composé de plusieurs morceaux mis bout à bout :
    un noyau (le cœur du système), un ou plusieurs systèmes de fichiers (les dossiers et fichiers de l'appareil), etc.
    La <strong>position</strong> indique où chaque morceau commence dans le fichier.</p>`);
  if (!findings.length) {
    html += emptyState("❔", "Moria n'a rien reconnu dans ce fichier. Il est peut-être chiffré, ou d'un format inconnu. Essaie l'« analyse approfondie » dans les options de l'accueil.");
  } else {
    html += `<div class="table-wrap"><table><caption>Éléments reconnus (${findings.length})</caption>
      <thead><tr><th scope="col">Position</th><th scope="col">Type</th><th scope="col">Détails</th><th scope="col" class="num">Taille</th><th scope="col">Certitude</th></tr></thead>
      <tbody>${findings.map(f => `<tr>
        <td class="mono">${hex(f.offset)}</td>
        <td><strong>${esc(f.type)}</strong><br><span class="small muted">${esc(TXT.categories[f.category] || f.category || "")}</span></td>
        <td class="small">${f.label ? `<span class="mono">${esc(f.label)}</span><br>` : ""}<span lang="en">${esc(f.description || "")}</span>
          ${f.compression && f.compression !== "none" ? `<br>Compression : ${esc(f.compression)}` : ""}${f.arch ? ` · Processeur : ${esc(f.arch)}` : ""}</td>
        <td class="num">${esc(fmtSize(f.size))}</td>
        <td><span class="badge ${f.confidence >= 90 ? "ok" : f.confidence >= 60 ? "info" : "none"}">${esc(TXT.confidenceTier[f.confidence_tier] || f.confidence_tier || "")} · ${f.confidence} %</span></td>
      </tr>`).join("")}</tbody></table></div>`;
  }
  if ((mor.unidentified_regions || []).length) {
    html += `<p class="muted" style="margin-top:1rem">${plural(mor.unidentified_regions.length, "zone du fichier n'a pas été reconnue", "zones du fichier n'ont pas été reconnues")}
      (données inconnues, compressées ou chiffrées).</p>`;
  }
  html += `<h2 style="margin-top:1.5rem">Extraction</h2>`;
  if (!extracted.length) {
    html += `<p>Rien n'a été extrait : Mithril a donc analysé le fichier tel quel.</p>`;
  } else {
    const ok = { ok: ["ok", "Réussie"], partial: ["med", "Partielle"], error: ["crit", "Échec"] };
    html += `<div class="table-wrap"><table><caption class="visually-hidden">Morceaux extraits</caption>
      <thead><tr><th scope="col">Morceau</th><th scope="col">Résultat</th><th scope="col" class="num">Fichiers</th><th scope="col" class="num">Dossiers</th><th scope="col" class="num">Volume</th></tr></thead>
      <tbody>${extracted.map(e => {
        const [cls, label] = ok[e.status] || ["none", e.status];
        return `<tr><td><strong>${esc(e.type)}</strong> <span class="mono small muted">(${hex(e.offset)})</span></td>
          <td><span class="badge ${cls}">${label}</span></td><td class="num">${(e.files || 0).toLocaleString("fr-FR")}</td>
          <td class="num">${(e.dirs || 0).toLocaleString("fr-FR")}</td><td class="num">${esc(fmtSize(e.bytes))}</td></tr>`;
      }).join("")}</tbody></table></div>
      ${meta.extracted ? `<p class="no-print" style="margin-top:1rem"><button id="open-extract-2" onclick="document.getElementById('open-extract').click()">📁 Voir les fichiers extraits dans l'Explorateur</button></p>` : ""}`;
  }
  return html;
}

function panelBoot(a) {
  let html = explain(`<p><strong>Démarrage sécurisé :</strong> un appareil bien protégé vérifie, à chaque démarrage, que son logiciel vient bien du fabricant.
    Sans cette vérification, quelqu'un pourrait y installer un logiciel modifié.</p>
    <p><strong>Clés faibles :</strong> les clés de chiffrement trouvées sont testées. Une clé « connue publiquement » ou cassable permet de se faire passer pour l'appareil.</p>`);
  html += `<h2>Clés faibles (${a.strongKeys.length})</h2>`;
  html += a.strongKeys.length ? a.strongKeys.map(k => findingCard(k, "keys", `<span class="badge crit">Clé faible</span>`)).join("")
    : emptyState("🔑", "Aucune clé faible ou publiquement connue.");
  if (a.oddKeys.length) {
    html += `<h2 style="margin-top:1.5rem">Clés mal formées (${a.oddKeys.length})</h2>
      <p class="muted">Mithril a lu ces fichiers comme des clés RSA, mais leurs valeurs n'ont pas de sens pour une clé RSA.
      C'est le plus souvent une <strong>fausse alerte</strong> : par exemple, un fichier <span class="mono">dhparam*.pem</span> contient des paramètres
      d'échange de clés (Diffie-Hellman), pas une clé RSA. Pas de danger dans ce cas.</p>`;
    html += a.oddKeys.map(k => findingCard(k, "keys", `<span class="badge info">À vérifier</span>`)).join("");
  }
  html += `<h2 style="margin-top:1.5rem">Démarrage (${a.bootGroups.length})</h2>`;
  html += a.bootGroups.length
    ? a.bootGroups.map(b => findingCard(b, "boot", BAD_BOOT.has(b.type) ? `<span class="badge high">Point faible</span>`
        : GOOD_BOOT.has(b.type) ? `<span class="badge ok">Bon point</span>` : `<span class="badge info">Info</span>`,
        { note: b.items.length > 1 ? `Trouvé ${b.items.length} fois (le firmware garde plusieurs copies de ses réglages de démarrage).` : "" })).join("")
    : emptyState("⚙️", "Aucune information sur le démarrage n'a été trouvée dans ce firmware.");
  return html;
}

function panelLicenses(licenses) {
  const html = explain(`<p>Les <strong>licences</strong> sont les conditions d'utilisation des logiciels libres présents. Certaines (comme la GPL)
    obligent le fabricant à publier le code source qu'il a utilisé.</p>`);
  if (!licenses.length) return html + emptyState("📜", "Aucune licence identifiée dans les fichiers.");
  return html + `<div class="table-wrap"><table><caption class="visually-hidden">Licences</caption>
    <thead><tr><th scope="col">Licence</th><th scope="col" class="num">Nombre de fichiers</th><th scope="col">Exemples d'emplacements</th></tr></thead>
    <tbody>${licenses.map(l => `<tr><td><strong>${esc(l.license)}</strong></td><td class="num">${l.count}</td>
      <td class="mono small">${l.paths.slice(0, 3).map(p => esc(prettyPath(p))).join("<br>")}${l.paths.length > 3 ? `<br><span class="muted">… et ${l.paths.length - 3} autres</span>` : ""}</td></tr>`).join("")}</tbody>
    </table></div>`;
}

// ==========================================================================
// Analyse approfondie (wsl/deep.py : carte, messages, cpu_rec, binbloom, binwalk)

const fileUrl = (id, name, download) =>
  `/api/analyses/${encodeURIComponent(id)}/file/${name}${download ? "?dl=1" : ""}`;

const ZONE_KIND = {
  code: ["Code ou données", "Instructions du programme ou données structurées."],
  sparse: ["Données simples", "Tables, textes, valeurs peu variées."],
  random: ["Chiffré ou compressé", "Contenu illisible tel quel : compressé ou chiffré."],
  empty: ["Vide (0xFF)", "Mémoire flash effacée, jamais écrite."],
  zero: ["Rempli de zéros", "Zone réservée ou effacée."],
};
const MSG_CAT = {
  error: ["Erreurs", "crit"], log: ["Journaux", "info"], version: ["Versions", "ok"], source: ["Fichiers source", "med"],
};

function hexRange(a, b) { return `${hex(a)} – ${hex(b)}`; }

// cpu_rec -> identifiant Ghidra (miroir de ARCH_TO_GHIDRA côté serveur), pour
// présélectionner le processeur dans le formulaire de rétro-ingénierie.
const ARCH_GHIDRA = {
  ARMel: "ARM:LE:32:v7", ARMhf: "ARM:LE:32:v7", ARMeb: "ARM:BE:32:v7", ARM64: "AARCH64:LE:64:v8A",
  MIPSel: "MIPS:LE:32:default", MIPSeb: "MIPS:BE:32:default", PPCeb: "PowerPC:BE:32:default",
  PPCel: "PowerPC:LE:32:default", "X86": "x86:LE:32:default", "X86-64": "x86:LE:64:default",
  "RISC-V": "RISCV:LE:32:default", Xtensa: "Xtensa:LE:32:default", SuperH: "SuperH4:LE:32:default",
  M68k: "68000:BE:32:default", SPARC: "sparc:BE:32:default", V850: "V850:LE:32:default", NDS32: "NDS32:LE:32:default",
};

// binbloom cherche une table UDS même dans un routeur : on ne montre cette piste
// que si le firmware a l'air automobile, ou si la table est assez fournie.
const AUTO_VENDORS = /Volkswagen|Bosch|Continental|ZF|Mobileye|Valeo|Aptiv|Hella|Denso|Magna|Vector|Elektrobit|ETAS|Infineon/;
function udsCredible(deep) {
  const uds = deep.base?.uds;
  if (!uds) return false;
  const cat = deep.catalog || {};
  const auto = (cat.systems || []).some(s => /AUTOSAR|OSEK/.test(s.name)) || (cat.vendors || []).some(v => AUTO_VENDORS.test(v.name));
  return auto || uds.count >= 5;
}

function deepSummary(deep) {
  const m = deep.map, cpu = deep.cpu || {}, cat = deep.catalog || {};
  const pct = k => Math.round((m.totals[k] || 0) / deep.size * 100);
  const out = [];
  const used = 100 - pct("empty") - pct("zero");
  out.push(`<li><strong>Remplissage :</strong> ${used} % du fichier contient quelque chose
    (${pct("code") + pct("sparse")} % de code ou données, ${pct("random")} % chiffré ou compressé) ; le reste est vide.</li>`);
  if (cpu.main) {
    const bytes = (cpu.segments || []).filter(s => s.arch === cpu.main).reduce((n, s) => n + s.end - s.start, 0);
    out.push(`<li><strong>Processeur :</strong> ${esc(cpu.labels?.[cpu.main] || cpu.main)}, reconnu sur ${esc(fmtSize(bytes))} de code.</li>`);
  } else if (cpu.available) {
    out.push(`<li><strong>Processeur :</strong> non reconnu avec certitude (voir plus bas).</li>`);
  }
  if (cat.systems?.length) out.push(`<li><strong>Système :</strong> ${cat.systems.map(s => esc(s.name)).join(", ")}.</li>`);
  if (cat.vendors?.length) out.push(`<li><strong>Marques citées :</strong> ${cat.vendors.map(s => esc(s.name)).join(", ")}.</li>`);
  const c = cat.counts || {};
  out.push(`<li><strong>Messages :</strong> ${plural(cat.total_strings || 0, "texte lisible", "textes lisibles")},
    dont ${plural(c.error || 0, "message d'erreur", "messages d'erreur")}, ${plural(c.log || 0, "message de journal", "messages de journal")}
    et ${plural(cat.modules?.length || 0, "module identifié", "modules identifiés")}.</li>`);
  if (udsCredible(deep)) out.push(`<li><strong>Diagnostic :</strong> une table de commandes UDS possible a été repérée (calculateur automobile probable).</li>`);
  return `<ul class="stack-list">${out.join("")}</ul>`;
}

function flashMap(deep, mor) {
  const m = deep.map, n = m.blocks.length, size = deep.size;
  const bar = m.blocks.map(k => `<span class="fb fb-${k}"></span>`).join("");
  const marks = (mor.findings || []).map(f => {
    const left = f.offset / size * 100, width = Math.max(0.4, (f.size || 0) / size * 100);
    return `<span class="fm${(f.confidence ?? 0) < 50 ? " weak" : ""}" style="left:${left}%;width:${Math.min(width, 100 - left)}%"
      title="${esc(f.type)} à ${hex(f.offset)} (${f.confidence} %)"></span>`;
  }).join("");
  const segs = (deep.cpu?.segments || m.segments).map(s => {
    const zones = m.zones.filter(z => z.start < s.end && z.end > s.start);
    const kinds = {};
    for (const z of zones) kinds[z.kind] = (kinds[z.kind] || 0) + Math.min(z.end, s.end) - Math.max(z.start, s.start);
    const main = Object.entries(kinds).sort((x, y) => y[1] - x[1])[0]?.[0];
    const arch = s.arch ? esc(deep.cpu.labels?.[s.arch] || s.arch) : s.samples ? `<span class="muted">non reconnu</span>` : `<span class="muted">—</span>`;
    return `<tr><td class="mono">${hexRange(s.start, s.end)}</td><td class="num">${esc(fmtSize(s.end - s.start))}</td>
      <td>${esc(ZONE_KIND[main]?.[0] || "")}</td><td>${arch}</td></tr>`;
  }).join("");
  return `
    <div class="flashmap" aria-hidden="true">
      <div class="flashbar" style="grid-template-columns:repeat(${n},1fr)">${bar}</div>
      <div class="flashmarks">${marks}</div>
      <div class="flashaxis"><span>0</span><span>${esc(fmtSize(size / 2))}</span><span>${esc(fmtSize(size))}</span></div>
    </div>
    <ul class="legend">
      ${Object.entries(ZONE_KIND).map(([k, [label, desc]]) => `<li><span class="sw fb-${k}"></span><strong>${label}</strong> : ${desc}
        <span class="muted">(${esc(fmtSize(m.totals[k] || 0))})</span></li>`).join("")}
      ${(mor.findings || []).length ? `<li><span class="sw sw-mark"></span><strong>Repères Moria</strong> : éléments reconnus par Moria (hachurés si peu fiables).</li>` : ""}
    </ul>
    <div class="table-wrap"><table>
      <caption>Parties remplies de la puce (séparées par des zones vides)</caption>
      <thead><tr><th scope="col">Adresses</th><th scope="col" class="num">Taille</th><th scope="col">Contenu principal</th><th scope="col">Processeur</th></tr></thead>
      <tbody>${segs}</tbody></table></div>`;
}

function cpuSection(cpu) {
  if (!cpu?.available) return `<p class="muted">cpu_rec n'est pas installé (voir « Outils »).</p>`;
  if (cpu.error) return notice("warn", "⚠", "cpu_rec n'a pas pu terminer.", esc(cpu.error));
  const total = cpu.samples.length;
  const byArch = {};
  for (const s of cpu.samples) byArch[s.arch || "—"] = (byArch[s.arch || "—"] || 0) + 1;
  const rows = Object.entries(byArch).sort((x, y) => y[1] - x[1]).map(([k, v]) => {
    const kind = k === "—" ? `<span class="muted">non reconnu</span>` : cpu.implausible?.includes(k)
      ? `${esc(k)} <span class="badge none">bruit, ignoré</span>` : esc(cpu.labels?.[k] || k);
    return `<tr><td>${kind}</td><td class="num">${v}</td><td class="num">${Math.round(v / total * 100)} %</td></tr>`;
  }).join("");
  return `
    ${cpu.main ? notice("ok", "🧠", `Processeur principal : ${cpu.labels?.[cpu.main] || cpu.main}`,
        "C'est le jeu d'instructions reconnu dans les zones de code. Il faut le connaître pour ouvrir le code dans un désassembleur (Ghidra, rizin…).")
      : notice("warn", "❔", "Processeur non reconnu avec certitude.",
        "Soit le code est compressé ou chiffré, soit son processeur ne fait pas partie de ceux que cpu_rec connaît (par exemple Infineon TriCore, très utilisé dans l'automobile).")}
    <details class="more"><summary>Détail des ${total} échantillons analysés</summary>
      <p class="small muted" style="margin-top:.6rem">cpu_rec compare des morceaux de 64 Ko à des exemples de code de 70 processeurs.
        Certains processeurs « exotiques » (IA-64, VAX…) sortent souvent à tort sur des données : ils sont ignorés.</p>
      <div class="table-wrap"><table><thead><tr><th scope="col">Résultat</th><th scope="col" class="num">Échantillons</th><th scope="col" class="num">Part</th></tr></thead>
      <tbody>${rows}</tbody></table></div>
    </details>`;
}

function baseSection(b, showUds) {
  if (!b?.available) return `<p class="muted">binbloom n'est pas installé (voir « Outils »).</p>`;
  if (b.error) return notice("warn", "⚠", "binbloom n'a pas pu terminer.", esc(b.error));
  if (b.skipped) return `<p>Recherche non lancée : ${esc(b.skipped)}. binbloom a besoin de savoir de quel processeur il s'agit.</p>`;
  const cands = (b.candidates || []).slice(0, 6).map(c => `<li class="mono">${esc(c.addr)} <span class="muted">(score ${c.score})</span></li>`).join("");
  return `
    <p>Le code d'un appareil est prévu pour être copié à une <strong>adresse précise</strong> de la mémoire avant de s'exécuter.
      Sans elle, un désassembleur ne sait pas relier le code à ses messages et à ses données. binbloom la devine à partir des pointeurs
      présents dans la zone de code la plus grande (${hexRange(b.segment.start, b.segment.end)}).</p>
    ${b.base ? notice(b.sure ? "ok" : "warn", "📍", `Adresse probable : ${b.base}${b.sure ? "" : " (hypothèse, binbloom n'est pas sûr)"}`,
        `Ordre des octets : ${b.endianness === "be" ? "gros-boutiste (big-endian)" : "petit-boutiste (little-endian)"} · mots de ${b.bits} bits · calcul en ${b.seconds} s.
         La zone analysée peut contenir plusieurs programmes : l'adresse ne vaut alors que pour l'un d'eux.`)
      : notice("warn", "❔", "Pas d'adresse trouvée.", b.timeout ? "Le calcul a été interrompu (trop long)." : "")}
    ${cands ? `<details class="more"><summary>Autres adresses candidates</summary><ul style="margin-top:.6rem">${cands}</ul></details>` : ""}
    ${b.uds && showUds ? `<h3 style="margin-top:1.2rem">Table de diagnostic UDS (hypothèse)</h3>
      <p>Les calculateurs automobiles répondent aux outils de diagnostic du garage via le protocole <strong>UDS</strong>.
        binbloom a repéré à <span class="mono">0x${esc(b.uds.at)}</span> (adresse mémoire) une table qui ressemble à la liste des commandes
        acceptées, avec ${b.uds.count} commandes différentes. C'est un bon point de départ pour comprendre ce que le calculateur sait faire en diagnostic.</p>` : ""}`;
}

function catalogSection(meta, cat) {
  const c = cat.counts || {};
  const cards = Object.entries(MSG_CAT).map(([k, [label, cls]]) =>
    `<button class="tile" data-msgcat="${k}"><span class="n">${(c[k] || 0).toLocaleString("fr-FR")}</span><span class="l">${label}</span></button>`).join("");
  const mods = (cat.modules || []).slice(0, 30).map(m => `<details class="module">
      <summary><strong>${esc(m.name)}</strong> <span class="muted">· ${plural(m.count, "message", "messages")}</span></summary>
      <ul class="mono small">${m.examples.map(e => `<li>${esc(e)}</li>`).join("")}</ul></details>`).join("");
  return `
    <p>Le firmware contient les textes qu'il est capable d'afficher : messages d'erreur, lignes de journal (avec des <span class="mono">%d</span>,
      <span class="mono">%s</span> remplacés par des valeurs au moment de l'affichage), numéros de version, noms de fichiers du code source…
      Ce ne sont pas des journaux enregistrés, mais ils décrivent <strong>ce que le programme fait et surveille</strong>.</p>
    <div class="tiles">${cards}</div>
    ${mods ? `<h3>Modules repérés</h3>
      <p class="muted small">Regroupés d'après le début des messages (« LAD_… », « Swid Update: … »). Chaque module correspond souvent à une fonction du produit.</p>
      <div class="modules">${mods}</div>` : ""}
    <h3 style="margin-top:1.2rem">Rechercher dans les messages</h3>
    <div class="filterbar">
      <label for="msg-q" class="visually-hidden">Rechercher un message</label>
      <input type="search" id="msg-q" placeholder="Rechercher (ex. version, CAN, boot…)">
      <label for="msg-cat" class="visually-hidden">Type de message</label>
      <select id="msg-cat"><option value="">Tous les types</option>
        ${Object.entries(MSG_CAT).map(([k, [l]]) => `<option value="${k}">${l}</option>`).join("")}</select>
      <span class="muted small" id="msg-count" aria-live="polite"></span>
    </div>
    <div class="table-wrap"><table id="msg-table">
      <caption class="visually-hidden">Messages trouvés</caption>
      <thead><tr><th scope="col">Position</th><th scope="col">Type</th><th scope="col">Texte</th></tr></thead>
      <tbody></tbody></table></div>
    <p class="small" style="margin-top:.6rem"><a href="${fileUrl(meta.id, "messages.txt", true)}" download>Télécharger tous les textes lisibles
      (${(cat.total_strings || 0).toLocaleString("fr-FR")})</a>${cat.truncated ? " · la liste ci-dessus est limitée aux 4 000 premiers messages classés" : ""}</p>`;
}

function hintsSection(cat) {
  const block = (title, list, empty) => `<h3>${title}</h3>` + (list?.length
    ? `<ul>${list.map(v => `<li><strong>${esc(v.name)}</strong> <span class="muted">(${v.count})</span><br>
        <span class="mono small">${v.examples.slice(0, 3).map(esc).join("<br>")}</span></li>`).join("")}</ul>`
    : `<p class="muted">${empty}</p>`);
  return block("Marques et composants cités", cat.vendors, "Aucune marque connue n'apparaît dans les textes.") +
    block("Système d'exploitation", cat.systems, "Aucun système connu repéré (Linux, AUTOSAR, FreeRTOS…).");
}

function binwalkSection(meta, bw) {
  if (!bw?.available) return `<p class="muted">binwalk n'est pas installé (voir « Outils »).</p>`;
  const rows = (bw.findings || []).map(f => `<tr><td class="mono">${hex(f.offset)}</td><td><strong>${esc(f.name)}</strong></td>
    <td class="small" lang="en">${esc(f.description)}</td><td>${f.also_moria ? `<span class="badge ok">aussi Moria</span>` : `<span class="badge info">binwalk seul</span>`}</td></tr>`).join("");
  return `
    <p>binwalk est l'outil historique d'identification des firmwares. Comparer son avis à celui de Moria permet de repérer ce que l'un
      des deux aurait manqué ou mal reconnu.</p>
    ${rows ? `<div class="table-wrap"><table><thead><tr><th scope="col">Position</th><th scope="col">Type</th><th scope="col">Description</th><th scope="col">Accord</th></tr></thead>
      <tbody>${rows}</tbody></table></div>` : `<p>binwalk ne reconnaît rien de particulier dans ce fichier.</p>`}
    ${bw.entropy_png ? `<details class="more"><summary>Graphique d'entropie de binwalk</summary>
      <p class="small muted" style="margin-top:.6rem">Plus la courbe est haute, plus le contenu est « désordonné » : proche de 1, c'est compressé ou chiffré ;
        à 0, c'est vide.</p>
      <img src="${fileUrl(meta.id, "entropy.png")}" alt="Courbe d'entropie du fichier, de son début à sa fin" style="background:#fff;border-radius:8px"></details>` : ""}`;
}

function panelDeep(meta, deep, mor, ghidra) {
  const intro = explain(`<p>Cette analyse ne cherche pas des failles : elle aide à <strong>comprendre ce qu'est ce firmware</strong>, surtout quand
    Moria ne sait pas l'ouvrir (calculateurs automobiles, microcontrôleurs, systèmes sans Linux). Elle dessine la carte de la puce,
    reconnaît le processeur, estime où le code est chargé en mémoire et rassemble tous les messages lisibles.</p>`);
  if (!deep) {
    const ready = STATUS?.deep_ready !== false;
    return intro + `<div class="card empty"><div class="big-icon" aria-hidden="true">🔬</div>
      <p>L'analyse approfondie n'a pas encore été faite pour ce fichier.</p>
      ${ready ? `<button class="primary" id="run-deep">🔬 Lancer l'analyse approfondie (1 à 3 minutes)</button>`
        : `<p>Les outils nécessaires ne sont pas installés. <a href="#/outils">Aller dans « Outils »</a>.</p>`}</div>`;
  }
  return intro + `
    <div class="card"><h2>En résumé</h2>${deepSummary(deep)}</div>
    <div class="card"><h2>Carte de la puce</h2>${flashMap(deep, mor)}</div>
    <div class="card"><h2>Processeur</h2>${cpuSection(deep.cpu)}</div>
    <div class="card"><h2>Adresse de chargement du code</h2>${baseSection(deep.base, udsCredible(deep))}</div>
    <div class="card"><h2>Messages du firmware</h2>${catalogSection(meta, deep.catalog || {})}</div>
    <div class="card"><h2>Indices sur l'origine</h2>${hintsSection(deep.catalog || {})}</div>
    <div class="card"><h2>Deuxième avis : binwalk</h2>${binwalkSection(meta, deep.binwalk)}</div>
    <div class="card" id="ghidra-card"><h2>Comprendre le code (Ghidra)</h2>${ghidraSection(meta, deep, ghidra)}</div>
    <p class="no-print"><button id="rerun-deep">🔄 Relancer l'analyse approfondie</button></p>`;
}

// ---- Rétro-ingénierie avec Ghidra -----------------------------------------

const GHIDRA_INTRO = `<p>Jusqu'ici on a lu ce que le firmware <em>contient</em>. Ghidra, l'outil de rétro-ingénierie publié par la NSA,
  va plus loin : il traduit le <strong>code machine</strong> en un pseudo-code proche du langage C, et relie chaque message
  à la fonction qui l'affiche. C'est ainsi qu'on comprend <strong>ce que fait vraiment le programme</strong>.</p>
  <p class="small muted">L'analyse porte sur une seule zone de code à la fois. Elle peut durer de quelques minutes à une demi-heure
    selon la taille. Le résultat dépend du bon choix du processeur : s'il est faux, Ghidra ne trouve rien de cohérent.</p>`;

function ghidraSection(meta, deep, ghidra) {
  if (ghidra) return ghidraResults(meta, ghidra);
  if (STATUS && !STATUS.ghidra) {
    return GHIDRA_INTRO + notice("info", "⬇", "Ghidra n'est pas encore installé.",
      `C'est un téléchargement de 570 Mo, à faire une seule fois. <a href="#/outils">Aller dans « Outils » pour l'installer</a>.`);
  }
  // Formulaire : segment, processeur, adresse — pré-remplis par l'analyse approfondie.
  const segs = deep?.cpu?.segments?.length ? deep.cpu.segments : (deep?.map?.segments || []);
  const withArch = segs.map((s, i) => ({ ...s, i })).filter(s => (s.end - s.start) >= 0x2000);
  const best = deep?.base?.segment;
  const defArch = deep?.cpu?.main ? (ARCH_GHIDRA[deep.cpu.main] || "") : "";
  const defBase = deep?.base?.base || "0x0";
  const options = withArch.map(s => {
    const chosen = best && s.start === best.start ? " selected" : "";
    const arch = s.arch ? ` — ${deep.cpu.labels?.[s.arch] || s.arch}` : "";
    return `<option value="${s.start}:${s.end}" data-arch="${s.arch ? (ARCH_GHIDRA[s.arch] || "") : ""}"${chosen}>${hexRange(s.start, s.end)} (${fmtSize(s.end - s.start)})${arch}</option>`;
  }).join("");
  return GHIDRA_INTRO + `
    <div class="gh-form">
      <div class="field">
        <label for="gh-seg">Zone de code à analyser</label>
        <select id="gh-seg">${options || `<option value="">(aucune zone de code trouvée)</option>`}</select>
        <p class="small muted">Une seule zone à la fois. La plus grande zone de code est présélectionnée.</p>
      </div>
      <div class="field">
        <label for="gh-lang">Processeur</label>
        <select id="gh-lang"></select>
        <p class="small muted">Pré-rempli d'après l'analyse approfondie. Si le résultat est incohérent, essaie une autre valeur
          (les calculateurs automobiles récents sont souvent en <strong>TriCore</strong> ou <strong>PowerPC VLE</strong>).</p>
      </div>
      <div class="field">
        <label for="gh-base">Adresse de chargement</label>
        <input type="text" id="gh-base" value="${esc(defBase)}" spellcheck="false">
        <p class="small muted">Où ce code est copié en mémoire (trouvé par binbloom). À laisser tel quel en cas de doute.</p>
      </div>
      <div id="gh-estimate" class="notice info" style="margin:0"><span class="icon">⏱️</span><div></div></div>
      <button class="primary big" id="gh-run" data-defarch="${esc(defArch)}">🔍 Lancer Ghidra sur cette zone</button>
    </div>`;
}

function ghidraResults(meta, g) {
  const gm = meta.ghidra || {};
  const funcs = g.functions || [];
  const withMsg = funcs.filter(f => f.strings && f.strings.length).length;
  const decompiled = new Set(g.decompiled || []);
  return `
    ${notice("ok", "🧩", `${(g.function_count || 0).toLocaleString("fr-FR")} fonctions retrouvées dans le code`,
      `Processeur : ${esc(gm.lang || g.language)} · chargé à ${esc(gm.base || g.image_base)} · ${plural(g.instructions || 0, "instruction", "instructions")}.
       ${withMsg} fonctions affichent des messages ; ${decompiled.size} sont traduites en pseudo-code ci-dessous.`)}
    <h3>Que fait le code ? — retrouver par un message</h3>
    <p>Tape un mot d'un message (« version », « error », « boot », « CAN »…) pour retrouver la fonction qui l'affiche,
      puis lis son pseudo-code.</p>
    <div class="filterbar">
      <label for="gh-q" class="visually-hidden">Rechercher</label>
      <input type="search" id="gh-q" placeholder="Rechercher un message ou un nom de fonction…" style="max-width:380px">
      <span class="muted small" id="gh-count" aria-live="polite"></span>
    </div>
    <div class="gh-layout">
      <div class="table-wrap gh-list"><table id="gh-table">
        <caption class="visually-hidden">Fonctions</caption>
        <thead><tr><th scope="col">Fonction</th><th scope="col" class="num">Taille</th><th scope="col" class="num">Appelée par</th><th scope="col">Messages</th></tr></thead>
        <tbody></tbody></table></div>
      <div class="gh-code" id="gh-code"><p class="muted">Choisis une fonction à gauche pour voir son pseudo-code.</p></div>
    </div>
    <p class="small muted" style="margin-top:1rem">Le pseudo-code est reconstruit automatiquement : les noms <span class="mono">FUN_…</span>,
      <span class="mono">DAT_…</span> et <span class="mono">uVar…</span> sont des étiquettes mises par Ghidra faute de noms d'origine.
      Les messages entre guillemets, eux, sont réels. <a href="${fileUrl(meta.id, "ghidra.json", true)}" download>Télécharger tout (JSON)</a>.</p>`;
}

function setupGhidra(meta, deep, ghidra) {
  if (ghidra) return setupGhidraResults(meta, ghidra);
  const run = $("#gh-run");
  if (!run) return;
  const seg = $("#gh-seg"), lang = $("#gh-lang"), base = $("#gh-base"), est = $("#gh-estimate div");

  // Remplit la liste des processeurs, en plaçant en tête celui déduit de l'analyse.
  api("GET", "ghidra-langs").then(({ langs }) => {
    lang.innerHTML = langs.map(([id, label]) => `<option value="${id}">${esc(label)} — ${id}</option>`).join("");
    applyDefaults();
  }).catch(() => { lang.innerHTML = `<option value="ARM:LE:32:v7">ARM 32 bits</option>`; });

  const applyDefaults = () => {
    const opt = seg.selectedOptions[0];
    const arch = opt?.dataset.arch || run.dataset.defarch;
    if (arch && [...lang.options].some(o => o.value === arch)) lang.value = arch;
    estimate();
  };
  const estimate = () => {
    const [s, e] = (seg.value || "0:0").split(":").map(Number);
    const mb = (e - s) / (1 << 20);
    const mins = Math.max(2, Math.round(mb * 2.5));
    est.innerHTML = mb > 24
      ? `Cette zone fait ${mb.toFixed(1)} Mo — trop grande. Choisis-en une plus petite (24 Mo maximum).`
      : `Zone de ${mb.toFixed(1)} Mo : compte environ ${mins} minute${mins > 1 ? "s" : ""}. Tu peux fermer l'onglet, l'analyse continue.`;
    run.disabled = mb > 24 || mb <= 0;
  };
  seg.onchange = applyDefaults;
  seg.addEventListener("change", estimate);
  run.onclick = async () => {
    const [start, end] = (seg.value || "0:0").split(":").map(Number);
    if (!lang.value) { toast("Choisis un processeur."); return; }
    try {
      const job = await api("POST", `analyses/${encodeURIComponent(meta.id)}/ghidra`,
        { start, end, lang: lang.value, base: base.value.trim() });
      location.hash = `#/tache/${job.id}`;
    } catch (e) { toast(e.message); }
  };
}

function setupGhidraResults(meta, g) {
  const funcs = (g.functions || []).slice();
  const byEntry = Object.fromEntries(funcs.map(f => [f.entry, f]));
  const q = $("#gh-q"), body = $("#gh-table tbody"), count = $("#gh-count"), code = $("#gh-code");
  const LIMIT = 200;
  const show = entry => {
    const f = byEntry[entry];
    if (!f) return;
    $$("#gh-table tbody tr").forEach(tr => tr.classList.toggle("sel", tr.dataset.entry === entry));
    if (!f.c) {
      code.innerHTML = `<p class="muted">Cette fonction n'a pas été traduite en pseudo-code (seules les plus parlantes le sont).
        Ses messages : </p><ul class="mono small">${(f.strings || []).map(s => `<li>${esc(s)}</li>`).join("") || "<li>aucun</li>"}</ul>`;
      return;
    }
    code.innerHTML = `<div class="gh-code-head"><strong class="mono">${esc(f.name)}</strong>
      <span class="small muted">${esc(f.entry)} · ${esc(fmtSize(f.size))} · appelée par ${f.callers}</span></div>
      <pre class="gh-c"><code>${esc(f.c)}${f.c_truncated ? "\n\n/* … pseudo-code tronqué … */" : ""}</code></pre>`;
    code.scrollTop = 0;
  };
  const draw = () => {
    const needle = q.value.trim().toLowerCase();
    const hits = funcs.filter(f => !needle || f.name.toLowerCase().includes(needle)
      || (f.strings || []).some(s => s.toLowerCase().includes(needle)));
    body.innerHTML = hits.slice(0, LIMIT).map(f => {
      const msg = (f.strings || [])[0];
      return `<tr data-entry="${f.entry}" class="${f.c ? "has-c" : ""}">
        <td><span class="mono small">${esc(f.name)}</span>${f.c ? ` <span class="badge ok">code</span>` : ""}</td>
        <td class="num small">${esc(fmtSize(f.size))}</td><td class="num">${f.callers}</td>
        <td class="small">${msg ? `<span class="mono">« ${esc(msg.slice(0, 50))} »</span>${f.strings.length > 1 ? ` <span class="muted">+${f.strings.length - 1}</span>` : ""}` : `<span class="muted">—</span>`}</td></tr>`;
    }).join("");
    count.textContent = hits.length > LIMIT ? `${hits.length} fonctions (200 affichées)` : plural(hits.length, "fonction", "fonctions");
    $$("#gh-table tbody tr").forEach(tr => tr.onclick = () => show(tr.dataset.entry));
  };
  q.oninput = draw;
  draw();
  // Ouvre d'emblée la première fonction décompilée la plus parlante.
  const first = funcs.find(f => f.c);
  if (first) show(first.entry);
}

function setupDeep(meta, deep) {
  const run = async () => {
    try {
      const job = await api("POST", `analyses/${encodeURIComponent(meta.id)}/deep`);
      location.hash = `#/tache/${job.id}`;
    } catch (e) { toast(e.message); }
  };
  $("#run-deep")?.addEventListener("click", run);
  $("#rerun-deep")?.addEventListener("click", run);
  if (!deep) return;

  const msgs = deep.catalog?.messages || [];
  const q = $("#msg-q"), cat = $("#msg-cat"), body = $("#msg-table tbody"), count = $("#msg-count");
  const LIMIT = 60;
  const draw = () => {
    const needle = q.value.trim().toLowerCase(), c = cat.value;
    const hits = msgs.filter(m => (!c || m.c === c) && (!needle || m.t.toLowerCase().includes(needle)));
    body.innerHTML = hits.slice(0, LIMIT).map(m => `<tr><td class="mono small">${hex(m.o)}</td>
      <td><span class="badge ${MSG_CAT[m.c]?.[1] || "none"}">${MSG_CAT[m.c]?.[0] || m.c}</span></td>
      <td class="mono small">${esc(m.t)}</td></tr>`).join("");
    count.textContent = hits.length > LIMIT ? `${hits.length.toLocaleString("fr-FR")} messages (${LIMIT} affichés, affine ta recherche)`
      : plural(hits.length, "message", "messages");
  };
  q.oninput = draw;
  cat.onchange = draw;
  $$("[data-msgcat]").forEach(b => b.onclick = () => { cat.value = b.dataset.msgcat; draw(); q.focus(); });
  draw();
}

function panelFiles(meta, r, deep, ghidra) {
  const dl = (name, label, desc) =>
    `<li style="margin-bottom:.8rem"><a href="${fileUrl(meta.id, name, true)}" download>${label}</a><br><span class="small muted">${desc}</span></li>`;
  return `<div class="card">
      <h2>Télécharger</h2>
      <ul>
        ${dl("sbom.cdx.json", "Inventaire logiciel (format CycloneDX)", "Le format standard le plus répandu, lisible par la plupart des outils de sécurité.")}
        ${dl("sbom.spdx.json", "Inventaire logiciel (format SPDX)", "L'autre format standard, souvent demandé pour les questions de licences.")}
        ${dl("mithril-report.json", "Rapport complet de Mithril (JSON)", "Toutes les données brutes de l'inspection.")}
        ${dl("moria.json", "Rapport complet de Moria (JSON)", "Toutes les données brutes de l'identification et de l'extraction.")}
        ${deep ? dl("deep.json", "Analyse approfondie (JSON)", "Carte de la puce, processeur, adresse de chargement, messages classés.") +
          dl("messages.txt", "Tous les textes lisibles (texte)", "Un texte par ligne, précédé de sa position dans le fichier.") : ""}
        ${ghidra ? dl("ghidra.json", "Rétro-ingénierie Ghidra (JSON)", "Fonctions, liens message→code et pseudo-code produits par Ghidra.") : ""}
      </ul>
      <div class="row"><button id="open-report">📂 Ouvrir le dossier du rapport</button></div>
    </div>
    <div class="card">
      <h2>Informations</h2>
      <dl class="kv">
        <dt>Fichier analysé</dt><dd class="mono">${esc(meta.source)}</dd>
        <dt>Date</dt><dd>${esc(fmtDate(meta.date))}</dd>
        <dt>Versions des outils</dt><dd>moria ${esc(meta.versions?.moria || "?")}, mithril ${esc(meta.versions?.mithril || "?")}</dd>
        <dt>Base de failles</dt><dd>${meta.cve_db ? `téléchargée le ${esc(fmtDay(meta.cve_db))}` : "absente"}</dd>
        <dt>Analyse approfondie</dt><dd>${deep ? `oui (${esc(fmtDate(deep.finished))})` : "non"}</dd>
        <dt>Reconnaissance élargie</dt><dd>${meta.broad ? "oui" : "non"}</dd>
        <dt>Volume examiné</dt><dd>${esc(fmtSize(r.bytes_scanned))} dans ${plural(r.file_count || 0, "fichier", "fichiers")}</dd>
        ${(r.errors || []).length ? `<dt>Fichiers illisibles</dt><dd>${r.errors.length}</dd>` : ""}
      </dl>
    </div>
    <div class="card">
      <h2>Supprimer cette analyse</h2>
      <p class="muted">Efface le rapport et les fichiers extraits. Le fichier firmware d'origine n'est pas touché.</p>
      <button class="danger" id="del">🗑️ Supprimer l'analyse</button>
    </div>`;
}

async function deleteAnalysis(meta) {
  const ok = await confirmBox("Supprimer cette analyse ?",
    `Le rapport de « ${meta.name} » et les fichiers extraits seront effacés. Cette action est définitive.`, "Supprimer");
  if (!ok) return;
  try {
    await api("DELETE", `analyses/${encodeURIComponent(meta.id)}`);
    toast("Analyse supprimée.");
    location.hash = "#/historique";
  } catch (e) { toast(e.message); }
}

// ==========================================================================
// Outils : installation et mises à jour

const TOOL_INFO = {
  moria: ["Moria", "ouvre le firmware et en extrait les fichiers"],
  mithril: ["Mithril", "cherche secrets, logiciels et failles"],
  cpu_rec: ["cpu_rec", "reconnaît le processeur (analyse approfondie)"],
  binbloom: ["binbloom", "trouve l'adresse de chargement (analyse approfondie)"],
  binwalk: ["binwalk", "deuxième avis et graphique d'entropie (analyse approfondie)"],
};

async function renderTools() {
  setTitle("Outils");
  main.innerHTML = `<h1>Outils</h1><p class="lead" role="status">Vérification de l'état des outils…</p>`;
  const st = await refreshStatus();
  if (!st) throw new Error("L'Atelier ne répond pas.");

  const dbAge = st.db ? Math.round((Date.now() - new Date(st.db)) / 86400000) : null;
  const repoCard = rp => {
    if (!rp.present) return `<li><strong>${rp.name}</strong> : dossier introuvable</li>`;
    const state = rp.modified ? `<span class="badge high">Modifié à la main</span>`
      : rp.behind == null ? `<span class="badge none">État inconnu</span>`
      : rp.behind === 0 ? `<span class="badge ok">À jour</span>`
      : `<span class="badge info">${plural(rp.behind, "nouveauté disponible", "nouveautés disponibles")}</span>`;
    return `<tr><th scope="row">${esc(rp.name)}</th><td>${rp.version ? esc(rp.version) : `<span class="mono small">${esc(rp.commit)}</span>`}</td>
      <td>${esc(fmtDay(rp.date))}<br><span class="small muted" lang="en">${esc(rp.subject)}</span></td><td>${state}</td></tr>`;
  };

  main.innerHTML = `
    <h1>Outils</h1>
    <p class="lead">Ici, tu installes et mets à jour les outils d'analyse et la base des failles connues. Tout se fait en un clic.</p>

    ${!st.wsl ? `<div class="card">${notice("error", "⚠", "Ubuntu (WSL) ne démarre pas.",
      "Moria et Mithril ont besoin d'Ubuntu. Redémarre l'ordinateur ; si le problème continue, demande de l'aide en montrant le message ci-dessous.")}
      <div class="log">${esc(st.wsl_error || "")}</div></div>` : ""}

    <div class="card">
      <h2>État</h2>
      <dl class="kv">
        <dt>Ubuntu (WSL)</dt><dd>${st.wsl ? `<span class="badge ok">Fonctionne</span>` : `<span class="badge crit">Ne démarre pas</span>`}</dd>
        ${Object.entries(TOOL_INFO).map(([t, [name, role]]) => {
          const v = st.tools[t];
          return `<dt>${name}</dt><dd>${v ? `<span class="badge ok">Installé${/\d/.test(v) ? ` · version ${esc(v)}` : ""}</span>`
            : `<span class="badge ${t in { moria: 1, mithril: 1 } ? "crit" : "med"}">Pas installé</span>`}
            <span class="small muted">${role}</span></dd>`;
        }).join("")}
        <dt>Base des failles</dt><dd>${st.db ? `<span class="badge ${dbAge > 14 ? "med" : "ok"}">Téléchargée le ${esc(fmtDay(st.db))}</span>` : `<span class="badge crit">Absente</span>`}</dd>
        <dt>Ghidra</dt><dd>${st.ghidra ? `<span class="badge ok">Installé</span>` : `<span class="badge med">Pas installé</span>`}
          <span class="small muted">rétro-ingénierie du code (facultatif)</span></dd>
      </dl>
      ${st.wsl && (!st.ready || !st.deep_ready) ? `<div class="row" style="margin-top:1rem"><button class="primary big" id="setup">🔧 Installer les outils</button>
        <span class="muted small">Compile tous les outils puis télécharge la base de failles (10 à 15 minutes la première fois).</span></div>` : ""}
    </div>

    ${st.wsl ? `<div class="card">
      <h2>Ghidra — rétro-ingénierie du code</h2>
      <p>Ghidra (publié par la NSA) traduit le code machine d'un firmware en pseudo-code lisible et relie chaque message
        à la fonction qui l'affiche. Utile pour les firmwares que Moria ne sait pas ouvrir (calculateurs automobiles, microcontrôleurs).
        Il se lance à la demande depuis l'onglet « Analyse approfondie » d'un rapport.</p>
      ${st.ghidra ? `<p><span class="badge ok">Installé</span></p>`
        : `<div class="row"><button class="${st.deep_ready ? "" : "primary"}" id="setup-ghidra">⬇️ Installer Ghidra</button>
           <span class="muted small">Télécharge Ghidra et Java (570 Mo, environ 2 Go une fois installé). À faire une seule fois.</span></div>`}
    </div>` : ""}

    ${st.ready ? `<div class="card">
      <h2>Base des failles connues</h2>
      <p>Chaque semaine, de nouvelles failles sont publiées. La base est reconstruite chaque semaine par l'auteur de Mithril :
        pense à la mettre à jour avant une analyse importante${dbAge == null ? "" : dbAge < 1 ? " (dernière mise à jour aujourd'hui)" : ` (dernière mise à jour il y a ${plural(dbAge, "jour", "jours")})`}.</p>
      <button id="update-db" class="${dbAge == null || dbAge > 14 ? "primary" : ""}">📚 Mettre à jour la base (environ 170 Mo)</button>
    </div>` : ""}

    <div class="card">
      <h2>Mises à jour des outils</h2>
      <p>Les auteurs des outils publient régulièrement des améliorations sur leur <strong>dépôt officiel</strong>.
        L'Atelier les récupère dans tes copies <em>sans jamais les modifier autrement</em>, puis recompile les outils concernés.</p>
      <div class="table-wrap"><table>
        <caption class="visually-hidden">Version de chaque dépôt</caption>
        <thead><tr><th scope="col">Outil</th><th scope="col">Version</th><th scope="col">Dernière modification</th><th scope="col">État</th></tr></thead>
        <tbody>${st.repos.map(repoCard).join("")}</tbody>
      </table></div>
      <div class="row" style="margin-top:1rem">
        <button id="check">🔍 Vérifier s'il y a des nouveautés</button>
        <button id="update-tools" class="${st.repos.some(r => r.behind > 0) ? "primary" : ""}" ${st.wsl ? "" : "disabled"}>⬇️ Mettre à jour et recompiler</button>
      </div>
      <details class="more"><summary>Et mon fork sur GitHub ?</summary>
        <p style="margin-top:.6rem">Tes forks sur GitHub ne sont pas nécessaires au fonctionnement de l'Atelier : il utilise les copies présentes sur ton PC,
          qu'il met à jour directement depuis le dépôt officiel. Si tu veux aussi garder tes forks GitHub à jour, ouvre la page de chaque fork
          (<a href="https://github.com/nicolasnt3-a11y/moria" target="_blank" rel="noopener">moria</a>,
          <a href="https://github.com/nicolasnt3-a11y/mithril" target="_blank" rel="noopener">mithril</a>)
          et clique sur le bouton <strong>« Sync fork »</strong> puis <strong>« Update branch »</strong>.
          cpu_rec, binbloom et binwalk sont copiés directement depuis leur dépôt officiel (pas de fork) : il n'y a rien à faire pour eux.</p>
      </details>
    </div>

    <div class="card">
      <h2>Fermer l'Atelier</h2>
      <p class="muted">L'Atelier s'arrête tout seul quelques minutes après la fermeture de cet onglet. Tu peux aussi l'arrêter tout de suite.</p>
      <button id="quit">⏻ Arrêter l'Atelier</button>
    </div>`;

  const launch = url => async () => {
    try { const job = await api("POST", url); location.hash = `#/tache/${job.id}`; }
    catch (e) { toast(e.message); }
  };
  $("#setup")?.addEventListener("click", launch("setup"));
  $("#setup-ghidra")?.addEventListener("click", launch("setup-ghidra"));
  $("#update-db")?.addEventListener("click", launch("update-db"));
  $("#update-tools").onclick = launch("update-tools");
  $("#check").onclick = async () => {
    const b = $("#check");
    b.disabled = true; b.textContent = "Vérification…";
    try { await api("POST", "check-updates"); await renderTools(); toast("Vérification terminée."); }
    catch (e) { toast(e.message); b.disabled = false; }
  };
  $("#quit").onclick = async () => {
    if (!await confirmBox("Arrêter l'Atelier ?", "Tu pourras le relancer à tout moment depuis son raccourci.", "Arrêter")) return;
    await api("POST", "quit").catch(() => {});
    document.body.innerHTML = `<main style="max-width:600px;margin:4rem auto;padding:1rem"><h1>L'Atelier est arrêté</h1>
      <p>Tu peux fermer cet onglet. Pour le relancer, double-clique sur le raccourci <strong>Atelier Firmware</strong> du bureau.</p></main>`;
  };
}

// ==========================================================================
// Aide

function renderHelp() {
  setTitle("Aide");
  main.innerHTML = `
    <h1>Aide</h1>
    <div class="card">
      <h2>En bref</h2>
      <ol>
        <li>Sur l'accueil, <strong>glisse un fichier firmware</strong> ou clique sur « Choisir un fichier ».</li>
        <li>Attends la fin de l'analyse (de quelques secondes à quelques minutes).</li>
        <li>Lis le <strong>verdict</strong> en haut du rapport, puis l'onglet <strong>« L'essentiel »</strong> : les problèmes y sont classés du plus grave au moins grave.</li>
        <li>Clique sur un point pour voir son explication détaillée.</li>
      </ol>
      <p>Où trouver des firmwares ? Sur le site d'assistance du fabricant de l'appareil (rubrique « Téléchargements » ou « Mises à jour »),
        ou sur <a href="https://downloads.openwrt.org" target="_blank" rel="noopener">downloads.openwrt.org</a> pour s'entraîner.</p>
    </div>
    <div class="card">
      <h2>Tes fichiers</h2>
      <dl class="kv">
        <dt>Rapports</dt><dd>Documents › Atelier Firmware › analyses</dd>
        <dt>Fichiers glissés</dt><dd>Documents › Atelier Firmware › fichiers-deposes</dd>
        <dt>Fichiers extraits</dt><dd>Dans Ubuntu (bouton « Voir les fichiers extraits » d'un rapport)</dd>
      </dl>
    </div>
    <div class="card">
      <h2>Petit lexique</h2>
      <dl class="glossary">${GLOSSARY.map(([t, d]) => `<dt>${esc(t)}</dt><dd>${esc(d)}</dd>`).join("")}</dl>
    </div>
    <div class="card">
      <h2>Un usage responsable</h2>
      <p>Analyse des firmwares que tu as le droit d'examiner (les tiens, ceux publiés par les fabricants, ou dans le cadre d'une mission autorisée).
        Si tu découvres une faille sérieuse, préviens le fabricant avant d'en parler publiquement.</p>
    </div>`;
}

// ==========================================================================
// Démarrage

// La vérification des outils passe par Ubuntu et prend quelques secondes :
// on affiche la page tout de suite et on complète quand la réponse arrive.
route();
refreshStatus().then(() => {
  const off = STATUS?.ready === false;
  ["#pick", "#go-path"].forEach(s => { const b = $(s); if (b) b.disabled = off; });
});
