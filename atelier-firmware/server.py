"""Atelier Firmware : interface web locale pour moria et mithril.

Le serveur tourne sous Windows, n'écoute que sur 127.0.0.1 et pilote les deux
outils installés dans Ubuntu (WSL). Il ne modifie jamais les dépôts moria et
mithril : il les compile hors de leurs dossiers et ne fait que lire leurs
sorties JSON.
"""

import datetime
import http.server
import json
import os
import re
import shlex
import shutil
import socketserver
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
import webbrowser
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
WEB_DIR = APP_DIR / "web"
REPOS_DIR = APP_DIR.parent                      # contient les dépôts des outils
DATA_DIR = Path.home() / "Documents" / "Atelier Firmware"
ANALYSES_DIR = DATA_DIR / "analyses"
UPLOADS_DIR = DATA_DIR / "fichiers-deposes"

DISTRO = "Ubuntu"
WSL_WORK = "/root/atelier"                      # extractions (côté Linux)
WSL_DB = "/root/.local/share/mithril"
HOST, PORT = "127.0.0.1", 8765
REQUIRED_TOOLS = ("moria", "mithril")           # indispensables à une analyse
DEEP_TOOLS = ("cpu_rec", "binbloom", "binwalk")  # analyse approfondie (facultatifs)
EXTRA_TOOLS = ("bulk_extractor", "yara")         # traces et crypto (facultatifs, ajoutés ensuite)
TOOLS = REQUIRED_TOOLS + DEEP_TOOLS + EXTRA_TOOLS  # commandes installées dans Ubuntu
# Dépôts à côté de l'Atelier. yara vient des paquets Ubuntu ; ses règles
# (findcrypt-yara) sont un dépôt, copié tel quel.
REPOS = REQUIRED_TOOLS + DEEP_TOOLS + ("bulk_extractor", "findcrypt-yara")
UPSTREAM_BRANCH = "upstream/master"             # si le dépôt ne connaît pas upstream/HEAD
YARA_RULES = "/opt/fwtools/src/findcrypt-yara/findcrypt3.rules"
DEEP_SCRIPT = APP_DIR / "wsl" / "deep.py"

# Ghidra (rétro-ingénierie, niveau 2) : téléchargé, pas compilé.
GHIDRA_DIR = "/opt/fwtools/ghidra/current"
GHIDRA_SCRIPT = APP_DIR / "wsl" / "export_ghidra.java"
GHIDRA_URL = ("https://github.com/NationalSecurityAgency/ghidra/releases/download/"
              "Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip")
GHIDRA_MAX_BYTES = 24 << 20     # au-delà, l'analyse serait trop longue

# cpu_rec -> identifiant de langage Ghidra. Plusieurs archi automobiles
# (TriCore…) ne sont pas reconnues par cpu_rec mais le sont par Ghidra : elles
# restent proposées à la main dans l'interface.
ARCH_TO_GHIDRA = {
    "ARMel": "ARM:LE:32:v7", "ARMhf": "ARM:LE:32:v7", "ARMeb": "ARM:BE:32:v7",
    "ARM64": "AARCH64:LE:64:v8A", "MIPSel": "MIPS:LE:32:default", "MIPSeb": "MIPS:BE:32:default",
    "PPCeb": "PowerPC:BE:32:default", "PPCel": "PowerPC:LE:32:default",
    "X86": "x86:LE:32:default", "X86-64": "x86:LE:64:default", "RISC-V": "RISCV:LE:32:default",
    "Xtensa": "Xtensa:LE:32:default", "SuperH": "SuperH4:LE:32:default", "M68k": "68000:BE:32:default",
    "SPARC": "sparc:BE:32:default", "V850": "V850:LE:32:default", "NDS32": "NDS32:LE:32:default",
}
# Liste proposée dans l'interface (choix manuel), avec un libellé lisible.
GHIDRA_LANGS = [
    ("ARM:LE:32:v7", "ARM 32 bits (petit-boutiste)"),
    ("ARM:BE:32:v7", "ARM 32 bits (gros-boutiste)"),
    ("AARCH64:LE:64:v8A", "ARM 64 bits (AArch64)"),
    ("MIPS:LE:32:default", "MIPS 32 bits (petit-boutiste)"),
    ("MIPS:BE:32:default", "MIPS 32 bits (gros-boutiste)"),
    ("PowerPC:BE:32:default", "PowerPC 32 bits"),
    ("tricore:LE:32:default", "Infineon TriCore (automobile)"),
    ("tricore:LE:32:tc176x", "Infineon TriCore TC176x"),
    ("V850:LE:32:default", "Renesas V850 / RH850"),
    ("SuperH4:LE:32:default", "Renesas SuperH"),
    ("Xtensa:LE:32:default", "Xtensa (ESP32…)"),
    ("RISCV:LE:32:default", "RISC-V 32 bits"),
    ("x86:LE:32:default", "x86 32 bits"),
    ("x86:LE:64:default", "x86 64 bits"),
    ("68000:BE:32:default", "Motorola 68000"),
    ("PowerPC:BE:64:VLE-32addr", "PowerPC VLE (e200, automobile)"),
]

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
GIT = shutil.which("git") or r"C:\Program Files\Git\cmd\git.exe"

# Fichiers d'une analyse que l'interface a le droit de servir.
REPORT_FILES = {
    "moria.json": "application/json",
    "mithril-report.json": "application/json",
    "sbom.cdx.json": "application/json",
    "sbom.spdx.json": "application/json",
    "deep.json": "application/json",
    "messages.txt": "text/plain; charset=utf-8",
    "traces.txt": "text/plain; charset=utf-8",
    "entropy.png": "image/png",
    "ghidra.json": "application/json",
}

SESSION_TIMEOUT = 180   # secondes sans nouvelles de la page avant arrêt


# --------------------------------------------------------------------------
# Outils : WSL, chemins, git

class UserError(Exception):
    """Erreur à montrer telle quelle à l'utilisateur (message en français)."""


def to_wsl(path) -> str:
    """C:\\Users\\x -> /mnt/c/Users/x"""
    p = Path(path).resolve()
    if len(p.drive) != 2 or p.drive[1] != ":":
        raise UserError("Ce fichier est sur un lecteur réseau. Copie-le d'abord sur ton PC "
                        "(par exemple dans Téléchargements), puis réessaie.")
    return "/mnt/" + p.drive[0].lower() + p.as_posix()[2:]


def q(s: str) -> str:
    return shlex.quote(s)


def wsl_popen(script: str):
    """Lance un script bash en root dans Ubuntu. Le script passe par l'entrée
    standard : aucun problème de guillemets entre Windows et Linux."""
    proc = subprocess.Popen(
        ["wsl.exe", "-d", DISTRO, "-u", "root", "--exec", "bash", "-s"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        creationflags=NO_WINDOW)
    proc.stdin.write(script.replace("\r\n", "\n").encode("utf-8"))
    proc.stdin.close()
    return proc


def wsl_capture(script: str, timeout=60) -> tuple[int, str]:
    try:
        proc = wsl_popen(script)
        out, _ = proc.communicate(timeout=timeout)
        return proc.returncode, out.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired) as e:
        return -1, str(e)


def git(repo: Path, *args, timeout=120) -> tuple[int, str]:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", LC_ALL="C")
    try:
        r = subprocess.run([GIT, "-C", str(repo), *args], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout,
                           creationflags=NO_WINDOW, env=env)
        return r.returncode, (r.stdout + r.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return -1, str(e)


def upstream_ref(repo: Path) -> str:
    """Branche principale du dépôt officiel (master, main…)."""
    rc, _ = git(repo, "rev-parse", "--verify", "-q", "refs/remotes/upstream/HEAD")
    return "upstream/HEAD" if rc == 0 else UPSTREAM_BRANCH


def repo_state(name: str) -> dict:
    repo = REPOS_DIR / name
    if not (repo / ".git").exists():
        return {"name": name, "present": False}
    _, head = git(repo, "log", "-1", "--format=%h|%cs|%s")
    h, date, subject = (head.split("|", 2) + ["", "", ""])[:3]
    _, dirty = git(repo, "status", "--porcelain")
    rc, behind = git(repo, "rev-list", "--count", f"HEAD..{upstream_ref(repo)}")
    # Seuls moria et mithril ont un fichier VERSION ; sinon on affiche le commit.
    vrc, version = git(repo, "show", "HEAD:VERSION")
    return {
        "name": name, "present": True, "commit": h, "date": date, "subject": subject,
        "version": version.strip() if vrc == 0 else "",
        "modified": bool(dirty.strip()),
        "behind": int(behind) if rc == 0 and behind.isdigit() else None,
    }


# --------------------------------------------------------------------------
# Tâches de fond (analyse, installation, mises à jour)

class Job:
    def __init__(self, kind: str, title: str):
        self.id = uuid.uuid4().hex[:12]
        self.kind, self.title = kind, title
        self.state = "running"          # running | done | error
        self.steps: list[dict] = []
        self.log: list[str] = []
        self.error = None
        self.result = None
        self.started = time.time()

    def step(self, label: str):
        for s in self.steps:
            if s["state"] == "running":
                s["state"] = "done"
        self.steps.append({"label": label, "state": "running"})
        self.say(f"== {label}")

    def say(self, line: str):
        self.log.append(line.rstrip())
        del self.log[:-400]

    def finish(self, result=None):
        for s in self.steps:
            if s["state"] == "running":
                s["state"] = "done"
        self.result, self.state = result, "done"

    def fail(self, message: str):
        for s in self.steps:
            if s["state"] == "running":
                s["state"] = "error"
        self.error, self.state = message, "error"
        self.say("ERREUR : " + message)

    def run(self, script: str) -> int:
        """Exécute un script dans Ubuntu en recopiant sa sortie dans le journal."""
        proc = wsl_popen(script)
        for raw in proc.stdout:
            self.say(raw.decode("utf-8", "replace"))
        return proc.wait()

    def to_dict(self):
        return {"id": self.id, "kind": self.kind, "title": self.title, "state": self.state,
                "steps": self.steps, "log": self.log[-200:], "error": self.error,
                "result": self.result, "elapsed": round(time.time() - self.started)}


JOBS: dict[str, Job] = {}
BUSY = threading.Lock()                 # une seule tâche lourde à la fois
LAST_SEEN = time.time()


def start_job(kind: str, title: str, target, *args) -> Job:
    if not BUSY.acquire(blocking=False):
        raise UserError("Une autre opération est déjà en cours. Attends qu'elle se termine.")
    job = Job(kind, title)
    JOBS[job.id] = job

    def runner():
        try:
            target(job, *args)
            if job.state == "running":
                job.finish(job.result)
        except UserError as e:
            job.fail(str(e))
        except Exception as e:          # garde-fou : l'interface doit toujours savoir
            job.fail(f"Erreur inattendue : {e!r}")
        finally:
            BUSY.release()

    threading.Thread(target=runner, daemon=True).start()
    return job


def job_running() -> bool:
    return any(j.state == "running" for j in JOBS.values())


# --------------------------------------------------------------------------
# État des outils

def tools_status() -> dict:
    # cpu_rec et binbloom n'ont pas d'option --version : on vérifie juste leur présence.
    script = f"""
for t in {' '.join(TOOLS)}; do
  printf '%s=' "$t"
  if ! command -v "$t" >/dev/null; then echo absent
  elif [ "$t" = cpu_rec ] || [ "$t" = binbloom ]; then echo installé
  elif [ "$t" = bulk_extractor ]; then bulk_extractor -V 2>/dev/null | head -1
  else "$t" --version 2>/dev/null | head -1; fi
done
if [ -s {WSL_DB}/osv-index.mdb ]; then printf 'db='; date -r {WSL_DB}/osv-index.mdb +%Y-%m-%d; else echo db=absent; fi
if [ -x {GHIDRA_DIR}/support/analyzeHeadless ]; then echo ghidra=installé; else echo ghidra=absent; fi
if command -v java >/dev/null; then echo java=présent; else echo java=absent; fi
if [ -s {YARA_RULES} ]; then echo rules=présentes; else echo rules=absentes; fi
"""
    rc, out = wsl_capture(script, timeout=90)
    st = {"wsl": rc == 0, "tools": {}, "db": None, "ghidra": False, "java": False,
          "wsl_error": None if rc == 0 else out.strip()[:500]}
    for line in out.splitlines():
        k, _, v = line.partition("=")
        v = v.strip()
        if k in TOOLS:
            st["tools"][k] = None if v in ("", "absent") else v.split()[-1]
        elif k == "db":
            st["db"] = None if v == "absent" else v
        elif k == "ghidra":
            st["ghidra"] = v == "installé"
        elif k == "java":
            st["java"] = v == "présent"
        elif k == "rules":
            st["yara_rules"] = v == "présentes"
    st["ready"] = st["wsl"] and all(st["tools"].get(t) for t in REQUIRED_TOOLS)
    st["deep_ready"] = st["wsl"] and all(st["tools"].get(t) for t in DEEP_TOOLS)
    st["extras_ready"] = (st["wsl"] and all(st["tools"].get(t) for t in EXTRA_TOOLS)
                          and st.get("yara_rules", False))
    st["repos"] = [repo_state(t) for t in REPOS]
    return st


# --------------------------------------------------------------------------
# Analyse d'un firmware

def slug(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-.")
    return (s or "firmware")[:60]


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def write_json(path: Path, data):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def run_deep(job: Job, aid: str, source: Path):
    """Analyse approfondie : carte de la puce, messages, processeur, adresse de chargement, binwalk,
    traces (bulk_extractor), crypto (yara)."""
    out = ANALYSES_DIR / aid
    job.step("Analyse approfondie : carte, messages, processeur, traces, crypto (2 à 5 minutes)")
    rc = job.run(f"python3 {q(to_wsl(DEEP_SCRIPT))} {q(to_wsl(source))} {q(to_wsl(out))} "
                 f"{q(to_wsl(out / 'moria.json'))}\n")
    if rc != 0 or read_json(out / "deep.json") is None:
        raise UserError("L'analyse approfondie n'a pas abouti. Le reste du rapport reste disponible ; "
                        "les détails techniques sont affichés plus bas.")


def do_deep_only(job: Job, aid: str):
    d = analysis_dir(aid)
    meta = read_json(d / "meta.json") or {}
    source = Path(meta.get("source", ""))
    if not source.is_file():
        raise UserError(f"Le fichier d'origine est introuvable ({source}). Remets-le à cet endroit, "
                        "ou relance une analyse complète depuis l'accueil.")
    job.result = {"analysis": aid}
    run_deep(job, aid, source)
    job.finish({"analysis": aid})


def do_ghidra(job: Job, aid: str, start: int, end: int, lang: str, base: str):
    """Rétro-ingénierie d'un segment avec Ghidra : fonctions, liens message->code, pseudo-code."""
    d = analysis_dir(aid)
    meta = read_json(d / "meta.json") or {}
    source = Path(meta.get("source", ""))
    if not source.is_file():
        raise UserError(f"Le fichier d'origine est introuvable ({source}). Remets-le à cet endroit.")
    if not re.fullmatch(r"[A-Za-z0-9:_./-]{3,60}", lang or ""):
        raise UserError("Processeur invalide.")
    if not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", base or ""):
        raise UserError("Adresse de chargement invalide (attendu : 0x...).")
    size = source.stat().st_size
    start = max(0, min(start, size))
    end = max(start + 0x1000, min(end or size, size))
    if end - start > GHIDRA_MAX_BYTES:
        raise UserError(f"La zone choisie fait {(end - start) >> 20} Mo. Choisis un segment de "
                        f"{GHIDRA_MAX_BYTES >> 20} Mo au maximum : l'analyse serait trop longue.")
    if not tools_status().get("ghidra"):
        raise UserError("Ghidra n'est pas installé. Va dans « Outils » et clique sur « Installer Ghidra ».")

    job.result = {"analysis": aid}
    wsrc, wout = to_wsl(source), to_wsl(d)
    wdir = f"{WSL_WORK}/{aid}/ghidra"
    mb = (end - start) / (1 << 20)
    job.step(f"Rétro-ingénierie avec Ghidra ({mb:.1f} Mo — compte plusieurs minutes)")
    job.say(f"Segment {hex(start)}–{hex(end)}, processeur {lang}, chargé à {base}.")
    # Timeout d'analyse proportionnel à la taille (au moins 10 min, au plus 45).
    timeout = int(min(2700, max(600, mb * 150)))
    script = f"""set -e
export _JAVA_OPTIONS="-Xmx6G"
rm -rf {q(wdir)}; mkdir -p {q(wdir)}/proj
python3 - "{wsrc}" "{wdir}/slice.bin" {start} {end} <<'PY'
import sys
src, dst, a, b = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
with open(src, "rb") as f:
    f.seek(a); data = f.read(b - a)
open(dst, "wb").write(data)
print("segment %d octets" % len(data))
PY
{GHIDRA_DIR}/support/analyzeHeadless {q(wdir)}/proj gh \\
  -import {q(wdir)}/slice.bin \\
  -processor {q(lang)} \\
  -loader BinaryLoader -loader-baseAddr {q(base)} \\
  -scriptPath {q(to_wsl(GHIDRA_SCRIPT.parent))} \\
  -postScript export_ghidra.java {q(wout + '/ghidra.json')} \\
  -deleteProject -analysisTimeoutPerFile {timeout} 2>&1 | grep -viE '^(WARNING|Picked up|INFO  (REPORT|SCRIPT|ANALYZING|/slice)|    )' | tail -40
rm -rf {q(wdir)}
"""
    rc = job.run(script)
    result = read_json(d / "ghidra.json")
    if rc != 0 or result is None:
        raise UserError("La rétro-ingénierie n'a pas abouti. Vérifie le processeur choisi : s'il ne correspond "
                        "pas au code, Ghidra ne trouve rien. Les détails techniques sont ci-dessous.")
    meta.setdefault("ghidra", {})
    meta["ghidra"] = {"start": start, "end": end, "lang": lang, "base": base,
                      "functions": result.get("function_count"), "links": len(result.get("message_links", [])),
                      "date": datetime.datetime.now().isoformat(timespec="seconds")}
    write_json(d / "meta.json", meta)
    job.finish({"analysis": aid})


def do_analyze(job: Job, source: Path, broad: bool, deep: bool):
    if not source.is_file():
        raise UserError("Le fichier choisi n'existe plus ou n'est pas lisible.")
    job.step("Vérification des outils")
    status = tools_status()
    if not status["ready"]:
        raise UserError("Les outils ne sont pas installés. Va dans « Outils » et clique sur « Installer ».")

    stamp = datetime.datetime.now()
    aid = f"{stamp:%Y%m%d-%H%M%S}-{slug(source.stem)}"
    out = ANALYSES_DIR / aid
    out.mkdir(parents=True, exist_ok=True)
    meta = {"id": aid, "name": source.name, "source": str(source), "size": source.stat().st_size,
            "date": stamp.isoformat(timespec="seconds"), "state": "running", "broad": broad, "deep": deep,
            "cve_db": status["db"], "versions": status["tools"]}
    write_json(out / "meta.json", meta)
    job.result = {"analysis": aid}

    wsrc, wout = to_wsl(source), to_wsl(out)
    wdir = f"{WSL_WORK}/{aid}"
    wext = f"{wdir}/extrait"

    job.step("Moria ouvre le firmware et en extrait le contenu")
    rc = job.run(f"set -o pipefail\nmkdir -p {q(wdir)}\n"
                 f"moria -j -e{' --broad' if broad else ''} -C {q(wext)} {q(wsrc)} > {q(wout + '/moria.json')}\n")
    moria = read_json(out / "moria.json")
    if rc != 0 or moria is None:
        meta["state"] = "error"
        write_json(out / "meta.json", meta)
        raise UserError("Moria n'a pas réussi à lire ce fichier. Vérifie qu'il s'agit bien d'un "
                        "firmware (fichier .bin, .img, .trx…) et que le fichier n'est pas ouvert ailleurs.")
    extracted = [e for e in (moria.get("extraction") or {}).get("extracted", [])
                 if e.get("status") == "ok"]
    job.say(f"{len(moria.get('findings', []))} élément(s) reconnu(s), {len(extracted)} extrait(s)")

    job.step("Mithril inspecte le contenu (secrets, logiciels, failles…)")
    # Sans extraction exploitable, mithril lit directement le fichier d'origine.
    target = wext if extracted else wsrc
    passes = "" if status["db"] else "--secrets --sbom --licenses --boot --keys"
    if not status["db"]:
        job.say("Base de failles absente : recherche de CVE ignorée.")
    rc = job.run(f"mithril -j -C {q(wout)} {passes} {q(target)} > /dev/null\n")
    report = read_json(out / "mithril-report.json")
    if report is None:
        meta["state"] = "error"
        write_json(out / "meta.json", meta)
        raise UserError(f"Mithril n'a pas pu terminer l'analyse (code {rc}). "
                        "Les détails techniques sont affichés plus bas.")

    meta.update(state="done", extracted=bool(extracted), wsl_extract=wext if extracted else None,
                summary=report.get("summary"), finished=datetime.datetime.now().isoformat(timespec="seconds"))
    write_json(out / "meta.json", meta)

    # Facultative : un échec ici ne doit pas faire perdre le rapport déjà prêt.
    if deep and status.get("deep_ready"):
        try:
            run_deep(job, aid, source)
        except UserError as e:
            job.say(str(e))
            for s in job.steps:
                if s["state"] == "running":
                    s["state"] = "error"
    elif deep:
        job.say("Outils d'analyse approfondie absents : étape ignorée (voir « Outils »).")

    job.step("Préparation du rapport")
    job.finish({"analysis": aid})


def list_analyses() -> list[dict]:
    items = []
    if ANALYSES_DIR.is_dir():
        for d in ANALYSES_DIR.iterdir():
            meta = read_json(d / "meta.json")
            if meta:
                items.append(meta)
    items.sort(key=lambda m: m.get("date", ""), reverse=True)
    return items


def analysis_dir(aid: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", aid or ""):
        raise UserError("Analyse inconnue.")
    d = ANALYSES_DIR / aid
    if not (d / "meta.json").is_file():
        raise UserError("Cette analyse n'existe plus.")
    return d


def delete_analysis(aid: str):
    d = analysis_dir(aid)
    wsl_capture(f"rm -rf {q(WSL_WORK + '/' + aid)}", timeout=300)
    shutil.rmtree(d, ignore_errors=True)


# --------------------------------------------------------------------------
# Installation et mises à jour

BUILD_SCRIPT = APP_DIR / "wsl" / "build.sh"


def do_setup(job: Job):
    job.step("Installation des outils de compilation dans Ubuntu (quelques minutes)")
    build = f"bash {q(to_wsl(BUILD_SCRIPT))} {q(to_wsl(REPOS_DIR))}"
    if job.run(build + " --deps\n") != 0:
        raise UserError("La compilation a échoué. Copie les détails techniques et demande de l'aide.")
    job.step("Téléchargement de la base des failles connues")
    if job.run("mithril --fetch-db 2>&1\n") != 0:
        raise UserError("Le téléchargement de la base de failles a échoué. Vérifie ta connexion Internet.")


def do_setup_ghidra(job: Job):
    job.step("Installation de Java (nécessaire à Ghidra)")
    if job.run("export DEBIAN_FRONTEND=noninteractive\napt-get update -qq\n"
               "apt-get install -y -qq openjdk-21-jdk-headless unzip curl 2>&1 | tail -3\n") != 0:
        raise UserError("L'installation de Java a échoué. Vérifie ta connexion Internet.")
    job.step("Téléchargement de Ghidra (570 Mo — plusieurs minutes)")
    script = f"""set -e
mkdir -p /opt/fwtools/ghidra
cd /opt/fwtools/ghidra
curl -# -SL -o ghidra.zip {q(GHIDRA_URL)} 2>&1 | tail -1
echo "téléchargé : $(wc -c <ghidra.zip) octets"
rm -rf ghidra_*_PUBLIC
unzip -q ghidra.zip
rm ghidra.zip
D=$(ls -d /opt/fwtools/ghidra/ghidra_*_PUBLIC)
ln -sfn "$D" /opt/fwtools/ghidra/current
echo "installé dans $D"
"""
    job.step("Installation de Ghidra")
    if job.run(script) != 0 or not tools_status().get("ghidra"):
        raise UserError("L'installation de Ghidra a échoué. Vérifie ta connexion Internet et l'espace disque "
                        "(il faut environ 2 Go).")


def do_update_db(job: Job):
    job.step("Téléchargement de la base des failles connues")
    if job.run("mithril --fetch-db 2>&1\n") != 0:
        raise UserError("Le téléchargement a échoué. Vérifie ta connexion Internet et réessaie.")


def do_update_tools(job: Job):
    changed = []
    for name in REPOS:
        repo = REPOS_DIR / name
        if not (repo / ".git").exists():
            continue
        job.step(f"Récupération des nouveautés de {name}")
        rc, out = git(repo, "fetch", "upstream")
        job.say(out)
        if rc != 0:
            raise UserError(f"Impossible de contacter le dépôt officiel de {name}. "
                            "Vérifie ta connexion Internet.")
        rc, dirty = git(repo, "status", "--porcelain")
        if dirty.strip():
            raise UserError(f"Des fichiers ont été modifiés à la main dans {name}. "
                            "Par sécurité, rien n'a été touché. Demande de l'aide avant de continuer.")
        ref = upstream_ref(repo)
        _, behind = git(repo, "rev-list", "--count", f"HEAD..{ref}")
        if behind.strip() == "0":
            job.say(f"{name} est déjà à jour.")
            continue
        rc, out = git(repo, "merge", "--ff-only", ref)
        job.say(out)
        if rc != 0:
            raise UserError(f"{name} contient des changements qui ne viennent pas du dépôt officiel : "
                            "la mise à jour automatique n'est pas possible sans risque.")
        changed.append(name)
        job.say(f"{name} : {behind.strip()} nouveauté(s) récupérée(s).")

    if changed:
        job.step(f"Recompilation de {', '.join(changed)}")
        if job.run(f"bash {q(to_wsl(BUILD_SCRIPT))} {q(to_wsl(REPOS_DIR))} {' '.join(changed)}\n") != 0:
            raise UserError("La recompilation a échoué. L'ancienne version reste utilisable. "
                            "Copie les détails techniques et demande de l'aide.")
    job.finish({"updated": changed})


def check_updates() -> list[dict]:
    for name in REPOS:
        git(REPOS_DIR / name, "fetch", "upstream")
    return [repo_state(t) for t in REPOS]


# --------------------------------------------------------------------------
# Fenêtres Windows (sélecteur de fichier, explorateur)

PICKER = r"""
import sys, tkinter as tk
from tkinter import filedialog
root = tk.Tk(); root.withdraw(); root.attributes('-topmost', True)
p = filedialog.askopenfilename(parent=root, title='Choisis le firmware à analyser',
    filetypes=[('Firmwares et images', '*.bin *.img *.trx *.chk *.fw *.rom *.hex *.zip *.tar *.gz *.xz *.ubi *.squashfs'),
               ('Tous les fichiers', '*.*')])
sys.stdout.write(p or '')
"""


def pick_file() -> str:
    exe = Path(sys.executable)
    python = exe.with_name("python.exe") if exe.name.lower() == "pythonw.exe" else exe
    r = subprocess.run([str(python), "-c", PICKER], capture_output=True, text=True,
                       encoding="utf-8", creationflags=NO_WINDOW)
    return str(Path(r.stdout.strip())) if r.stdout.strip() else ""


def open_in_explorer(path: str):
    subprocess.Popen(["explorer.exe", path], creationflags=NO_WINDOW)


# --------------------------------------------------------------------------
# Serveur HTTP

STATIC_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
                ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml",
                ".ico": "image/x-icon", ".png": "image/png"}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "AtelierFirmware"

    def log_message(self, fmt, *args):     # silencieux
        pass

    # -- réponses

    def send_json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path: Path, ctype: str, download_name=None):
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if download_name:
            self.send_header("Content-Disposition",
                             f"attachment; filename*=UTF-8''{urllib.parse.quote(download_name)}")
        self.end_headers()
        self.wfile.write(data)

    def read_body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except ValueError:
            raise UserError("Requête illisible.")

    # -- sécurité : uniquement depuis la page de l'Atelier

    def allowed(self, write: bool) -> bool:
        host = self.headers.get("Host", "")
        if host not in (f"{HOST}:{PORT}", f"localhost:{PORT}"):
            return False
        # Une autre page web ne peut pas ajouter cet en-tête sans autorisation.
        return not write or self.headers.get("X-Atelier") == "1"

    def dispatch(self, method: str):
        global LAST_SEEN
        LAST_SEEN = time.time()
        if not self.allowed(method != "GET"):
            self.send_json({"error": "Accès refusé."}, 403)
            return
        url = urllib.parse.urlsplit(self.path)
        parts = [urllib.parse.unquote(p) for p in url.path.strip("/").split("/") if p]
        try:
            if parts[:1] == ["api"]:
                self.api(method, parts[1:], urllib.parse.parse_qs(url.query))
            elif method == "GET":
                self.static(parts)
            else:
                self.send_json({"error": "Introuvable."}, 404)
        except UserError as e:
            self.send_json({"error": str(e)}, 400)
        except (ConnectionError, BrokenPipeError):
            pass
        except Exception as e:
            self.send_json({"error": f"Erreur inattendue : {e!r}"}, 500)

    def do_GET(self): self.dispatch("GET")
    def do_POST(self): self.dispatch("POST")
    def do_PUT(self): self.dispatch("PUT")
    def do_DELETE(self): self.dispatch("DELETE")

    def static(self, parts):
        rel = "/".join(parts) or "index.html"
        path = (WEB_DIR / rel).resolve()
        if WEB_DIR not in path.parents or not path.is_file():
            path = WEB_DIR / "index.html"
        self.send_file(path, STATIC_TYPES.get(path.suffix, "application/octet-stream"))

    # -- API

    def api(self, method, p, query):
        route = (method, p[0] if p else "")

        if route == ("GET", "status"):
            self.send_json(tools_status())
        elif route == ("POST", "ping"):
            self.send_json({"ok": True})
        elif route == ("GET", "jobs") and len(p) == 2:
            job = JOBS.get(p[1])
            self.send_json(job.to_dict() if job else {"error": "Tâche inconnue."}, 200 if job else 404)
        elif route == ("GET", "analyses") and len(p) == 1:
            self.send_json(list_analyses())
        elif route == ("GET", "analyses") and len(p) == 2:
            d = analysis_dir(p[1])
            self.send_json({"meta": read_json(d / "meta.json"), "moria": read_json(d / "moria.json"),
                            "mithril": read_json(d / "mithril-report.json"), "deep": read_json(d / "deep.json"),
                            "ghidra": read_json(d / "ghidra.json")})
        elif route == ("GET", "analyses") and len(p) == 4 and p[2] == "file":
            d, name = analysis_dir(p[1]), p[3]
            if name not in REPORT_FILES or not (d / name).is_file():
                raise UserError("Fichier indisponible.")
            # ?dl=1 : téléchargement ; sinon affichage dans la page (image du graphique).
            self.send_file(d / name, REPORT_FILES[name], f"{p[1]}-{name}" if query.get("dl") else None)
        elif route == ("POST", "analyses") and len(p) == 3 and p[2] == "deep":
            analysis_dir(p[1])
            job = start_job("deep", "Analyse approfondie", do_deep_only, p[1])
            self.send_json(job.to_dict())
        elif route == ("POST", "analyses") and len(p) == 3 and p[2] == "ghidra":
            analysis_dir(p[1])
            body = self.read_body()
            job = start_job("ghidra", "Rétro-ingénierie (Ghidra)", do_ghidra, p[1],
                            int(body.get("start", 0)), int(body.get("end", 0)),
                            str(body.get("lang", "")), str(body.get("base", "0x0")))
            self.send_json(job.to_dict())
        elif route == ("DELETE", "analyses") and len(p) == 2:
            delete_analysis(p[1])
            self.send_json({"ok": True})
        elif route == ("POST", "pick"):
            self.send_json({"path": pick_file()})
        elif route == ("PUT", "upload"):
            self.send_json({"path": str(self.receive_upload(query))})
        elif route == ("POST", "analyze"):
            body = self.read_body()
            src = Path(str(body.get("path", "")).strip().strip('"'))
            if not str(src) or not src.is_file():
                raise UserError("Ce fichier est introuvable. Vérifie le chemin ou choisis-le à nouveau.")
            job = start_job("analyze", f"Analyse de {src.name}", do_analyze, src,
                            bool(body.get("broad")), body.get("deep", True) is not False)
            self.send_json(job.to_dict())
        elif route == ("POST", "open"):
            body = self.read_body()
            d = analysis_dir(body.get("id", ""))
            if body.get("what") == "extract":
                meta = read_json(d / "meta.json") or {}
                if not meta.get("wsl_extract"):
                    raise UserError("Aucun fichier n'a été extrait pour cette analyse.")
                open_in_explorer(r"\\wsl.localhost" + "\\" + DISTRO + meta["wsl_extract"].replace("/", "\\"))
            else:
                open_in_explorer(str(d))
            self.send_json({"ok": True})
        elif route == ("POST", "setup"):
            self.send_json(start_job("setup", "Installation des outils", do_setup).to_dict())
        elif route == ("POST", "setup-ghidra"):
            self.send_json(start_job("setup-ghidra", "Installation de Ghidra", do_setup_ghidra).to_dict())
        elif route == ("GET", "ghidra-langs"):
            self.send_json({"langs": GHIDRA_LANGS, "arch_map": ARCH_TO_GHIDRA})
        elif route == ("POST", "update-db"):
            self.send_json(start_job("update-db", "Mise à jour de la base de failles", do_update_db).to_dict())
        elif route == ("POST", "update-tools"):
            self.send_json(start_job("update-tools", "Mise à jour des outils", do_update_tools).to_dict())
        elif route == ("POST", "check-updates"):
            self.send_json(check_updates())
        elif route == ("POST", "quit"):
            self.send_json({"ok": True})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        else:
            self.send_json({"error": "Introuvable."}, 404)

    def receive_upload(self, query) -> Path:
        name = Path((query.get("name") or ["firmware.bin"])[0]).name
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            raise UserError("Le fichier déposé est vide.")
        UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
        dest = UPLOADS_DIR / slug(name)
        if dest.exists():
            dest = dest.with_name(f"{dest.stem}-{uuid.uuid4().hex[:6]}{dest.suffix}")
        with open(dest, "wb") as f:
            left = length
            while left:
                chunk = self.rfile.read(min(left, 1 << 20))
                if not chunk:
                    break
                f.write(chunk)
                left -= len(chunk)
        if left:
            dest.unlink(missing_ok=True)
            raise UserError("Le dépôt du fichier a été interrompu. Réessaie.")
        return dest


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = False


def watchdog(server):
    """Arrête le serveur quand la page est fermée depuis un moment."""
    while True:
        time.sleep(15)
        if not job_running() and time.time() - LAST_SEEN > SESSION_TIMEOUT:
            server.shutdown()
            return


def already_running() -> bool:
    try:
        with urllib.request.urlopen(f"http://{HOST}:{PORT}/api/ping", timeout=2):
            return True
    except Exception as e:
        # /api/ping n'accepte que POST : une réponse 404/405 prouve qu'un serveur répond.
        return getattr(e, "code", None) is not None


def main():
    url = f"http://{HOST}:{PORT}/"
    if sys.stdout is None:                  # lancé avec pythonw : pas de console
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        sys.stdout = sys.stderr = open(DATA_DIR / "atelier.log", "a", encoding="utf-8")
    if already_running():
        webbrowser.open(url)
        return
    ANALYSES_DIR.mkdir(parents=True, exist_ok=True)
    server = Server((HOST, PORT), Handler)
    threading.Thread(target=watchdog, args=(server,), daemon=True).start()
    print(f"Atelier Firmware : {url}", flush=True)
    if "--no-browser" not in sys.argv:
        webbrowser.open(url)
    server.serve_forever()


if __name__ == "__main__":
    main()
