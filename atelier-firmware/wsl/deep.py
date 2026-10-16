#!/usr/bin/env python3
"""Analyse approfondie d'un firmware brut (lancée dans Ubuntu par l'Atelier).

    deep.py <fichier> <dossier-de-sortie> [moria.json]

Écrit dans le dossier de sortie :
  deep.json      résultats structurés lus par l'interface
  messages.txt   tous les textes lisibles trouvés, avec leur position
  entropy.png    graphique d'entropie de binwalk (si disponible)

Outils externes utilisés s'ils sont installés : cpu_rec, binbloom, binwalk.
Chaque étape est indépendante : si un outil manque ou échoue, les autres
résultats sont quand même produits.
"""

import collections
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

CPU_REC_DIR = "/opt/fwtools/src/cpu_rec"
MAX_CPU_SAMPLES = 72          # ~0,4 s par échantillon
CPU_WINDOW = 0x10000
BINBLOOM_TIMEOUT = 180
BINBLOOM_MAX = 16 << 20       # binbloom devient très lent au-delà
MAX_MESSAGES = 4000


def say(msg):
    print(msg, flush=True)


# --------------------------------------------------------------------------
# 1. Carte de la puce : entropie bloc par bloc

def entropy(buf):
    if not buf:
        return 0.0
    n = len(buf)
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(buf).values())


def classify(buf):
    if buf.count(0xFF) == len(buf):
        return "empty"
    if buf.count(0) == len(buf):
        return "zero"
    e = entropy(buf)
    if e > 7.5:
        return "random"       # chiffré ou compressé
    if e > 4.0:
        return "code"         # code ou données
    return "sparse"           # tables, textes, données peu variées


def flash_map(data):
    size = len(data)
    # Au plus ~1024 blocs, jamais moins de 4 Ko.
    block = max(0x1000, 1 << max(12, math.ceil(math.log2(max(size, 1) / 1024))))
    blocks = []
    for off in range(0, size, block):
        b = data[off:off + block]
        blocks.append({"k": classify(b), "e": round(entropy(b), 2)})
    zones = []
    for i, b in enumerate(blocks):
        if zones and zones[-1]["kind"] == b["k"]:
            zones[-1]["end"] = min((i + 1) * block, size)
            zones[-1]["_e"].append(b["e"])
        else:
            zones.append({"start": i * block, "end": min((i + 1) * block, size), "kind": b["k"], "_e": [b["e"]]})
    for z in zones:
        z["entropy"] = round(sum(z.pop("_e")) / max(1, (z["end"] - z["start"] + block - 1) // block), 2)
    totals = collections.Counter()
    for z in zones:
        totals[z["kind"]] += z["end"] - z["start"]
    # Segments : parties non vides séparées par du vide (0xFF ou zéros).
    segments = []
    for i, b in enumerate(blocks):
        filled = b["k"] not in ("empty", "zero")
        if filled and segments and segments[-1]["end"] == i * block:
            segments[-1]["end"] = min((i + 1) * block, size)
        elif filled:
            segments.append({"start": i * block, "end": min((i + 1) * block, size)})
    return {"block": block, "blocks": [b["k"] for b in blocks], "zones": zones,
            "totals": dict(totals), "segments": segments}


# --------------------------------------------------------------------------
# 2. Catalogue des messages

STRING_RE = re.compile(rb"[\x20-\x7e\t]{6,}")
FMT_RE = re.compile(r"%[-+ 0#]*(\d+|\*)?(\.\d+)?(hh|h|ll|l|z|j|t)?[diouxXsScpfegEG]")
CATEGORIES = [
    ("error", re.compile(r"\berr(or)?\b|fail|fault|panic|abort|assert|invalid|timeout|time-out|exception|"
                         r"corrupt|denied|unable|cannot|can't|not found|overflow|illegal|mismatch|crc", re.I)),
    ("version", re.compile(r"version|\bv\d+\.\d+|\bbuild\b|release|\b(19|20)\d\d[-/.](0[1-9]|1[0-2])[-/.]\d\d|"
                           r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ \d]\d (19|20)\d\d", re.I)),
    ("source", re.compile(r"[\w/\\.-]+\.(c|cc|cpp|h|hpp|s|S)\b")),
]
VENDORS = {
    "Volkswagen / Audi / Skoda / Seat / Porsche": r"\bVW\b|Volkswagen|\bAudi\b|Skoda|\bSeat\b|Porsche|\bVAG\b|\bMQB\b|\bMLB\b|\bMEB\b",
    "Bosch": r"\bBosch\b|\bRBOS\b",
    "Continental": r"Continental|\bConti\b",
    "ZF / TRW": r"\bZF\b|\bTRW\b",
    "Mobileye": r"Mobileye|EyeQ",
    "Valeo": r"Valeo",
    "Aptiv / Delphi": r"Aptiv|Delphi",
    "Hella": r"\bHella\b",
    "Denso": r"Denso",
    "Magna": r"\bMagna\b",
    "Harman": r"Harman",
    "Infineon": r"Infineon|Aurix|TriCore|\bTC3\d\d|\bTC2\d\d",
    "Renesas": r"Renesas|RH850|R-Car|\bRL78\b",
    "NXP / Freescale": r"\bNXP\b|Freescale|\bS32[GKV]\b|\bMPC5\d\d\d|i\.MX",
    "Texas Instruments": r"Texas Instruments|\bTDA[234]\w*|Jacinto|\bTMS570|\bTMS320",
    "STMicroelectronics": r"STMicro|\bSTM32|\bSPC5\d",
    "Qualcomm": r"Qualcomm|Snapdragon|\bQCOM\b",
    "MediaTek": r"MediaTek|\bMTK\b",
    "Broadcom": r"Broadcom|\bBCM\d{4}",
    "Realtek": r"Realtek",
    "Xilinx / AMD": r"Xilinx|Zynq|MicroBlaze",
    "Vector": r"\bVector\b|MICROSAR",
    "Elektrobit": r"Elektrobit|\bEB tresos",
    "ETAS": r"\bETAS\b|RTA-OS",
}
SYSTEMS = {
    "Linux": r"Linux version|\bvmlinux\b|/proc/|/sys/|busybox",
    "U-Boot": r"U-Boot|\bbootcmd\b|\bbootargs\b",
    "Android": r"\bAndroid\b|\bfastboot\b|\babootimg\b",
    "AUTOSAR": r"AUTOSAR|\bDet_|\bDem_|\bDcm_|\bCanIf_|\bPduR_|\bComM_|\bEcuM_|\bBswM_|\bNvM_|Det Error",
    "OSEK": r"\bOSEK\b|ErrorHook|Errorhook|ActivateTask|TerminateTask",
    "FreeRTOS": r"FreeRTOS|xTaskCreate|vTaskDelay",
    "ThreadX": r"ThreadX|\btx_thread",
    "QNX": r"\bQNX\b|procnto",
    "VxWorks": r"VxWorks|\btaskSpawn\b",
    "INTEGRITY": r"INTEGRITY|Green Hills",
    "Zephyr": r"\bZephyr\b|\bk_thread",
    "µC/OS": r"uC/OS|\bOSTaskCreate",
    "NuttX": r"\bNuttX\b",
    "eCos": r"\beCos\b",
}
# Préfixe de module : « LAD_EXPOSURE_… », « VAL SensorFusi: », « Swid Update: », « daddy crc … »
MODULE_RE = re.compile(r"^\s*\[?([A-Za-z][A-Za-z0-9]{1,15})(?:[_ :\]\-]|$)")
MODULE_STOP = {"the", "The", "not", "Not", "and", "for", "with", "from", "this", "This", "Error", "error",
               "ERROR", "Warning", "WARNING", "Info", "INFO", "Unknown", "Invalid", "Failed", "failed",
               "Could", "could", "Can", "can", "Cannot", "Unable", "No", "no", "is", "in", "of", "to", "on"}


def looks_like_text(s):
    letters = sum(ch.isalpha() for ch in s)
    if letters < 4 or letters / len(s) < 0.45:
        return False
    if not re.search(r"[A-Za-z]{3}", s):
        return False
    # Trop de symboles collés : probablement des données
    return len(re.findall(r"[^\w\s%.,:;!?'\"()\[\]/\\=<>+\-#@&*]", s)) / len(s) < 0.15


def catalog(data):
    all_strings = []
    for m in STRING_RE.finditer(data):
        s = m.group().decode("ascii").strip()
        if len(s) >= 6 and looks_like_text(s):
            all_strings.append((m.start(), s))

    messages = []
    counts = collections.Counter()
    modules = collections.defaultdict(list)
    for off, s in all_strings:
        cat = next((c for c, rx in CATEGORIES if rx.search(s)), None)
        if cat is None and FMT_RE.search(s):
            cat = "log"
        if cat is None:
            continue
        # Anti-bruit : une vraie phrase a un espace, ou est un jeton bien formé
        # (LAD_EXPOSURE_…). On écarte « aP%odnFn », « 2#n%ifj »…
        if " " not in s and not re.fullmatch(r"[A-Za-z0-9_.:/-]{6,}", s):
            continue
        counts[cat] += 1
        messages.append({"o": off, "c": cat, "t": s[:300]})
        m = MODULE_RE.match(s)
        if m and m.group(1) not in MODULE_STOP:
            modules[m.group(1)].append(s[:200])

    # « LAD » et « lad » : même module. On garde l'écriture la plus fréquente.
    merged = collections.defaultdict(list)
    spelling = collections.defaultdict(collections.Counter)
    for k, v in modules.items():
        merged[k.lower()] += v
        spelling[k.lower()][k] += len(v)
    mods = [{"name": spelling[k].most_common(1)[0][0], "count": len(v), "examples": list(dict.fromkeys(v))[:10]}
            for k, v in merged.items() if len(v) >= 3]
    mods.sort(key=lambda x: -x["count"])

    text = "\n".join(s for _, s in all_strings)
    def hits(table):
        out = []
        for name, rx in table.items():
            found = re.findall(rf"[^\n]{{0,60}}(?:{rx})[^\n]{{0,60}}", text)
            # Une vraie mention est dans une phrase (avec des espaces), pas dans des octets au hasard.
            found = [f for f in found if " " in f.strip()]
            if found:
                out.append({"name": name, "count": len(found), "examples": list(dict.fromkeys(f.strip() for f in found))[:5]})
        out.sort(key=lambda x: -x["count"])
        return out

    return all_strings, {
        "total_strings": len(all_strings),
        "counts": dict(counts),
        "modules": mods[:60],
        "messages": messages[:MAX_MESSAGES],
        "truncated": len(messages) > MAX_MESSAGES,
        "vendors": hits(VENDORS),
        "systems": hits(SYSTEMS),
    }


# --------------------------------------------------------------------------
# 3. Processeur (cpu_rec, sur des échantillons)

# Endianness et taille de mot pour binbloom, selon l'architecture reconnue.
ARCH_INFO = {
    "ARMel": ("le", 32), "ARMhf": ("le", 32), "ARMeb": ("be", 32), "ARM64": ("le", 64),
    "MIPSel": ("le", 32), "MIPSeb": ("be", 32), "MIPS16": (None, 32),
    "PPCel": ("le", 32), "PPCeb": ("be", 32), "X86": ("le", 32), "X86-64": ("le", 64),
    "RISC-V": ("le", 32), "Xtensa": ("le", 32), "SuperH": (None, 32), "M68k": ("be", 32),
    "SPARC": ("be", 32), "V850": ("le", 32), "RX": ("le", 32), "NIOS-II": ("le", 32),
    "MicroBlaze": (None, 32), "ARcompact": ("le", 32), "ARC32el": ("le", 32), "ARC32eb": ("be", 32),
    "Blackfin": ("le", 32), "TMS320C6x": ("le", 32), "NDS32": ("le", 32), "MCore": ("be", 32),
}
ARCH_LABEL = {
    "ARMel": "ARM (32 bits)", "ARMhf": "ARM Thumb-2 (32 bits)", "ARMeb": "ARM gros-boutiste (32 bits)",
    "ARM64": "ARM 64 bits (AArch64)", "MIPSel": "MIPS petit-boutiste", "MIPSeb": "MIPS gros-boutiste",
    "PPCeb": "PowerPC", "PPCel": "PowerPC petit-boutiste", "X86": "x86 (32 bits)", "X86-64": "x86-64",
    "V850": "Renesas V850 / RH850", "RX": "Renesas RX", "SuperH": "Renesas SuperH", "Xtensa": "Xtensa (ESP32…)",
    "RISC-V": "RISC-V", "TMS320C6x": "DSP TI C6000", "TMS320C2x": "DSP TI C2000", "Blackfin": "DSP Blackfin",
}


# Architectures du corpus de cpu_rec qu'on ne rencontre pas dans un firmware
# embarqué : cpu_rec les « reconnaît » souvent à tort dans des zones de données.
IMPLAUSIBLE = {"IA-64", "VAX", "Alpha", "Cray", "MMIX", "OCaml", "PDP-11", "HP-Focus", "HP-PA", "CLIPPER",
               "WE32000", "S-390", "i860", "TILEPro", "CUDA", "WASM", "Cell-SPU", "Epiphany", "ROMP",
               "Visium", "#6502#cc65", "M88k", "IQ2000", "FT32", "Moxie", "Stormy16", "TriMedia", "Mico32"}


def segment_verdict(votes, n):
    """Architecture retenue pour une zone, ou None si les échantillons ne sont pas assez nets."""
    plausible = collections.Counter({a: c for a, c in votes.items() if a not in IMPLAUSIBLE})
    if not plausible:
        return None
    ranked = plausible.most_common(2)
    best, bn = ranked[0]
    second = ranked[1][1] if len(ranked) > 1 else 0
    if n == 1:
        return best
    return best if bn >= 2 and bn * 4 >= n and bn >= 2 * second else None


def cpu_scan(data, fmap):
    sys.path.insert(0, CPU_REC_DIR)
    try:
        from cpu_rec import which_arch
    except Exception as e:           # outil absent
        return {"available": False, "error": str(e)}
    t0 = time.time()
    which_arch()                      # prépare le corpus
    block = fmap["block"]
    candidates = [i * block for i, k in enumerate(fmap["blocks"]) if k in ("code", "sparse")]
    step = max(1, len(candidates) // MAX_CPU_SAMPLES)
    samples = []
    for off in candidates[::step][:MAX_CPU_SAMPLES]:
        arch = which_arch(data[off:off + CPU_WINDOW])
        samples.append({"o": off, "arch": arch})
    say(f"   {len(samples)} échantillons analysés en {time.time() - t0:.0f} s")

    segs = []
    for s in fmap["segments"]:
        votes = collections.Counter(x["arch"] for x in samples if s["start"] <= x["o"] < s["end"] and x["arch"])
        n = sum(1 for x in samples if s["start"] <= x["o"] < s["end"])
        segs.append({**s, "samples": n, "votes": dict(votes), "arch": segment_verdict(votes, n)})
    overall = collections.Counter()
    for s in segs:
        if s["arch"]:
            overall[s["arch"]] += s["end"] - s["start"]
    main_arch = overall.most_common(1)[0][0] if overall else None
    noise = sum(1 for x in samples if x["arch"] in IMPLAUSIBLE)
    unknown = sum(1 for x in samples if not x["arch"])
    return {"available": True, "samples": samples, "segments": segs, "main": main_arch,
            "noise": noise, "unknown": unknown, "implausible": sorted(IMPLAUSIBLE),
            "labels": {k: ARCH_LABEL.get(k, k) for k in set(overall) | set(x["arch"] for x in samples if x["arch"])}}


# --------------------------------------------------------------------------
# 4. Adresse de chargement (binbloom)

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def run_binbloom(args, timeout):
    try:
        r = subprocess.run(["binbloom", *args], capture_output=True, text=True, timeout=timeout,
                           errors="replace")
        out = r.stdout + r.stderr
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        out += "\n[timeout]"
    lines = [ANSI.sub("", l).strip() for l in out.replace("\r", "\n").splitlines()]
    return [l for l in lines if l and "%" not in l]


def base_address(data, cpu):
    if not shutil.which("binbloom"):
        return {"available": False}
    if not cpu.get("available") or not cpu.get("main"):
        return {"available": True, "skipped": "processeur non reconnu"}
    endian, bits = ARCH_INFO.get(cpu["main"], (None, 32))
    segs = [s for s in cpu["segments"] if s["arch"] == cpu["main"]]
    seg = max(segs, key=lambda s: s["end"] - s["start"])
    start, end = seg["start"], min(seg["end"], seg["start"] + BINBLOOM_MAX)
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(data[start:end])
        path = f.name
    try:
        args = ["-t", str(os.cpu_count() or 4), "-a", str(bits)] + (["-e", endian] if endian else []) + [path]
        t0 = time.time()
        lines = run_binbloom(args, BINBLOOM_TIMEOUT)
        res = {"available": True, "segment": {"start": start, "end": end}, "arch": cpu["main"],
               "endianness": endian, "bits": bits, "seconds": round(time.time() - t0), "raw": lines[-40:]}
        res["timeout"] = any("[timeout]" in l for l in lines)
        for l in lines:
            m = re.search(r"Endianness is (LE|BE)", l)
            if m:
                res["endianness"] = m.group(1).lower()
            m = re.search(r"Base address (?:found|seems to be)[: ]+(0x[0-9a-f]+)", l, re.I)
            if m:
                res["base"] = m.group(1)
                res["sure"] = "not sure" not in l
        res["candidates"] = [{"addr": m.group(1), "score": float(m.group(2))}
                             for l in lines for m in [re.match(r"(0x[0-9a-f]+) \(([\d.]+)\)", l)] if m][:10]
        # Table des commandes de diagnostic UDS (calculateurs automobiles)
        if res.get("base"):
            uds = run_binbloom(["-a", str(bits), "-e", res["endianness"] or "le", "-b", res["base"], path], 120)
            for l in uds:
                m = re.search(r"UDS DB is located at @?([0-9a-fx]+), found (\d+) different UDS", l)
                if m:
                    res["uds"] = {"at": m.group(1), "count": int(m.group(2))}
        return res
    finally:
        os.unlink(path)


# --------------------------------------------------------------------------
# 5. Deuxième avis : binwalk

def binwalk_scan(path, out):
    if not shutil.which("binwalk"):
        return {"available": False}
    res = {"available": True, "findings": []}
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "bw.json")
        subprocess.run(["binwalk", "-q", "-l", log, path], capture_output=True, timeout=600, cwd=tmp)
        try:
            for entry in json.load(open(log)):
                for f in (entry.get("Analysis") or {}).get("file_map", []):
                    res["findings"].append({k: f.get(k) for k in ("offset", "size", "name", "confidence", "description")})
        except (OSError, ValueError):
            res["error"] = "lecture du résultat impossible"
        png = os.path.join(out, "entropy.png")
        r = subprocess.run(["binwalk", "-E", "-p", png, path], capture_output=True, timeout=600, cwd=tmp)
        res["entropy_png"] = os.path.exists(png)
    return res


# --------------------------------------------------------------------------

def main():
    path, out = sys.argv[1], sys.argv[2]
    moria = None
    if len(sys.argv) > 3 and os.path.exists(sys.argv[3]):
        try:
            moria = json.load(open(sys.argv[3], encoding="utf-8"))
        except ValueError:
            pass
    os.makedirs(out, exist_ok=True)
    with open(path, "rb") as f:
        data = f.read()
    result = {"schema": 1, "size": len(data), "started": time.strftime("%Y-%m-%dT%H:%M:%S")}

    say("-- Carte de la puce")
    result["map"] = flash_map(data)

    say("-- Catalogue des messages")
    strings, result["catalog"] = catalog(data)
    with open(os.path.join(out, "messages.txt"), "w", encoding="utf-8") as f:
        for off, s in strings:
            f.write(f"0x{off:08x}  {s}\n")
    say(f"   {len(strings)} textes lisibles, {sum(result['catalog']['counts'].values())} messages classés")

    say("-- Processeur (cpu_rec)")
    try:
        result["cpu"] = cpu_scan(data, result["map"])
    except Exception as e:
        result["cpu"] = {"available": True, "error": repr(e)}

    say("-- Adresse de chargement (binbloom)")
    try:
        result["base"] = base_address(data, result["cpu"])
    except Exception as e:
        result["base"] = {"available": True, "error": repr(e)}

    say("-- Deuxième avis (binwalk)")
    try:
        result["binwalk"] = binwalk_scan(path, out)
    except Exception as e:
        result["binwalk"] = {"available": True, "error": repr(e)}

    if moria:
        known = {f.get("offset") for f in moria.get("findings", [])}
        for f in result["binwalk"].get("findings", []):
            f["also_moria"] = f.get("offset") in known

    result["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    with open(os.path.join(out, "deep.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False)
    say("-- Terminé")


if __name__ == "__main__":
    main()
