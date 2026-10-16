# Script exécuté PAR Ghidra (Jython) après l'analyse automatique d'un firmware.
# Il exporte un JSON lisible par l'Atelier :
#   - inventaire des fonctions (adresse, taille, nombre d'appelants/appelés)
#   - lien « message -> fonction » : quelle fonction affiche quel texte
#   - pseudo-code C des fonctions les plus parlantes (celles qui affichent des
#     messages, puis les plus grosses), pour comprendre ce que fait le firmware.
#
# Argument : le chemin du fichier JSON de sortie.
# @category Atelier
import json
import re

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

MAX_DECOMPILE = 60          # fonctions décompilées au maximum
MAX_C_CHARS = 12000         # taille maxi du pseudo-code par fonction
MAX_MSG_LINKS = 1200        # liens message -> fonction exportés
DECOMPILE_TIMEOUT = 45      # secondes par fonction

# Un message « parlant » : erreur, version, journal (avec % ), diagnostic…
INTERESTING = re.compile(
    r"err|fail|fault|panic|abort|assert|invalid|timeout|version|build|"
    r"\bv\d+\.\d|%[-0-9.]*[dsxup]|uds|diag|boot|init|reset|update|flash|"
    r"can|lin|ethernet|calib|sensor|task|watchdog|wdt|crc|checksum",
    re.I)


def out_path():
    args = getScriptArgs()
    return args[0] if args else "/tmp/ghidra.json"


def func_of(addr):
    return getFunctionContaining(addr)


def collect_strings(prog):
    """Chaque chaîne définie -> (texte, [fonctions qui la référencent])."""
    listing = prog.getListing()
    ref_mgr = prog.getReferenceManager()
    out = []
    data = listing.getDefinedData(True)
    for d in data:
        if not d.hasStringValue():
            continue
        try:
            text = d.getValue()
        except Exception:
            continue
        if text is None:
            continue
        text = unicode(text)
        if len(text) < 4:
            continue
        callers = []
        for ref in ref_mgr.getReferencesTo(d.getAddress()):
            f = func_of(ref.getFromAddress())
            if f is not None:
                callers.append(f)
        out.append((d.getAddress(), text, callers))
    return out


def run():
    prog = getCurrentProgram()
    monitor = ConsoleTaskMonitor()
    fm = prog.getFunctionManager()
    funcs = list(fm.getFunctions(True))

    result = {
        "schema": 1,
        "language": str(prog.getLanguageID()),
        "compiler": str(prog.getCompilerSpec().getCompilerSpecID()),
        "image_base": str(prog.getImageBase()),
        "function_count": fm.getFunctionCount(),
        "defined_data": prog.getListing().getNumDefinedData(),
        "instructions": prog.getListing().getNumInstructions(),
    }

    # Inventaire des fonctions.
    finfo = {}
    for f in funcs:
        body = f.getBody()
        entry = f.getEntryPoint()
        callers = f.getCallingFunctions(monitor)
        called = f.getCalledFunctions(monitor)
        finfo[str(entry)] = {
            "name": f.getName(),
            "entry": str(entry),
            "size": int(body.getNumAddresses()),
            "callers": len(callers),
            "calls": len(called),
            "strings": [],
            "thunk": f.isThunk(),
        }

    # Lien message -> fonction.
    strings = collect_strings(prog)
    links = []
    interest = {}          # entry -> score d'intérêt
    for addr, text, callers in strings:
        names = []
        for f in callers:
            e = str(f.getEntryPoint())
            names.append(e)
            if e in finfo and len(finfo[e]["strings"]) < 25:
                finfo[e]["strings"].append(text[:160])
            if INTERESTING.search(text):
                interest[e] = interest.get(e, 0) + 1
        if names and len(links) < MAX_MSG_LINKS:
            links.append({"addr": str(addr), "text": text[:200], "funcs": list(set(names))})

    # Fonctions à décompiler : d'abord celles qui affichent des messages
    # intéressants, puis les plus grosses.
    ranked = sorted(finfo.values(),
                    key=lambda x: (interest.get(x["entry"], 0), x["size"]),
                    reverse=True)
    to_decompile = [f for f in ranked if not f["thunk"]][:MAX_DECOMPILE]

    decomp = DecompInterface()
    decomp.openProgram(prog)
    for info in to_decompile:
        f = fm.getFunctionAt(toAddr(info["entry"]))
        if f is None:
            continue
        try:
            res = decomp.decompileFunction(f, DECOMPILE_TIMEOUT, monitor)
            if res and res.decompileCompleted():
                c = res.getDecompiledFunction().getC()
                info["c"] = c[:MAX_C_CHARS]
                info["c_truncated"] = len(c) > MAX_C_CHARS
        except Exception as e:
            info["c_error"] = str(e)

    result["functions"] = ranked[:400]
    result["message_links"] = links
    result["decompiled"] = [f["entry"] for f in to_decompile if "c" in f]

    with open(out_path(), "w") as fp:
        fp.write(json.dumps(result))
    print("[Atelier] export terminé : %d fonctions, %d liens message, %d décompilées"
          % (len(funcs), len(links), len(result["decompiled"])))


run()
