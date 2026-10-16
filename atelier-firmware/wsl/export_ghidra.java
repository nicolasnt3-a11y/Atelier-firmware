// Script exécuté PAR Ghidra après l'analyse automatique d'un firmware.
// Exporte un JSON lisible par l'Atelier :
//   - inventaire des fonctions (adresse, taille, appelants/appelés)
//   - lien « message -> fonction » : quelle fonction affiche quel texte
//   - pseudo-code C des fonctions les plus parlantes.
// Écrit en Java pour ne dépendre ni de Jython ni de PyGhidra.
// Argument : chemin du fichier JSON de sortie.
// @category Atelier
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class export_ghidra extends GhidraScript {

    static final int MAX_DECOMPILE = 60;
    static final int MAX_C_CHARS = 12000;
    static final int MAX_MSG_LINKS = 1200;
    static final int MAX_FUNCTIONS = 400;
    static final int DECOMPILE_TIMEOUT = 45;

    static final Pattern INTERESTING = Pattern.compile(
        "err|fail|fault|panic|abort|assert|invalid|timeout|version|build|" +
        "v\\d+\\.\\d|%[-0-9.]*[dsxup]|uds|diag|boot|init|reset|update|flash|" +
        "\\bcan\\b|lin|ethernet|calib|sensor|task|watchdog|wdt|crc|checksum",
        Pattern.CASE_INSENSITIVE);

    // --- petit générateur JSON (sans dépendance) -------------------------
    static void esc(StringBuilder b, String s) {
        b.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20 || c > 0x7e) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        b.append('"');
    }

    static class FInfo {
        String name, entry;
        long size;
        int callers, calls;
        boolean thunk;
        List<String> strings = new ArrayList<String>();
        String c; boolean cTrunc; String cErr;
        int score;
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "/tmp/ghidra.json";

        TaskMonitor monitor = new ConsoleTaskMonitor();
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        ReferenceManager refs = currentProgram.getReferenceManager();

        Map<String, FInfo> byEntry = new HashMap<String, FInfo>();
        List<FInfo> all = new ArrayList<FInfo>();
        for (Function f : fm.getFunctions(true)) {
            FInfo fi = new FInfo();
            fi.name = f.getName();
            fi.entry = f.getEntryPoint().toString();
            fi.size = f.getBody().getNumAddresses();
            fi.thunk = f.isThunk();
            fi.callers = f.getCallingFunctions(monitor).size();
            fi.calls = f.getCalledFunctions(monitor).size();
            byEntry.put(fi.entry, fi);
            all.add(fi);
        }

        // Lien message -> fonction.
        List<String> linkJson = new ArrayList<String>();
        DataIterator data = listing.getDefinedData(true);
        while (data.hasNext() && linkJson.size() < MAX_MSG_LINKS) {
            Data d = data.next();
            if (!d.hasStringValue()) continue;
            Object v = d.getValue();
            if (v == null) continue;
            String text = v.toString();
            if (text.length() < 4) continue;
            if (text.length() > 200) text = text.substring(0, 200);

            Set<String> hitFuncs = new LinkedHashSet<String>();
            boolean interesting = INTERESTING.matcher(text).find();
            for (Reference r : refs.getReferencesTo(d.getAddress())) {
                Function f = getFunctionContaining(r.getFromAddress());
                if (f == null) continue;
                String e = f.getEntryPoint().toString();
                hitFuncs.add(e);
                FInfo fi = byEntry.get(e);
                if (fi != null) {
                    if (fi.strings.size() < 25) fi.strings.add(text);
                    if (interesting) fi.score++;
                }
            }
            if (!hitFuncs.isEmpty()) {
                StringBuilder b = new StringBuilder("{\"addr\":");
                esc(b, d.getAddress().toString());
                b.append(",\"text\":"); esc(b, text);
                b.append(",\"funcs\":[");
                boolean first = true;
                for (String e : hitFuncs) { if (!first) b.append(','); esc(b, e); first = false; }
                b.append("]}");
                linkJson.add(b.toString());
            }
        }

        // Classement : d'abord les fonctions qui affichent des messages parlants,
        // puis les plus grosses.
        all.sort((x, y) -> {
            if (x.score != y.score) return y.score - x.score;
            return Long.compare(y.size, x.size);
        });

        // Décompilation des mieux classées.
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        List<String> decompiled = new ArrayList<String>();
        int done = 0;
        for (FInfo fi : all) {
            if (done >= MAX_DECOMPILE) break;
            if (fi.thunk) continue;
            Function f = fm.getFunctionAt(toAddr(fi.entry));
            if (f == null) continue;
            done++;
            try {
                DecompileResults res = decomp.decompileFunction(f, DECOMPILE_TIMEOUT, monitor);
                if (res != null && res.decompileCompleted()) {
                    String c = res.getDecompiledFunction().getC();
                    fi.cTrunc = c.length() > MAX_C_CHARS;
                    fi.c = fi.cTrunc ? c.substring(0, MAX_C_CHARS) : c;
                    decompiled.add(fi.entry);
                }
            } catch (Exception e) {
                fi.cErr = e.toString();
            }
        }
        decomp.dispose();

        // --- écriture du JSON --------------------------------------------
        StringBuilder b = new StringBuilder();
        b.append("{\"schema\":1");
        b.append(",\"language\":"); esc(b, currentProgram.getLanguageID().toString());
        b.append(",\"compiler\":"); esc(b, currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        b.append(",\"image_base\":"); esc(b, currentProgram.getImageBase().toString());
        b.append(",\"function_count\":").append(fm.getFunctionCount());
        b.append(",\"instructions\":").append(listing.getNumInstructions());
        b.append(",\"defined_data\":").append(listing.getNumDefinedData());

        b.append(",\"functions\":[");
        int n = Math.min(all.size(), MAX_FUNCTIONS);
        for (int i = 0; i < n; i++) {
            FInfo fi = all.get(i);
            if (i > 0) b.append(',');
            b.append("{\"name\":"); esc(b, fi.name);
            b.append(",\"entry\":"); esc(b, fi.entry);
            b.append(",\"size\":").append(fi.size);
            b.append(",\"callers\":").append(fi.callers);
            b.append(",\"calls\":").append(fi.calls);
            b.append(",\"score\":").append(fi.score);
            b.append(",\"strings\":[");
            for (int j = 0; j < fi.strings.size(); j++) { if (j > 0) b.append(','); esc(b, fi.strings.get(j)); }
            b.append(']');
            if (fi.c != null) { b.append(",\"c\":"); esc(b, fi.c); b.append(",\"c_truncated\":").append(fi.cTrunc); }
            if (fi.cErr != null) { b.append(",\"c_error\":"); esc(b, fi.cErr); }
            b.append('}');
        }
        b.append(']');

        b.append(",\"message_links\":[");
        for (int i = 0; i < linkJson.size(); i++) { if (i > 0) b.append(','); b.append(linkJson.get(i)); }
        b.append(']');

        b.append(",\"decompiled\":[");
        for (int i = 0; i < decompiled.size(); i++) { if (i > 0) b.append(','); esc(b, decompiled.get(i)); }
        b.append(']');
        b.append('}');

        Writer w = new OutputStreamWriter(new FileOutputStream(outPath), StandardCharsets.UTF_8);
        w.write(b.toString());
        w.close();
        println("[Atelier] export : " + all.size() + " fonctions, " + linkJson.size()
                + " liens message, " + decompiled.size() + " décompilées");
    }
}
