package ghidrassistmcp.tools;

import java.util.*;
import java.nio.charset.StandardCharsets;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/** One bounded latest checkpoint per function; revisions are not durable fingerprints. */
final class PortLedger {
    static final String CATEGORY = "PORT";
    static final int MAX_TEXT = 4096;
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Set<String> KEYS = Set.of("operation_id", "source_program_id", "source_address", "source_fingerprint", "method", "evidence_reference");
    private PortLedger() {}

    static void validateMetadata(Map<String,Object> source) {
        if (source == null || !KEYS.containsAll(source.keySet())) throw new IllegalArgumentException("Unknown or missing PORT metadata");
        for (String key : List.of("operation_id", "source_program_id", "source_address", "source_fingerprint", "method")) {
            if (!(source.get(key) instanceof String s) || s.isBlank()) throw new IllegalArgumentException("port_metadata." + key + " is required");
        }
        for (var entry : source.entrySet()) {
            int maximum = entry.getKey().equals("source_program_id") ? 2048 : entry.getKey().equals("evidence_reference") ? 1024 : 128;
            if (!(entry.getValue() instanceof String s) || s.length() > maximum) throw new IllegalArgumentException("PORT metadata fields must be bounded strings");
        }
        if (!((String)source.get("source_fingerprint")).matches("[0-9a-f]{64}")) throw new IllegalArgumentException("source_fingerprint must be lowercase SHA-256 hex");
        // Reserve the complete envelope and destination fingerprint before preview/apply.
        encoded(row(source, "0".repeat(64), "applied_unverified"));
    }

    private static Map<String,Object> row(Map<String,Object> source, String fingerprint, String state) {
        var row = new LinkedHashMap<String,Object>();
        row.put("version", 1); row.put("operation_id", source.get("operation_id"));
        row.put("source", new TreeMap<>(source)); row.put("destination_fingerprint", fingerprint);
        row.put("verification", state); return row;
    }

    static void appliedUnverified(Program program, Function function, String operationId, Map<String,Object> source) {
        validateMetadata(source);
        var next = row(source, fingerprint(function), "applied_unverified");
        var previous = read(function);
        // Repeating the exact checkpoint preserves its verification and creates no growth.
        if (previous != null && Objects.equals(previous.get("operation_id"), source.get("operation_id")) &&
                Objects.equals(previous.get("source"), next.get("source")) &&
                Objects.equals(previous.get("destination_fingerprint"), next.get("destination_fingerprint"))) return;
        program.getBookmarkManager().setBookmark(function.getEntryPoint(), "NOTE", CATEGORY, encoded(next));
    }

    static boolean markVerified(Program program, Function function, long revision, String operationId) {
        if (function == null || program.getModificationNumber() != revision) return false;
        var row = read(function);
        if (row == null || !Objects.equals(operationId, row.get("operation_id")) ||
                !Objects.equals(fingerprint(function), row.get("destination_fingerprint"))) return false;
        if ("verified".equals(row.get("verification"))) return true;
        if (!"applied_unverified".equals(row.get("verification"))) return false;
        row.put("verification", "verified");
        program.getBookmarkManager().setBookmark(function.getEntryPoint(), "NOTE", CATEGORY, encoded(row));
        return true;
    }

    static Map<String,Object> read(Function function) {
        if (function == null) return null;
        var b = function.getProgram().getBookmarkManager().getBookmark(function.getEntryPoint(), "NOTE", CATEGORY);
        return b == null ? null : parse(b.getComment());
    }

    @SuppressWarnings("unchecked") static Map<String,Object> parse(String text) {
        if (text == null || text.length() > MAX_TEXT || text.getBytes(StandardCharsets.UTF_8).length > MAX_TEXT) return null;
        try {
            Map<String,Object> row = JSON.readValue(text, Map.class);
            if (!Integer.valueOf(1).equals(row.get("version")) || !(row.get("source") instanceof Map<?,?>)) return null;
            validateMetadata((Map<String,Object>)row.get("source"));
            if (!Objects.equals(row.get("operation_id"), ((Map<?,?>)row.get("source")).get("operation_id"))) return null;
            return row;
        } catch (Exception e) { return null; }
    }

    static String fingerprint(Function f) {
        try {
            var p = f.getProgram();
            long total = f.getBody().getNumAddresses();
            if (total < 1 || total > 1_048_576) throw new IllegalArgumentException("function body must be 1..1048576 bytes to fingerprint");
            var digest = java.security.MessageDigest.getInstance("SHA-256");
            frame(digest, "port-function-v1"); frame(digest, p.getLanguageID().toString());
            frame(digest, p.getCompilerSpec().getCompilerSpecID().toString());
            frame(digest, f.getEntryPoint().toString()); frame(digest, f.getName());
            frame(digest, f.getPrototypeString(false, false));
            byte[] bytes = new byte[8192];
            for (var range : f.getBody().getAddressRanges()) {
                frame(digest, range.getMinAddress().toString()); frame(digest, Long.toString(range.getLength()));
                long remaining = range.getLength(); var cursor = range.getMinAddress();
                while (remaining > 0) {
                    if (Thread.currentThread().isInterrupted()) throw new java.util.concurrent.CancellationException("Fingerprint cancelled");
                    int n = (int)Math.min(bytes.length, remaining);
                    if (p.getMemory().getBytes(cursor, bytes, 0, n) != n) throw new IllegalArgumentException("Incomplete function memory");
                    digest.update(bytes, 0, n); remaining -= n;
                    if (remaining > 0) cursor = cursor.addNoWrap(n);
                }
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (Exception e) { throw new IllegalArgumentException("Unable to fingerprint function: " + e.getMessage(), e); }
    }
    private static void frame(java.security.MessageDigest digest, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        digest.update(java.nio.ByteBuffer.allocate(4).putInt(bytes.length).array()); digest.update(bytes);
    }
    private static String encoded(Map<String,Object> row) {
        try {
            String text = JSON.writeValueAsString(row);
            if (text.getBytes(StandardCharsets.UTF_8).length > MAX_TEXT) throw new IllegalArgumentException("PORT provenance exceeds 4096 encoded bytes");
            return text;
        } catch (java.io.IOException e) { throw new IllegalArgumentException("Invalid PORT metadata", e); }
    }
}
