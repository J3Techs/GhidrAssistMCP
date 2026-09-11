package ghidrassistmcp.bsim;

import java.io.IOException;
import java.nio.file.*;
import java.math.BigDecimal;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.protocol.BSimQuery;
import ghidra.features.bsim.query.protocol.QueryResponseRecord;
import io.modelcontextprotocol.spec.McpSchema;

public final class BsimSupport {
    public static final ObjectMapper JSON = new ObjectMapper();
    private BsimSupport() {}
    public static String text(Map<String, Object> args, String key) {
        if (args.get(key) instanceof String value && !value.isBlank()) return value.trim();
        throw new IllegalArgumentException(key + " is required");
    }
    public static String text(Map<String, Object> args, String key, String fallback) {
        return args.containsKey(key) ? text(args, key) : fallback;
    }
    public static int integer(Map<String, Object> args, String key, int fallback, int max) {
        if (!args.containsKey(key)) return fallback;
        if (!(args.get(key) instanceof Number n)) throw new IllegalArgumentException(key + " must be an integer");
        try {
            int value = new BigDecimal(n.toString()).intValueExact();
            if (value < 0 || value > max) throw new IllegalArgumentException(key + " must be 0.." + max);
            return value;
        } catch (ArithmeticException e) { throw new IllegalArgumentException(key + " must be 0.." + max); }
    }
    public static boolean bool(Map<String, Object> args, String key, boolean fallback) {
        if (!args.containsKey(key)) return fallback;
        if (args.get(key) instanceof Boolean value) return value;
        throw new IllegalArgumentException(key + " must be a boolean");
    }
    public static double decimal(Map<String, Object> args, String key, double fallback, double min, double max) {
        if (!args.containsKey(key)) return fallback;
        if (!(args.get(key) instanceof Number n) || !Double.isFinite(n.doubleValue()) || n.doubleValue() < min || n.doubleValue() > max)
            throw new IllegalArgumentException(key + " must be " + min + ".." + max);
        return n.doubleValue();
    }
    public static <T extends QueryResponseRecord> T query(FunctionDatabase database, BSimQuery<T> query) throws IOException {
        T response = query.execute(database);
        if (response == null) {
            var error = database.getLastError();
            throw new IOException(error == null ? "BSim query failed" : error.category + ": " + redact(error.message));
        }
        return response;
    }
    public static String redact(String value) {
        if (value == null) return "BSim operation failed";
        return value.replaceAll("(://[^/@\\s:]+):[^@/\\s]+@", "$1:***@")
            .replaceAll("(?i)([?&](?:password|passwd|token|access_token|secret|api_key)=)[^&#\\s]*", "$1***");
    }
    public static String digest(String value) {
        try { return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8))); }
        catch (java.security.NoSuchAlgorithmException e) { throw new AssertionError(e); }
    }
    public static String vectorConfiguration(generic.lsh.vector.LSHVectorFactory factory) throws IOException {
        return JSON.writeValueAsString(Map.of("settings", factory.getSettings(),
            "significance_scale", factory.getSignificanceScale(), "significance_addend", factory.getSignificanceAddend()));
    }
    public static void requireSaved(ghidra.program.model.listing.Program program) {
        boolean analyzing = ghidra.app.plugin.core.analysis.AutoAnalysisManager.hasAutoAnalysisManager(program)
            && ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(program).isAnalyzing();
        if (program.isChanged() || program.getCurrentTransactionInfo() != null || program.getDomainFile().isBusy() || analyzing)
            throw new IllegalStateException("Save the program and wait for analysis/transactions before starting resumable BSim work");
    }
    @SuppressWarnings("unchecked") public static Map<String, Object> copy(Map<String, Object> values) {
        return JSON.convertValue(values, LinkedHashMap.class);
    }
    public static McpSchema.CallToolResult result(Map<String, Object> value) {
        try { return McpSchema.CallToolResult.builder().structuredContent(value).addTextContent(JSON.writeValueAsString(value)).build(); }
        catch (Exception e) { return error(e); }
    }
    public static McpSchema.CallToolResult error(Exception error) {
        String message = redact(error.getMessage());
        return McpSchema.CallToolResult.builder().isError(true)
            .structuredContent(Map.of("error", error.getClass().getSimpleName(), "message", message))
            .addTextContent(message).build();
    }
    public static void atomicJson(Path target, Object value) throws IOException {
        Files.createDirectories(target.toAbsolutePath().getParent());
        Path temporary = Files.createTempFile(target.toAbsolutePath().getParent(), ".bsim-", ".tmp");
        try {
            JSON.writerWithDefaultPrettyPrinter().writeValue(temporary.toFile(), value);
            try { Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING); }
            catch (AtomicMoveNotSupportedException e) { Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING); }
        } finally { Files.deleteIfExists(temporary); }
    }
    @SuppressWarnings("unchecked") public static Map<String, Object> readJson(Path path) throws IOException {
        return JSON.readValue(path.toFile(), LinkedHashMap.class);
    }
    public static Map<String, Object> stringProperty(String description) { return Map.of("type", "string", "description", description); }
}
