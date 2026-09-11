package ghidrassistmcp.bsim;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.awt.GraphicsEnvironment;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.framework.Application;
import ghidra.framework.client.HeadlessClientAuthenticator;

/** Secret-free, atomic BSim connection profiles. */
public final class BsimConnections {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final TypeReference<List<Map<String, Object>>> PROFILES =
        new TypeReference<>() {};
    private static final List<String> SECRET_KEYS = List.of(
        "password", "secret", "token", "credential", "passphrase", "private_key");

    private final Path settingsRoot;
    private final Path profilesFile;

    public BsimConnections(Path settingsRoot) {
        this.settingsRoot = Objects.requireNonNull(settingsRoot, "settingsRoot").toAbsolutePath().normalize();
        this.profilesFile = this.settingsRoot.resolve("bsim-connections.json");
    }

    public Path settingsFile() { return profilesFile; }

    public synchronized List<Map<String, Object>> list() throws IOException {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map<String, Object> profile : readProfiles()) {
            result.add(Collections.unmodifiableMap(new LinkedHashMap<>(profile)));
        }
        return result;
    }

    public synchronized Map<String, Object> configure(Map<String, Object> arguments) throws IOException {
        Map<String, Object> profile = sanitizeProfile(arguments);
        String id = text(profile, "profile_id");
        if (id == null) id = text(profile, "id");
        if (id == null) id = UUID.randomUUID().toString();
        profile.put("profile_id", id);
        profile.remove("id");
        List<Map<String, Object>> profiles = readProfiles();
        final String profileId = id;
        profiles.removeIf(p -> profileId.equals(text(p, "profile_id")));
        profiles.add(profile);
        writeProfiles(profiles);
        return Collections.unmodifiableMap(new LinkedHashMap<>(profile));
    }

    public synchronized boolean remove(String profileId) throws IOException {
        Objects.requireNonNull(profileId, "profileId");
        List<Map<String, Object>> profiles = readProfiles();
        boolean removed = profiles.removeIf(p -> profileId.equals(text(p, "profile_id")));
        if (removed) writeProfiles(profiles);
        return removed;
    }

    /** Open a stock BSim client. The caller owns and must close the result. */
    public FunctionDatabase open(Map<String, Object> arguments, boolean initialize) throws Exception {
        String urlText = text(arguments, "database_url");
        if (urlText == null) urlText = text(arguments, "url");
        if (urlText == null) {
            String selector = text(arguments, "database");
            if (selector != null && looksLikeUrl(selector)) urlText = selector;
            else if (selector != null) arguments = Map.of("profile_id", selector);
        }
        if (urlText == null) {
            String profileId = text(arguments, "profile_id");
            if (profileId == null) profileId = text(arguments, "connection");
            if (profileId == null) throw new IllegalArgumentException(
                "database_url or profile_id is required");
            Map<String, Object> profile = find(profileId);
            arguments = profile;
            urlText = text(profile, "database_url");
            if (urlText == null) urlText = text(profile, "url");
        }
        if (urlText == null || urlText.isBlank()) {
            throw new IllegalArgumentException("connection profile has no database URL");
        }
        rejectSecretUrl(urlText);
        URL url = BSimClientFactory.deriveBSimURL(urlText.trim());
        installNonPromptingHeadlessAuth(url, arguments);
        FunctionDatabase database = BSimClientFactory.buildClient(url, false);
        if (initialize && !database.initialize()) {
            String error = database.getLastError() == null ? "initialization failed" :
                database.getLastError().toString();
            database.close();
            throw new IOException(error);
        }
        return database;
    }

    public synchronized Map<String, Object> find(String profileId) throws IOException {
        for (Map<String, Object> profile : readProfiles()) {
            if (profileId.equals(text(profile, "profile_id"))) {
                return new LinkedHashMap<>(profile);
            }
        }
        throw new IllegalArgumentException("unknown BSim profile: " + profileId);
    }

    /** Discover persisted BSim definitions without opening or modifying them. */
    public synchronized List<Map<String, Object>> discoverSavedDefinitions() throws IOException {
        List<Map<String, Object>> result = new ArrayList<>();
        try {
            for (File file : Application.getUserSettingsFiles("bsim", ".server.properties")) {
                if (!file.isFile()) continue;
                Map<String, Object> definition = JSON.readValue(file, new TypeReference<>() {});
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("path", file.toPath().toString());
                row.put("kind", "ghidra_server_definition");
                for (String key : List.of("DBType", "Name", "User", "Host", "Port")) {
                    if (definition.containsKey(key)) row.put(key, definition.get(key));
                }
                result.add(row);
            }
        }
        catch (Exception ignored) {
            // Discovery is best effort and must never prompt or mutate settings.
        }
        if (!Files.isDirectory(settingsRoot)) return result;
        try (var paths = Files.walk(settingsRoot, 3)) {
            paths.filter(Files::isRegularFile)
                .filter(p -> !p.equals(profilesFile))
                .filter(p -> p.getFileName().toString().toLowerCase().contains("bsim"))
                .forEach(p -> result.add(Map.of("path", p.toString(), "kind", "saved_definition")));
        }
        return result;
    }

    public static List<Map<String, Object>> backendCapabilities() {
        return List.of(
            capability("h2", "file", true, false, true, true, false, false),
            capability("postgres", "postgresql", false, true, true, true, true, true),
            capability("elastic", "elastic/https", false, true, true, true, true, false));
    }

    private static Map<String, Object> capability(String name, String protocol,
            boolean local, boolean remote, boolean create, boolean drop,
            boolean rebuild, boolean prewarm) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("backend", name);
        row.put("protocol", protocol);
        row.put("local", local);
        row.put("remote", remote);
        row.put("supports_create", create);
        row.put("supports_drop", drop);
        row.put("supports_index_rebuild", rebuild);
        row.put("supports_prewarm", prewarm);
        row.put("headless_auth", !local);
        return row;
    }

    private Map<String, Object> sanitizeProfile(Map<String, Object> arguments) throws IOException {
        if (arguments == null) throw new IllegalArgumentException("profile is required");
        for (String key : arguments.keySet()) {
            String lower = key.toLowerCase();
            for (String secret : SECRET_KEYS) {
                if (lower.contains(secret)) {
                    throw new IllegalArgumentException("secret-bearing profile fields are not persisted");
                }
            }
        }
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : arguments.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof String s) {
                if (entry.getKey().equals("url") || entry.getKey().equals("database_url")) rejectSecretUrl(s);
                result.put(entry.getKey(), s.trim());
            }
            else if (value instanceof Number || value instanceof Boolean) {
                result.put(entry.getKey(), value);
            }
            else if (value != null) {
                throw new IllegalArgumentException("profile fields must be scalar: " + entry.getKey());
            }
        }
        if (text(result, "database_url") == null && text(result, "url") == null) {
            throw new IllegalArgumentException("database_url or url is required");
        }
        return result;
    }

    private List<Map<String, Object>> readProfiles() throws IOException {
        if (!Files.exists(profilesFile)) return new ArrayList<>();
        List<Map<String, Object>> profiles =
            JSON.readValue(Files.readString(profilesFile), PROFILES);
        if (profiles == null) return new ArrayList<>();
        for (Map<String, Object> profile : profiles) {
            for (String key : profile.keySet()) {
                String lower = key.toLowerCase();
                for (String secret : SECRET_KEYS) {
                    if (lower.contains(secret)) throw new IOException("stored BSim profile contains secret field");
                }
            }
            String url = text(profile, "database_url");
            if (url == null) url = text(profile, "url");
            if (url != null) rejectSecretUrl(url);
        }
        return new ArrayList<>(profiles);
    }

    private void writeProfiles(List<Map<String, Object>> profiles) throws IOException {
        Files.createDirectories(settingsRoot);
        Path temp = Files.createTempFile(settingsRoot, "bsim-connections-", ".tmp");
        try {
            Files.writeString(temp,
                JSON.writerWithDefaultPrettyPrinter().writeValueAsString(profiles),
                StandardCharsets.UTF_8);
            try {
                Files.move(temp, profilesFile, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            }
            catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, profilesFile, StandardCopyOption.REPLACE_EXISTING);
            }
        }
        finally {
            Files.deleteIfExists(temp);
        }
    }

    private static String text(Map<String, Object> values, String key) {
        Object value = values == null ? null : values.get(key);
        return value instanceof String s && !s.isBlank() ? s.trim() : null;
    }

    private static boolean looksLikeUrl(String value) {
        return value.contains("://") || value.startsWith("file:");
    }

    private static void rejectSecretUrl(String value) {
        try {
            URL url = new URL(value);
            if (url.getUserInfo() != null && url.getUserInfo().contains(":")) {
                throw new IllegalArgumentException("database URL must not contain a password");
            }
            String query = url.getQuery();
            if (query != null && query.toLowerCase().matches(".*(password|secret|token|credential).*")) {
                throw new IllegalArgumentException("database URL must not contain secret query fields");
            }
        }
        catch (java.net.MalformedURLException e) {
            throw new IllegalArgumentException("invalid database URL", e);
        }
    }

    private static void installNonPromptingHeadlessAuth(URL url, Map<String, Object> arguments)
            throws IOException {
        if (!GraphicsEnvironment.isHeadless() ||
            ("file".equals(url.getProtocol()))) return;
        String user = text(arguments, "user");
        String keystore = text(arguments, "keystore");
        HeadlessClientAuthenticator.installHeadlessClientAuthenticator(user, keystore, false);
    }
}
