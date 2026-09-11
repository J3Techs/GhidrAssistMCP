package ghidrassistmcp.bsim;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BsimConnectionsTest {
    @Test
    void profilesAreAtomicAndNeverPersistSecrets(@TempDir Path temporary) throws Exception {
        BsimConnections connections = new BsimConnections(temporary);
        Map<String, Object> saved = connections.configure(Map.of(
            "profile_id", "local",
            "database_url", "file:/tmp/bsim.mv.db",
            "backend", "h2"));
        assertEquals("local", saved.get("profile_id"));
        assertTrue(Files.exists(connections.settingsFile()));
        String json = Files.readString(connections.settingsFile());
        assertFalse(json.contains("password"));
        assertEquals("file:/tmp/bsim.mv.db",
            connections.find("local").get("database_url"));
        assertTrue(connections.remove("local"));
        assertFalse(connections.remove("local"));
    }

    @Test
    void secretFieldsAndPasswordUrlsAreRejected(@TempDir Path temporary) {
        BsimConnections connections = new BsimConnections(temporary);
        assertThrows(IllegalArgumentException.class, () -> connections.configure(Map.of(
            "profile_id", "bad", "database_url", "postgresql://host/db",
            "password", "should-not-persist")));
        assertThrows(IllegalArgumentException.class, () -> connections.configure(Map.of(
            "profile_id", "bad", "database_url", "postgresql://user:pw@host/db")));
        assertThrows(IllegalArgumentException.class, () -> connections.open(
            Map.of("database", "postgresql://user:pw@host/db"), false));
    }

    @Test
    void databaseSelectorResolvesProfile(@TempDir Path temporary) throws Exception {
        BsimConnections connections = new BsimConnections(temporary);
        connections.configure(Map.of("profile_id", "local", "database_url", "file:/tmp/bsim.mv.db"));
        assertDoesNotThrow(() -> connections.find("local"));
    }

    @Test
    void discoveryIsReadOnlyAndReportsSavedDefinitionFiles(@TempDir Path temporary) throws Exception {
        Path saved = temporary.resolve("bsim123.server.properties");
        Files.writeString(saved, "{\"DBType\":\"file\",\"Name\":\"fixture\"}");
        BsimConnections connections = new BsimConnections(temporary);
        assertTrue(connections.discoverSavedDefinitions().stream()
            .anyMatch(row -> saved.toString().equals(row.get("path"))));
        assertTrue(Files.exists(saved));
    }

    @Test
    void capabilitiesExposeOnlySupportedStockBackends() {
        assertEquals(java.util.Set.of("h2", "postgres", "elastic"),
            BsimConnections.backendCapabilities().stream()
                .map(row -> row.get("backend")).collect(java.util.stream.Collectors.toSet()));
    }
}
