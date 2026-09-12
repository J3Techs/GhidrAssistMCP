package ghidrassistmcp.bsim;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.HeadlessClientAuthenticator;

/** Explicit process-owned authentication; a tool call cannot replace JVM credentials. */
final class BsimAuthentication {
    private static final Owner PROCESS = new Owner();
    private BsimAuthentication() {}
    record Configuration(String user, String keystore) {}
    @FunctionalInterface interface Installer { Object install(Configuration config) throws IOException; }

    static void ensure(String requestedUser, String requestedKeystore) throws IOException {
        var configured = configuration(System.getProperty("ghidrassistmcp.bsim.auth.user"),
            System.getProperty("ghidrassistmcp.bsim.auth.keystore"));
        var requested = configuration(requestedUser, requestedKeystore);
        PROCESS.ensure(configured, requested, config -> {
            HeadlessClientAuthenticator.installHeadlessClientAuthenticator(config.user(), config.keystore(), false);
            return ClientUtil.getClientAuthenticator();
        }, ClientUtil::getClientAuthenticator);
    }

    static Configuration configuration(String user, String keystore) throws IOException {
        user = user == null || user.isBlank() ? null : user.trim();
        if (keystore != null && !keystore.isBlank()) {
            Path path = Path.of(keystore).toRealPath();
            if (!Files.isRegularFile(path) || !Files.isReadable(path)) throw new IOException("BSim keystore must be a readable file");
            keystore = path.toString();
        } else keystore = null;
        return new Configuration(user, keystore);
    }

    static final class Owner {
        private Configuration installed;
        private Object authenticator;
        private boolean failed;

        synchronized void ensure(Configuration configured, Configuration requested, Installer installer,
                java.util.function.Supplier<Object> current) throws IOException {
            if (failed) throw new IOException("BSim authentication initialization previously failed; correct startup configuration and restart the JVM");
            if (requested.user() != null && !Objects.equals(requested.user(), configured.user()) ||
                    requested.keystore() != null && !Objects.equals(requested.keystore(), configured.keystore()))
                throw new IOException("Connection authentication differs from process configuration; configure ghidrassistmcp.bsim.auth.user/keystore at startup");
            if (installed != null) {
                if (!installed.equals(configured) || current.get() != authenticator)
                    throw new IOException("Process authentication changed after BSim initialization; use a separately configured JVM");
                return;
            }
            if (configured.user() == null && configured.keystore() == null) return;
            try {
                authenticator = installer.install(configured);
                installed = configured;
            } catch (IOException | RuntimeException error) {
                failed = true; // Ghidra installation may have partially changed global state.
                throw error;
            }
        }
    }
}
