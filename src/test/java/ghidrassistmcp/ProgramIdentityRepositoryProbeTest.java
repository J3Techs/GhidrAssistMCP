package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import org.junit.jupiter.api.Test;

class ProgramIdentityRepositoryProbeTest {
    @Test void localSelectorsNeverProbeUnrelatedSharedRepositories() throws Exception {
        var probes = new AtomicInteger();
        var programs = new ArrayList<Program>();
        for (int i = 0; i < 24; i++) programs.add(program("p" + i, "/folder/p" + i, probes, false));
        Program target = programs.getLast();
        String local = target.getDomainFile().getLocalProjectURL(null).toString();
        for (String selector : List.of("p23", "/folder/p23", local, local + "#version=7"))
            assertSame(target, ProgramIdentity.resolve(selector, programs), selector);
        assertThrows(ProgramIdentity.NotOpenException.class, () -> ProgramIdentity.resolve("missing", programs));
        assertThrows(ProgramIdentity.NotOpenException.class, () -> ProgramIdentity.resolve(local + "#version=6", programs));
        assertEquals(0, probes.get());
    }

    @Test void localIdentityAndDiagnosticsDoNotProbeSharedRepository() throws Exception {
        var probes = new AtomicInteger();
        var program = program("space # name", "/folder/space # name", probes, false);
        assertTrue(ProgramIdentity.id(program).endsWith("#version=7"));
        assertEquals("space # name", ProgramIdentity.describe(program).get("name"));
        assertEquals(0, probes.get());
    }

    @Test void duplicateNamesStillRejectWithoutRepositoryProbes() throws Exception {
        var probes = new AtomicInteger();
        var programs = List.of(program("same", "/a/same", probes, false), program("same", "/b/same", probes, false));
        assertThrows(IllegalArgumentException.class, () -> ProgramIdentity.resolve("same", programs));
        assertSame(programs.get(1), ProgramIdentity.resolve("/b/same", programs));
        assertEquals(0, probes.get());
    }

    @Test void explicitSharedUrlAliasIsRetainedAndLookedUpOnlyOnce() throws Exception {
        var probes = new AtomicInteger();
        var program = program("remote", "/folder/remote", probes, true);
        assertSame(program, ProgramIdentity.resolve("ghidra://example.invalid/FORD/folder/remote", List.of(program)));
        assertEquals(1, probes.get());
    }

    private static Program program(String name, String path, AtomicInteger probes, boolean allowShared) throws Exception {
        URL local = url("ghidra:/C:/fixture/FORD?" + path);
        URL shared = url("ghidra://example.invalid/FORD" + path);
        DomainFile file = (DomainFile) Proxy.newProxyInstance(DomainFile.class.getClassLoader(), new Class<?>[]{DomainFile.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "getName" -> name;
                case "getPathname", "getFileID" -> path;
                case "getVersion" -> 7;
                case "getLocalProjectURL" -> local;
                case "getSharedProjectURL" -> {
                    probes.incrementAndGet();
                    if (!allowShared) throw new AssertionError("Unrequested shared-repository probe for " + path);
                    yield shared;
                }
                case "getProjectLocator" -> null;
                case "isReadOnly", "isBusy", "canSave" -> false;
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> throw new UnsupportedOperationException(method.getName());
            });
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(), new Class<?>[]{Program.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "getName" -> name;
                case "getDomainFile" -> file;
                case "getModificationNumber" -> 1L;
                case "getCurrentTransactionInfo" -> null;
                case "isClosed", "isChanged", "isChangeable" -> false;
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> throw new UnsupportedOperationException(method.getName());
            });
    }

    private static URL url(String value) throws Exception {
        return new URL(null, value, new URLStreamHandler() {
            @Override protected URLConnection openConnection(URL ignored) { throw new AssertionError("No network in fixture"); }
        });
    }
}
