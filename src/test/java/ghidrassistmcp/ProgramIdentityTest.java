package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.Proxy;
import java.util.List;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import org.junit.jupiter.api.Test;

class ProgramIdentityTest {
    @Test void missingSelectorIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> ProgramIdentity.resolve("missing", List.of(program("one", "/one"))));
    }
    @Test void duplicateNameIsRejectedAsAmbiguous() {
        assertThrows(IllegalArgumentException.class, () -> ProgramIdentity.resolve("same", List.of(program("same", "/a/same"), program("same", "/b/same"))));
    }
    @Test void exactPathSelectsOneDuplicateName() {
        Program selected = ProgramIdentity.resolve("/b/same", List.of(program("same", "/a/same"), program("same", "/b/same")));
        assertEquals("/b/same", selected.getDomainFile().getPathname());
    }
    private static Program program(String name, String path) {
        DomainFile file = (DomainFile) Proxy.newProxyInstance(DomainFile.class.getClassLoader(), new Class<?>[]{DomainFile.class},
            (p, m, a) -> switch (m.getName()) {
                case "getName" -> name; case "getPathname" -> path; case "getFileID" -> path;
                case "getLocalProjectURL", "getSharedProjectURL", "getProjectLocator" -> null; case "getVersion" -> 0;
                case "isClosed" -> false; case "equals" -> p == a[0]; case "hashCode" -> System.identityHashCode(p);
                default -> throw new UnsupportedOperationException(m.getName()); });
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(), new Class<?>[]{Program.class},
            (p, m, a) -> switch (m.getName()) {
                case "getName" -> name; case "getDomainFile" -> file; case "isClosed" -> false;
                case "equals" -> p == a[0]; case "hashCode" -> System.identityHashCode(p);
                default -> throw new UnsupportedOperationException(m.getName()); });
    }
}
