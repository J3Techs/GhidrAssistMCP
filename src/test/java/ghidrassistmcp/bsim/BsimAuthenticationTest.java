package ghidrassistmcp.bsim;

import static org.junit.jupiter.api.Assertions.*;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class BsimAuthenticationTest {
    @Test void unconfiguredCallsPreserveExistingProcessAuthentication() throws Exception {
        var owner = new BsimAuthentication.Owner();
        var empty = new BsimAuthentication.Configuration(null, null);
        owner.ensure(empty, empty, c -> { fail("Must not install"); return null; }, () -> { fail("Must not touch global authentication"); return null; });
        assertThrows(IOException.class, () -> owner.ensure(empty, new BsimAuthentication.Configuration("different", null), c -> null, () -> null));
    }
    @Test void repeatedConfigurationInstallsOnceAndConflictsFail() throws Exception {
        var owner = new BsimAuthentication.Owner();
        var config = new BsimAuthentication.Configuration("fixture", null);
        var empty = new BsimAuthentication.Configuration(null, null);
        var calls = new AtomicInteger(); Object identity = new Object();
        BsimAuthentication.Installer install = c -> { calls.incrementAndGet(); return identity; };
        owner.ensure(config, empty, install, () -> identity);
        owner.ensure(config, config, install, () -> identity);
        assertEquals(1, calls.get());
        assertThrows(IOException.class, () -> owner.ensure(empty, empty, install, () -> identity));
        assertThrows(IOException.class, () -> owner.ensure(config, config, install, Object::new));
        assertEquals(1, calls.get());
    }
    @Test void failedInstallationCannotSilentlyRetryPartiallyChangedGlobalState() {
        var owner = new BsimAuthentication.Owner();
        var config = new BsimAuthentication.Configuration("fixture", null);
        assertThrows(IOException.class, () -> owner.ensure(config, config, c -> { throw new IOException("fixture failure"); }, Object::new));
        assertThrows(IOException.class, () -> owner.ensure(config, config, c -> { fail("Must not retry installation"); return null; }, Object::new));
    }
}
