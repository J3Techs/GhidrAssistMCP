package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.*;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;

class PostCommitGuardTest {
    private final Object consumer = new Object();
    private ProgramDB program;

    @BeforeAll
    static void initialize() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(
            new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))),
            new HeadlessGhidraApplicationConfiguration());
    }

    @BeforeEach
    void fixture() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        program = new ProgramDB("post-commit-guard-fixture", language, language.getDefaultCompilerSpec(), consumer);
    }

    @AfterEach
    void release() { program.release(consumer); }

    @Test
    void callbackAllowsAnotherWriterToAcquireGuard() throws Exception {
        McpMutationGuard.LOCK.lock();
        try {
            AtomicBoolean acquired = new AtomicBoolean();
            String value = McpMutationGuard.afterCommit(program, () -> {
                Thread writer = new Thread(() -> {
                    try {
                        acquired.set(McpMutationGuard.LOCK.tryLock(2, TimeUnit.SECONDS));
                        if (acquired.get()) McpMutationGuard.LOCK.unlock();
                    } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                });
                writer.start();
                try { writer.join(3000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                return "verified";
            });
            assertEquals("verified", value);
            assertTrue(acquired.get(), "post-commit verification must not monopolize the writer guard");
            assertEquals(1, McpMutationGuard.LOCK.getHoldCount());
        } finally { McpMutationGuard.LOCK.unlock(); }
    }

    @Test
    void callbackExceptionRestoresEveryEnclosingHold() {
        McpMutationGuard.LOCK.lock();
        McpMutationGuard.LOCK.lock();
        try {
            assertThrows(IllegalArgumentException.class,
                () -> McpMutationGuard.afterCommit(program, () -> { throw new IllegalArgumentException("verification failed"); }));
            assertEquals(2, McpMutationGuard.LOCK.getHoldCount());
        } finally { McpMutationGuard.LOCK.unlock(); McpMutationGuard.LOCK.unlock(); }
    }

    @Test
    void activeProgramTransactionIsRejectedBeforeCallback() {
        int tx = program.startTransaction("active transaction");
        try {
            AtomicBoolean invoked = new AtomicBoolean();
            assertThrows(IllegalStateException.class,
                () -> McpMutationGuard.afterCommit(program, () -> { invoked.set(true); return null; }));
            assertFalse(invoked.get());
        } finally { program.endTransaction(tx, true); }
    }
}
