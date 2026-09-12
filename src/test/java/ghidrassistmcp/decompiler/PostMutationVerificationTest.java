package ghidrassistmcp.decompiler;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import ghidra.GhidraApplicationLayout;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidrassistmcp.McpMutationGuard;
import ghidrassistmcp.tools.SetFunctionPrototypeTool;

class PostMutationVerificationTest {
    @Test void failedVerificationRetainsCommittedSignatureAndReportsUnavailable() throws Exception {
        Fixture fixture = new Fixture(false);
        try {
            var result = fixture.tool.execute(Map.of("function_address", "1000", "prototype", "int fixture(int value)",
                "return_code", true), fixture.program);
            assertFalse(Boolean.TRUE.equals(result.isError()));
            assertEquals("int fixture(int value)", fixture.function.getPrototypeString(false, false));
            Map<?, ?> body = (Map<?, ?>) result.structuredContent();
            assertEquals("committed", body.get("mutation_status"));
            assertEquals("unavailable", body.get("verification_status"));
            assertNotNull(body.get("verification_diagnostic"));
            assertEquals(ghidrassistmcp.ProgramIdentity.id(fixture.program), body.get("program_id"));
            assertTrue(String.valueOf(body.get("function_entry")).endsWith("1000"));
            assertFalse(fixture.inTransaction.get());
            assertFalse(fixture.guardHeld.get());
        } finally { fixture.close(); }
    }

    @Test void interveningRevisionReportsStaleWhileMutationRemainsCommitted() throws Exception {
        Fixture fixture = new Fixture(true);
        try {
            var result = fixture.tool.execute(Map.of("function_address", "1000", "prototype", "int fixture(int value)",
                "return_code", true), fixture.program);
            Map<?, ?> body = (Map<?, ?>) result.structuredContent();
            assertEquals("committed", body.get("mutation_status"));
            assertEquals("stale", body.get("verification_status"));
            assertNotEquals(body.get("committed_revision"), body.get("observed_revision"));
            assertEquals("int fixture(int value)", fixture.function.getPrototypeString(false, false));
        } finally { fixture.close(); }
    }

    @Test void verificationReturnsBoundedCodeAndRestoresEnclosingGuardHold() throws Exception {
        String code = "int fixture(void) { return \uD83D\uDE00; }";
        Fixture fixture = new Fixture(false, code);
        McpMutationGuard.LOCK.lock();
        try {
            var result = fixture.tool.execute(Map.of("function_address", "1000", "prototype", "int fixture(void)",
                "return_code", true, "max_chars", 28), fixture.program);
            Map<?, ?> body = (Map<?, ?>) result.structuredContent();
            assertEquals("verified", body.get("verification_status"));
            assertEquals(code.substring(0, 27), body.get("code"));
            assertFalse(((String) body.get("code")).endsWith("\uD83D"));
            assertEquals(Boolean.TRUE, body.get("code_truncated"));
            assertFalse(fixture.inTransaction.get());
            assertFalse(fixture.guardHeld.get());
            assertTrue(McpMutationGuard.LOCK.isHeldByCurrentThread());
        } finally {
            McpMutationGuard.LOCK.unlock();
            fixture.close();
        }
    }

    private static final class Fixture {
        final ProgramDB program;
        final Function function;
        final AtomicBoolean inTransaction = new AtomicBoolean();
        final AtomicBoolean guardHeld = new AtomicBoolean();
        final SetFunctionPrototypeTool tool;
        Fixture(boolean mutateDuringVerification) throws Exception {
            this(mutateDuringVerification, null);
        }
        Fixture(boolean mutateDuringVerification, String code) throws Exception {
            if (!Application.isInitialized()) Application.initializeApplication(new GhidraApplicationLayout(
                new File(System.getProperty("ghidra.install.dir"))), new HeadlessGhidraApplicationConfiguration());
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
            program = new ProgramDB("post-verification", language, language.getDefaultCompilerSpec(), this);
            var address = program.getAddressFactory().getAddress("1000");
            int tx = program.startTransaction("fixture");
            function = program.getFunctionManager().createFunction("fixture", address, new AddressSet(address), SourceType.USER_DEFINED);
            program.endTransaction(tx, true);
            FakeDecompiler decompiler = new FakeDecompiler(mutateDuringVerification, code, program, function, inTransaction, guardHeld);
            tool = new SetFunctionPrototypeTool(new DecompilerService(p -> null,
                (s, p) -> new DecompileOptions(), () -> decompiler));
        }
        void close() { program.release(this); }
    }

    private static final class FakeDecompiler extends DecompInterface {
        final boolean mutate;
        final String code;
        final ProgramDB program;
        final Function function;
        final AtomicBoolean inTransaction, guardHeld;
        FakeDecompiler(boolean mutate, String code, ProgramDB program, Function function, AtomicBoolean inTransaction, AtomicBoolean guardHeld) {
            this.mutate = mutate; this.code = code; this.program = program; this.function = function;
            this.inTransaction = inTransaction; this.guardHeld = guardHeld;
        }
        @Override public boolean setOptions(DecompileOptions options) { return true; }
        @Override public boolean openProgram(ghidra.program.model.listing.Program p) { return true; }
        @Override public void dispose() {}
        @Override public DecompileResults decompileFunction(Function f, int timeout, ghidra.util.task.TaskMonitor monitor) {
            inTransaction.set(program.getCurrentTransactionInfo() != null);
            guardHeld.set(McpMutationGuard.LOCK.isHeldByCurrentThread());
            if (mutate) {
                int tx = program.startTransaction("intervening GUI edit");
                function.setComment("changed during verification");
                program.endTransaction(tx, true);
            }
            if (code != null) return new DecompileResults(f, null, null, null, "", null,
                ghidra.app.decompiler.DecompileProcess.DisposeState.NOT_DISPOSED) {
                @Override public boolean decompileCompleted() { return true; }
                @Override public ghidra.app.decompiler.DecompiledFunction getDecompiledFunction() {
                    return new ghidra.app.decompiler.DecompiledFunction(f.getName(), code);
                }
            };
            return new DecompileResults(f, null, null, null, "verification fixture failure", null,
                ghidra.app.decompiler.DecompileProcess.DisposeState.NOT_DISPOSED);
        }
    }
}
