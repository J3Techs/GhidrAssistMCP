package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.io.File;
import java.util.Map;
import org.junit.jupiter.api.Test;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** Backend-level regression for native post-mutation prototype verification. */
class BackendPostMutationNativeTest {
    @Test void backendPrototypeToolUsesSharedDecompilerAndPreservesName() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(new GhidraApplicationLayout(
            new File(System.getProperty("ghidra.install.dir"))), new HeadlessGhidraApplicationConfiguration());
        var lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB("backend-post-mutation", lang, lang.getDefaultCompilerSpec(), this);
        try {
            Address start = program.getAddressFactory().getAddress("1000");
            int tx = program.startTransaction("fixture");
            try {
                program.getMemory().createInitializedBlock("text", start, 32, (byte)0x90, TaskMonitor.DUMMY, false).setExecute(true);
                program.getMemory().setBytes(start, new byte[] {0x55, (byte)0x89, (byte)0xe5, (byte)0xb8, 0x2a, 0, 0, 0, 0x5d, (byte)0xc3});
                assertTrue(new ghidra.app.cmd.disassemble.DisassembleCommand(start, new AddressSet(start, start.add(9)), true).applyTo(program));
                if (program.getFunctionManager().getFunctionAt(start) == null)
                    program.getFunctionManager().createFunction("original_name", start, new AddressSet(start, start.add(9)), SourceType.USER_DEFINED);
            } finally { program.endTransaction(tx, true); }
            var backend = new GhidrAssistMCPBackend() {
                @Override public Program getCurrentProgram() { return program; }
                @Override public java.util.List<Program> getAllOpenPrograms() { return java.util.List.of(program); }
            };
            try {
                var result = backend.callTool("set_function_prototype", Map.of("function_address", "1000",
                    "prototype", "int fixture(int value)", "return_code", true));
                assertFalse(result.isError(), result.content().toString());
                Map<?, ?> body = (Map<?, ?>) result.structuredContent();
                assertEquals("verified", body.get("verification_status"));
                assertTrue(body.get("code") instanceof String && !((String) body.get("code")).isBlank());
                assertEquals("original_name", program.getFunctionManager().getFunctionAt(start).getName());
                assertEquals("int original_name(int value)", program.getFunctionManager().getFunctionAt(start).getPrototypeString(false, false));
            } finally { backend.shutdownWorkers(); }
        } finally { program.release(this); }
    }
}
