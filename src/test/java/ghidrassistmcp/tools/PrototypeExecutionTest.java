package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.io.File;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.Test;

class PrototypeExecutionTest {
    @Test void commandWorksOnEdtAndInvalidPrototypeLeavesNoCommentOrSignatureChange() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(new GhidraApplicationLayout(
            new File(System.getProperty("ghidra.install.dir"))), new HeadlessGhidraApplicationConfiguration());
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB("prototype-fixture", language, language.getDefaultCompilerSpec(), this);
        try {
            var address = program.getAddressFactory().getAddress("1000");
            int tx = program.startTransaction("fixture");
            var function = program.getFunctionManager().createFunction("fixture", address, new AddressSet(address), SourceType.USER_DEFINED);
            program.endTransaction(tx, true);
            var result = new AtomicReference<McpSchema.CallToolResult>();
            javax.swing.SwingUtilities.invokeAndWait(() -> result.set(new SetFunctionPrototypeTool().execute(
                Map.of("function_address", "1000", "prototype", "int fixture(int value)"), program)));
            assertFalse(Boolean.TRUE.equals(result.get().isError()));
            assertEquals(1, function.getParameterCount());
            String signature = function.getSignature().toString(), comment = function.getComment();
            assertTrue(new SetFunctionPrototypeTool().execute(Map.of("function_address", "1000", "prototype", "invalid invalid ((("), program).isError());
            assertEquals(signature, function.getSignature().toString());
            assertEquals(comment, function.getComment());
        } finally { program.release(this); }
    }
}
