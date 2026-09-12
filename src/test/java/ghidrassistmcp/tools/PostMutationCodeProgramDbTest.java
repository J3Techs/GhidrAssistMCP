package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.io.File;
import java.util.Map;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import org.junit.jupiter.api.Test;

/** Real database coverage for committed prototype return semantics. */
class PostMutationCodeProgramDbTest {
    @Test void returnCodeReportsStoredPrototypeAndDuplicateCommentIsIdempotent() throws Exception {
        init();
        var lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB("post-code-fixture", lang, lang.getDefaultCompilerSpec(), this);
        try {
            var address = program.getAddressFactory().getAddress("1000");
            int tx = program.startTransaction("fixture");
            var function = program.getFunctionManager().createFunction("fixture", address, new AddressSet(address), SourceType.USER_DEFINED);
            program.endTransaction(tx, true);
            var tool = new SetFunctionPrototypeTool();
            Map<String, Object> args = Map.of("function_address", "1000", "prototype", "int fixture(int value)", "return_code", true);
            var first = tool.execute(args, program);
            assertFalse(Boolean.TRUE.equals(first.isError()));
            assertTrue(String.valueOf(first.structuredContent()).contains("stored_prototype"));
            String comment = function.getComment();
            tool.execute(args, program);
            assertEquals(comment, function.getComment());
            assertTrue(tool.execute(Map.of("function_address", "1000", "prototype", "int bad(void)", "max_chars", 0), program).isError());
            assertEquals("int fixture(int value)", function.getSignature().toString());
        } finally { program.release(this); }
    }

    @Test void variablesPrototypeDelegatesAndReturnsStoredSignature() throws Exception {
        init();
        var lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB("variables-prototype-fixture", lang, lang.getDefaultCompilerSpec(), this);
        try {
            var address = program.getAddressFactory().getAddress("1000");
            int tx = program.startTransaction("fixture");
            program.getFunctionManager().createFunction("fixture", address, new AddressSet(address), SourceType.USER_DEFINED);
            program.endTransaction(tx, true);
            var result = new VariablesTool(null).execute(Map.of("action", "set_prototype", "function_address", "1000",
                "prototype", "int fixture(int value)", "return_code", true), program);
            assertFalse(Boolean.TRUE.equals(result.isError()));
            assertTrue(String.valueOf(result.structuredContent()).contains("stored_prototype"));
        } finally { program.release(this); }
    }

    private static void init() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(new GhidraApplicationLayout(
            new File(System.getProperty("ghidra.install.dir"))), new HeadlessGhidraApplicationConfiguration());
    }
}
