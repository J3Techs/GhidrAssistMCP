package ghidrassistmcp.bsim;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
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

class BsimComparisonTest {
    private static final Object CONSUMER = new Object();

    @BeforeAll
    static void initializeGhidra() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(
            new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))),
            new HeadlessGhidraApplicationConfiguration());
    }

    @Test
    void comparesTwoFunctionsWithoutDatabase() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        Program program = new ProgramDB("comparison", language, language.getDefaultCompilerSpec(), CONSUMER);
        try {
            int tx = program.startTransaction("comparison fixture");
            try {
                Address base = program.getAddressFactory().getAddress("1000");
                program.getMemory().createInitializedBlock("text", base, 0x300, (byte) 0x90,
                    TaskMonitor.DUMMY, false).setExecute(true);
                byte[] same = {(byte) 0x8b, (byte) 0x44, (byte) 0x24, (byte) 0x04,
                    (byte) 0x83, (byte) 0xc0, (byte) 0x07, (byte) 0xc3};
                byte[] different = {(byte) 0x31, (byte) 0xc0, (byte) 0x40, (byte) 0xc3};
                Address second = base.add(0x40), third = base.add(0x80);
                program.getMemory().setBytes(base, same);
                program.getMemory().setBytes(second, same);
                program.getMemory().setBytes(third, different);
                new DisassembleCommand(base, new AddressSet(base, base.add(7)), false).applyTo(program, TaskMonitor.DUMMY);
                new DisassembleCommand(second, new AddressSet(second, second.add(7)), false).applyTo(program, TaskMonitor.DUMMY);
                new DisassembleCommand(third, new AddressSet(third, third.add(3)), false).applyTo(program, TaskMonitor.DUMMY);
                program.getFunctionManager().createFunction("same_left", base, new AddressSet(base, base.add(7)), SourceType.USER_DEFINED);
                program.getFunctionManager().createFunction("same_right", second, new AddressSet(second, second.add(7)), SourceType.USER_DEFINED);
                program.getFunctionManager().createFunction("different", third, new AddressSet(third, third.add(3)), SourceType.USER_DEFINED);
                program.endTransaction(tx, true);
            } catch (Exception e) { program.endTransaction(tx, false); throw e; }
            BsimContext context = new BsimContext(program, null, null, java.nio.file.Files.createTempDirectory("bsim-compare"), null);
            BsimOperation compare = BsimQueryOperations.operations().stream()
                .filter(operation -> operation.name().equals("compare_functions")).findFirst().orElseThrow();
            Map<String, Object> equal = compare.handler().execute(context,
                Map.of("left", "1000", "right", "1040"), TaskMonitor.DUMMY);
            assertTrue(((Number) equal.get("similarity")).doubleValue() > 0.99, equal::toString);
            Map<String, Object> unequal = compare.handler().execute(context,
                Map.of("left", "1000", "right", "1080"), TaskMonitor.DUMMY);
            assertTrue(((Number) unequal.get("similarity")).doubleValue() < 0.99, unequal::toString);
        } finally { program.release(CONSUMER); }
    }
}
