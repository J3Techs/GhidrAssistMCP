package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.ProgramIdentity;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * x86 ProgramDB coverage for structured {@code search_bytes}: entry vs interior vs
 * raw-block hits, executable-only default scan, cap/truncation uniqueness, and
 * invalid patterns.
 */
class SearchBytesStructuredProgramDbTest {
    private static final Object CONSUMER = new Object();
    private static final byte[] MOV_EAX_1 = {(byte) 0xb8, 0x01, 0x00, 0x00, 0x00};
    private static final String PATTERN = "b8 01 00 00 00";

    private ProgramDB program;
    private Address entryAddr;
    private Address interiorAddr;
    private Address blockAddr;
    private Address dataAddr;

    @BeforeAll
    static void init() throws Exception {
        if (!Application.isInitialized()) {
            Application.initializeApplication(
                new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))),
                new HeadlessGhidraApplicationConfiguration());
        }
    }

    @BeforeEach
    void fixture() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        program = new ProgramDB("search-bytes-fixture", language, language.getDefaultCompilerSpec(), CONSUMER);
        int tx = program.startTransaction("fixture");
        try {
            Address base = program.getAddressFactory().getAddress("1000");
            MemoryBlock text = program.getMemory().createInitializedBlock(
                "text", base, 0x100, (byte) 0xcc, TaskMonitor.DUMMY, false);
            text.setExecute(true);

            entryAddr = base;
            interiorAddr = base.add(5);
            blockAddr = base.add(0x20);
            program.getMemory().setBytes(entryAddr, MOV_EAX_1);
            program.getMemory().setBytes(interiorAddr, MOV_EAX_1);
            program.getMemory().setByte(base.add(10), (byte) 0xc3);
            program.getMemory().setBytes(blockAddr, MOV_EAX_1);
            program.getFunctionManager().createFunction("known_insn", entryAddr,
                new AddressSet(entryAddr, base.add(10)), SourceType.USER_DEFINED);

            dataAddr = program.getAddressFactory().getAddress("2000");
            MemoryBlock data = program.getMemory().createInitializedBlock(
                "data", dataAddr, 0x20, (byte) 0xcc, TaskMonitor.DUMMY, false);
            data.setExecute(false);
            program.getMemory().setBytes(dataAddr, MOV_EAX_1);
            program.endTransaction(tx, true);
        } catch (Exception e) {
            program.endTransaction(tx, false);
            throw e;
        }
    }

    @AfterEach
    void release() {
        if (program != null && !program.isClosed()) program.release(CONSUMER);
    }

    @Test
    void schemaIsDeclaredAndMissingProgramIsAnError() {
        SearchBytesTool tool = new SearchBytesTool();
        assertNotNull(tool.getOutputSchema());
        assertTrue(tool.execute(Map.of("pattern", PATTERN), null).isError());
        assertTrue(tool.isLongRunning());
    }

    @Test
    void knownInstructionHitsEntryInteriorAndRawBlockButNotNonExecutable() {
        Map<String, Object> body = ok(Map.of("pattern", PATTERN, "limit", 20));
        assertEquals(ProgramIdentity.id(program), body.get("program_id"));
        assertEquals(Long.toString(program.getModificationNumber()), body.get("modification_number"));
        assertEquals("executable_loaded_memory", body.get("scan_scope"));
        assertEquals(Boolean.TRUE, body.get("scan_complete"));
        assertEquals(Boolean.FALSE, body.get("scan_truncated"));
        assertEquals(Boolean.FALSE, body.get("cancelled"));
        assertEquals(Boolean.FALSE, body.get("unique"));
        assertEquals(3, body.get("candidate_count"));
        assertEquals(1, body.get("blocks_scanned"));

        List<Map<String, Object>> matches = matches(body);
        assertEquals(3, matches.size());

        Map<String, Map<String, Object>> byAddress = new HashMap<>();
        for (Map<String, Object> match : matches) {
            byAddress.put(String.valueOf(match.get("address")), match);
            assertEquals("text", match.get("block_name"));
            assertEquals(ProgramIdentity.id(program), match.get("program_id"));
            assertEquals(Long.toString(program.getModificationNumber()), match.get("modification_number"));
        }

        Map<String, Object> entry = byAddress.get(entryAddr.toString());
        Map<String, Object> interior = byAddress.get(interiorAddr.toString());
        Map<String, Object> rawBlock = byAddress.get(blockAddr.toString());
        assertNotNull(entry, () -> "missing entry hit in " + byAddress.keySet());
        assertNotNull(interior, () -> "missing interior hit in " + byAddress.keySet());
        assertNotNull(rawBlock, () -> "missing block hit in " + byAddress.keySet());

        assertEquals("entry", entry.get("position"));
        assertEquals(Boolean.TRUE, entry.get("at_entry"));
        assertEquals("known_insn", ((Map<?, ?>) entry.get("containing_function")).get("name"));
        assertEquals(entryAddr.toString(), ((Map<?, ?>) entry.get("containing_function")).get("entry"));

        assertEquals("interior", interior.get("position"));
        assertEquals(Boolean.FALSE, interior.get("at_entry"));
        assertEquals("known_insn", ((Map<?, ?>) interior.get("containing_function")).get("name"));

        assertEquals("block", rawBlock.get("position"));
        assertEquals(Boolean.FALSE, rawBlock.get("at_entry"));
        assertNull(rawBlock.get("containing_function"));

        Set<String> addresses = new HashSet<>(byAddress.keySet());
        assertFalse(addresses.contains(dataAddr.toString()), "non-executable data block must not be scanned");
    }

    @Test
    void capAndTruncationForceUniqueFalse() {
        Map<String, Object> capped = ok(Map.of("pattern", PATTERN, "limit", 1));
        assertEquals(1, capped.get("candidate_count"));
        assertEquals(1, capped.get("result_cap"));
        assertEquals(Boolean.TRUE, capped.get("scan_truncated"));
        assertEquals(Boolean.FALSE, capped.get("scan_complete"));
        assertEquals(Boolean.FALSE, capped.get("unique"));
        assertEquals(1, matches(capped).size());

        Map<String, Object> two = ok(Map.of("pattern", PATTERN, "limit", 2));
        assertEquals(2, two.get("candidate_count"));
        assertEquals(Boolean.TRUE, two.get("scan_truncated"));
        assertEquals(Boolean.FALSE, two.get("unique"));
    }

    @Test
    void invalidPatternAndLimitAreToolErrors() {
        SearchBytesTool tool = new SearchBytesTool();
        assertTrue(tool.execute(Map.of("pattern", "gg"), program).isError());
        assertTrue(tool.execute(Map.of("pattern", "abc"), program).isError());
        assertTrue(tool.execute(Map.of("pattern", "b8 01 0"), program).isError());
        assertTrue(tool.execute(Map.of("pattern", ""), program).isError());
        assertTrue(tool.execute(Map.of(), program).isError());
        assertTrue(tool.execute(Map.of("pattern", PATTERN, "limit", 0), program).isError());
        assertTrue(tool.execute(Map.of("pattern", PATTERN, "limit", 1001), program).isError());
        String message = text(tool.execute(Map.of("pattern", "zz"), program));
        assertTrue(message.toLowerCase().contains("invalid pattern"), message);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> ok(Map<String, Object> args) {
        McpSchema.CallToolResult result = new SearchBytesTool().execute(args, program);
        assertFalse(Boolean.TRUE.equals(result.isError()), () -> String.valueOf(result.content()));
        assertNotNull(result.structuredContent());
        assertTrue(result.content().stream().filter(McpSchema.TextContent.class::isInstance)
            .map(McpSchema.TextContent.class::cast).anyMatch(t -> {
                try { return new com.fasterxml.jackson.databind.ObjectMapper().readTree(t.text()).equals(
                    new com.fasterxml.jackson.databind.ObjectMapper().readTree(
                        new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(result.structuredContent()))); }
                catch (Exception e) { return false; }
            }), "standalone equivalent JSON text fallback is required");
        return (Map<String, Object>) result.structuredContent();
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> matches(Map<String, Object> body) {
        return (List<Map<String, Object>>) body.get("matches");
    }

    private static String text(McpSchema.CallToolResult result) {
        return ((McpSchema.TextContent) result.content().getFirst()).text();
    }
}
