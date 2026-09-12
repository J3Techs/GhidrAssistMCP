package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Proxy;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.BiFunction;

import org.junit.jupiter.api.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.*;

class SearchQueryContractTest {
    @Test
    void pageBoundsRejectTruncationOverflowAndInvalidTypes() {
        for (Object invalid : List.of(-1, 0, 1001, 1.5, Long.MAX_VALUE, Double.NaN, "100")) {
            assertThrows(IllegalArgumentException.class,
                () -> QueryPageBounds.integer(Map.of("limit", invalid), "limit", 100, 1, 1000));
        }
        assertEquals(100, QueryPageBounds.integer(Map.of(), "limit", 100, 1, 1000));
        assertEquals(1000, QueryPageBounds.integer(Map.of("limit", new BigDecimal("1000.0")), "limit", 100, 1, 1000));
    }

    @Test
    void missingProgramsAndBadInputsAreToolErrors() {
        assertTrue(new SearchStringsTool().execute(Map.of("pattern", "x"), null).isError());
        assertTrue(new SearchFunctionsByNameTool().execute(Map.of("search_term", "x"), null).isError());
        assertTrue(new ListStringsTool().execute(Map.of(), null).isError());
        Program unused = proxy(Program.class, (method, args) -> { throw new AssertionError(method); });
        assertTrue(new SearchStringsTool().execute(Map.of("pattern", 123), unused).isError());
        assertTrue(new SearchFunctionsByNameTool().execute(Map.of("search_term", "x", "limit", 0), unused).isError());
        assertTrue(new ListStringsTool().execute(Map.of("offset", -1), unused).isError());
    }

    @Test
    void searchPagesSkipMatchesAndDistinguishExactLimitFromTruncation() {
        var tool = new SearchFunctionsByNameTool();
        Program program = functionProgram(List.of("match_one", "other", "match_two", "match_three"));
        Map<?, ?> first = (Map<?, ?>) tool.execute(Map.of("search_term", "match", "limit", 2), program).structuredContent();
        assertEquals(true, first.get("has_more"));
        assertEquals(2L, first.get("next_offset"));
        assertEquals(2, ((List<?>) first.get("functions")).size());
        Map<?, ?> second = (Map<?, ?>) tool.execute(Map.of("search_term", "match", "limit", 2, "offset", 2), program).structuredContent();
        assertEquals(false, second.get("has_more"));
        assertNull(second.get("next_offset"));
        assertEquals("match_three", ((Map<?, ?>) ((List<?>) second.get("functions")).getFirst()).get("name"));
        Map<?, ?> exact = (Map<?, ?>) tool.execute(Map.of("search_term", "match", "limit", 3), program).structuredContent();
        assertEquals(false, exact.get("has_more"));
    }

    @Test
    void stringPagesBoundValuesAndHandleNoFurtherMatches() {
        var tool = new SearchStringsTool();
        Program program = stringProgram(List.of("match" + "x".repeat(500), "other", "match_two"));
        Map<?, ?> page = (Map<?, ?>) tool.execute(Map.of("pattern", "match", "limit", 1), program).structuredContent();
        assertEquals(true, page.get("has_more"));
        Map<?, ?> row = (Map<?, ?>) ((List<?>) page.get("strings")).getFirst();
        assertEquals(256, ((String) row.get("value")).length());
        assertEquals(505, row.get("length"));
        assertEquals(true, row.get("value_truncated"));
        Map<?, ?> end = (Map<?, ?>) tool.execute(Map.of("pattern", "match", "offset", 2), program).structuredContent();
        assertEquals(false, end.get("has_more"));
        assertEquals(0, end.get("count"));
    }

    @Test
    void caseInsensitiveSearchDoesNotDependOnHostLocale() {
        Locale original = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            assertEquals(1, ((Map<?, ?>) new SearchFunctionsByNameTool().execute(Map.of("search_term", "init"), functionProgram(List.of("INIT"))).structuredContent()).get("count"));
            assertEquals(1, ((Map<?, ?>) new SearchStringsTool().execute(Map.of("pattern", "init"), stringProgram(List.of("INIT"))).structuredContent()).get("count"));
        } finally { Locale.setDefault(original); }
    }

    @Test
    void interruptedQueriesReturnErrorsAndPreserveInterruptFlag() {
        Thread.currentThread().interrupt();
        try {
            assertTrue(new SearchFunctionsByNameTool().execute(Map.of("search_term", "x"), functionProgram(List.of("x"))).isError());
            assertTrue(new SearchStringsTool().execute(Map.of("pattern", "x"), stringProgram(List.of("x"))).isError());
            assertTrue(new ListStringsTool().execute(Map.of(), stringProgram(List.of("xxxx"))).isError());
            assertTrue(Thread.currentThread().isInterrupted());
        } finally { Thread.interrupted(); }
    }

    @Test
    void structuredSearchesAlsoIncludeSerializedJsonTextFallback() throws Exception {
        var result = new SearchFunctionsByNameTool().execute(Map.of("search_term", "x"), functionProgram(List.of("x")));
        assertEquals(2, result.content().size());
        String json = ((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().get(1)).text();
        var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        assertEquals(mapper.valueToTree(result.structuredContent()), mapper.readTree(json));
        var strings = new SearchStringsTool().execute(Map.of("pattern", "x"), stringProgram(List.of("x")));
        String stringJson = ((io.modelcontextprotocol.spec.McpSchema.TextContent) strings.content().get(1)).text();
        assertEquals(mapper.valueToTree(strings.structuredContent()), mapper.readTree(stringJson));
    }

    private static Program functionProgram(List<String> names) {
        List<Function> functions = new ArrayList<>();
        for (int i = 0; i < names.size(); i++) {
            String name = names.get(i); Address address = address(i);
            functions.add(proxy(Function.class, (method, args) -> switch (method) {
                case "getName" -> name;
                case "getEntryPoint" -> address;
                case "getParameterCount" -> 0;
                default -> throw new AssertionError(method);
            }));
        }
        FunctionManager manager = proxy(FunctionManager.class, (method, args) -> {
            if (method.equals("getFunctions")) return iterator(FunctionIterator.class, functions);
            throw new AssertionError(method);
        });
        return proxy(Program.class, (method, args) -> {
            if (method.equals("getFunctionManager")) return manager;
            throw new AssertionError(method);
        });
    }

    private static Program stringProgram(List<String> values) {
        List<Data> data = new ArrayList<>();
        for (int i = 0; i < values.size(); i++) {
            String value = values.get(i); Address address = address(i);
            data.add(proxy(Data.class, (method, args) -> switch (method) {
                case "hasStringValue" -> true;
                case "getDefaultValueRepresentation" -> "\"" + value + "\"";
                case "getAddress" -> address;
                default -> throw new AssertionError(method);
            }));
        }
        Listing listing = proxy(Listing.class, (method, args) -> {
            if (method.equals("getDefinedData")) return iterator(DataIterator.class, data);
            throw new AssertionError(method);
        });
        return proxy(Program.class, (method, args) -> {
            if (method.equals("getListing")) return listing;
            throw new AssertionError(method);
        });
    }

    private static Address address(int offset) {
        return new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0).getAddress(0x1000 + offset);
    }

    private static <T> T iterator(Class<T> type, List<?> values) {
        var iterator = values.iterator();
        Object[] self = new Object[1];
        self[0] = proxy(type, (method, args) -> switch (method) {
            case "hasNext" -> iterator.hasNext();
            case "next" -> iterator.next();
            case "iterator" -> self[0];
            default -> throw new AssertionError(method);
        });
        return type.cast(self[0]);
    }

    private static <T> T proxy(Class<T> type, BiFunction<String, Object[], Object> invocation) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type },
            (object, method, args) -> invocation.apply(method.getName(), args)));
    }
}
