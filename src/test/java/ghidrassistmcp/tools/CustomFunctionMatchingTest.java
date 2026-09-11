package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Proxy;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

class CustomFunctionMatchingTest {
    private final ListFunctionsTool tool = new ListFunctionsTool();

    @Test
    void basenameGlobStillMatchesNamespacedFunctions() {
        String result = text(tool.execute(Map.of("pattern", "Read*"), program()));
        assertTrue(result.contains("Core::ReadData"));
        assertFalse(result.contains("Other::WriteData"));
    }

    @Test
    void qualifiedGlobAndRegexCanSelectNamespaces() {
        String glob = text(tool.execute(Map.of("pattern", "Other::*"), program()));
        assertTrue(glob.contains("Other::WriteData"));
        assertFalse(glob.contains("Core::ReadData"));
        String regex = text(tool.execute(Map.of("pattern", "Core::Read.*", "match_mode", "regex"), program()));
        assertTrue(regex.contains("Core::ReadData"));
        assertFalse(regex.contains("Other::WriteData"));
    }

    @Test
    void paginationCountsMatchesAndInvalidRegexReturnsAnError() {
        String result = text(tool.execute(Map.of("pattern", "*Data", "offset", 1, "limit", 1), program()));
        assertTrue(result.contains("Other::WriteData"));
        assertFalse(result.contains("Core::ReadData"));
        assertTrue(tool.execute(Map.of("pattern", "[", "match_mode", "regex"), program()).isError());
    }

    private static String text(McpSchema.CallToolResult result) {
        return ((McpSchema.TextContent) result.content().get(0)).text();
    }

    private static Program program() {
        FunctionManager manager = (FunctionManager) Proxy.newProxyInstance(
            FunctionManager.class.getClassLoader(), new Class<?>[] {FunctionManager.class},
            (proxy, method, args) -> {
                if (method.getName().equals("getFunctions")) {
                    Iterator<Function> functions = List.of(function("ReadData", "Core", 0x100),
                        function("WriteData", "Other", 0x200)).iterator();
                    return new FunctionIterator() {
                        @Override public boolean hasNext() { return functions.hasNext(); }
                        @Override public Function next() { return functions.next(); }
                        @Override public Iterator<Function> iterator() { return this; }
                    };
                }
                throw new UnsupportedOperationException(method.getName());
            });
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] {Program.class}, (proxy, method, args) -> {
                if (method.getName().equals("getFunctionManager")) return manager;
                throw new UnsupportedOperationException(method.getName());
            });
    }

    private static Function function(String name, String namespace, int offset) {
        AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        return (Function) Proxy.newProxyInstance(Function.class.getClassLoader(),
            new Class<?>[] {Function.class}, (proxy, method, args) -> switch (method.getName()) {
                case "getName" -> args != null && Boolean.TRUE.equals(args[0]) ? namespace + "::" + name : name;
                case "getEntryPoint" -> space.getAddress(offset);
                case "getParameterCount" -> 0;
                default -> throw new UnsupportedOperationException(method.getName());
            });
    }
}
