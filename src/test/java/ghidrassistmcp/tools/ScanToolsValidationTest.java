package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;
import java.lang.reflect.Proxy;
import java.math.BigInteger;

import org.junit.jupiter.api.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.ProgramContext;

class ScanToolsValidationTest {
    @Test
    void instructionLimitsAreExplicitAndBounded() {
        Map<?, ?> limitSchema = (Map<?, ?>) new ScanInstructionsTool().getInputSchema().properties().get("max_instructions");
        assertEquals(1, limitSchema.get("minimum"));
        assertEquals(100000, limitSchema.get("maximum"));
        Map<?, ?> mnemonics = (Map<?, ?>) new ScanInstructionsTool().getInputSchema().properties().get("mnemonics");
        assertEquals(256, mnemonics.get("maxItems"));
        assertEquals(1000, ScanInstructionsTool.limit(null));
        assertEquals(12, ScanInstructionsTool.limit(12));
        assertThrows(IllegalArgumentException.class, () -> ScanInstructionsTool.limit(0));
        assertThrows(IllegalArgumentException.class, () -> ScanInstructionsTool.limit(100001));
        assertThrows(IllegalArgumentException.class, () -> ScanInstructionsTool.limit("12"));
    }

    @Test
    void mnemonicPredicateRequiresStringArrayAndPreservesValues() {
        assertEquals(List.of("mov", "lea"), ScanInstructionsTool.strings(List.of("mov", "lea")));
        assertEquals(List.of(), ScanInstructionsTool.strings(null));
        assertThrows(IllegalArgumentException.class, () -> ScanInstructionsTool.strings(Map.of()));
        assertThrows(IllegalArgumentException.class, () -> ScanInstructionsTool.strings(List.of("")));
    }

    @Test
    void mutatingCandidateToolDefaultsToPreviewAndSetterIsMarkedMutable() {
        assertTrue(new RunScriptTool().isOpenWorld());
        assertTrue(new ScanFunctionCandidatesTool().getDescription().contains("preview"));
        assertFalse(new ScanFunctionCandidatesTool().isReadOnly());
        assertFalse(new SetRegisterContextTool().isReadOnly());
        assertTrue(new ScanInstructionsTool().isReadOnly());
        assertEquals("get_register_context", new GetRegisterContextTool().getName());
    }

    @Test
    void valueSegmentsDetectInteriorRegisterChangesWithEqualEndpoints() {
        AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        Address a = space.getAddress(0x100), b = space.getAddress(0x104), c = space.getAddress(0x108), d = space.getAddress(0x10c);
        AddressRange first = range(a, b), middle = range(b, c), last = range(c, d);
        AddressRangeIterator iterator = iterator(List.of(first, middle, last));
        // The proxy context ignores the register identity; using null keeps this test
        // independent of a live language/ProgramDB fixture while exercising intervals.
        ghidra.program.model.lang.Register register = null;
        ProgramContext context = (ProgramContext) Proxy.newProxyInstance(ProgramContext.class.getClassLoader(),
            new Class<?>[] {ProgramContext.class}, (p, m, x) -> {
                if (m.getName().equals("getRegisterValueAddressRanges")) return iterator(List.of(first, middle, last));
                if (m.getName().equals("getValue")) return ((Address) x[1]).equals(b) ? BigInteger.TWO : BigInteger.ONE;
                throw new UnsupportedOperationException(m.getName());
            });
        List<SetRegisterContextTool.ValueSegment> segments = SetRegisterContextTool.valueSegments(
            context, register, new SetRegisterContextTool.AddressRange(a, d), 10);
        assertEquals(3, segments.size());
        assertEquals(BigInteger.ONE, segments.get(0).value);
        assertEquals(BigInteger.TWO, segments.get(1).value);
        assertEquals(BigInteger.ONE, segments.get(2).value);
    }

    private static AddressRange range(Address min, Address max) {
        return (AddressRange) Proxy.newProxyInstance(AddressRange.class.getClassLoader(),
            new Class<?>[] {AddressRange.class}, (p, m, x) -> switch (m.getName()) {
                case "getMinAddress" -> min;
                case "getMaxAddress" -> max.subtract(1);
                default -> throw new UnsupportedOperationException(m.getName());
            });
    }
    private static AddressRangeIterator iterator(List<AddressRange> ranges) {
        java.util.Iterator<AddressRange> it = ranges.iterator();
        return (AddressRangeIterator) Proxy.newProxyInstance(AddressRangeIterator.class.getClassLoader(),
            new Class<?>[] {AddressRangeIterator.class}, (p, m, x) -> switch (m.getName()) {
                case "hasNext" -> it.hasNext();
                case "next" -> it.next();
                default -> throw new UnsupportedOperationException(m.getName());
            });
    }
}
