package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

/**
 * WP08 ProgramDB instruction/context fixtures for {@link InstructionMaskBuilder}.
 * Does not exercise {@code LanguageFacts.fromLanguageId}.
 *
 * Expected builder API:
 * {@code Plan plan(Program, Function, byte[], MaskMode, TaskMonitor)}
 * {@code Plan plan(Program, Address, int length, byte[], MaskMode, TaskMonitor)}
 * {@code InstructionMaskBuilder.Kind}: RAW, RELOCATABLE_OPERANDS, UNSUPPORTED.
 */
class MatcherInstructionProgramDbTest {
    static final String X86 = "x86:LE:32:default";
    static final String ARM = "ARM:LE:32:v7";
    static final String THUMB = "ARM:LE:32:v8T";
    static final String VLE = "PowerPC:BE:64:VLE-32addr";

    // push ebp; mov ebp,esp; call +5; pop ebp; ret
    static final byte[] X86_CALL = hex("55 8B EC E8 05 00 00 00 5D C3");
    static final byte[] X86_CALL_RELOC = hex("55 8B EC E8 10 00 00 00 5D C3");
    static final byte[] X86_JMP = hex("55 8B EC E9 05 00 00 00 5D C3");
    static final int[] X86_OPCODES = { 0, 1, 2, 3, 8, 9 };
    static final int[] X86_DISP = { 4, 5, 6, 7 };

    // mov r0,#0; bl +0; bx lr
    static final byte[] ARM_BL = hex("00 00 A0 E3 00 00 00 EB 1E FF 2F E1");
    static final byte[] ARM_BL_RELOC = hex("00 00 A0 E3 04 00 00 EB 1E FF 2F E1");
    static final byte[] ARM_B = hex("00 00 A0 E3 00 00 00 EA 1E FF 2F E1");
    static final int[] ARM_OPCODES = { 0, 1, 2, 3, 7, 8, 9, 10, 11 };
    static final int[] ARM_DISP = { 4, 5, 6 };

    // push {lr}; bl #0; pop {pc}
    static final byte[] THUMB_BL = hex("00 B5 00 F0 00 F8 00 BD");
    static final byte[] THUMB_BL_RELOC = hex("00 B5 00 F0 02 F8 00 BD");
    static final byte[] THUMB_BW = hex("00 B5 00 F0 00 B8 00 BD");
    // Byte 3 contains low BL displacement bits in this Ghidra prototype mask.
    static final int[] THUMB_OPCODES = { 0, 1, 6, 7 };
    static final int[] THUMB_DISP = { 2, 4 };

    // se_li r3,0; e_bl +0; se_blr
    static final byte[] VLE_EBL = hex("48 03 78 00 00 01 00 04");
    static final byte[] VLE_EBL_RELOC = hex("48 03 78 00 00 05 00 04");
    static final byte[] VLE_EB = hex("48 03 78 00 00 00 00 04");
    // The low bit of byte 2 belongs to the branch displacement; high 7 bits are opcode.
    static final int[] VLE_OPCODES = { 0, 1, 6, 7 };
    static final int[] VLE_DISP = { 3, 4 };

    @BeforeAll
    static void init() throws Exception {
        if (!Application.isInitialized()) {
            Application.initializeApplication(
                new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))),
                new HeadlessGhidraApplicationConfiguration());
        }
    }

    @Test
    void x86NoneIsAlwaysRawAndSound() throws Exception {
        try (Fixture f = Fixture.function(X86, X86_CALL, null, 0)) {
            InstructionMaskBuilder.Plan none = plan(f, MatcherContracts.MaskMode.NONE);
            assertEquals(InstructionMaskBuilder.Kind.RAW, none.kind());
            assertTrue(none.sound(), none.explanation());
            assertEquals(f.bytes.length, none.mask().length);
            assertAllFf(none.mask());
        }
        try (Fixture f = Fixture.function(X86, hex("E8 05 00 00 00"), null, 0)) {
            InstructionMaskBuilder.Plan none = plan(f, MatcherContracts.MaskMode.NONE);
            assertEquals(InstructionMaskBuilder.Kind.RAW, none.kind());
            assertTrue(none.sound(), none.explanation());
            assertEquals(f.bytes.length, none.mask().length);
            assertAllFf(none.mask());
        }
    }

    @Test
    void x86CompoundMemoryOperandPreservesBaseRegister() throws Exception {
        byte[] original = hex("55 8B EC 8B 43 04 5D C3");
        byte[] differentRegister = hex("55 8B EC 8B 41 04 5D C3");
        try (Fixture f = Fixture.function(X86, original, null, 0)) {
            var mask = plan(f, MatcherContracts.MaskMode.AUTO);
            assertTrue(mask.sound(), mask.explanation());
            assertFalse(maskedEqual(original, differentRegister, mask.mask()), "base register must discriminate candidates");
        }
    }

    @Test
    void x86GenuineCallCorrespondenceMasksRelocationAndNoneDistinguishes() throws Exception {
        try (Fixture f = Fixture.function(X86, X86_CALL, null, 0)) {
            requireMnemonic(f, "CALL");
            assertGenuineRelocation(f, X86_CALL_RELOC, X86_OPCODES, X86_DISP);
        }
    }

    @Test
    void x86DifferentOpcodeCallVsJmpKeepsDiscriminatingBits() throws Exception {
        try (Fixture f = Fixture.function(X86, X86_CALL, null, 0)) {
            requireMnemonic(f, "CALL");
            assertNegativeOpcode(f, X86_JMP);
        }
    }

    @Test
    void x86LowInformationWindowIsUnsupported() throws Exception {
        try (Fixture f = Fixture.function(X86, hex("E8 05 00 00 00"), null, 0)) {
            assertUnsupportedAuto(f, "x86 CALL-only window is almost-all-operand");
        }
        try (Fixture f = Fixture.disassembled(X86, X86_CALL, null, 0)) {
            byte[] disp = new byte[] { 0x05, 0x00 };
            InstructionMaskBuilder.Plan auto = rangePlan(f, f.base.add(4), 2, disp, MatcherContracts.MaskMode.AUTO);
            assertUnsupported(auto, "too-short x86 displacement window");
        }
    }

    @Test
    void x86InteriorDisassemblyWithoutFunctionPlansHonestly() throws Exception {
        try (Fixture f = Fixture.disassembled(X86, X86_CALL, null, 0)) {
            assertNull(f.function);
            assertInteriorPlan(f, X86_CALL_RELOC, X86_OPCODES, X86_DISP);
        }
    }

    @Test
    void armGenuineBlCorrespondenceMasksRelocationAndNoneDistinguishes() throws Exception {
        try (Fixture f = Fixture.function(ARM, ARM_BL, "TMode", 0)) {
            requireMnemonicOrGap(f, ARM, "bl");
            assertGenuineRelocation(f, ARM_BL_RELOC, ARM_OPCODES, ARM_DISP);
        }
    }

    @Test
    void armDifferentOpcodeBlVsBKeepsDiscriminatingBits() throws Exception {
        try (Fixture f = Fixture.function(ARM, ARM_BL, "TMode", 0)) {
            requireMnemonicOrGap(f, ARM, "bl");
            assertNegativeOpcode(f, ARM_B);
        }
    }

    @Test
    void armLowInformationWindowIsUnsupported() throws Exception {
        try (Fixture f = Fixture.function(ARM, hex("00 00 00 EB"), "TMode", 0)) {
            assertUnsupportedAuto(f, "ARM BL-only window is almost-all-operand");
        }
    }

    @Test
    void armInteriorDisassemblyWithoutFunctionPlansHonestly() throws Exception {
        try (Fixture f = Fixture.disassembled(ARM, ARM_BL, "TMode", 0)) {
            assertNull(f.function);
            requireMnemonicOrGap(f, ARM, "bl");
            assertInteriorPlan(f, ARM_BL_RELOC, ARM_OPCODES, ARM_DISP);
        }
    }

    @Test
    void thumbGenuineBlCorrespondenceMasksRelocationAndNoneDistinguishes() throws Exception {
        try (Fixture f = Fixture.function(THUMB, THUMB_BL, "TMode", 1)) {
            requireMnemonicOrGap(f, THUMB, "bl");
            assertGenuineRelocation(f, THUMB_BL_RELOC, THUMB_OPCODES, THUMB_DISP);
        }
    }

    @Test
    void thumbDifferentOpcodeBlVsBwKeepsDiscriminatingBits() throws Exception {
        try (Fixture f = Fixture.function(THUMB, THUMB_BL, "TMode", 1)) {
            requireMnemonicOrGap(f, THUMB, "bl");
            assertNegativeOpcode(f, THUMB_BW);
        }
    }

    @Test
    void thumbLowInformationWindowIsUnsupported() throws Exception {
        try (Fixture f = Fixture.function(THUMB, hex("00 F0 00 F8"), "TMode", 1)) {
            assertUnsupportedAuto(f, "Thumb BL-only window is almost-all-operand");
        }
    }

    @Test
    void thumbInteriorDisassemblyWithoutFunctionPlansHonestly() throws Exception {
        try (Fixture f = Fixture.disassembled(THUMB, THUMB_BL, "TMode", 1)) {
            assertNull(f.function);
            requireMnemonicOrGap(f, THUMB, "bl");
            assertInteriorPlan(f, THUMB_BL_RELOC, THUMB_OPCODES, THUMB_DISP);
        }
    }

    @Test
    void mixedTModeWindowIsUnsupportedWhilePureArmAndThumbQualifySeparately() throws Exception {
        try (Fixture f = Fixture.mixedArmThumb()) {
            assertNotNull(f.function);
            assertNotNull(f.secondary);
            InstructionMaskBuilder.Plan mixedAuto = rangePlan(f, f.base, f.bytes.length, f.bytes, MatcherContracts.MaskMode.AUTO);
            assertEquals(InstructionMaskBuilder.Kind.UNSUPPORTED, mixedAuto.kind(),
                "mixed TMode in one window must be UNSUPPORTED: " + mixedAuto.explanation());
            assertFalse(mixedAuto.sound(), "mixed TMode must not claim a sound mask: " + mixedAuto.explanation());

            InstructionMaskBuilder.Plan armPlan = InstructionMaskBuilder.plan(
                f.program, f.function, ARM_BL, MatcherContracts.MaskMode.AUTO, TaskMonitor.DUMMY);
            InstructionMaskBuilder.Plan thumbPlan = InstructionMaskBuilder.plan(
                f.program, f.secondary, THUMB_BL, MatcherContracts.MaskMode.AUTO, TaskMonitor.DUMMY);
            assertTrue(hasMnemonic(f, f.base, ARM_BL.length, "bl")
                    && hasRelocatableInstruction(f, f.base, ARM_BL.length), f.listing());
            assertEquals(InstructionMaskBuilder.Kind.RELOCATABLE_OPERANDS, armPlan.kind(), armPlan.explanation());
            assertTrue(armPlan.sound(), armPlan.explanation());
            assertTrue(hasMnemonic(f, f.base.add(ARM_BL.length), THUMB_BL.length, "bl")
                    && hasRelocatableInstruction(f, f.base.add(ARM_BL.length), THUMB_BL.length), f.listing());
            assertEquals(InstructionMaskBuilder.Kind.RELOCATABLE_OPERANDS, thumbPlan.kind(), thumbPlan.explanation());
            assertTrue(thumbPlan.sound(), thumbPlan.explanation());
        }
    }

    @Test
    void vleGenuineEblCorrespondenceMasksRelocationAndNoneDistinguishes() throws Exception {
        try (Fixture f = Fixture.function(VLE, VLE_EBL, "vle", 1)) {
            requireMnemonicOrGap(f, VLE, "e_bl");
            assertGenuineRelocation(f, VLE_EBL_RELOC, VLE_OPCODES, VLE_DISP);
        }
    }

    @Test
    void vleDifferentMnemonicEblVsEbKeepsDiscriminatingBits() throws Exception {
        try (Fixture f = Fixture.function(VLE, VLE_EBL, "vle", 1)) {
            requireMnemonicOrGap(f, VLE, "e_bl");
            assertNegativeOpcode(f, VLE_EB);
        }
    }

    @Test
    void vleLowInformationWindowIsUnsupported() throws Exception {
        try (Fixture f = Fixture.function(VLE, hex("78 00 00 01"), "vle", 1)) {
            assertUnsupportedAuto(f, "VLE e_bl-only window is almost-all-operand");
        }
    }

    @Test
    void vleInteriorDisassemblyWithoutFunctionPlansHonestly() throws Exception {
        try (Fixture f = Fixture.disassembled(VLE, VLE_EBL, "vle", 1)) {
            assertNull(f.function);
            requireMnemonicOrGap(f, VLE, "e_bl");
            assertInteriorPlan(f, VLE_EBL_RELOC, VLE_OPCODES, VLE_DISP);
        }
    }

    private static InstructionMaskBuilder.Plan plan(Fixture f, MatcherContracts.MaskMode mode) {
        assertNotNull(f.function, "function plan requires a function");
        return InstructionMaskBuilder.plan(f.program, f.function, f.bytes, mode, TaskMonitor.DUMMY);
    }

    private static InstructionMaskBuilder.Plan rangePlan(Fixture f, Address start, int length, byte[] sourceBytes,
            MatcherContracts.MaskMode mode) {
        return InstructionMaskBuilder.plan(f.program, start, length, sourceBytes, mode, TaskMonitor.DUMMY);
    }

    private static void assertGenuineRelocation(Fixture f, byte[] relocated, int[] opcodeOffsets, int[] operandOffsets) {
        assertTrue(hasRelocatableInstruction(f),
            "fixture must decode a named instruction with an address/relative operand: " + f.listing());
        InstructionMaskBuilder.Plan auto = plan(f, MatcherContracts.MaskMode.AUTO);
        assertEquals(InstructionMaskBuilder.Kind.RELOCATABLE_OPERANDS, auto.kind(),
            "AUTO must qualify relocatable operands: " + auto.explanation() + " listing=" + f.listing());
        assertTrue(auto.sound(), auto.explanation());
        assertNotNull(auto.mask());
        assertEquals(f.bytes.length, auto.mask().length);
        assertMaskedEqual(f.bytes, relocated, auto.mask());
        assertOperandAndOpcodeBytes(f.bytes, relocated, auto.mask(), opcodeOffsets, operandOffsets, auto.explanation());

        InstructionMaskBuilder.Plan none = plan(f, MatcherContracts.MaskMode.NONE);
        assertEquals(InstructionMaskBuilder.Kind.RAW, none.kind(), none.explanation());
        assertTrue(none.sound(), none.explanation());
        assertEquals(f.bytes.length, none.mask().length);
        assertAllFf(none.mask());
        assertFalse(maskedEqual(f.bytes, relocated, none.mask()),
            "NONE/raw must distinguish relocated immediates");
        assertTrue(maskedEqual(f.bytes, relocated, auto.mask()),
            "AUTO must still match after relocation of operand bits only");
    }

    private static void assertNegativeOpcode(Fixture f, byte[] otherOpcode) {
        InstructionMaskBuilder.Plan auto = plan(f, MatcherContracts.MaskMode.AUTO);
        if (auto.kind() == InstructionMaskBuilder.Kind.UNSUPPORTED) {
            assertUnsupported(auto, "low-information reject of opcode-change window");
            return;
        }
        assertEquals(InstructionMaskBuilder.Kind.RELOCATABLE_OPERANDS, auto.kind(), auto.explanation());
        assertTrue(auto.sound(), auto.explanation());
        assertTrue(unmaskedBitsDiffer(f.bytes, otherOpcode, auto.mask()),
            "remaining 0xFF bits must distinguish different opcodes; mask=" + hex(auto.mask())
                + " explanation=" + auto.explanation());
    }

    private static void assertUnsupportedAuto(Fixture f, String why) {
        InstructionMaskBuilder.Plan auto = plan(f, MatcherContracts.MaskMode.AUTO);
        assertUnsupported(auto, why);
    }

    private static void assertUnsupported(InstructionMaskBuilder.Plan plan, String why) {
        assertEquals(InstructionMaskBuilder.Kind.UNSUPPORTED, plan.kind(),
            why + ": " + plan.explanation());
        assertFalse(plan.sound(), why + " must not claim a sound hollow mask: " + plan.explanation());
        if (plan.mask() != null) {
            assertFalse(plan.sound() && isHollow(plan.mask()),
                why + " returned a hollow mask: " + hex(plan.mask()));
        }
        assertNotNull(plan.explanation());
        assertFalse(plan.explanation().isBlank());
    }

    private static void assertInteriorPlan(Fixture f, byte[] relocated, int[] opcodeOffsets, int[] operandOffsets) {
        InstructionMaskBuilder.Plan auto = rangePlan(f, f.base, f.bytes.length, f.bytes, MatcherContracts.MaskMode.AUTO);
        if (auto.kind() == InstructionMaskBuilder.Kind.UNSUPPORTED) {
            assertUnsupported(auto, "interior hit without a function may be UNSUPPORTED honestly");
            return;
        }
        assertEquals(InstructionMaskBuilder.Kind.RELOCATABLE_OPERANDS, auto.kind(), auto.explanation());
        assertTrue(auto.sound(), auto.explanation());
        assertMaskedEqual(f.bytes, relocated, auto.mask());
        assertOperandAndOpcodeBytes(f.bytes, relocated, auto.mask(), opcodeOffsets, operandOffsets, auto.explanation());
    }

    private static void assertOperandAndOpcodeBytes(byte[] original, byte[] relocated, byte[] mask,
            int[] opcodeOffsets, int[] operandOffsets, String explanation) {
        for (int i = 0; i < original.length; i++) {
            int changed = (original[i] ^ relocated[i]) & 0xFF;
            assertEquals(0, mask[i] & changed,
                "relocated operand bits at byte " + i + " must be 0 in AUTO mask; " + explanation);
        }
        for (int off : operandOffsets) {
            assertEquals(0, mask[off] & 0xFF,
                "relocatable operand byte " + off + " must be 0 in AUTO mask; " + explanation);
        }
        for (int off : opcodeOffsets) {
            if (contains(operandOffsets, off) || original[off] != relocated[off]) {
                continue;
            }
            assertEquals(0xFF, mask[off] & 0xFF, "opcode byte " + off + " must stay 0xFF; " + explanation);
        }
    }

    private static void requireMnemonic(Fixture f, String mnemonic) {
        assertTrue(hasMnemonic(f, mnemonic),
            "expected " + mnemonic + " with a relocatable operand, listing=" + f.listing());
    }

    private static boolean requireMnemonicOrGap(Fixture f, String languageId, String mnemonic) {
        assertTrue(hasMnemonic(f, mnemonic) && hasRelocatableInstruction(f),
            languageId + " fixture must decode " + mnemonic
                + " with an address/relative operand; listing=" + f.listing());
        return true;
    }

    private static boolean hasMnemonic(Fixture f, String mnemonic) {
        return hasMnemonic(f, f.base, f.bytes.length, mnemonic);
    }

    private static boolean hasMnemonic(Fixture f, Address start, int length, String mnemonic) {
        String want = mnemonic.toLowerCase(Locale.ROOT);
        for (Instruction ins : f.instructions(start, length)) {
            if (ins.getMnemonicString() != null && ins.getMnemonicString().toLowerCase(Locale.ROOT).contains(want)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasRelocatableInstruction(Fixture f) {
        return hasRelocatableInstruction(f, f.base, f.bytes.length);
    }

    private static boolean hasRelocatableInstruction(Fixture f, Address start, int length) {
        for (Instruction ins : f.instructions(start, length)) {
            if (isRelocatable(ins)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isRelocatable(Instruction ins) {
        for (int i = 0; i < ins.getNumOperands(); i++) {
            int type = ins.getOperandType(i);
            if (OperandType.isAddress(type) || OperandType.isRelative(type) || OperandType.isCodeReference(type)) {
                return true;
            }
        }
        return ins.getFlowType() != null && (ins.getFlowType().isCall() || ins.getFlowType().isJump());
    }

    private static void assertMaskedEqual(byte[] a, byte[] b, byte[] mask) {
        assertTrue(maskedEqual(a, b, mask),
            "masked bytes should match; a=" + hex(a) + " b=" + hex(b) + " mask=" + hex(mask));
    }

    private static boolean maskedEqual(byte[] a, byte[] b, byte[] mask) {
        if (a.length != b.length || a.length != mask.length) {
            return false;
        }
        for (int i = 0; i < a.length; i++) {
            if (((a[i] ^ b[i]) & mask[i]) != 0) {
                return false;
            }
        }
        return true;
    }

    private static boolean unmaskedBitsDiffer(byte[] a, byte[] b, byte[] mask) {
        int n = Math.min(a.length, Math.min(b.length, mask.length));
        for (int i = 0; i < n; i++) {
            if (((a[i] ^ b[i]) & mask[i]) != 0) {
                return true;
            }
        }
        return false;
    }

    private static void assertAllFf(byte[] mask) {
        assertNotNull(mask);
        for (int i = 0; i < mask.length; i++) {
            assertEquals(0xFF, mask[i] & 0xFF, "NONE mask byte " + i);
        }
    }

    private static boolean isHollow(byte[] mask) {
        for (byte b : mask) {
            if ((b & 0xFF) != 0) {
                return false;
            }
        }
        return mask.length > 0;
    }

    private static boolean contains(int[] values, int want) {
        for (int v : values) {
            if (v == want) {
                return true;
            }
        }
        return false;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] hex(String text) {
        String[] parts = text.trim().split("\\s+");
        byte[] out = new byte[parts.length];
        for (int i = 0; i < parts.length; i++) {
            out[i] = (byte) Integer.parseInt(parts[i], 16);
        }
        return out;
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) {
                sb.append(' ');
            }
            sb.append(String.format("%02X", bytes[i] & 0xFF));
        }
        return sb.toString();
    }

    private static Language requireLanguage(String languageId) {
        try {
            return DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        } catch (Exception e) {
            fail("Required language not installed: " + languageId + " (" + e.getClass().getSimpleName() + ": "
                + e.getMessage() + ")");
            throw new AssertionError();
        }
    }

    private static final class Fixture implements AutoCloseable {
        final Object consumer = new Object();
        final Program program;
        final Address base;
        final byte[] bytes;
        final Function function;
        final Function secondary;

        static Fixture function(String languageId, byte[] bytes, String contextRegister, int contextValue)
                throws Exception {
            return new Fixture(languageId, bytes, contextRegister, contextValue, true, 0);
        }

        static Fixture disassembled(String languageId, byte[] bytes, String contextRegister, int contextValue)
                throws Exception {
            return new Fixture(languageId, bytes, contextRegister, contextValue, false, 0);
        }

        static Fixture mixedArmThumb() throws Exception {
            return new Fixture(ARM, concat(ARM_BL, THUMB_BL), "TMode", 0, true, ARM_BL.length);
        }

        private Fixture(String languageId, byte[] bytes, String contextRegister, int contextValue,
                boolean createFunction, int splitAt) throws Exception {
            this.bytes = bytes.clone();
            Language language = requireLanguage(languageId);
            ProgramDB db = new ProgramDB("matcher-instr-" + languageId, language, language.getDefaultCompilerSpec(),
                consumer);
            Address start = db.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
            this.base = start;
            int tx = db.startTransaction("fixture");
            try {
                db.getMemory().createInitializedBlock("text", start, 0x100, (byte) 0, TaskMonitor.DUMMY, false)
                    .setExecute(true);
                db.getMemory().setBytes(start, this.bytes);
                Address end = start.add(this.bytes.length - 1);
                Function created = null;
                Function createdSecondary = null;
                if (splitAt > 0) {
                    Address split = start.add(splitAt);
                    Address armEnd = start.add(splitAt - 1);
                    setContext(db, "TMode", start, armEnd, 0);
                    setContext(db, "TMode", split, end, 1);
                    disassemble(db, start, splitAt);
                    disassemble(db, split, this.bytes.length - splitAt);
                    if (createFunction) {
                        created = db.getFunctionManager().createFunction("arm_fixture", start,
                            new AddressSet(start, armEnd), SourceType.USER_DEFINED);
                        createdSecondary = db.getFunctionManager().createFunction("thumb_fixture", split,
                            new AddressSet(split, end), SourceType.USER_DEFINED);
                    }
                } else {
                    if (contextRegister != null) {
                        setContext(db, contextRegister, start, end, contextValue);
                    }
                    disassemble(db, start, this.bytes.length);
                    if (createFunction) {
                        created = db.getFunctionManager().createFunction("fixture", start,
                            new AddressSet(start, end), SourceType.USER_DEFINED);
                    }
                }
                db.endTransaction(tx, true);
                this.program = db;
                this.function = created;
                this.secondary = createdSecondary;
            } catch (Exception e) {
                db.endTransaction(tx, false);
                db.release(consumer);
                throw e;
            }
        }

        List<Instruction> instructions() {
            return instructions(base, bytes.length);
        }

        List<Instruction> instructions(Address start, int length) {
            List<Instruction> out = new ArrayList<>();
            Address end = start.add(length - 1);
            Instruction ins = program.getListing().getInstructionAt(start);
            while (ins != null && ins.getMinAddress().compareTo(end) <= 0) {
                out.add(ins);
                ins = ins.getNext();
            }
            return out;
        }

        String listing() {
            StringBuilder sb = new StringBuilder(program.getLanguageID().toString());
            for (Instruction ins : instructions()) {
                sb.append('\n').append(ins.getAddress()).append(' ').append(ins);
                sb.append(" operands=").append(ins.getNumOperands());
                for (int i = 0; i < ins.getNumOperands(); i++) {
                    sb.append(" [").append(i).append('=')
                        .append(ins.getDefaultOperandRepresentation(i))
                        .append(" type=").append(Integer.toHexString(ins.getOperandType(i)))
                        .append(']');
                }
            }
            if (outEmpty(sb)) {
                sb.append("\n(no instructions)");
            }
            return sb.toString();
        }

        private static boolean outEmpty(StringBuilder sb) {
            return sb.indexOf("\n") < 0;
        }

        @Override
        public void close() {
            if (program != null && !program.isClosed()) {
                program.release(consumer);
            }
        }
    }

    private static void setContext(Program program, String name, Address start, Address end, int value) {
        Register register = program.getProgramContext().getRegister(name);
        if (register == null) {
            for (Register candidate : program.getLanguage().getRegisters()) {
                if (candidate != null && name.equalsIgnoreCase(candidate.getName())) {
                    register = candidate;
                    break;
                }
            }
        }
        assertNotNull(register, "missing context register " + name + " for " + program.getLanguageID());
        try {
            program.getProgramContext().setValue(register, start, end, BigInteger.valueOf(value));
        } catch (ghidra.program.model.listing.ContextChangeException e) {
            throw new AssertionError("Failed to set context register " + name + " on " + program.getLanguageID(), e);
        }
    }

    private static void disassemble(Program program, Address start, int length) {
        Address end = start.add(length - 1);
        boolean ok = new DisassembleCommand(start, new AddressSet(start, end), false)
            .applyTo(program, TaskMonitor.DUMMY);
        assertNotNull(program.getListing().getInstructionAt(start),
            "disassembly produced no instruction at " + start + " language=" + program.getLanguageID()
                + " apply=" + ok);
    }
}
