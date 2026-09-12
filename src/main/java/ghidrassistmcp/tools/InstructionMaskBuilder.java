package ghidrassistmcp.tools;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Mask;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Instruction-aware search masks for fixture-proven languages only. AUTO/AGGRESSIVE
 * zero relocatable operand bits that are not also instruction-mask (opcode) bits.
 * Not a generic all-architecture decoder.
 *
 * Qualified Ghidra 12.0.3 ids: {@code x86:LE:32:default}, {@code ARM:LE:32:v7},
 * {@code ARM:LE:32:v8T}, {@code PowerPC:BE:64:VLE-32addr}, {@code PowerPC:BE:64:VLEALT-32addr}.
 * There is no {@code PowerPC:BE:32:VLE}. Classifier helpers are not instruction qualification.
 */
public final class InstructionMaskBuilder {
    public enum Kind { RAW, RELOCATABLE_OPERANDS, UNSUPPORTED }

    public static final int MIN_DISCRIMINATING_BYTES = 4;
    public static final int MIN_DISCRIMINATING_BITS = 16;
    public static final double MAX_MASKED_BYTE_RATIO = 0.75;
    public static final int MAX_PATTERN_BYTES = 65536;
    public static final int MAX_SCAN_BYTES = 1024 * 1024;
    public static final Set<String> QUALIFIED_LANGUAGE_IDS = Set.of(
        "x86:LE:32:default",
        "ARM:LE:32:v7",
        "ARM:LE:32:v8T",
        "PowerPC:BE:64:VLE-32addr");

    private InstructionMaskBuilder() {}

    public static final class Plan {
        private final Kind kind;
        private final byte[] mask;
        private final String explanation;
        private final boolean sound;
        private final List<String> maskedOperands;
        private final String languageId;
        private final int windowBytes;
        private final BigInteger tmode;
        private final MatcherContracts.RangeVleContext vleContext;

        Plan(Kind kind, byte[] mask, String explanation, boolean sound,
                List<String> maskedOperands, String languageId, int windowBytes,
                BigInteger tmode, MatcherContracts.RangeVleContext vleContext) {
            this.kind = kind;
            this.mask = mask == null ? null : mask.clone();
            this.explanation = explanation == null ? "" : explanation;
            this.sound = sound;
            this.maskedOperands = List.copyOf(maskedOperands == null ? List.of() : maskedOperands);
            this.languageId = languageId == null ? "" : languageId;
            this.windowBytes = windowBytes;
            this.tmode = tmode;
            this.vleContext = vleContext;
        }

        public Kind kind() { return kind; }
        public byte[] mask() { return mask == null ? null : mask.clone(); }
        public String explanation() { return explanation; }
        public boolean sound() { return sound; }
        public List<String> maskedOperands() { return maskedOperands; }
        public String languageId() { return languageId; }
        public int windowBytes() { return windowBytes; }
        public BigInteger tmode() { return tmode; }
        public MatcherContracts.RangeVleContext vleContext() { return vleContext; }
    }

    public static Plan plan(Program program, Function function, byte[] sourceBytes,
            MatcherContracts.MaskMode mode, TaskMonitor monitor) {
        return planStatic(program, function, sourceBytes, mode, monitor);
    }

    public static Plan plan(Program program, Address start, int length, byte[] sourceBytes,
            MatcherContracts.MaskMode mode, TaskMonitor monitor) {
        if (sourceBytes != null && sourceBytes.length < length) {
            return unsupported(program, "getBytes returned " + sourceBytes.length
                + " bytes but the mask window requested " + length);
        }
        return planStatic(program, start, length, mode, monitor, null);
    }

    public static Plan plan(Program program, Address start, int length,
            MatcherContracts.MaskMode mode, TaskMonitor monitor) {
        return planStatic(program, start, length, mode, monitor, null);
    }

    private static Plan planStatic(Program program, Function function, byte[] sourceBytes,
            MatcherContracts.MaskMode mode, TaskMonitor monitor) {
        requireMode(mode);
        int length = sourceBytes == null ? 0 : sourceBytes.length;
        if (mode == MatcherContracts.MaskMode.NONE) return raw(program, length);
        if (function == null) return unsupported(program, "Function is required for a function-scoped relocatable mask");
        return planStatic(program != null ? program : function.getProgram(),
            function.getEntryPoint(), length, mode, monitor, function);
    }

    private static Plan planStatic(Program program, Address start, int length,
            MatcherContracts.MaskMode mode, TaskMonitor monitor, Function function) {
        requireMode(mode);
        if (mode == MatcherContracts.MaskMode.NONE) return raw(program, length);
        if (program == null) return unsupported(null, "Program is required");
        if (start == null || length < 1) {
            return unsupported(program, "Instruction mask requires a positive byte window at a valid address");
        }
        if (length > MAX_PATTERN_BYTES) {
            return unsupported(program, "Mask window exceeds " + MAX_PATTERN_BYTES + " bytes");
        }
        String languageError = validateQualifiedLanguage(program);
        if (languageError != null) return unsupported(program, languageError);
        Address windowEnd;
        try {
            windowEnd = start.addNoWrap(length - 1L);
        } catch (AddressOverflowException e) {
            return unsupported(program, "Byte window exceeds the address space");
        }
        if (function != null) {
            String bodyError = bodyCoversInstructions(function, start, windowEnd);
            if (bodyError != null) return unsupported(program, bodyError);
        }
        String id = languageId(program);
        if (isVleLanguage(id)) {
            MatcherContracts.RangeVleContext vle = MatcherContracts.rangeVleContext(program, start, windowEnd);
            if (vle != MatcherContracts.RangeVleContext.VLE_ON) {
                return unsupported(program, "PowerPC VLE mask requires proven VLE context over the full window (got "
                    + vle + "). Unknown/mixed/off is unsupported.");
            }
        }
        TaskMonitor mon = monitor == null ? TaskMonitor.DUMMY : monitor;
        try {
            Plan decoded = decodeWindow(program, start, length, id, mon);
            if (decoded.kind() != Kind.RELOCATABLE_OPERANDS) return decoded;
            String explanation = decoded.explanation();
            if (mode == MatcherContracts.MaskMode.AGGRESSIVE) {
                explanation += " aggressive equals auto on relocatable bits; extra heuristics are not applied.";
            }
            return new Plan(decoded.kind(), decoded.mask, explanation, decoded.sound(),
                decoded.maskedOperands(), decoded.languageId(), decoded.windowBytes(),
                decoded.tmode(), decoded.vleContext());
        } catch (CancelledException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Reject masked search against a target whose language, compiler, endian, or
     * instruction-mode context does not match the source plan.
     */
    public static String maskedTargetError(Program source, Address sourceStart, int windowBytes,
            Plan sourcePlan, Program target, Address targetStart, Address targetEnd) {
        if (source == null || target == null) return "Source and target programs are required";
        String srcId = languageId(source);
        String dstId = languageId(target);
        if (!srcId.equalsIgnoreCase(dstId)) {
            return "Masked matching requires identical language IDs (source=" + srcId + ", target=" + dstId
                + "). Use mask_mode=none, native VT, or BSim.";
        }
        if (source.getLanguage().isBigEndian() != target.getLanguage().isBigEndian()) {
            return "Masked matching requires identical endianness";
        }
        CompilerSpecID srcCs = source.getCompilerSpec().getCompilerSpecID();
        CompilerSpecID dstCs = target.getCompilerSpec().getCompilerSpecID();
        if (srcCs != null && dstCs != null && !srcCs.equals(dstCs)) {
            return "Masked matching requires identical compiler specs (" + srcCs + " vs " + dstCs + ")";
        }
        if (isArmLanguage(srcId)) {
            BigInteger srcMode = sourcePlan == null ? readTmode(source, sourceStart) : sourcePlan.tmode();
            if (srcMode == null) return "Source ARM TMode is unknown; masked matching is unsupported";
            Address lo = targetStart != null ? targetStart : minExec(target);
            Address hi = targetEnd != null ? targetEnd : maxExec(target);
            if (lo == null || hi == null) return "Target has no executable range for ARM TMode proof";
            BigInteger dstMode = readTmode(target, lo);
            if (dstMode == null) return "Target ARM TMode is unknown at " + lo + "; masked matching is unsupported";
            if (srcMode.compareTo(dstMode) != 0) {
                return "Source/target ARM TMode mismatch (cross ARM/Thumb). Use mask_mode=none or a single mode.";
            }
            if (tmodeMixed(target, lo, hi)) {
                return "Target scan range has mixed ARM/Thumb TMode; masked matching is unsupported";
            }
        }
        if (isVleLanguage(srcId) && sourcePlan != null
                && sourcePlan.vleContext() != MatcherContracts.RangeVleContext.VLE_ON) {
            return "Source VLE context is not proven VLE_ON";
        }
        if (isVleLanguage(srcId)) {
            Address lo = targetStart != null ? targetStart : minExec(target);
            Address hi = targetEnd != null ? targetEnd : maxExec(target);
            MatcherContracts.RangeVleContext tgt = MatcherContracts.rangeVleContext(target, lo, hi);
            if (tgt != MatcherContracts.RangeVleContext.VLE_ON) {
                return "Target VLE context is " + tgt + "; masked matching requires VLE_ON over the scan range";
            }
        }
        return null;
    }

    public static boolean acceptCandidate(Plan sourcePlan, Program target, Address hit) {
        if (sourcePlan == null || target == null || hit == null) return false;
        if (isArmLanguage(sourcePlan.languageId())) {
            BigInteger hitMode = readTmode(target, hit);
            if (hitMode == null || sourcePlan.tmode() == null) return false;
            if (sourcePlan.tmode().compareTo(hitMode) != 0) return false;
        }
        Plan candidate = plan(target, hit, sourcePlan.windowBytes(), MatcherContracts.MaskMode.AUTO, TaskMonitor.DUMMY);
        return candidate.sound() && candidate.windowBytes() == sourcePlan.windowBytes()
            && Arrays.equals(sourcePlan.mask(), candidate.mask());
    }

    public static String validateScanRange(Address start, Address end) {
        if (start == null || end == null) return null;
        if (!start.getAddressSpace().equals(end.getAddressSpace())) {
            return "start_address and end_address must be in the same address space";
        }
        if (start.compareTo(end) > 0) return "start_address must not exceed end_address";
        try {
            if (end.subtract(start) + 1 > MAX_SCAN_BYTES) {
                return "Scan range exceeds " + MAX_SCAN_BYTES + " bytes";
            }
        } catch (Exception e) {
            return "Scan range is not a bounded address distance";
        }
        return null;
    }

    private static Plan decodeWindow(Program program, Address start, int length, String languageId,
            TaskMonitor monitor) throws CancelledException {
        byte[] searchMask = allOnes(length);
        List<String> maskedOperands = new ArrayList<>();
        Register tmodeReg = contextRegister(program, "TMode");
        BigInteger firstTmode = null;
        Address addr = start;
        int covered = 0;
        if (isArmLanguage(languageId) && tmodeReg == null) {
            return unsupported(program, "ARM masked matching requires a TMode context register");
        }
        while (covered < length) {
            monitor.checkCancelled();
            Instruction instr = program.getListing().getInstructionAt(addr);
            if (instr == null) {
                return unsupported(program, "Undefined or undecoded bytes at " + addr
                    + "; disassemble complete instructions before masked matching");
            }
            InstructionPrototype proto = instr.getPrototype();
            if (proto == null) {
                return unsupported(program, "Instruction at " + addr + " has no prototype");
            }
            int instrLen = instr.getLength();
            if (instrLen < 1) return unsupported(program, "Zero-length instruction at " + addr);
            int remaining = length - covered;
            if (instrLen > remaining) {
                if (covered == 0) {
                    return unsupported(program, "First instruction at " + addr + " is longer than the mask window");
                }
                searchMask = Arrays.copyOf(searchMask, covered);
                break;
            }
            Address instrEnd;
            try {
                instrEnd = addr.addNoWrap(instrLen - 1L);
            } catch (AddressOverflowException e) {
                return unsupported(program, "Instruction at " + addr + " exceeds the address space");
            }
            if (isArmLanguage(languageId)) {
                BigInteger value = program.getProgramContext().getValue(tmodeReg, addr, false);
                if (value == null) {
                    return unsupported(program, "Unknown ARM TMode at " + addr
                        + " (null is not ARM-mode false); masked matching is unsupported");
                }
                if (firstTmode == null) firstTmode = value;
                else if (firstTmode.compareTo(value) != 0) {
                    return unsupported(program, "Mixed ARM/Thumb TMode in the mask window");
                }
            }
            String applyError = applyRelocatableOperands(instr, proto, instrLen, searchMask, covered, maskedOperands);
            if (applyError != null) return unsupported(program, applyError);
            try {
                addr = addr.addNoWrap(instrLen);
            } catch (AddressOverflowException e) {
                covered += instrLen;
                searchMask = Arrays.copyOf(searchMask, covered);
                break;
            }
            covered += instrLen;
        }
        MatcherContracts.RangeVleContext vle = isVleLanguage(languageId)
            ? MatcherContracts.rangeVleContext(program, start, start.add(Math.max(0, covered - 1L)))
            : MatcherContracts.RangeVleContext.UNKNOWN;
        return specificity(program, languageId, searchMask, maskedOperands, covered, firstTmode, vle);
    }

    private static String applyRelocatableOperands(Instruction instr, InstructionPrototype proto,
            int instrLen, byte[] searchMask, int covered, List<String> maskedOperands) {
        Mask instructionMask = proto.getInstructionMask();
        byte[] keep = instructionMask == null || instructionMask.getBytes() == null
            ? new byte[instrLen] : instructionMask.getBytes();
        int operandCount = proto.getNumOperands();
        for (int op = 0; op < operandCount; op++) {
            int operandType;
            try { operandType = instr.getOperandType(op); }
            catch (Exception e) { continue; }
            if (OperandType.isRegister(operandType) && !OperandType.isAddress(operandType)
                    && !OperandType.isCodeReference(operandType) && !OperandType.isDataReference(operandType)) {
                continue;
            }
            if (!relocatable(operandType)) continue;
            // A compound memory operand can include base/index register fields in its
            // value mask. Retain the entire operand unless relocation can be isolated
            // without erasing those registers.
            boolean compoundRegister = false;
            for (Object object : instr.getOpObjects(op)) {
                if (object instanceof Register) { compoundRegister = true; break; }
            }
            if (compoundRegister) continue;
            Mask operandMask = proto.getOperandValueMask(op);
            if (operandMask == null || operandMask.getBytes() == null) {
                return "Null relocatable operand mask for op" + op + " at " + instr.getMinAddress();
            }
            byte[] bits = operandMask.getBytes();
            if (bits.length != instrLen) {
                return "Operand value mask length mismatches instruction length at "
                    + instr.getMinAddress() + " op" + op;
            }
            for (int i = 0; i < instrLen; i++) {
                int opcodeKeep = i < keep.length ? (keep[i] & 0xFF) : 0;
                int relocatableBits = (bits[i] & 0xFF) & ~opcodeKeep;
                searchMask[covered + i] &= (byte) ~relocatableBits;
            }
            maskedOperands.add(operandLabel(op, operandType));
        }
        return null;
    }

    private static boolean relocatable(int operandType) {
        return OperandType.isAddress(operandType)
            || OperandType.isRelative(operandType)
            || OperandType.isCodeReference(operandType)
            || OperandType.isDataReference(operandType);
    }

    private static String operandLabel(int index, int operandType) {
        StringBuilder label = new StringBuilder("op").append(index);
        if (OperandType.isAddress(operandType)) label.append(" ADDRESS");
        if (OperandType.isRelative(operandType)) label.append(" RELATIVE");
        if (OperandType.isCodeReference(operandType)) label.append(" CODE_REFERENCE");
        if (OperandType.isDataReference(operandType)) label.append(" DATA_REFERENCE");
        if (OperandType.isRegister(operandType)) label.append(" REGISTER");
        return label.toString();
    }

    private static Plan specificity(Program program, String languageId, byte[] searchMask,
            List<String> maskedOperands, int windowBytes, BigInteger tmode,
            MatcherContracts.RangeVleContext vle) {
        int fullBytes = 0, bits = 0, maskedBytes = 0;
        for (byte value : searchMask) {
            int u = value & 0xFF;
            bits += Integer.bitCount(u);
            if (u == 0xFF) fullBytes++;
            else maskedBytes++;
        }
        double ratio = searchMask.length == 0 ? 1.0 : maskedBytes / (double) searchMask.length;
        if (fullBytes < MIN_DISCRIMINATING_BYTES || bits < MIN_DISCRIMINATING_BITS
                || ratio > MAX_MASKED_BYTE_RATIO) {
            return unsupported(program, "Low-information relocatable mask on " + languageId
                + " (full opcode bytes=" + fullBytes + ", bits=" + bits + ", masked-byte-ratio="
                + String.format(Locale.ROOT, "%.2f", ratio)
                + "). Not generic-all-arch. Use mask_mode=none, native VT, or BSim.");
        }
        String extra = maskedOperands.isEmpty() ? " (no relocatable operands in window)" : "";
        return new Plan(Kind.RELOCATABLE_OPERANDS, searchMask,
            "Relocatable operand bits (excluding instruction-mask/opcode bits) on qualified " + languageId + extra,
            true, maskedOperands, languageId, windowBytes, tmode, vle);
    }

    private static Plan raw(Program program, int length) {
        if (length < 0) return unsupported(program, "Byte window length must not be negative");
        if (length > MAX_PATTERN_BYTES) return unsupported(program, "Mask window exceeds " + MAX_PATTERN_BYTES);
        return new Plan(Kind.RAW, allOnes(length),
            "mask_mode=none uses exact raw-byte comparison (not an instruction-qualified mask)",
            true, List.of(), languageId(program), length, null, MatcherContracts.RangeVleContext.UNKNOWN);
    }

    private static String validateQualifiedLanguage(Program program) {
        String id = languageId(program);
        if (!QUALIFIED_LANGUAGE_IDS.contains(id)) {
            return "Instruction-qualified masks are implemented only for " + QUALIFIED_LANGUAGE_IDS
                + " (this program is " + id + "). Not generic-all-arch. Use mask_mode=none, native VT, or BSim.";
        }
        if (id.contains(":BE:") && !program.getLanguage().isBigEndian()) {
            return "Language id/endian mismatch for " + id;
        }
        if (id.contains(":LE:") && program.getLanguage().isBigEndian()) {
            return "Language id/endian mismatch for " + id;
        }
        return null;
    }

    private static String bodyCoversInstructions(Function function, Address start, Address windowEnd) {
        AddressSetView body = function.getBody();
        if (body == null || body.isEmpty()) return "Function body is empty";
        Address cursor = start;
        while (true) {
            if (!body.contains(cursor)) {
                return "Function body does not contain the full mask window at " + cursor;
            }
            if (cursor.equals(windowEnd)) break;
            try { cursor = cursor.addNoWrap(1); }
            catch (AddressOverflowException e) { return "Byte window exceeds the address space"; }
        }
        return null;
    }

    private static void requireMode(MatcherContracts.MaskMode mode) {
        if (mode == null) {
            throw new IllegalArgumentException("Unknown mask_mode. Supported values: none, auto, aggressive.");
        }
    }

    private static Register contextRegister(Program program, String name) {
        if (program == null || program.getLanguage() == null) return null;
        Register exact = program.getLanguage().getRegister(name);
        if (exact != null && exact.isProcessorContext()) return exact;
        for (Register register : program.getLanguage().getRegisters()) {
            if (register != null && register.isProcessorContext() && register.getName() != null
                    && register.getName().equalsIgnoreCase(name)) {
                return register;
            }
        }
        return null;
    }

    private static BigInteger readTmode(Program program, Address addr) {
        Register tmode = contextRegister(program, "TMode");
        if (tmode == null || addr == null) return null;
        return program.getProgramContext().getValue(tmode, addr, false);
    }

    private static boolean tmodeMixed(Program program, Address start, Address end) {
        Register tmode = contextRegister(program, "TMode");
        if (tmode == null || start == null || end == null) return true;
        BigInteger first = program.getProgramContext().getValue(tmode, start, false);
        if (first == null) return true;
        var ranges = program.getProgramContext().getRegisterValueAddressRanges(tmode, start, end);
        while (ranges.hasNext()) {
            var range = ranges.next();
            BigInteger value = program.getProgramContext().getValue(tmode, range.getMinAddress(), false);
            if (value == null || first.compareTo(value) != 0) return true;
        }
        return false;
    }

    private static Address minExec(Program program) {
        for (var block : program.getMemory().getBlocks()) {
            if (block.isExecute() && block.isInitialized()) return block.getStart();
        }
        return null;
    }

    private static Address maxExec(Program program) {
        Address max = null;
        for (var block : program.getMemory().getBlocks()) {
            if (block.isExecute() && block.isInitialized()) max = block.getEnd();
        }
        return max;
    }

    private static boolean isArmLanguage(String id) {
        return id != null && id.startsWith("ARM:");
    }

    private static boolean isVleLanguage(String id) {
        return id != null && (id.equals("PowerPC:BE:64:VLE-32addr") || id.equals("PowerPC:BE:64:VLEALT-32addr"));
    }

    private static Plan unsupported(Program program, String explanation) {
        return new Plan(Kind.UNSUPPORTED, null, explanation, false, List.of(), languageId(program), 0,
            null, MatcherContracts.RangeVleContext.UNKNOWN);
    }

    private static byte[] allOnes(int length) {
        byte[] mask = new byte[Math.max(0, length)];
        Arrays.fill(mask, (byte) 0xFF);
        return mask;
    }

    private static String languageId(Program program) {
        if (program == null || program.getLanguageID() == null) return "";
        return program.getLanguageID().toString();
    }
}
