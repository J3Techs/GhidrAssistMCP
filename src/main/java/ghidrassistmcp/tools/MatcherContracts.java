package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigInteger;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.ProgramIdentity;

/**
 * Architecture-qualified matcher contracts for WP08's first slice.
 * Masked auto/aggressive comparison is fail-closed: proven PowerPC, big-endian,
 * language variant {@code VLE}, and proven per-range VLE instruction mode.
 * Register presence and substring {@code VLE} in a language id are not enough.
 * LE VLE, mixed/unknown context, and e200-with-vle-register are rejected until
 * fixtures exist. Generic ARM/x86/Thumb masks are not implemented.
 */
public final class MatcherContracts {
    static final ObjectMapper JSON = new ObjectMapper();
    public static final int DEFAULT_BYTE_MATCH_CAP = 20;
    public static final int DEFAULT_ANCHOR_PREVIEW = 60;
    public static final List<String> SUPPORTED_VLE_LANGUAGE_IDS = List.of(
        "PowerPC:BE:64:VLE-32addr", "PowerPC:BE:64:VLEALT-32addr");

    private MatcherContracts() {}

    public enum MaskMode {
        NONE("none"), AUTO("auto"), AGGRESSIVE("aggressive");
        private final String wire;
        MaskMode(String wire) { this.wire = wire; }
        public String wireName() { return wire; }
    }

    public enum CompareMode {
        RAW_BYTES,
        POWERPC_VLE_OPERAND_MASK,
        REJECTED
    }

    public enum RegionCompareMode {
        EXACT_BYTES,
        POWERPC_VLE_OPCODE_MASK,
        REJECTED
    }

    /** Per-range VLE instruction mode. Register presence is not a value. */
    public enum RangeVleContext {
        UNKNOWN, VLE_ON, VLE_OFF, MIXED
    }

    public static final class LanguageFacts {
        private final String languageId;
        private final String processor;
        private final int sizeBits;
        private final int instructionAlignment;
        private final boolean bigEndian;
        private final List<String> contextRegisters;
        private final RangeVleContext rangeContext;

        public LanguageFacts(String languageId, String processor, int sizeBits, int instructionAlignment,
                boolean bigEndian, Collection<String> contextRegisters) {
            this(languageId, processor, sizeBits, instructionAlignment, bigEndian, contextRegisters,
                RangeVleContext.UNKNOWN);
        }

        public LanguageFacts(String languageId, String processor, int sizeBits, int instructionAlignment,
                boolean bigEndian, Collection<String> contextRegisters, RangeVleContext rangeContext) {
            this.languageId = languageId == null ? "" : languageId;
            this.processor = processor == null ? "" : processor;
            this.sizeBits = sizeBits;
            this.instructionAlignment = instructionAlignment;
            this.bigEndian = bigEndian;
            this.contextRegisters = List.copyOf(contextRegisters == null ? List.of() : List.copyOf(contextRegisters));
            this.rangeContext = rangeContext == null ? RangeVleContext.UNKNOWN : rangeContext;
        }

        public String languageId() { return languageId; }
        public String processor() { return processor; }
        public int sizeBits() { return sizeBits; }
        public int instructionAlignment() { return instructionAlignment; }
        public boolean bigEndian() { return bigEndian; }
        public List<String> contextRegisters() { return contextRegisters; }
        public RangeVleContext rangeContext() { return rangeContext; }
        public LanguageFacts withRangeContext(RangeVleContext context) {
            return new LanguageFacts(languageId, processor, sizeBits, instructionAlignment, bigEndian,
                contextRegisters, context);
        }

        /** String classifier used by unit tests that must not initialize Ghidra Application. */
        public static LanguageFacts fromLanguageId(String languageId) {
            String id = languageId == null ? "" : languageId.trim();
            String processor = id;
            int colon = id.indexOf(':');
            if (colon > 0) processor = id.substring(0, colon);
            return new LanguageFacts(id, processor, sizeBitsFromId(id), alignmentFromId(id),
                id.toUpperCase(Locale.ROOT).contains(":BE:"), List.of());
        }

        public static LanguageFacts of(String languageId, String processor, Collection<String> contextRegisters) {
            String id = languageId == null ? "" : languageId;
            return new LanguageFacts(id, processor, sizeBitsFromId(id), alignmentFromId(id),
                id.toUpperCase(Locale.ROOT).contains(":BE:"), contextRegisters);
        }
    }

    public static final class MaskDecision {
        private final boolean allowed;
        private final MaskMode mode;
        private final CompareMode compareMode;
        private final String message;

        MaskDecision(boolean allowed, MaskMode mode, CompareMode compareMode, String message) {
            this.allowed = allowed;
            this.mode = mode;
            this.compareMode = compareMode;
            this.message = message;
        }

        public boolean allowed() { return allowed; }
        public MaskMode mode() { return mode; }
        public CompareMode compareMode() { return compareMode; }
        public String message() { return message; }
    }

    public static final class RegionDecision {
        private final boolean allowed;
        private final RegionCompareMode mode;
        private final String message;

        RegionDecision(boolean allowed, RegionCompareMode mode, String message) {
            this.allowed = allowed;
            this.mode = mode;
            this.message = message;
        }

        public boolean allowed() { return allowed; }
        public RegionCompareMode mode() { return mode; }
        public String message() { return message; }
    }

    public static final class ScanStatus {
        private final int candidateCount;
        private final int resultCap;
        private final boolean scanComplete;
        private final boolean scanTruncated;
        private final boolean cancelled;
        private final boolean unique;

        ScanStatus(int candidateCount, int resultCap, boolean scanComplete, boolean scanTruncated,
                boolean cancelled, boolean unique) {
            this.candidateCount = candidateCount;
            this.resultCap = resultCap;
            this.scanComplete = scanComplete;
            this.scanTruncated = scanTruncated;
            this.cancelled = cancelled;
            this.unique = unique;
        }

        public int candidateCount() { return candidateCount; }
        public int resultCap() { return resultCap; }
        public boolean scanComplete() { return scanComplete; }
        public boolean scanTruncated() { return scanTruncated; }
        public boolean cancelled() { return cancelled; }
        public boolean unique() { return unique; }
    }

    public static LanguageFacts fromProgram(Program program) {
        if (program == null) return LanguageFacts.fromLanguageId("");
        var language = program.getLanguage();
        List<String> context = new ArrayList<>();
        Register base = language.getContextBaseRegister();
        if (base != null) {
            context.add(base.getName());
            var children = base.getChildRegisters();
            if (children != null) {
                for (Register child : children) {
                    if (child != null) context.add(child.getName());
                }
            }
        }
        for (Register register : language.getRegisters()) {
            if (register != null && register.isProcessorContext() && !context.contains(register.getName())) {
                context.add(register.getName());
            }
        }
        var description = language.getLanguageDescription();
        return new LanguageFacts(
            language.getLanguageID().toString(),
            language.getProcessor().toString(),
            description == null ? 0 : description.getSize(),
            language.getInstructionAlignment(),
            language.isBigEndian(),
            context);
    }

    /**
     * Read the actual VLE context register VALUE over a range. Presence of a
     * {@code vle} register is not proof. A dedicated {@code :VLE} language with
     * no such register is VLE_ON. Missing range, unread values, mixed bits, and
     * non-qualifying languages are UNKNOWN.
     */
    public static RangeVleContext rangeVleContext(Program program, Address start, Address end) {
        if (program == null) return RangeVleContext.UNKNOWN;
        LanguageFacts facts = fromProgram(program);
        if (!languageAllowsVleMasks(facts)) return RangeVleContext.UNKNOWN;
        if (start == null || end == null || !start.getAddressSpace().equals(end.getAddressSpace())
                || start.compareTo(end) > 0) {
            return RangeVleContext.UNKNOWN;
        }
        Register vle = null;
        for (Register register : program.getLanguage().getRegisters()) {
            if (register != null && register.isProcessorContext() && register.getName() != null
                    && register.getName().equalsIgnoreCase("vle")) {
                vle = register;
                break;
            }
        }
        if (vle == null) return RangeVleContext.VLE_ON;
        try {
            var context = program.getProgramContext();
            var intervals = context.getRegisterValueAddressRanges(vle, start, end);
            Boolean on = null;
            Address expected = start;
            boolean coveredEnd = false;
            while (intervals.hasNext()) {
                var interval = intervals.next();
                Address min = interval.getMinAddress();
                Address max = interval.getMaxAddress();
                if (!min.getAddressSpace().equals(expected.getAddressSpace())) return RangeVleContext.UNKNOWN;
                if (min.compareTo(expected) > 0) return RangeVleContext.UNKNOWN;
                BigInteger value = context.getValue(vle, min.compareTo(start) < 0 ? start : min, false);
                if (value == null) return RangeVleContext.UNKNOWN;
                boolean flag = value.signum() != 0;
                if (on == null) on = flag;
                else if (on != flag) return RangeVleContext.MIXED;
                if (max.compareTo(end) >= 0) {
                    coveredEnd = true;
                    break;
                }
                expected = max.addNoWrap(1);
            }
            if (!coveredEnd || on == null) return RangeVleContext.UNKNOWN;
            return on ? RangeVleContext.VLE_ON : RangeVleContext.VLE_OFF;
        } catch (Exception e) {
            return RangeVleContext.UNKNOWN;
        }
    }

    public static MaskMode parseMaskMode(String raw) {
        if (raw == null || raw.isBlank()) return MaskMode.AUTO;
        String value = raw.trim().toLowerCase(Locale.ROOT);
        return switch (value) {
            case "none" -> MaskMode.NONE;
            case "auto" -> MaskMode.AUTO;
            case "aggressive" -> MaskMode.AGGRESSIVE;
            default -> throw new IllegalArgumentException(
                "Unknown mask_mode '" + raw + "'. Supported values: none, auto, aggressive.");
        };
    }

    /**
     * Language-level VLE mask eligibility: proven PowerPC, big-endian, and a
     * {@code :VLE} language variant. Does not inspect range context.
     * Substring matches and vle register presence are not sufficient.
     */
    public static boolean isPowerPcVle(LanguageFacts facts) {
        return languageAllowsVleMasks(facts);
    }

    public static boolean languageAllowsVleMasks(LanguageFacts facts) {
        if (facts == null) return false;
        return isPowerPc(facts.processor()) && facts.bigEndian() && isVleLanguageVariant(facts.languageId());
    }

    public static boolean provenRangeVle(LanguageFacts facts) {
        return facts != null && facts.rangeContext() == RangeVleContext.VLE_ON;
    }

    public static boolean sameLanguage(LanguageFacts source, LanguageFacts target) {
        if (source == null || target == null) return false;
        String left = source.languageId();
        String right = target.languageId();
        return !left.isBlank() && left.equalsIgnoreCase(right);
    }

    public static MaskDecision qualifyMaskMode(String rawMode, LanguageFacts source, LanguageFacts target) {
        return qualify(parseMaskMode(rawMode), source, target);
    }

    public static MaskDecision qualify(MaskMode mode, LanguageFacts source, LanguageFacts target) {
        if (mode == MaskMode.NONE) {
            return new MaskDecision(true, mode, CompareMode.RAW_BYTES,
                "mask_mode=none uses exact raw-byte comparison on any architecture.");
        }
        if (!languageAllowsVleMasks(source) || !languageAllowsVleMasks(target) || !sameLanguage(source, target)
                || !provenRangeVle(source) || !provenRangeVle(target)) {
            return new MaskDecision(false, mode, CompareMode.REJECTED,
                unsupportedMaskedModeMessage(mode, source, target));
        }
        return new MaskDecision(true, mode, CompareMode.POWERPC_VLE_OPERAND_MASK,
            "PowerPC BE VLE operand masks (bytes 2-3 of 32-bit VLE forms) with proven per-range VLE mode. Generic instruction-aware masks are not implemented.");
    }

    /**
     * Region offset detection and opcode verification share this guard.
     * Matching non-VLE languages use exact bytes; mismatched or unknown pairs fail
     * rather than applying VLE masks.
     */
    public static RegionDecision regionCompare(LanguageFacts source, LanguageFacts target) {
        if (source == null || target == null || source.languageId().isBlank() || target.languageId().isBlank()) {
            return new RegionDecision(false, RegionCompareMode.REJECTED,
                unsupportedRegionCompareMessage(source, target));
        }
        if (!sameLanguage(source, target)) {
            return new RegionDecision(false, RegionCompareMode.REJECTED,
                unsupportedRegionCompareMessage(source, target));
        }
        if (languageAllowsVleMasks(source) && languageAllowsVleMasks(target)
                && provenRangeVle(source) && provenRangeVle(target)) {
            return new RegionDecision(true, RegionCompareMode.POWERPC_VLE_OPCODE_MASK,
                "PowerPC BE VLE opcode-word masks (keep bytes 0-1 of each 4-byte word) with proven per-range VLE mode. Generic instruction-aware masks are not implemented.");
        }
        if (languageAllowsVleMasks(source) || languageAllowsVleMasks(target)) {
            return new RegionDecision(false, RegionCompareMode.REJECTED,
                unsupportedRegionCompareMessage(source, target)
                    + " Masked opcode compare requires proven per-range VLE context (not register presence, LE, mixed, or unknown).");
        }
        return new RegionDecision(true, RegionCompareMode.EXACT_BYTES,
            "Source and target languages match (" + source.languageId()
                + ") but are not PowerPC VLE; operand masking is unsupported. Using exact-byte comparison. "
                + "For relocated operands use native Version Tracking or BSim.");
    }

    public static String unsupportedMaskedModeMessage(MaskMode mode, LanguageFacts source, LanguageFacts target) {
        return "mask_mode=" + (mode == null ? "auto" : mode.wireName())
            + " applies PowerPC BE VLE operand masks only when both programs are PowerPC:BE:64:VLE-32addr/VLEALT-32addr "
            + "with proven per-range VLE instruction mode. Source=" + describe(source)
            + " range=" + rangeLabel(source) + "; target=" + describe(target)
            + " range=" + rangeLabel(target)
            + ". LE VLE, mixed/unknown context, and vle-register presence without a context VALUE are rejected. "
            + "Use mask_mode=none, native Version Tracking, or BSim. Masked comparison does not fall back to exact bytes.";
    }

    public static String unsupportedRegionCompareMessage(LanguageFacts source, LanguageFacts target) {
        return "Region opcode comparison cannot apply PowerPC VLE operand masks to mismatched or unsupported architectures (source="
            + describe(source) + ", target=" + describe(target)
            + "). Use matching architectures with exact-byte comparison, native Version Tracking, or BSim.";
    }

    /**
     * Supported-mode table for this slice. auto/aggressive are true only for PowerPC VLE.
     * ARM/x86/Thumb remain none-only until instruction-aware fixtures exist.
     */
    public static List<Map<String, Object>> supportedModeTable() {
        List<Map<String, Object>> rows = new ArrayList<>();
        rows.add(modeRow("PowerPC BE VLE", "PowerPC:BE:64:VLE-32addr or VLEALT-32addr with proven per-range VLE context VALUE",
            true, true, true, "Documented ids: " + SUPPORTED_VLE_LANGUAGE_IDS
                + ". LE VLE, e200 register presence, mixed/unknown context are rejected."));
        rows.add(modeRow("x86", "x86:*", true, false, false, "Use mask_mode=none, native VT, or BSim"));
        rows.add(modeRow("ARM", "ARM:*", true, false, false, "Use mask_mode=none, native VT, or BSim"));
        rows.add(modeRow("Thumb", "ARM:* with TMode/Thumb", true, false, false, "Use mask_mode=none, native VT, or BSim"));
        return rows;
    }

    public static boolean isDefaultScanSpace(boolean loadedMemorySpace, boolean hashSpace,
            boolean execute, boolean initialized) {
        return loadedMemorySpace && !hashSpace && execute && initialized;
    }

    /**
     * A result cap never establishes uniqueness. A truncated or cancelled scan cannot
     * claim a unique match even when exactly one candidate was returned.
     */
    public static boolean isUnique(int candidateCount, int resultCap, boolean scanTruncated,
            boolean scanComplete, boolean cancelled) {
        if (scanTruncated || cancelled || !scanComplete) return false;
        if (candidateCount != 1) return false;
        if (resultCap <= 0) return false;
        return true;
    }

    /** Hitting the result cap is never itself uniqueness evidence. */
    public static boolean uniqueBecauseCapped(int candidateCount, int resultCap) {
        return false;
    }

    public static ScanStatus scanStatus(int returnedCount, int resultCap, boolean moreExist,
            boolean cancelled, boolean finishedAllRanges) {
        boolean truncated = moreExist;
        boolean complete = !cancelled && !truncated && finishedAllRanges;
        boolean unique = isUnique(returnedCount, resultCap, truncated, complete, cancelled);
        return new ScanStatus(returnedCount, resultCap, complete, truncated, cancelled, unique);
    }

    public static Map<String, Object> scanFields(ScanStatus status) {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("candidate_count", status.candidateCount());
        fields.put("result_cap", status.resultCap());
        fields.put("scan_complete", status.scanComplete());
        fields.put("scan_truncated", status.scanTruncated());
        fields.put("cancelled", status.cancelled());
        fields.put("unique", status.unique());
        return fields;
    }

    /**
     * Full anchor text is always preserved. Preview is a separate prefix and never
     * replaces the only copy of the string.
     */
    public static Map<String, Object> anchorFields(String fullText, int previewLimit) {
        String text = fullText == null ? "" : fullText;
        int limit = Math.max(0, previewLimit);
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("anchor_string", text);
        fields.put("anchor_preview", text.length() <= limit ? text : text.substring(0, limit));
        fields.put("anchor_truncated", text.length() > limit);
        fields.put("anchor_length", text.length());
        return fields;
    }

    public static boolean uniqueAnchor(int occurrenceCount, int functionRefCount) {
        return occurrenceCount == 1 && functionRefCount == 1;
    }

    public static Map<String, Object> programRef(Program program) {
        Map<String, Object> ref = new LinkedHashMap<>();
        if (program == null) {
            ref.put("program_id", "");
            ref.put("name", "");
            ref.put("modification_number", "0");
            ref.put("language", "");
            ref.put("processor", "");
            return ref;
        }
        LanguageFacts facts = fromProgram(program);
        ref.put("program_id", ProgramIdentity.id(program));
        ref.put("name", program.getName());
        ref.put("modification_number", Long.toString(program.getModificationNumber()));
        ref.put("language", facts.languageId());
        ref.put("processor", facts.processor());
        return ref;
    }

    public static String toJson(Object value) {
        try {
            return JSON.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("JSON serialization failed: " + e.getMessage(), e);
        }
    }

    public static Map<String, Object> fromJsonObject(String json) {
        try {
            return JSON.readValue(json, new TypeReference<Map<String, Object>>() {});
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("JSON parse failed: " + e.getMessage(), e);
        }
    }

    /** Last colon component must be a supported VLE variant; substring matches are rejected. */
    private static boolean isVleLanguageVariant(String languageId) {
        if (languageId == null || languageId.isBlank()) return false;
        String[] parts = languageId.split(":");
        if (parts.length < 4) return false;
        if (!parts[1].equalsIgnoreCase("BE")) return false;
        String variant = parts[parts.length - 1];
        return variant.equalsIgnoreCase("VLE") || variant.equalsIgnoreCase("VLE-32addr");
    }

    private static String rangeLabel(LanguageFacts facts) {
        return facts == null ? "unknown" : facts.rangeContext().name().toLowerCase(Locale.ROOT);
    }

    private static boolean containsVle(String languageId) {
        return isVleLanguageVariant(languageId);
    }

    private static boolean isPowerPc(String processor) {
        if (processor == null || processor.isBlank()) return false;
        String normalized = processor.toUpperCase(Locale.ROOT).replace(" ", "");
        return normalized.equals("POWERPC") || normalized.equals("PPC");
    }

    private static boolean hasVleContext(Collection<String> contextRegisters) {
        if (contextRegisters == null) return false;
        for (String name : contextRegisters) {
            if (name != null && name.equalsIgnoreCase("vle")) return true;
        }
        return false;
    }

    private static String describe(LanguageFacts facts) {
        if (facts == null || facts.languageId().isBlank()) return "(unknown)";
        String processor = facts.processor().isBlank() ? "unknown" : facts.processor();
        return facts.languageId() + " (" + processor + ")";
    }

    private static Map<String, Object> modeRow(String architecture, String languagePattern,
            boolean none, boolean auto, boolean aggressive, String notes) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("architecture", architecture);
        row.put("language_pattern", languagePattern);
        row.put("mask_mode_none", none);
        row.put("mask_mode_auto", auto);
        row.put("mask_mode_aggressive", aggressive);
        row.put("notes", notes);
        return row;
    }

    private static int sizeBitsFromId(String languageId) {
        String[] parts = languageId.split(":");
        if (parts.length >= 3) {
            try { return Integer.parseInt(parts[2]); }
            catch (NumberFormatException ignored) { return 0; }
        }
        return 0;
    }

    private static int alignmentFromId(String languageId) {
        String upper = languageId.toUpperCase(Locale.ROOT);
        if (upper.contains("X86")) return 1;
        if (upper.contains("THUMB") || upper.contains("VLE")) return 2;
        if (upper.contains("ARM") || upper.contains("POWERPC")) return 4;
        return 0;
    }

    static Map<String, Object> objectSchema(Map<String, Object> properties, List<String> required) {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", properties);
        schema.put("required", required);
        return schema;
    }

    static Map<String, Object> nullable(Map<String, Object> schema) {
        Map<String, Object> result = new LinkedHashMap<>(schema);
        Object type = schema.get("type");
        if (type instanceof String name) {
            result.put("type", List.of(name, "null"));
            return result;
        }
        Map<String, Object> union = new LinkedHashMap<>();
        union.put("anyOf", List.of(schema, Map.of("type", "null")));
        return union;
    }
}
