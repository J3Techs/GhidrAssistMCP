package ghidrassistmcp.tools;

import java.util.*;
import ghidra.program.model.data.*;

/** Explicit collision behavior shared by structure/enum/typedef creation. */
final class TypeCreationSupport {
    private TypeCreationSupport() {}
    static Map<String, Object> schema() {
        return Map.of("type", "string", "enum", List.of("fail", "replace"), "default", "fail",
            "description", "Creation collision policy. Default fail preserves incompatible existing types; replace explicitly permits replacement.");
    }
    static String policy(Map<String, Object> args) {
        Object value = args.getOrDefault("conflict_policy", "fail");
        if (!(value instanceof String s) || !List.of("fail", "replace").contains(s))
            throw new IllegalArgumentException("conflict_policy must be fail or replace");
        return s;
    }
    static DataType add(DataTypeManager target, DataType candidate, String policy) {
        if (policy.equals("replace")) return target.addDataType(candidate, DataTypeConflictHandler.REPLACE_HANDLER);
        // Inspect the entire dependency graph so collisions cannot be hidden behind a new root.
        var seen = Collections.newSetFromMap(new IdentityHashMap<DataType, Boolean>());
        var pending = new ArrayDeque<DataType>(); pending.add(candidate);
        while (!pending.isEmpty()) {
            DataType type = pending.remove();
            if (!seen.add(type)) continue;
            if (seen.size() > 10000) throw new IllegalArgumentException("Type dependency graph exceeds 10000 entries");
            DataType existing = target.getDataType(type.getCategoryPath(), type.getName());
            if (existing != null && !existing.isEquivalent(type))
                throw new IllegalArgumentException("Type conflict at " + type.getPathName() + "; use conflict_policy=replace explicitly");
            if (type instanceof Composite c) for (var field : c.getDefinedComponents()) pending.add(field.getDataType());
            else if (type instanceof TypeDef d) pending.add(d.getBaseDataType());
            else if (type instanceof Pointer p && p.getDataType() != null) pending.add(p.getDataType());
            else if (type instanceof Array a) pending.add(a.getDataType());
            else if (type instanceof BitFieldDataType b) pending.add(b.getBaseDataType());
            else if (type instanceof FunctionDefinition f) {
                pending.add(f.getReturnType()); for (var arg : f.getArguments()) pending.add(arg.getDataType());
            }
        }
        return target.addDataType(candidate, new DataTypeConflictHandler() {
            public ConflictResult resolveConflict(DataType incoming, DataType existing) {
                if (!existing.isEquivalent(incoming)) throw new IllegalArgumentException("Type conflict at " + incoming.getPathName());
                return ConflictResult.USE_EXISTING;
            }
            public boolean shouldUpdate(DataType source, DataType local) { return false; }
            public DataTypeConflictHandler getSubsequentHandler() { return this; }
        });
    }
}
