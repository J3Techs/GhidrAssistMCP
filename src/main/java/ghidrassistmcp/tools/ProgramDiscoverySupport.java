package ghidrassistmcp.tools;

import java.util.*;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.ProgramIdentity;

/** Shared, bounded discovery representation used by list_binaries and capabilities. */
public final class ProgramDiscoverySupport {
    static final int DEFAULT_LIMIT = 16, MAX_LIMIT = 100;
    private ProgramDiscoverySupport() {}

    public static List<Program> unique(List<Program> input) {
        Set<Program> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        List<Program> result = new ArrayList<>();
        for (Program p : input) if (p != null && !p.isClosed() && seen.add(p)) result.add(p);
        result.sort(Comparator.comparing(ProgramDiscoverySupport::sortKey));
        return result;
    }

    static String sortKey(Program p) {
        return ProgramIdentity.id(p) + "\u0000" + path(p) + "\u0000" + safe(p.getName())
            + "\u0000" + Integer.toUnsignedString(System.identityHashCode(p));
    }
    static String path(Program p) { DomainFile f=p.getDomainFile(); return f == null ? "" : safe(f.getPathname()); }
    private static String safe(String s) { return s == null ? "" : s; }

    static String revision(List<Program> programs) {
        try {
            var d=java.security.MessageDigest.getInstance("SHA-256"); StringBuilder b=new StringBuilder();
            for (Program p : programs) b.append(ProgramIdentity.id(p)).append('\u0000').append(Integer.toUnsignedString(System.identityHashCode(p))).append('\n');
            byte[] hash=d.digest(b.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8)); StringBuilder out=new StringBuilder();
            for(byte x:hash)out.append(String.format("%02x",x)); return out.toString();
        } catch(Exception e) { throw new IllegalStateException("Unable to compute inventory revision",e); }
    }

    static Map<String,Object> row(Program p, Map<String,Integer> collisions) {
        Map<String,Object> r = new LinkedHashMap<>();
        DomainFile f=p.getDomainFile();
        String id=ProgramIdentity.id(p);
        r.put("program_id", id); r.put("name", p.getName()); r.put("project_path", path(p));
        r.put("program_url", f == null ? null : url(f)); r.put("file_id", f == null ? null : f.getFileID());
        r.put("version", f == null ? null : f.getVersion()); r.put("executable_path", p.getExecutablePath());
        r.put("format", p.getExecutableFormat()); r.put("language", String.valueOf(p.getLanguageID()));
        r.put("compiler", p.getCompilerSpec() == null ? null : String.valueOf(p.getCompilerSpec().getCompilerSpecID()));
        r.put("active", false); r.put("modification_number", p.getModificationNumber());
        r.put("dirty", p.isChanged()); r.put("changeable", p.isChangeable());
        r.put("read_only", f == null ? null : f.isReadOnly()); r.put("can_save", f == null ? null : f.canSave());
        r.put("busy", f == null ? null : f.isBusy());
        int n=collisions.getOrDefault(id, 0); r.put("collision", n > 1); r.put("collision_count", n);
        return r;
    }
    private static String url(DomainFile f) { try { var u=f.getLocalProjectURL(null); if(u==null)u=f.getSharedProjectURL(null); return u==null?null:u.toString(); } catch(Throwable e){return null;} }

    static List<Map<String,Object>> rows(List<Program> programs) {
        Map<String,Integer> c=new HashMap<>(); for(Program p:programs)c.merge(ProgramIdentity.id(p),1,Integer::sum);
        List<Map<String,Object>> out=new ArrayList<>(); for(Program p:programs)out.add(row(p,c)); return out;
    }
    static List<Map<String,Object>> rows(List<Program> programs, int from, int to) {
        Map<String,Integer> c=new HashMap<>(); for(Program p:programs)c.merge(ProgramIdentity.id(p),1,Integer::sum);
        List<Map<String,Object>> out=new ArrayList<>(); for(int i=from;i<to;i++)out.add(row(programs.get(i),c)); return out;
    }
    static long integer(Object v, String key, long defaultValue) {
        if (v == null) return defaultValue;
        if (!(v instanceof Number) || v instanceof Float || v instanceof Double) throw new IllegalArgumentException(key+" must be an integer");
        long n=((Number)v).longValue(); if (!v.toString().equals(Long.toString(n)) && !(v instanceof Integer || v instanceof Long)) throw new IllegalArgumentException(key+" must be an integer"); return n;
    }
}
