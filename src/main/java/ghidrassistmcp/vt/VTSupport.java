package ghidrassistmcp.vt;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelatorFactory;
import ghidra.framework.model.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.*;
import io.modelcontextprotocol.spec.McpSchema;

/** Native session ownership is serialized by VTTool for the lifetime of each operation. */
final class VTSupport {
    static final Object LOCK = new Object();
    static final Object CONSUMER = new Object();
    static final int MAX_LIMIT = 500;
    /** Practical cap on offset+limit so sorted paging cannot retain a huge priority queue. */
    static final int MAX_PAGE_WINDOW = 5000;
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Map<String, VTSessionDB> OPEN = new LinkedHashMap<>();
    private static final ThreadLocal<Project> CONTEXT = new ThreadLocal<>();
    private static volatile Project testProject;
    private VTSupport() {}

    static McpSchema.CallToolResult result(Map<String,Object> value) { return result(value,false); }
    static McpSchema.CallToolResult result(Map<String,Object> value, boolean error) {
        try { return McpSchema.CallToolResult.builder().isError(error).structuredContent(value)
            .addTextContent(JSON.writeValueAsString(value)).build(); }
        catch(Exception e) { return error(e); }
    }
    static McpSchema.CallToolResult error(Exception e) {
        return McpSchema.CallToolResult.builder().isError(true)
            .addTextContent(e.getMessage()==null?e.getClass().getSimpleName():e.getMessage()).build();
    }
    static String required(Map<String,Object> a,String key) {
        if(a.get(key) instanceof String s && !s.isBlank()) return s.trim();
        throw new IllegalArgumentException(key+" is required");
    }
    static int integer(Map<String,Object> a,String key,int fallback,int min,int max) {
        if(!a.containsKey(key) || a.get(key)==null) return fallback;
        return exactInt(a.get(key), key, min, max);
    }
    static int exactInt(Object v, String key, int min, int max) {
        try {
            int parsed;
            if (v instanceof Integer i) parsed = i;
            else if (v instanceof Long l) parsed = Math.toIntExact(l);
            else if (v instanceof Short s) parsed = s.intValue();
            else if (v instanceof Byte b) parsed = b.intValue();
            else if (v instanceof BigInteger bi) parsed = bi.intValueExact();
            else if (v instanceof BigDecimal bd) parsed = bd.intValueExact();
            else if (v instanceof Number n) parsed = new BigDecimal(n.toString()).intValueExact();
            else throw new IllegalArgumentException(key+" must be an integer in "+min+".."+max);
            if (parsed < min || parsed > max) throw new IllegalArgumentException(key+" must be an integer in "+min+".."+max);
            return parsed;
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException(key+" must be an integer in "+min+".."+max);
        }
    }
    static long exactLong(Object v, String key, long min, long max) {
        try {
            long parsed;
            if (v instanceof Long l) parsed = l;
            else if (v instanceof Integer i) parsed = i.longValue();
            else if (v instanceof Short s) parsed = s.longValue();
            else if (v instanceof Byte b) parsed = b.longValue();
            else if (v instanceof BigInteger bi) parsed = bi.longValueExact();
            else if (v instanceof BigDecimal bd) parsed = bd.longValueExact();
            else if (v instanceof Number n) parsed = new BigDecimal(n.toString()).longValueExact();
            else throw new IllegalArgumentException(key+" must be an integer");
            if (parsed < min || parsed > max) throw new IllegalArgumentException(key+" must be an integer in "+min+".."+max);
            return parsed;
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException(key+" must be an integer in "+min+".."+max);
        }
    }
    static int limit(Map<String,Object>a){return integer(a,"limit",100,1,MAX_LIMIT);}
    static int offset(Map<String,Object>a){return integer(a,"offset",0,0,Integer.MAX_VALUE);}
    static void bind(GhidrAssistMCPBackend backend,Map<String,Object> args) {
        Project p=backend==null?testProject:backend.getProject();
        if(p==null && backend==null) {var t=GhidrAssistMCPManager.getInstance().getActiveTool();p=t==null?null:t.getProject();}
        if(args.containsKey("__project_identity")&&!Objects.equals(args.get("__project_identity"),p==null?"<none>":String.valueOf(p.getProjectLocator())))
            throw new IllegalStateException("The project changed while the VT operation was queued");
        CONTEXT.set(p);
    }
    static void unbind(){CONTEXT.remove();}
    static Project project(){Project p=CONTEXT.get();return p==null?testProject:p;}
    static void setProjectForTests(Project p){testProject=p;}
    static DomainFile file(Map<String,Object>a,String key) {
        Project p=project(); if(p==null)throw new IllegalStateException("No project bound to this MCP session");
        String path=required(a,key).replace('\\','/');
        if(path.matches("^[A-Za-z]:.*")||path.startsWith("//"))throw new IllegalArgumentException("Use a Ghidra project path");
        if(!path.startsWith("/"))path="/"+path;
        for(String part:path.split("/"))if(part.equals(".")||part.equals(".."))throw new IllegalArgumentException("Invalid project path");
        DomainFile f=p.getProjectData().getFile(path);
        if(f==null)throw new IllegalArgumentException("Project file not found: "+path);
        return f;
    }
    static String canonical(DomainFile f){return f.getProjectLocator()+"|"+f.getFileID();}
    static VTSessionDB session(Map<String,Object>a,TaskMonitor monitor)throws Exception {
        DomainFile f=file(a,"session");String key=canonical(f);VTSessionDB s=OPEN.get(key);
        if(s!=null&&!s.isClosed())return s;
        if(!VTSessionDB.class.isAssignableFrom(f.getDomainObjectClass()))throw new IllegalArgumentException("File is not a native VT session");
        DomainObject object=f.getDomainObject(CONSUMER,false,false,monitor);
        if(!(object instanceof VTSessionDB opened)){object.release(CONSUMER);throw new IllegalArgumentException("Not a VT session");}
        OPEN.put(key,opened);return opened;
    }
    static VTSessionDB session(Map<String,Object>a)throws Exception{return session(a,TaskMonitor.DUMMY);}
    static void register(String key,VTSessionDB s){OPEN.put(key,s);}
    static void unregister(String key){OPEN.remove(key);}
    static List<Map<String,Object>> sessions(){
        Project p=project();if(p==null)throw new IllegalStateException("No project");
        String prefix=p.getProjectLocator()+"|";
        return OPEN.entrySet().stream().filter(e->e.getKey().startsWith(prefix)&&!e.getValue().isClosed()).map(e->describe(e.getValue())).toList();
    }
    static Map<String,Object> identity(Program p){return ProgramIdentity.describe(p);}
    static Map<String,Object> describe(VTSessionDB s){return Map.of("session",s.getDomainFile().getPathname(),"source",identity(s.getSourceProgram()),"destination",identity(s.getDestinationProgram()),"match_sets",s.getMatchSets().size(),"session_dirty",s.isChanged(),"destination_dirty",s.getDestinationProgram().isChanged());}
    static void writable(VTSessionDB s) {
        for(DomainObject d:List.of(s,s.getDestinationProgram())) {
            if(!d.isChangeable()||!d.canSave())throw new IllegalStateException("VT session and destination must be writable project objects");
            if(d.getCurrentTransactionInfo()!=null)throw new IllegalStateException("VT session or destination has an active transaction; finish analysis or edits first");
        }
    }
    static void sameProject(Program src,Program dst){
        Project p=project();
        for(Program program:List.of(src,dst)){
            DomainFile f=program.getDomainFile();
            if(p==null||f.getParent()==null||!Objects.equals(f.getProjectLocator(),p.getProjectLocator())||p.getProjectData().getFileByID(f.getFileID())==null)
                throw new IllegalArgumentException("Source, destination and session must belong to the bound project");
        }
        if(src==dst||Objects.equals(src.getDomainFile().getFileID(),dst.getDomainFile().getFileID()))throw new IllegalArgumentException("Source and destination must differ");
    }
    static Address address(Program p,String s){Address a=p.getAddressFactory().getAddress(s);if(a==null||!a.isMemoryAddress())throw new IllegalArgumentException("Invalid memory address: "+s);return a;}
    static VTMatch find(VTSession s,Map<String,Object>a){
        int set=integer(a,"match_set_id",-1,-1,Integer.MAX_VALUE);
        Address sa=address(s.getSourceProgram(),required(a,"source_address"));Address da=address(s.getDestinationProgram(),required(a,"destination_address"));VTMatch found=null;
        for(VTMatchSet ms:s.getMatchSets())if(set<0||ms.getID()==set)for(VTMatch m:ms.getMatches())if(sa.equals(m.getSourceAddress())&&da.equals(m.getDestinationAddress())){if(found!=null)throw new IllegalArgumentException("Match is ambiguous; specify match_set_id");found=m;}
        if(found==null)throw new IllegalArgumentException("Match not found");return found;
    }
    static Map<String,Object> match(VTMatch m){
        Map<String,Object> r=new LinkedHashMap<>();r.put("match_set_id",m.getMatchSet().getID());r.put("source_address",m.getSourceAddress().toString());r.put("destination_address",m.getDestinationAddress().toString());r.put("source_length",m.getSourceLength());r.put("destination_length",m.getDestinationLength());r.put("type",m.getAssociation().getType().toString());r.put("status",m.getAssociation().getStatus().toString());r.put("similarity",m.getSimilarityScore()==null?null:m.getSimilarityScore().getScore());r.put("confidence",m.getConfidenceScore()==null?null:m.getConfidenceScore().getScore());return r;
    }

    /**
     * Lightweight sort key for {@code vt_matches}. A sorted page may visit every filtered match
     * (scan cost, two passes) without retaining a {@code List<VTMatch>} of the session; only these
     * keys for the current {@code offset+limit} window are kept.
     */
    record MatchQueryKey(double similarity, double confidence, int matchSetId, String sourceAddress, String destinationAddress, int scanIndex) {
        MatchQueryKey {
            sourceAddress = sourceAddress == null ? "" : sourceAddress;
            destinationAddress = destinationAddress == null ? "" : destinationAddress;
        }
    }
    record MatchPage(List<MatchQueryKey> items, int total, int offset, int limit) {
        boolean hasMore() { return (long) offset + items.size() < total; }
    }

    /** Native names pass through; missing or blank names stay JSON null and are never invented. */
    static String namesOrNull(String nativeName) {
        return nativeName == null || nativeName.isBlank() ? null : nativeName;
    }
    static boolean pageInvalidated(Long expected, long actual) {
        return expected != null && expected.longValue() != actual;
    }
    static int compareKeys(MatchQueryKey a, MatchQueryKey b) {
        int c = Double.compare(b.similarity(), a.similarity());
        if (c != 0) return c;
        c = Double.compare(b.confidence(), a.confidence());
        if (c != 0) return c;
        c = Integer.compare(a.matchSetId(), b.matchSetId());
        if (c != 0) return c;
        c = a.sourceAddress().compareTo(b.sourceAddress());
        if (c != 0) return c;
        c = a.destinationAddress().compareTo(b.destinationAddress());
        if (c != 0) return c;
        return Integer.compare(a.scanIndex(), b.scanIndex());
    }
    static String normalizeStatusFilter(String raw) {
        if (raw == null || raw.isBlank())
            throw new IllegalArgumentException("status must be accepted, rejected, available, blocked, or native ACCEPTED/REJECTED/AVAILABLE/BLOCKED");
        return switch (raw.trim().toUpperCase(Locale.ROOT)) {
            case "ACCEPTED" -> "ACCEPTED";
            case "REJECTED" -> "REJECTED";
            case "AVAILABLE" -> "AVAILABLE";
            case "BLOCKED" -> "BLOCKED";
            default -> throw new IllegalArgumentException("status must be accepted, rejected, available, blocked, or native ACCEPTED/REJECTED/AVAILABLE/BLOCKED");
        };
    }
    static boolean acceptStatus(String nativeStatus, String statusFilter) {
        return statusFilter == null || statusFilter.equals(nativeStatus);
    }
    static boolean acceptMinScore(Double similarity, Double minScore) {
        if (minScore == null) return true;
        return similarity != null && Double.isFinite(similarity) && similarity >= minScore;
    }
    static boolean accept(String nativeStatus, Double similarity, String statusFilter, Double minScore) {
        String normalized = statusFilter == null || statusFilter.isBlank() ? null : normalizeStatusFilter(statusFilter);
        return acceptStatus(nativeStatus, normalized) && acceptMinScore(similarity, minScore);
    }
    static int pageWindowCap(int offset, int limit) {
        if (offset < 0 || limit < 1) throw new IllegalArgumentException("offset must be >= 0 and limit >= 1");
        long window = (long) offset + (long) limit;
        if (window > MAX_PAGE_WINDOW) {
            throw new IllegalArgumentException("offset+limit exceeds " + MAX_PAGE_WINDOW
                + "; use filters or next_offset from a previous page instead of a large offset");
        }
        return (int) window;
    }
    static void consider(PriorityQueue<MatchQueryKey> best, MatchQueryKey key, int window) {
        if (window <= 0 || key == null) return;
        if (best.size() < window) best.add(key);
        else if (compareKeys(key, best.peek()) < 0) { best.poll(); best.add(key); }
    }
    static List<MatchQueryKey> pageFromWindow(PriorityQueue<MatchQueryKey> best, int offset, int limit) {
        List<MatchQueryKey> ranked = new ArrayList<>(best);
        ranked.sort(VTSupport::compareKeys);
        int from = Math.min(offset, ranked.size());
        int to = Math.min(offset + limit, ranked.size());
        return from >= to ? List.of() : new ArrayList<>(ranked.subList(from, to));
    }
    /** Bounded sorted page over lightweight keys; retains at most offset+limit keys, not native matches. */
    static MatchPage selectPage(Collection<MatchQueryKey> keys, int offset, int limit) {
        int window = pageWindowCap(offset, limit);
        PriorityQueue<MatchQueryKey> best = new PriorityQueue<>((x, y) -> compareKeys(y, x));
        int total = 0;
        for (MatchQueryKey key : keys) { total++; consider(best, key, window); }
        return new MatchPage(pageFromWindow(best, offset, limit), total, offset, limit);
    }
    static Long optionalRevision(Map<String,Object> a) { return optionalRevision(a, "session_revision"); }
    static Long optionalRevision(Map<String,Object> a, String key) {
        if (!a.containsKey(key) || a.get(key) == null) return null;
        return exactLong(a.get(key), key, 0, Long.MAX_VALUE);
    }
    static String optionalId(Map<String,Object> a, String key) {
        if (!a.containsKey(key) || a.get(key) == null) return null;
        if (a.get(key) instanceof String s && !s.isBlank()) return s;
        throw new IllegalArgumentException(key+" must be a non-blank string");
    }
    static Integer matchSetFilter(Map<String,Object> a) {
        if (!a.containsKey("match_set_id") || a.get("match_set_id") == null) return null;
        return integer(a, "match_set_id", -1, 0, Integer.MAX_VALUE);
    }
    static String statusFilter(Map<String,Object> a) {
        if (!a.containsKey("status") || a.get("status") == null) return null;
        if (!(a.get("status") instanceof String s) || s.isBlank())
            throw new IllegalArgumentException("status must be accepted, rejected, available, blocked, or native ACCEPTED/REJECTED/AVAILABLE/BLOCKED");
        return normalizeStatusFilter(s);
    }
    static Double minScore(Map<String,Object> a) {
        if (!a.containsKey("min_score") || a.get("min_score") == null) return null;
        Object v = a.get("min_score");
        if (!(v instanceof Number n) || !Double.isFinite(n.doubleValue()))
            throw new IllegalArgumentException("min_score must be a finite number (native VT similarity)");
        return n.doubleValue();
    }
    static double sortScore(Double score) {
        return score == null || !Double.isFinite(score) ? Double.NEGATIVE_INFINITY : score;
    }
    static String statusOf(VTMatch m) {
        return m.getAssociation() == null || m.getAssociation().getStatus() == null ? null : m.getAssociation().getStatus().toString();
    }
    static Double similarityOf(VTMatch m) {
        return m.getSimilarityScore() == null ? null : m.getSimilarityScore().getScore();
    }
    static MatchQueryKey key(VTMatch m) { return key(m, 0); }
    static MatchQueryKey key(VTMatch m, int scanIndex) {
        return new MatchQueryKey(sortScore(similarityOf(m)),
            sortScore(m.getConfidenceScore() == null ? null : m.getConfidenceScore().getScore()),
            m.getMatchSet() == null ? Integer.MIN_VALUE : m.getMatchSet().getID(),
            m.getSourceAddress() == null ? "" : m.getSourceAddress().toString(),
            m.getDestinationAddress() == null ? "" : m.getDestinationAddress().toString(),
            scanIndex);
    }
    static String correlatorName(VTMatchSet set) {
        if (set == null || set.getProgramCorrelatorInfo() == null) return null;
        return namesOrNull(set.getProgramCorrelatorInfo().getName());
    }
    static String matchSetProvenance(VTSession session, VTMatchSet set) {
        if (session == null || set == null) return null;
        VTMatchSet manual = session.getManualMatchSet();
        if (manual != null && (set == manual || set.getID() == manual.getID())) return "manual";
        VTMatchSet implied = session.getImpliedMatchSet();
        if (implied != null && (set == implied || set.getID() == implied.getID())) return "implied";
        return "correlator";
    }
    static void putSideNames(Map<String,Object> row, Program program, Address address, String side, VTAssociationType type) {
        String name = null, source = null;
        if (program != null && address != null) {
            if (type == null || type == VTAssociationType.FUNCTION) {
                Function function = program.getFunctionManager().getFunctionAt(address);
                if (function != null) {
                    name = namesOrNull(function.getName());
                    Symbol symbol = function.getSymbol();
                    source = symbol == null ? null : String.valueOf(symbol.getSource());
                }
            }
            if (name == null && type != VTAssociationType.FUNCTION) {
                Data data = program.getListing().getDefinedDataAt(address);
                Symbol symbol = data != null ? data.getPrimarySymbol() : program.getSymbolTable().getPrimarySymbol(address);
                if (symbol != null) {
                    name = namesOrNull(symbol.getName());
                    source = String.valueOf(symbol.getSource());
                }
            }
        }
        row.put(side + "_name", name);
        row.put(side + "_name_source", source);
    }
    static Map<String,Object> matchQueryRow(VTMatch m) {
        Map<String,Object> r = match(m);
        VTMatchSet set = m.getMatchSet();
        VTSession session = set == null ? null : set.getSession();
        r.put("correlator", correlatorName(set));
        r.put("match_set_provenance", matchSetProvenance(session, set));
        VTAssociationType type = m.getAssociation() == null ? null : m.getAssociation().getType();
        putSideNames(r, session == null ? null : session.getSourceProgram(), m.getSourceAddress(), "source", type);
        putSideNames(r, session == null ? null : session.getDestinationProgram(), m.getDestinationAddress(), "destination", type);
        return r;
    }
    static List<Map<String,Object>> materialize(VTSession s, List<MatchQueryKey> pageKeys, Integer setId, String status, Double min, TaskMonitor m) throws Exception {
        if (pageKeys.isEmpty()) return List.of();
        Set<MatchQueryKey> wanted = new HashSet<>(pageKeys);
        Map<MatchQueryKey, Map<String,Object>> found = new HashMap<>();
        for (VTMatchSet set : s.getMatchSets()) {
            m.checkCancelled();
            if (setId != null && set.getID() != setId) continue;
            int scanIndex = 0;
            for (VTMatch match : set.getMatches()) {
                m.checkCancelled();
                if (!accept(statusOf(match), similarityOf(match), status, min)) continue;
                MatchQueryKey k = key(match, scanIndex++);
                if (wanted.contains(k)) found.putIfAbsent(k, matchQueryRow(match));
                if (found.size() == wanted.size()) break;
            }
            if (found.size() == wanted.size()) break;
        }
        List<Map<String,Object>> rows = new ArrayList<>(pageKeys.size());
        for (MatchQueryKey k : pageKeys) {
            Map<String,Object> row = found.get(k);
            if (row != null) rows.add(row);
        }
        return rows;
    }
    /**
     * Filtered, stably sorted {@code vt_matches} page. Does not retain a {@code List<VTMatch>} of
     * the session; a globally sorted page still scans every filtered match.
     */
    static Map<String,Object> queryMatches(VTSessionDB s, Map<String,Object> a, TaskMonitor m) throws Exception {
        if (m == null) m = TaskMonitor.DUMMY;
        long revision = s.getModificationNumber();
        Long expected = optionalRevision(a);
        if (pageInvalidated(expected, revision))
            throw new IllegalStateException("session_revision mismatch (expected "+expected+", current "+revision+"); restart paging from offset 0");
        int off = offset(a), limit = limit(a);
        Integer setId = matchSetFilter(a);
        String status = statusFilter(a);
        Double min = minScore(a);
        int window = pageWindowCap(off, limit);
        Program source = s.getSourceProgram(), destination = s.getDestinationProgram();
        String sourceId = ProgramIdentity.id(source), destinationId = ProgramIdentity.id(destination);
        long sourceRev = source.getModificationNumber(), destinationRev = destination.getModificationNumber();
        String expectedSourceId = optionalId(a, "source_program_id");
        String expectedDestinationId = optionalId(a, "destination_program_id");
        if (pageInvalidated(optionalRevision(a, "source_revision"), sourceRev)
                || pageInvalidated(optionalRevision(a, "destination_revision"), destinationRev)
                || (expectedSourceId != null && !expectedSourceId.equals(sourceId))
                || (expectedDestinationId != null && !expectedDestinationId.equals(destinationId))) {
            throw new IllegalStateException("vt_matches paging identity changed (session/source/destination revision tuple); restart from offset 0");
        }
        PriorityQueue<MatchQueryKey> best = new PriorityQueue<>((x, y) -> compareKeys(y, x));
        int total = 0, matchSetCount = s.getMatchSets().size();
        for (VTMatchSet set : s.getMatchSets()) {
            m.checkCancelled();
            if (setId != null && set.getID() != setId) continue;
            int scanIndex = 0;
            for (VTMatch match : set.getMatches()) {
                m.checkCancelled();
                if (!accept(statusOf(match), similarityOf(match), status, min)) continue;
                total++;
                consider(best, key(match, scanIndex++), window);
            }
        }
        if (s.getModificationNumber() != revision || source.getModificationNumber() != sourceRev
                || destination.getModificationNumber() != destinationRev)
            throw new IllegalStateException("vt_matches paging identity changed during the scan; restart from offset 0");
        List<MatchQueryKey> pageKeys = pageFromWindow(best, off, limit);
        List<Map<String,Object>> rows = materialize(s, pageKeys, setId, status, min, m);
        if (s.getModificationNumber() != revision || source.getModificationNumber() != sourceRev
                || destination.getModificationNumber() != destinationRev)
            throw new IllegalStateException("vt_matches paging identity changed during materialization; restart from offset 0");
        boolean more = (long) off + rows.size() < total;
        Integer nextOffset = more ? Integer.valueOf(off + rows.size()) : null;
        boolean windowExhausted = nextOffset != null && (long) nextOffset + 1 > MAX_PAGE_WINDOW;
        if (windowExhausted) nextOffset = null;
        Map<String,Object> out = new LinkedHashMap<>();
        out.put("matches", rows);
        out.put("offset", off);
        out.put("limit", limit);
        out.put("total", total);
        out.put("truncated", more);
        out.put("has_more", more && !windowExhausted);
        out.put("next_offset", nextOffset);
        out.put("page_window_exhausted", windowExhausted);
        out.put("requires_filter", windowExhausted);
        out.put("session_revision", revision);
        out.put("source_program_id", sourceId);
        out.put("source_revision", sourceRev);
        out.put("destination_program_id", destinationId);
        out.put("destination_revision", destinationRev);
        out.put("match_set_count", matchSetCount);
        out.put("paging_identity", "Supply session_revision, source_program_id, source_revision, destination_program_id and destination_revision with next_offset. A name-only GUI edit still changes program revision.");
        return out;
    }
    static void closeAll(){synchronized(LOCK){for(VTSessionDB s:OPEN.values())if(!s.isClosed())s.release(CONSUMER);OPEN.clear();}}
    static void closeProject(Project project){synchronized(LOCK){
        String prefix=project.getProjectLocator()+"|";
        for(var entry:new ArrayList<>(OPEN.entrySet())) if(entry.getKey().startsWith(prefix)) {
            VTSessionDB session=entry.getValue();
            if(!session.isClosed()) {
                if(session.isChanged()||session.getDestinationProgram().isChanged())ghidra.util.Msg.warn(VTSupport.class,"Releasing unsaved VT session: "+session.getName());
                session.release(CONSUMER);
            }
            OPEN.remove(entry.getKey());
        }
    }}
    static List<VTProgramCorrelatorFactory> factories(){return new ArrayList<>(ClassSearcher.getInstances(VTAbstractProgramCorrelatorFactory.class));}
}
