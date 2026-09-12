package ghidrassistmcp.vt;

import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelatorFactory;
import ghidra.framework.model.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.*;
import io.modelcontextprotocol.spec.McpSchema;

/** Native session ownership is serialized by VTTool for the lifetime of each operation. */
final class VTSupport {
    static final Object LOCK = new Object();
    static final Object CONSUMER = new Object();
    static final int MAX_LIMIT = 500;
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
        if(!a.containsKey(key)) return fallback;
        Object v=a.get(key);
        if(!(v instanceof Number n)||!Double.isFinite(n.doubleValue())||n.doubleValue()!=n.longValue()||n.longValue()<min||n.longValue()>max)
            throw new IllegalArgumentException(key+" must be an integer in "+min+".."+max);
        return n.intValue();
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
