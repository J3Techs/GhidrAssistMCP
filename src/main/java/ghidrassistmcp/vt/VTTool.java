package ghidrassistmcp.vt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTSessionFileUtil;
import ghidra.feature.vt.gui.plugin.AddressCorrelatorManager;
import ghidra.feature.vt.gui.util.MatchInfoFactory;
import ghidra.framework.model.*;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.*;
import ghidrassistmcp.tasks.*;
import io.modelcontextprotocol.spec.McpSchema;

/** Native Version Tracking lifecycle, correlation, review and selected markup operations. */
public final class VTTool implements McpTool {
    private final String name;
    public VTTool(String name){this.name=name;}
    public static void closeProjectSessions(Project project){VTSupport.closeProject(project);}
    @Override public String getName(){return name;}
    @Override public String getDescription(){return switch(name){
        case "vt_sessions"->"List MCP-open native Version Tracking sessions, or inspect one (action=get).";
        case "vt_session"->"Create, get, save or close a native VT session. Saves destination and session separately with per-object outcomes.";
        case "vt_correlators"->"List installed native VT correlators and their typed options, plus native markup policy options.";
        case "vt_correlate"->"Run a native correlator using validated options and optional inclusive address ranges. Cancellable; changes stay unsaved.";
        case "vt_matches"->"Page native VT matches, association status and native scores (scores are not probabilities).";
        case "vt_add_matches"->"Add a manually reviewed function or defined-data association; validates both native objects and their lengths.";
        case "vt_review_matches"->"Accept, reject or clear a native match association. Does not save or apply markup.";
        case "vt_markup"->"Preview mapped native markup, stable item IDs, apply policies and a freshness token. Page results before choosing IDs.";
        case "vt_apply_markup"->"Apply selected markup IDs from a fresh preview to an accepted association using native options. Explicit save is separate.";
        case "vt_unapply_markup"->"Undo selected applied markup from a fresh preview. All native collateral IDs must be explicitly selected.";
        default->"Native Version Tracking";};}
    private static Map<String,Object> prop(String t){return Map.of("type",t);}
    @Override public McpSchema.JsonSchema getInputSchema(){
        Map<String,Object> p=new LinkedHashMap<>();List<String> req=new ArrayList<>();
        if(!name.equals("vt_correlators")){p.put("session",prop("string"));if(!name.equals("vt_sessions")&&!name.equals("vt_session"))req.add("session");}
        switch(name){
        case "vt_sessions"->p.put("action",Map.of("type","string","enum",List.of("list","get")));
        case "vt_session"->{p.put("action",Map.of("type","string","enum",List.of("create","get","save","close")));req.add("action");p.put("name",prop("string"));p.put("destination_program",prop("string"));p.put("discard",prop("boolean"));}
        case "vt_correlate"->{p.put("correlator",prop("string"));req.add("correlator");p.put("options",prop("object"));for(String side:List.of("source","destination"))for(String bound:List.of("start","end"))p.put(side+"_range_"+bound,prop("string"));}
        case "vt_review_matches","vt_add_matches","vt_markup","vt_apply_markup","vt_unapply_markup"->{
            for(String key:List.of("source_address","destination_address")){p.put(key,prop("string"));req.add(key);}p.put("match_set_id",prop("integer"));
            if(name.equals("vt_review_matches")){p.put("status",Map.of("type","string","enum",List.of("accepted","rejected","available")));req.add("status");}
            if(name.equals("vt_add_matches")){p.put("type",Map.of("type","string","enum",List.of("function","data")));p.put("source_length",prop("integer"));p.put("destination_length",prop("integer"));}
            if(name.contains("markup")){p.put("options",prop("object"));p.put("markup_ids",Map.of("type","array","items",prop("string"),"minItems",1,"maxItems",VTSupport.MAX_LIMIT,"uniqueItems",true));p.put("preview_token",prop("string"));if(!name.equals("vt_markup"))req.addAll(List.of("markup_ids","preview_token"));}
        }
        default->{}
        }
        if(name.equals("vt_matches")||name.equals("vt_markup")){p.put("offset",Map.of("type","integer","minimum",0));p.put("limit",Map.of("type","integer","minimum",1,"maximum",VTSupport.MAX_LIMIT));}
        return new McpSchema.JsonSchema("object",p,req,null,null,null);
    }
    @Override public boolean isReadOnly(){return Set.of("vt_sessions","vt_correlators","vt_matches","vt_markup").contains(name);}
    @Override public boolean isLongRunning(){return Set.of("vt_correlate","vt_markup","vt_apply_markup","vt_unapply_markup").contains(name);}
    @Override public McpSchema.CallToolResult execute(Map<String,Object>a,Program p){return execute(a,p,null,null);}
    @Override public McpSchema.CallToolResult execute(Map<String,Object>a,Program p,GhidrAssistMCPBackend b){return execute(a,p,b,null);}
    @Override public McpSchema.CallToolResult execute(Map<String,Object>a,Program p,GhidrAssistMCPBackend b,McpTask task){
        TaskMonitor monitor=task==null?TaskMonitor.DUMMY:new McpTaskMonitor(task,0,100,"Version Tracking");
        synchronized(VTSupport.LOCK){try{
            VTSupport.bind(b,a);monitor.checkCancelled();
            return switch(name){
                case "vt_sessions"->readSessions(a,monitor);
                case "vt_session"->lifecycle(a,p,monitor);
                case "vt_correlators"->correlators();
                case "vt_correlate"->correlate(a,monitor);
                case "vt_matches"->matches(a,monitor);
                case "vt_review_matches"->review(a,monitor);
                case "vt_add_matches"->add(a,monitor);
                case "vt_markup"->markup(a,monitor);
                case "vt_apply_markup","vt_unapply_markup"->changeMarkup(a,monitor,name.equals("vt_unapply_markup"));
                default->throw new IllegalArgumentException("Unknown VT tool");
            };
        }catch(Exception e){return VTSupport.error(e);}finally{VTSupport.unbind();}}
    }
    private McpSchema.CallToolResult readSessions(Map<String,Object>a,TaskMonitor m)throws Exception{
        String action=String.valueOf(a.getOrDefault("action",a.containsKey("session")?"get":"list"));
        return switch(action){case "list"->VTSupport.result(Map.of("sessions",VTSupport.sessions()));case "get"->VTSupport.result(VTSupport.describe(VTSupport.session(a,m)));default->throw new IllegalArgumentException("vt_sessions is read-only; use vt_session for lifecycle changes");};
    }
    private McpSchema.CallToolResult lifecycle(Map<String,Object>a,Program source,TaskMonitor m)throws Exception{
        String action=VTSupport.required(a,"action");
        if(action.equals("create"))return create(a,source,m);
        VTSessionDB s=VTSupport.session(a,m);
        return switch(action){
        case "get"->VTSupport.result(VTSupport.describe(s));
        case "save"->{
            VTSupport.writable(s);Map<String,Object> out=new LinkedHashMap<>();boolean failure=false;
            for(var entry:Map.<String,DomainObject>of("destination",s.getDestinationProgram(),"session",s).entrySet()){
                String key=entry.getKey();DomainObject obj=entry.getValue();
                try{m.checkCancelled();obj.save("MCP Version Tracking save",m);boolean saved=!obj.isChanged();out.put(key+"_saved",saved);failure|=!saved;}
                catch(Exception e){failure=true;out.put(key+"_saved",false);out.put(key+"_error",String.valueOf(e.getMessage()));}
                out.put(key+"_dirty",obj.isChanged());
            }
            out.put("atomic",false);yield VTSupport.result(out,failure);
        }
        case "close"->{
            boolean dirty=s.isChanged()||s.getDestinationProgram().isChanged();
            if(dirty&&!Boolean.TRUE.equals(a.get("discard")))throw new IllegalArgumentException("Session or destination is dirty; save or explicitly set discard=true");
            if(s.getCurrentTransactionInfo()!=null||s.getDestinationProgram().getCurrentTransactionInfo()!=null)throw new IllegalStateException("Cannot close during an active transaction");
            VTSupport.unregister(VTSupport.canonical(s.getDomainFile()));s.release(VTSupport.CONSUMER);
            yield VTSupport.result(Map.of("action","closed","released_mcp_consumer",true,"had_unsaved_changes",dirty,"note","Other consumers may retain these objects and their unsaved changes"));
        }
        default->throw new IllegalArgumentException("Unknown session action");};
    }
    private McpSchema.CallToolResult create(Map<String,Object>a,Program source,TaskMonitor m)throws Exception{
        if(source==null)throw new IllegalArgumentException("Select a source program");
        String sessionName=VTSupport.required(a,"name");if(sessionName.contains("/")||sessionName.contains("\\"))throw new IllegalArgumentException("name must be a project filename");
        DomainFile df=VTSupport.file(a,"destination_program");VTSessionFileUtil.validateSourceProgramFile(source.getDomainFile(),true);VTSessionFileUtil.validateDestinationProgramFile(df,true,true);
        Object temporary=new Object();DomainObject opened=df.getDomainObject(temporary,false,false,m);VTSessionDB session=null;boolean registered=false;
        try{
            if(!(opened instanceof Program destination))throw new IllegalArgumentException("Destination must be a program");
            VTSupport.sameProject(source,destination);
            if(source.isChanged()||destination.isChanged()||source.getCurrentTransactionInfo()!=null||destination.getCurrentTransactionInfo()!=null)throw new IllegalStateException("Save source and destination and finish their transactions before session creation");
            DomainFolder root=VTSupport.project().getProjectData().getRootFolder();if(root.getFile(sessionName)!=null)throw new IllegalArgumentException("Session file already exists");
            session=VTSessionDB.createVTSession(sessionName,source,destination,VTSupport.CONSUMER);
            DomainFile file=root.createFile(sessionName,session,m);VTSupport.register(VTSupport.canonical(file),session);registered=true;
            return VTSupport.result(VTSupport.describe(session));
        }finally{if(session!=null&&!registered&&!session.isClosed())session.release(VTSupport.CONSUMER);opened.release(temporary);}
    }
    private McpSchema.CallToolResult correlators(){
        List<Map<String,Object>> rows=new ArrayList<>();for(var f:VTSupport.factories())rows.add(Map.of("name",f.getName(),"description",f.getDescription(),"priority",f.getPriority(),"address_restriction",f.getAddressRestrictionPreference().toString(),"options",VTOptionsSupport.describe(f.createDefaultOptions())));
        return VTSupport.result(Map.of("correlators",rows,"markup_options",VTOptionsSupport.describe(VTOptionsSupport.applyOptions(Map.of()))));
    }
    @SuppressWarnings("unchecked") private static Map<String,Object> options(Map<String,Object>a){Object v=a.get("options");if(v==null)return Map.of();if(!(v instanceof Map<?,?> map)||map.keySet().stream().anyMatch(k->!(k instanceof String)))throw new IllegalArgumentException("options must be an object");return (Map<String,Object>)map;}
    private static AddressSet range(Map<String,Object>a,String side,Program p){
        String start=side+"_range_start",end=side+"_range_end";
        if(!a.containsKey(start)&&!a.containsKey(end))return new AddressSet(p.getMemory());
        Address first=VTSupport.address(p,VTSupport.required(a,start)),last=VTSupport.address(p,VTSupport.required(a,end));
        if(!first.getAddressSpace().equals(last.getAddressSpace())||first.compareTo(last)>0)throw new IllegalArgumentException("Invalid inclusive "+side+" range");
        return new AddressSet(first,last).intersect(p.getMemory());
    }
    private McpSchema.CallToolResult correlate(Map<String,Object>a,TaskMonitor m)throws Exception{
        VTSessionDB s=VTSupport.session(a,m);VTSupport.writable(s);String wanted=VTSupport.required(a,"correlator");
        var f=VTSupport.factories().stream().filter(x->x.getName().equals(wanted)).findFirst().orElseThrow(()->new IllegalArgumentException("Unknown correlator: "+wanted));
        if(a.keySet().stream().anyMatch(k->k.contains("_range_"))&&f.getAddressRestrictionPreference().toString().contains("NOT_ALLOWED"))throw new IllegalArgumentException("Correlator does not permit address restrictions");
        var nativeOptions=f.createDefaultOptions();VTOptionsSupport.configure(nativeOptions,options(a));
        var c=f.createCorrelator(s.getSourceProgram(),range(a,"source",s.getSourceProgram()),s.getDestinationProgram(),range(a,"destination",s.getDestinationProgram()),nativeOptions);
        int tx=s.startTransaction("MCP VT correlation");boolean commit=false;
        try{VTMatchSet set=c.correlate(s,m);m.checkCancelled();commit=true;return VTSupport.result(Map.of("match_set_id",set.getID(),"match_count",set.getMatchCount(),"correlator",c.getName(),"saved",false));}finally{s.endTransaction(tx,commit);}
    }
    private McpSchema.CallToolResult matches(Map<String,Object>a,TaskMonitor m)throws Exception{
        VTSessionDB s=VTSupport.session(a,m);int off=VTSupport.offset(a),limit=VTSupport.limit(a),total=0;List<Map<String,Object>> rows=new ArrayList<>();
        for(VTMatchSet set:s.getMatchSets())for(VTMatch match:set.getMatches()){m.checkCancelled();if(total>=off&&rows.size()<limit)rows.add(VTSupport.match(match));total++;}
        return VTSupport.result(Map.of("matches",rows,"offset",off,"limit",limit,"total",total,"truncated",(long)off+rows.size()<total));
    }
    private McpSchema.CallToolResult review(Map<String,Object>a,TaskMonitor m)throws Exception{
        VTSessionDB s=VTSupport.session(a,m);VTSupport.writable(s);VTMatch match=VTSupport.find(s,a);
        int tx=s.startTransaction("MCP VT review");boolean commit=false;
        try{switch(VTSupport.required(a,"status")){case "accepted"->match.getAssociation().setAccepted();case "rejected"->match.getAssociation().setRejected();case "available"->match.getAssociation().clearStatus();default->throw new IllegalArgumentException("Invalid association status");}m.checkCancelled();commit=true;return VTSupport.result(VTSupport.match(match));}finally{s.endTransaction(tx,commit);}
    }
    private McpSchema.CallToolResult add(Map<String,Object>a,TaskMonitor m)throws Exception{
        VTSessionDB s=VTSupport.session(a,m);VTSupport.writable(s);Program src=s.getSourceProgram(),dst=s.getDestinationProgram();Address sa=VTSupport.address(src,VTSupport.required(a,"source_address")),da=VTSupport.address(dst,VTSupport.required(a,"destination_address"));
        String type=String.valueOf(a.getOrDefault("type","function"));int sl,dl;VTAssociationType association;
        for(VTMatch existing:s.getManualMatchSet().getMatches())if(sa.equals(existing.getSourceAddress())&&da.equals(existing.getDestinationAddress()))
            throw new IllegalArgumentException("Manual match already exists for these addresses");
        if(type.equals("function")){var sf=src.getFunctionManager().getFunctionAt(sa);var df=dst.getFunctionManager().getFunctionAt(da);if(sf==null||df==null)throw new IllegalArgumentException("Both addresses must be function entries");sl=Math.toIntExact(sf.getBody().getNumAddresses());dl=Math.toIntExact(df.getBody().getNumAddresses());association=VTAssociationType.FUNCTION;}
        else if(type.equals("data")){var sd=src.getListing().getDefinedDataAt(sa);var dd=dst.getListing().getDefinedDataAt(da);if(sd==null||dd==null)throw new IllegalArgumentException("Both addresses must begin defined data");sl=sd.getLength();dl=dd.getLength();association=VTAssociationType.DATA;}
        else throw new IllegalArgumentException("type must be function or data");
        if(VTSupport.integer(a,"source_length",sl,1,Integer.MAX_VALUE)!=sl||VTSupport.integer(a,"destination_length",dl,1,Integer.MAX_VALUE)!=dl)throw new IllegalArgumentException("Provided lengths must match native object lengths");
        VTMatchInfo info=new VTMatchInfo(s.getManualMatchSet());info.setAssociationType(association);info.setSourceAddress(sa);info.setDestinationAddress(da);info.setSourceLength(sl);info.setDestinationLength(dl);info.setSimilarityScore(new VTScore(0));info.setConfidenceScore(new VTScore(0));
        int tx=s.startTransaction("MCP manual VT match");boolean commit=false;
        try{VTMatch match=s.getManualMatchSet().addMatch(info);m.checkCancelled();commit=true;Map<String,Object> row=VTSupport.match(match);row.put("provenance","manual");return VTSupport.result(row);}finally{s.endTransaction(tx,commit);}
    }
    private record Item(String id,VTMarkupItem nativeItem,Address mappedDestination,Map<String,Object> row){}
    private record Preview(VTSessionDB session,VTMatch match,List<Item> items,String token){}
    private static String hash(String value)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}
    private Preview preview(Map<String,Object>a,TaskMonitor m)throws Exception{
        VTSessionDB s=VTSupport.session(a,m);VTMatch match=VTSupport.find(s,a);ToolOptions opts=VTOptionsSupport.applyOptions(options(a));
        var mapper=new AddressCorrelatorManager(()->s);
        ghidra.program.util.AddressCorrelation correlation=null;
        if(match.getAssociation().getType()==VTAssociationType.FUNCTION){
            var sf=s.getSourceProgram().getFunctionManager().getFunctionAt(match.getSourceAddress());
            var df=s.getDestinationProgram().getFunctionManager().getFunctionAt(match.getDestinationAddress());
            if(sf!=null&&df!=null)correlation=mapper.getCorrelator(sf,df);
        } else {
            var sd=s.getSourceProgram().getListing().getDataAt(match.getSourceAddress());
            var dd=s.getDestinationProgram().getListing().getDataAt(match.getDestinationAddress());
            if(sd!=null&&dd!=null)correlation=mapper.getCorrelator(sd,dd);
        }
        var nativeItems=match.getAssociation().getMarkupItems(m);m.checkCancelled();List<Item> items=new ArrayList<>();Set<String> ids=new HashSet<>();
        for(VTMarkupItem item:nativeItems){
            m.checkCancelled();if(items.size()>=10000)throw new IllegalStateException("Association has more than 10000 markup items; refine matches");
            String id=hash(item.getMarkupType().getClass().getName()+"|"+item.getSourceAddress());if(!ids.add(id))throw new IllegalStateException("Native markup IDs are ambiguous");
            // Map a detached transient item for preview: setting a default on a stored
            // considered native item would otherwise write to the session during a read.
            VTMarkupItem display=item;Address mapped=item.getDestinationAddress();
            if(mapped==null&&correlation!=null){var range=correlation.getCorrelatedDestinationRange(item.getSourceAddress(),m);if(range!=null){
                var detached=new ghidra.feature.vt.api.impl.MarkupItemImpl(item.getAssociation(),item.getMarkupType(),item.getSourceAddress());
                detached.setDefaultDestinationAddress(range.getMinAddress(),range.getCorrelatorName());mapped=detached.getDestinationAddress();display=detached;
            }}
            Map<String,Object> row=new LinkedHashMap<>();row.put("id",id);row.put("type",item.getMarkupType().getDisplayName());row.put("status",item.getStatus().toString());row.put("source_address",String.valueOf(item.getSourceAddress()));row.put("destination_address",String.valueOf(mapped));row.put("can_apply",item.canApply()&&display.canApply());row.put("can_unapply",item.canUnapply());row.put("source_value",String.valueOf(item.getSourceValue()));row.put("current_destination_value",String.valueOf(display.getCurrentDestinationValue()));row.put("original_destination_value",String.valueOf(item.getOriginalDestinationValue()));row.put("apply_action",String.valueOf(item.getMarkupType().getApplyAction(opts)));items.add(new Item(id,item,mapped,row));
        }
        items.sort(Comparator.comparing(Item::id));
        for(Item i:items)i.row.put("unapply_affected_ids",items.stream().filter(x->x.nativeItem.canUnapply()&&x.nativeItem.getMarkupType().equals(i.nativeItem.getMarkupType())&&Objects.equals(x.nativeItem.getDestinationAddress(),i.nativeItem.getDestinationAddress())).map(Item::id).toList());
        String content=new ObjectMapper().writeValueAsString(Map.of("session",VTSupport.canonical(s.getDomainFile()),"session_modification",s.getModificationNumber(),"source",tokenIdentity(s.getSourceProgram()),"destination",tokenIdentity(s.getDestinationProgram()),"match",VTSupport.match(match),"items",items.stream().map(Item::row).toList(),"options",new TreeMap<>(options(a))));
        return new Preview(s,match,items,hash(content));
    }
    private Map<String,Object> tokenIdentity(Program program){return Map.of("id",ProgramIdentity.id(program),"revision",program.getModificationNumber());}
    private McpSchema.CallToolResult markup(Map<String,Object>a,TaskMonitor m)throws Exception{
        Preview p=preview(a,m);int off=VTSupport.offset(a),limit=VTSupport.limit(a);List<Map<String,Object>> rows=p.items.stream().skip(off).limit(limit).map(Item::row).toList();
        return VTSupport.result(Map.of("markup",rows,"preview_token",p.token,"total",p.items.size(),"offset",off,"truncated",(long)off+rows.size()<p.items.size(),"saved",false));
    }
    private McpSchema.CallToolResult changeMarkup(Map<String,Object>a,TaskMonitor m,boolean unapply)throws Exception{
        Program source=VTSupport.session(a,m).getSourceProgram();
        if(!source.lock("MCP VT source snapshot"))throw new IllegalStateException("Source has active edits or analysis; retry when idle");
        try{return changeMarkupWithSourceLocked(a,m,unapply);}finally{source.unlock();}
    }
    private McpSchema.CallToolResult changeMarkupWithSourceLocked(Map<String,Object>a,TaskMonitor m,boolean unapply)throws Exception{
        Preview p=preview(a,m);VTSupport.writable(p.session);
        if(!p.token.equals(VTSupport.required(a,"preview_token")))throw new IllegalStateException("Stale preview_token; inspect markup with the same options again");
        if(!(a.get("markup_ids") instanceof List<?> supplied)||supplied.isEmpty()||supplied.size()>VTSupport.MAX_LIMIT)throw new IllegalArgumentException("markup_ids must contain 1..500 unique IDs");
        Set<String> selected=new LinkedHashSet<>();for(Object id:supplied)if(!(id instanceof String value)||!selected.add(value))throw new IllegalArgumentException("markup_ids must contain unique strings");
        List<Item> targets=p.items.stream().filter(i->selected.contains(i.id)).toList();if(targets.size()!=selected.size())throw new IllegalArgumentException("Unknown markup ID");
        ToolOptions opts=VTOptionsSupport.applyOptions(options(a));
        if(!unapply&&p.match.getAssociation().getStatus()!=VTAssociationStatus.ACCEPTED)throw new IllegalArgumentException("Accept association before applying markup");
        for(Item i:targets){if(unapply){if(!i.nativeItem.canUnapply())throw new IllegalArgumentException("Selected item cannot be unapplied: "+i.id);for(Object affected:(List<?>)i.row.get("unapply_affected_ids"))if(!selected.contains(affected))throw new IllegalArgumentException("Unapply also affects "+affected+"; select every affected ID shown in preview");}
            else {var action=i.nativeItem.getMarkupType().getApplyAction(opts);if(!i.nativeItem.canApply()||action==null||!i.nativeItem.supportsApplyAction(action))throw new IllegalArgumentException("Selected markup is excluded or cannot be applied with these options: "+i.id);}}
        int tx=p.session.startTransaction(unapply?"MCP VT unapply":"MCP VT apply");boolean commit=false;List<Map<String,Object>> results=new ArrayList<>();
        try{
            if(p.session.getCurrentTransactionInfo().getOpenSubTransactions().stream().anyMatch(description -> !description.endsWith(": ") && !description.endsWith(unapply?": MCP VT unapply":": MCP VT apply"))){commit=true;throw new IllegalStateException("Another writer started a transaction; no markup applied");}
            if(!p.token.equals(preview(a,m).token))throw new IllegalStateException("Program or session changed before apply; preview again");
            for(Item i:targets){m.checkCancelled();if(unapply){if(i.nativeItem.canUnapply())i.nativeItem.unapply();}else {
                if(i.nativeItem.getDestinationAddress()==null&&i.mappedDestination!=null)i.nativeItem.setDefaultDestinationAddress(i.mappedDestination,"MCP native address correlation");
                i.nativeItem.apply(i.nativeItem.getMarkupType().getApplyAction(opts),opts);
            }results.add(Map.of("id",i.id,"status",i.nativeItem.getStatus().toString(),"can_unapply",i.nativeItem.canUnapply()));}m.checkCancelled();commit=true;return VTSupport.result(Map.of("items",results,"saved",false));
        }finally{p.session.endTransaction(tx,commit);}
    }
}
