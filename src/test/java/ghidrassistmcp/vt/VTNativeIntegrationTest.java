package ghidrassistmcp.vt;

import static org.junit.jupiter.api.Assertions.*;
import java.io.File;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import ghidra.GhidraApplicationLayout;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.feature.vt.api.db.VTSessionDB;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;

/** Native VT persistence and review smoke test.  This exercises the public VTTool entry points. */
class VTNativeIntegrationTest {
    private static final Object C = new Object();
    @BeforeAll static void init() throws Exception { if(!Application.isInitialized()) Application.initializeApplication(new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))),new HeadlessGhidraApplicationConfiguration()); }
    @AfterEach void releaseSessions(){VTSupport.closeAll();VTSupport.setProjectForTests(null);}

    @Test void markupApplyAndUnapplyPersistAcrossCompleteProjectReopens(@TempDir Path dir)throws Exception{
        GhidraProject project=GhidraProject.createProject(dir.toString(),"MarkupDisk",false);
        Program source=program("source"),destination=program("destination");
        Map<String,Object> selector=new LinkedHashMap<>(Map.of("session","/session","source_address","1000","destination_address","1000"));
        try{
            project.getProjectData().getRootFolder().createFile("source",source,TaskMonitor.DUMMY);project.getProjectData().getRootFolder().createFile("destination",destination,TaskMonitor.DUMMY);
            VTSupport.setProjectForTests(project.getProject());VTTool lifecycle=new VTTool("vt_session");
            assertOk(lifecycle.execute(Map.of("action","create","name","session","destination_program","/destination"),source));
            assertOk(new VTTool("vt_add_matches").execute(selector,source));assertTrue(new VTTool("vt_add_matches").execute(selector,source).isError());
            selector.put("status","accepted");assertOk(new VTTool("vt_review_matches").execute(selector,source));
            Map<?,?> preview=(Map<?,?>)new VTTool("vt_markup").execute(selector,source).structuredContent();
            String id=(String)((Map<?,?>)((List<?>)preview.get("markup")).stream().filter(row->"Function Name".equals(((Map<?,?>)row).get("type"))).findFirst().orElseThrow()).get("id");
            selector.put("markup_ids",List.of(id));selector.put("preview_token",preview.get("preview_token"));
            assertOk(new VTTool("vt_apply_markup").execute(selector,source));assertEquals("source_fn",destination.getFunctionManager().getFunctionAt(destination.getAddressFactory().getAddress("1000")).getName());
            assertOk(lifecycle.execute(Map.of("action","save","session","/session"),source));assertOk(lifecycle.execute(Map.of("action","close","session","/session"),source));
            source.release(C);destination.release(C);source=null;destination=null;project.close();project=GhidraProject.openProject(dir.toString(),"MarkupDisk",false);VTSupport.setProjectForTests(project.getProject());
            assertOk(lifecycle.execute(Map.of("action","get","session","/session"),null));
            var session=VTSupport.session(selector);assertEquals("source_fn",session.getDestinationProgram().getFunctionManager().getFunctionAt(session.getDestinationProgram().getAddressFactory().getAddress("1000")).getName());
            preview=(Map<?,?>)new VTTool("vt_markup").execute(selector,null).structuredContent();selector.put("preview_token",preview.get("preview_token"));
            assertOk(new VTTool("vt_unapply_markup").execute(selector,null));assertOk(lifecycle.execute(Map.of("action","save","session","/session"),null));assertOk(lifecycle.execute(Map.of("action","close","session","/session"),null));
            project.close();project=GhidraProject.openProject(dir.toString(),"MarkupDisk",false);VTSupport.setProjectForTests(project.getProject());session=VTSupport.session(selector);
            assertEquals("FUN_00001000",session.getDestinationProgram().getFunctionManager().getFunctionAt(session.getDestinationProgram().getAddressFactory().getAddress("1000")).getName());
            assertFalse(session.getAssociationManager().getAssociation(session.getSourceProgram().getAddressFactory().getAddress("1000"),session.getDestinationProgram().getAddressFactory().getAddress("1000")).getMarkupItems(TaskMonitor.DUMMY).stream().anyMatch(x->x.canUnapply()));
        }finally{VTSupport.closeAll();if(source!=null&&!source.isClosed())source.release(C);if(destination!=null&&!destination.isClosed())destination.release(C);project.close();}
    }

    @Test void createManualAcceptPreviewApplySaveReopenUnapply(@TempDir Path dir) throws Exception {
        GhidraProject project=GhidraProject.createProject(dir.toString(),"VTFixture",false); Program src=program("source"), dst=program("destination");
        try {
            project.getProjectData().getRootFolder().createFile("source",src,TaskMonitor.DUMMY); project.getProjectData().getRootFolder().createFile("destination",dst,TaskMonitor.DUMMY); VTSupport.setProjectForTests(project.getProject());
            VTTool sessions=new VTTool("vt_session"); assertOk(sessions.execute(Map.of("action","create","name","session","destination_program","/destination"),src));
            Map<String,Object> base=Map.of("session","/session","source_address","1000","destination_address","1000");
            assertOk(new VTTool("vt_add_matches").execute(base,src));
            Map<String,Object> match=(Map<String,Object>)new VTTool("vt_matches").execute(Map.of("session","/session","limit",10),src).structuredContent();
            Map<?,?> row=(Map<?,?>)((List<?>)match.get("matches")).get(0); Map<String,Object> selector=new LinkedHashMap<>(base); selector.put("match_set_id",row.get("match_set_id")); selector.put("status","accepted"); assertOk(new VTTool("vt_review_matches").execute(selector,src));
            Map<String,Object> markup=(Map<String,Object>)new VTTool("vt_markup").execute(selector,src).structuredContent(); String token=(String)markup.get("preview_token"); List<?> items=(List<?>)markup.get("markup"); assertFalse(items.isEmpty());
            Map<?,?> functionName=items.stream().map(x->(Map<?,?>)x).filter(x->"Function Name".equals(x.get("type"))).findFirst().orElseThrow(); String markupId=String.valueOf(functionName.get("id")); selector.put("markup_ids",List.of(markupId)); selector.put("preview_token","stale"); assertTrue(new VTTool("vt_apply_markup").execute(selector,src).isError()); selector.put("preview_token",token); selector.put("options",Map.of()); assertOk(new VTTool("vt_apply_markup").execute(selector,src));
            Map<?,?> saved=(Map<?,?>)sessions.execute(Map.of("action","save","session","/session"),src).structuredContent(); assertEquals(true,saved.get("session_saved"));
            assertOk(sessions.execute(Map.of("action","close","session","/session"),src));
            assertOk(sessions.execute(Map.of("action","get","session","/session"),src));
            Map<String,Object> fresh=(Map<String,Object>)new VTTool("vt_markup").execute(selector,src).structuredContent(); Map<String,Object> unapplyPreview=new LinkedHashMap<>(selector); unapplyPreview.put("markup_ids",List.of(markupId)); unapplyPreview.put("preview_token",fresh.get("preview_token")); assertOk(new VTTool("vt_unapply_markup").execute(unapplyPreview,src)); assertOk(sessions.execute(Map.of("action","save","session","/session"),src)); assertOk(sessions.execute(Map.of("action","close","session","/session"),src));
        } finally { VTSupport.setProjectForTests(null); if(!src.isClosed())src.release(C); if(!dst.isClosed())dst.release(C); project.close(); }
    }

    @Test void dirtyCloseRequiresExplicitDiscard(@TempDir Path dir) throws Exception {
        GhidraProject p=GhidraProject.createProject(dir.toString(),"VTDirty",false); Program s=program("s"),d=program("d"); try {p.getProjectData().getRootFolder().createFile("s",s,TaskMonitor.DUMMY);p.getProjectData().getRootFolder().createFile("d",d,TaskMonitor.DUMMY);VTSupport.setProjectForTests(p.getProject());VTTool t=new VTTool("vt_session");assertOk(t.execute(Map.of("action","create","name","x","destination_program","/d"),s));assertOk(new VTTool("vt_add_matches").execute(Map.of("session","/x","source_address","1000","destination_address","1000"),s));assertTrue(t.execute(Map.of("action","close","session","/x"),s).isError());assertOk(t.execute(Map.of("action","close","session","/x","discard",true),s));}finally{VTSupport.setProjectForTests(null);if(!s.isClosed())s.release(C);if(!d.isClosed())d.release(C);p.close();}}

    private static Program program(String n)throws Exception{var l=DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));ProgramDB p=new ProgramDB(n,l,l.getDefaultCompilerSpec(),C);int tx=p.startTransaction("fixture");Address a=p.getAddressFactory().getAddress("1000");p.getMemory().createInitializedBlock("text",a,0x20,(byte)0x90,TaskMonitor.DUMMY,false).setExecute(true);p.getFunctionManager().createFunction(n.equals("source")?"source_fn":"FUN_1000",a,new AddressSet(a,a.add(7)),n.equals("source")?SourceType.USER_DEFINED:SourceType.DEFAULT);p.endTransaction(tx,true);return p;}
    private static void assertOk(CallToolResult r){assertFalse(Boolean.TRUE.equals(r.isError()),()->r.content().toString());}

    @Test void savedSessionReopensFromDiskWithAcceptedMatch(@TempDir Path dir) throws Exception {
        GhidraProject project=GhidraProject.createProject(dir.toString(),"VTDisk",false); Program src=program("src"), dst=program("dst");
        try {
            project.getProjectData().getRootFolder().createFile("src",src,TaskMonitor.DUMMY); project.getProjectData().getRootFolder().createFile("dst",dst,TaskMonitor.DUMMY); VTSupport.setProjectForTests(project.getProject());
            VTTool sessions=new VTTool("vt_session"); assertOk(sessions.execute(Map.of("action","create","name","disk_session","destination_program","/dst"),src));
            Map<String,Object> selector=new LinkedHashMap<>(Map.of("session","/disk_session","source_address","1000","destination_address","1000")); assertOk(new VTTool("vt_add_matches").execute(selector,src));
            Map<?,?> rows=(Map<?,?>)new VTTool("vt_matches").execute(Map.of("session","/disk_session","limit",10),src).structuredContent(); Map<?,?> row=(Map<?,?>)((List<?>)rows.get("matches")).get(0); selector.put("match_set_id",row.get("match_set_id")); selector.put("status","accepted"); assertOk(new VTTool("vt_review_matches").execute(selector,src));
            Map<?,?> saved=(Map<?,?>)sessions.execute(Map.of("action","save","session","/disk_session"),src).structuredContent(); assertEquals(true,saved.get("session_saved")); assertOk(sessions.execute(Map.of("action","close","session","/disk_session"),src));
            src.release(C); dst.release(C); src=null; dst=null; project.close(); project=null; VTSupport.setProjectForTests(null);
            GhidraProject reopened=GhidraProject.openProject(dir.toString(),"VTDisk",true); try {
                Object consumer=new Object(); var sf=reopened.getProjectData().getFile("/disk_session"); assertNotNull(sf); VTSessionDB disk=(VTSessionDB)sf.getDomainObject(consumer,true,true,TaskMonitor.DUMMY); try { assertEquals(1,disk.getMatchSets().stream().mapToInt(x->x.getMatchCount()).sum()); var match=disk.getMatchSets().stream().flatMap(x->x.getMatches().stream()).filter(x->x.getSourceAddress().getOffset()==0x1000).findFirst().orElseThrow(); assertEquals("ACCEPTED",match.getAssociation().getStatus().toString()); } finally {disk.release(consumer);} } finally {reopened.close();}
        } finally { VTSupport.setProjectForTests(null); if(src!=null&&!src.isClosed())src.release(C); if(dst!=null&&!dst.isClosed())dst.release(C); if(project!=null)project.close(); }
    }
}
