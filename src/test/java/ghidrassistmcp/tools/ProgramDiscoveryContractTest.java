package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.resources.RuntimeCapabilitiesResource;
import io.modelcontextprotocol.json.McpJsonDefaults;
import org.junit.jupiter.api.Test;

/** Contract coverage for bounded discovery and compact runtime orientation. */
class ProgramDiscoveryContractTest {
    private static Program program(String name, String path, String id) {
        DomainFile f=(DomainFile)Proxy.newProxyInstance(DomainFile.class.getClassLoader(),new Class<?>[]{DomainFile.class},(o,m,a)->switch(m.getName()){
            case "getName"->name; case "getPathname"->path; case "getFileID"->id;
            case "getVersion"->1; case "isReadOnly","canSave"->false; case "isBusy"->false;
            case "getLocalProjectURL","getSharedProjectURL"->null; case "getProjectLocator"->new ghidra.framework.model.ProjectLocator("C:/fixture", "discovery");
            default->defaultValue(m.getReturnType()); });
        return (Program)Proxy.newProxyInstance(Program.class.getClassLoader(),new Class<?>[]{Program.class},(o,m,a)->switch(m.getName()){
            case "getName"->name; case "getDomainFile"->f; case "isClosed","isChanged","isChangeable"->false;
            case "getCurrentTransactionInfo"->null; case "getModificationNumber"->0L; case "getExecutablePath"->path;
            case "getExecutableFormat"->"x86"; case "getLanguageID","getCompilerSpec"->null;
            case "equals"->o==a[0]; case "hashCode"->System.identityHashCode(o);
            default->defaultValue(m.getReturnType()); });
    }
    private static Object defaultValue(Class<?> t) { if(!t.isPrimitive())return null; if(t==boolean.class)return false; if(t==long.class)return 0L; if(t==int.class)return 0; if(t==short.class)return (short)0; if(t==byte.class)return (byte)0; if(t==double.class)return 0d; if(t==float.class)return 0f; if(t==char.class)return '\0'; return null; }
    private static final class Backend extends GhidrAssistMCPBackend { List<Program> ps=new ArrayList<>(); @Override public List<Program> getAllOpenPrograms(){return ps;} @Override public Program getCurrentProgram(){return ps.isEmpty()?null:ps.get(0);} }
    private static Map<?,?> body(io.modelcontextprotocol.spec.McpSchema.CallToolResult r){ return (Map<?,?>)r.structuredContent(); }

    @Test void duplicateNamesAndDistinctIdsRemainVisible() {
        Backend b=new Backend(); b.ps.add(program("same","/a/same","a")); b.ps.add(program("same","/b/same","b"));
        var r=body(new ListProgramsTool().execute(Map.of("limit",10),null,b)); assertEquals(2,((List<?>)r.get("programs")).size());
        assertEquals("same",((Map<?,?>)((List<?>)r.get("programs")).get(0)).get("name"));
    }
    @Test void repeatedReferenceCollapsesButCollidingPersistentIdsDoNot() {
        Backend b=new Backend(); Program a=program("one","/one","collision"); Program c=program("one","/one","collision"); b.ps.add(a); b.ps.add(a); b.ps.add(c);
        var rows=(List<?>)body(new ListProgramsTool().execute(Map.of(),null,b)).get("programs"); assertEquals(2,rows.size());
        assertTrue(((Map<?,?>)rows.get(0)).get("collision_count").equals(2)); assertTrue(((Map<?,?>)rows.get(1)).get("collision").equals(true));
    }
    @Test void cursorRejectsMembershipChangeAndBoundsAreStrict() {
        Backend b=new Backend(); b.ps.add(program("a","/a","a")); b.ps.add(program("b","/b","b"));
        Map<?,?> first=body(new ListProgramsTool().execute(Map.of("limit",1),null,b)); String cursor=(String)first.get("next_cursor"); b.ps.add(program("c","/c","c"));
        var changed=new ListProgramsTool().execute(Map.of("cursor",cursor,"limit",1),null,b); assertTrue(changed.isError()); assertEquals("inventory_changed",body(changed).get("error"));
        assertTrue(new ListProgramsTool().execute(Map.of("limit",1.5),null,b).isError()); assertTrue(new ListProgramsTool().execute(Map.of("limit",0),null,b).isError());
    }
    @Test void compactAndFullCapabilitiesValidate() {
        Backend b=new Backend(); b.ps.add(program("a","/a","a")); var t=new RuntimeCapabilitiesTool();
        var compact=body(t.execute(Map.of("include_programs",false),null,b)); assertFalse(compact.containsKey("open_programs")); assertEquals(1,compact.get("program_count"));
        var full=body(t.execute(Map.of(),null,b)); assertTrue(full.containsKey("open_programs")); var s=McpJsonDefaults.getSchemaValidator(); assertTrue(s.validate(t.getOutputSchema(),compact).valid()); assertTrue(s.validate(t.getOutputSchema(),full).valid());
    }
    @Test void longUnicodeInventoryStaysBoundedAndSchemaValid() throws Exception {
        Backend b=new Backend(); String longPath="/"+"漢字🚗".repeat(100); for(int i=0;i<32;i++)b.ps.add(program("p"+i,longPath+i,"id"+i));
        var r=new ListProgramsTool().execute(Map.of(),null,b); assertFalse(r.isError()); assertTrue(new ObjectMapper().writeValueAsString(r.structuredContent()).getBytes(StandardCharsets.UTF_8).length<20000);
        assertTrue(McpJsonDefaults.getSchemaValidator().validate(new ListProgramsTool().getOutputSchema(),r.structuredContent()).valid());
    }
    @Test void resourceRetainsFullRepresentation() {
        Backend b=new Backend(); b.ps.add(program("a","/a","a")); Map<?,?> full=new RuntimeCapabilitiesResource(()->b).snapshot(); assertTrue(full.containsKey("open_programs")); assertEquals(true,full.get("include_programs"));
    }
}
