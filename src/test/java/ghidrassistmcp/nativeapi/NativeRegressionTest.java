package ghidrassistmcp.nativeapi;

import static org.junit.jupiter.api.Assertions.*;
import java.io.File;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.*;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;

class NativeRegressionTest {
    private final Object owner=new Object();
    @BeforeAll static void init()throws Exception{if(!Application.isInitialized())Application.initializeApplication(new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))),new HeadlessGhidraApplicationConfiguration());}
    private Program program(String name)throws Exception{var language=DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));return new ProgramDB(name,language,language.getDefaultCompilerSpec(),owner);}
    private static McpTool tool(String name){return NativeAnalysisTools.tools().stream().filter(t->t.getName().equals(name)).findFirst().orElseThrow();}
    private static Map<?,?> body(CallToolResult result){assertFalse(Boolean.TRUE.equals(result.isError()),()->result.content().toString());return (Map<?,?>)result.structuredContent();}
    private static Map<String,Object> commitArgs(Map<String,Object> args,Map<?,?> preview){Map<String,Object> out=new LinkedHashMap<>(args);out.put("dry_run",false);out.put("preview_token",preview.get("preview_token"));return out;}

    @Test void importedArchiveIdentitySurvivesLocalRenameAndConflictsArePreviewed()throws Exception{
        Program p=program("types");try{
            Map<?,?> parsed=body(tool("parse_c_declarations").execute(Map.of("text","struct Packet { unsigned int value; };"),p));
            String path=(String)((Map<?,?>)((List<?>)parsed.get("types")).stream().filter(row->((Map<?,?>)row).get("name").equals("Packet")).findFirst().orElseThrow()).get("path");
            Map<String,Object> args=new LinkedHashMap<>(Map.of("path",parsed.get("staging_path"),"names",List.of(path),"conflict_policy","preserve"));
            Map<?,?> preview=body(tool("datatype_import_selected").execute(args,p));
            body(tool("datatype_import_selected").execute(commitArgs(args,preview),p));
            Structure imported=(Structure)p.getDataTypeManager().getDataType(path);int tx=p.startTransaction("local change");imported.setName("LocallyRenamed");imported.add(IntegerDataType.dataType,"extra",null);p.endTransaction(tx,true);
            assertTrue(tool("datatype_import_selected").execute(commitArgs(args,preview),p).isError());
            args.put("conflict_policy","fail");Map<?,?> conflict=body(tool("datatype_import_selected").execute(args,p));
            assertEquals(false,conflict.get("can_apply"));assertFalse(((List<?>)conflict.get("conflicts")).isEmpty());
            assertTrue(tool("datatype_import_selected").execute(commitArgs(args,conflict),p).isError());assertEquals(8,imported.getLength());
            args.put("conflict_policy","preserve");body(tool("datatype_import_selected").execute(commitArgs(args,body(tool("datatype_import_selected").execute(args,p))),p));assertEquals(8,imported.getLength());
        }finally{p.release(owner);}
    }
    @Test void explicitHeaderParsingWorksAndReportsExactPaths(@TempDir Path dir)throws Exception{
        Files.writeString(dir.resolve("base.h"),"typedef unsigned int COUNT;\n");Files.writeString(dir.resolve("main.h"),"#include \"base.h\"\nstruct Header { COUNT count; };\n");Program p=program("headers");try{
            Map<?,?> parsed=body(tool("parse_c_declarations").execute(Map.of("header_paths",List.of(dir.resolve("main.h").toString()),"include_paths",List.of(dir.toString())),p));
            assertTrue(((List<?>)parsed.get("types")).stream().anyMatch(row->"Header".equals(((Map<?,?>)row).get("name"))));assertEquals(0,p.getDataTypeManager().getDataTypeCount(false));
        }finally{p.release(owner);}
    }
    @Test void diffToolHonorsExactRangeAndCategories()throws Exception{
        Program a=program("a"),b=program("b");GhidrAssistMCPBackend backend=new GhidrAssistMCPBackend(){public List<Program> getAllOpenPrograms(){return List.of(a,b);}};
        try{
            for(Program p:List.of(a,b)){int tx=p.startTransaction("fixture");Address at=p.getAddressFactory().getAddress("1000");p.getMemory().createInitializedBlock("text",at,32,(byte)0,TaskMonitor.DUMMY,false);p.getListing().createData(at,DWordDataType.dataType);p.endTransaction(tx,true);}
            int tx=b.startTransaction("difference");b.getMemory().setByte(b.getAddressFactory().getAddress("1001"),(byte)2);b.getMemory().setByte(b.getAddressFactory().getAddress("1005"),(byte)3);b.endTransaction(tx,true);
            Map<?,?> result=body(tool("program_diff").execute(Map.of("program_a","a","program_b","b","categories",List.of("bytes"),"start","1001","end","1001"),a,backend));
            assertEquals(1L,((Number)result.get("count")).longValue());assertEquals(1,((List<?>)result.get("addresses")).size());
            assertTrue(tool("program_diff").execute(Map.of("program_a","a","program_b","b","categories",List.of("bogus")),a,backend).isError());
        }finally{backend.getTaskManager().shutdown();a.release(owner);b.release(owner);}
    }
}
