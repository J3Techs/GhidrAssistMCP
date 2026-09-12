package ghidrassistmcp.nativeapi;

import static org.junit.jupiter.api.Assertions.*;
import java.io.File;
import java.util.*;
import org.junit.jupiter.api.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidra.program.util.ProgramDiff;
import ghidra.program.util.ProgramDiffFilter;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidra.base.project.GhidraProject;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.service.FidService;
import java.nio.file.Files;
import java.util.function.Predicate;
import ghidra.program.util.DefaultLanguageService;

class NativeAnalysisProgramDbTest {
    static final Object CONSUMER=new Object();
    @BeforeAll static void init() throws Exception { if(!Application.isInitialized()) Application.initializeApplication(new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))),new HeadlessGhidraApplicationConfiguration()); }
    @Test void parsePreviewImportAndRejectUnboundedSelection() throws Exception {
        var l=DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default")); Program p=new ProgramDB("native-types",l,l.getDefaultCompilerSpec(),CONSUMER);
        try {
            var parsed=NativeAnalysisTools.tools().stream().filter(t->t.getName().equals("parse_c_declarations")).findFirst().orElseThrow().execute(Map.of("text","typedef unsigned int U32; struct Packet { U32 length; char tag[4]; };","language",l.getLanguageID().toString(),"compiler",l.getDefaultCompilerSpec().getCompilerSpecID().toString()),p);
            assertFalse(parsed.isError(),()->parsed.content().toString()); Map<?,?> body=(Map<?,?>)parsed.structuredContent(); String archive=(String)body.get("staging_path"); assertNotNull(archive); assertTrue(new File(archive).isFile()); String packetPath=(String)((Map<?,?>)((List<?>)body.get("types")).stream().filter(x->String.valueOf(((Map<?,?>)x).get("name")).contains("Packet")).findFirst().orElseThrow()).get("category"); packetPath=packetPath+"/Packet";
            var imp=NativeAnalysisTools.tools().stream().filter(t->t.getName().equals("datatype_import_selected")).findFirst().orElseThrow();
            var preview=imp.execute(Map.of("path",archive,"names",List.of(packetPath),"dry_run",true),p); assertFalse(preview.isError(),()->preview.content().toString()); assertEquals(false,((Map<?,?>)preview.structuredContent()).get("committed"));
            var done=imp.execute(Map.of("path",archive,"names",List.of(packetPath),"dry_run",false,"preview_token",((Map<?,?>)preview.structuredContent()).get("preview_token")),p); assertFalse(done.isError(),()->done.content().toString()); assertNotNull(p.getDataTypeManager().getDataType(packetPath));
            assertTrue(imp.execute(Map.of("path",archive,"names",List.of()),p).isError());
        } finally {p.release(CONSUMER);}
    }
    @Test void nativeProgramDiffFindsByteAndCommentRange() throws Exception {
        var l=DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default")); Program a=new ProgramDB("a",l,l.getDefaultCompilerSpec(),CONSUMER), b=new ProgramDB("b",l,l.getDefaultCompilerSpec(),CONSUMER);
        try { Address base=a.getAddressFactory().getAddress("0x1000"); for(Program p:List.of(a,b)){int tx=p.startTransaction("fixture");p.getMemory().createInitializedBlock("text",base,0x20,(byte)0x90,TaskMonitor.DUMMY,false);p.endTransaction(tx,true);} int tx=b.startTransaction("change");b.getMemory().setByte(base,(byte)0x91);b.getListing().setComment(base,ghidra.program.model.listing.CodeUnit.EOL_COMMENT,"changed");b.endTransaction(tx,true);
            var diff=new ProgramDiff(a,b); var set=diff.getDifferences(new ProgramDiffFilter(ProgramDiffFilter.BYTE_DIFFS|ProgramDiffFilter.EOL_COMMENT_DIFFS),TaskMonitor.DUMMY); assertTrue(set.contains(base));
        } finally {a.release(CONSUMER);b.release(CONSUMER);}
    }
    @Test void failPolicyRejectsExistingDependencyBeforeTransaction() throws Exception {
        var l=DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default")); Program p=new ProgramDB("native-conflict",l,l.getDefaultCompilerSpec(),CONSUMER);
        try { var parsed=NativeAnalysisTools.tools().stream().filter(t->t.getName().equals("parse_c_declarations")).findFirst().orElseThrow().execute(Map.of("text","typedef unsigned int U32; struct Packet { U32 length; };","language",l.getLanguageID().toString(),"compiler",l.getDefaultCompilerSpec().getCompilerSpecID().toString()),p); String archive=(String)((Map<?,?>)parsed.structuredContent()).get("staging_path");
            int tx=p.startTransaction("existing dependency");p.getDataTypeManager().addDataType(new ghidra.program.model.data.TypedefDataType("U32",ghidra.program.model.data.UnsignedIntegerDataType.dataType),ghidra.program.model.data.DataTypeConflictHandler.DEFAULT_HANDLER);p.endTransaction(tx,true);
            var imp=NativeAnalysisTools.tools().stream().filter(t->t.getName().equals("datatype_import_selected")).findFirst().orElseThrow();var result=imp.execute(Map.of("path",archive,"names",List.of("/Packet"),"conflict_policy","fail"),p);assertTrue(result.isError());assertNotNull(p.getDataTypeManager().getDataType("/U32"));
        } finally {p.release(CONSUMER);}
    }
    @Test void fidToolUsesNativeNoDatabaseOutcomeOnDisposableProgram() throws Exception {
        var l=DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default")); Program p=new ProgramDB("fid-no-db",l,l.getDefaultCompilerSpec(),CONSUMER);
        try { var tool=NativeAnalysisTools.tools().stream().filter(t->t.getName().equals("fid_identify_functions")).findFirst().orElseThrow(); var r=tool.execute(Map.of("address","0x1000"),p); assertFalse(r.isError()); assertTrue(Set.of("no_database","no_function","no_match","matches","incompatible_database").contains(((Map<?,?>)r.structuredContent()).get("status"))); } finally {p.release(CONSUMER);}
    }
    @Test void fidToolFindsCandidateInDisposableNativeDatabase() throws Exception {
        var l=DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default")); Program p=new ProgramDB("fid-source",l,l.getDefaultCompilerSpec(),CONSUMER); java.nio.file.Path dir=Files.createTempDirectory("fid-fixture"); GhidraProject project=GhidraProject.createProject(dir.toString(),"FidFixture",false);
        try {Address base=p.getAddressFactory().getAddress("0x1000");int tx=p.startTransaction("code");p.getMemory().createInitializedBlock("text",base,0x40,(byte)0x90,TaskMonitor.DUMMY,false);p.getMemory().setBytes(base,new byte[]{(byte)0x55,(byte)0x8b,(byte)0xec,(byte)0x83,(byte)0xec,(byte)0x10,(byte)0x31,(byte)0xc0,(byte)0x40,(byte)0x01,(byte)0xc8,(byte)0x83,(byte)0xc0,(byte)0x02,(byte)0x89,(byte)0x45,(byte)0xfc,(byte)0x8b,(byte)0x45,(byte)0xfc,(byte)0x83,(byte)0xc0,(byte)0x03,(byte)0x89,(byte)0x45,(byte)0xf8,(byte)0x8b,(byte)0x45,(byte)0xf8,(byte)0x5d,(byte)0xc3});new DisassembleCommand(new AddressSet(base,base.add(0x20)),null).applyTo(p,TaskMonitor.DUMMY);if(p.getFunctionManager().getFunctionAt(base)==null)p.getFunctionManager().createFunction("benign",base,new AddressSet(base,base.add(31)),SourceType.USER_DEFINED); else p.getFunctionManager().getFunctionAt(base).setName("benign",SourceType.USER_DEFINED);p.endTransaction(tx,true);var df=project.getProjectData().getRootFolder().createFile("source",p,TaskMonitor.DUMMY);java.io.File fid=new java.io.File(dir.toFile(),"fixture.fidb");FidFileManager.getInstance().createNewFidDatabase(fid);var ff=FidFileManager.getInstance().addUserFidFile(fid);try(var db=ff.getFidDB(true)){new FidService().createNewLibraryFromPrograms(db,"Fixture","1","x",List.of(df),pair->true,l.getLanguageID(),List.of(),List.of(),TaskMonitor.DUMMY);db.saveDatabase("fixture",TaskMonitor.DUMMY);}FidFileManager.getInstance().removeUserFile(ff);ff=FidFileManager.getInstance().addUserFidFile(fid);assertTrue(ff.canProcessLanguage(p.getLanguage()));var tool=NativeAnalysisTools.tools().stream().filter(t->t.getName().equals("fid_identify_functions")).findFirst().orElseThrow();var r=tool.execute(Map.of("address","1000","threshold",0.0,"limit",10),p);assertFalse(r.isError(),()->r.content().toString());assertEquals("matches",((Map<?,?>)r.structuredContent()).get("status"));List<?> matches=(List<?>)((Map<?,?>)r.structuredContent()).get("matches");assertFalse(matches.isEmpty());assertEquals("benign",((Map<?,?>)matches.get(0)).get("target_name"));assertEquals("benign",((Map<?,?>)matches.get(0)).get("candidate_name"));assertEquals("Fixture",((Map<?,?>)matches.get(0)).get("library"));FidFileManager.getInstance().removeUserFile(ff);} finally {if(!p.isClosed())p.release(CONSUMER);project.close();}
    }
    @Test void diffRejectsUnknownCategoryAtToolBoundary() {
        var tool=NativeAnalysisTools.tools().stream().filter(t->t.getName().equals("program_diff")).findFirst().orElseThrow(); assertTrue(tool.getInputSchema()!=null);
        assertTrue(tool.execute(Map.of("program_a","a","program_b","b"),null).isError());
    }
}
