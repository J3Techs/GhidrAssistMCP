package ghidrassistmcp;

import java.io.File;
import java.nio.file.*;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.GhidraApplicationLayout;
import ghidra.base.project.GhidraProject;
import ghidra.framework.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.util.task.TaskMonitor;

/** Standalone disposable project server for real client conformance. Never opens user projects. */
public final class UpgradeFixtureServer {
    public static void main(String[] args) throws Exception {
        Path root = Path.of(args[0]).toAbsolutePath();
        Files.createDirectories(root);
        Path projectRoot = Files.createTempDirectory(root, "project-");
        Application.initializeApplication(new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))),
            new HeadlessGhidraApplicationConfiguration());
        Object owner = new Object();
        GhidraProject project = GhidraProject.createProject(projectRoot.toString(), "UpgradeFixture", false);
        try {
            var backend = new HeadlessProjectBackend(project.getProject());
            var server = new GhidrAssistMCPServer("127.0.0.1", 0, backend);
            List<ProgramDB> programs = new ArrayList<>();
            try {
                var lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
                for (String name : List.of("source", "target", "space # selector")) {
                    var p = new ProgramDB(name, lang, lang.getDefaultCompilerSpec(), owner);
                    programs.add(p);
                    var entry = p.getAddressFactory().getAddress("1000");
                    int tx = p.startTransaction("disposable fixture");
                    try {
                        var block = p.getMemory().createInitializedBlock("text", entry, 256, (byte)0x90, TaskMonitor.DUMMY, false);
                        block.setExecute(true);
                        // push ebp; mov ebp,esp; mov eax,42; pop ebp; ret
                        p.getMemory().setBytes(entry, new byte[]{0x55,(byte)0x89,(byte)0xe5,(byte)0xb8,42,0,0,0,0x5d,(byte)0xc3});
                        if (!new DisassembleCommand(entry, new AddressSet(entry, entry.add(9)), true).applyTo(p, TaskMonitor.DUMMY))
                            throw new IllegalStateException("fixture disassembly failed");
                        p.getFunctionManager().createFunction(name.equals("source") ? "answer" : null, entry,
                            new AddressSet(entry, entry.add(9)), name.equals("source") ? SourceType.USER_DEFINED : SourceType.DEFAULT);
                    } finally { p.endTransaction(tx, true); }
                    project.getProjectData().getRootFolder().createFile(name, p, TaskMonitor.DUMMY);
                    backend.adoptProgram(p);
                }
                server.start();
                var evidence = new LinkedHashMap<String,Object>();
                evidence.put("endpoint", "http://127.0.0.1:" + server.getLocalPort() + "/mcp");
                evidence.put("project_directory", projectRoot.toString());
                evidence.put("pid", ProcessHandle.current().pid());
                evidence.put("backend_code_source", GhidrAssistMCPBackend.class.getProtectionDomain().getCodeSource().getLocation().toString());
                evidence.put("build_info", new ghidrassistmcp.resources.RuntimeCapabilitiesResource(() -> backend).snapshot().get("build_info"));
                evidence.put("programs", programs.stream().map(p -> Map.of("name", p.getName(), "program_id", ProgramIdentity.id(p))).toList());
                new ObjectMapper().writeValue(root.resolve("ready.json").toFile(), evidence);
                System.out.println("UPGRADE_FIXTURE_READY " + server.getLocalPort());
                while (!Files.exists(root.resolve("stop"))) Thread.sleep(250);
            } finally {
                try { server.stop(); } finally { backend.shutdownHeadlessPrograms(); }
                for (var p : programs) if (!p.isClosed() && p.isUsedBy(owner)) p.release(owner);
            }
        } finally { project.close(); }
        Files.writeString(root.resolve("stopped"), "owned server and project closed");
    }
}
