// Ghidra script wrapper - delegates to compiled extension class. The extension
// releases GhidraScript's transaction before wait mode, allowing MCP saves and VT.
// Must NOT have a package declaration for Ghidra's script engine to load it.
public class GAMCPStartServerScript extends ghidrassistmcp.scripts.GAMCPStartServerScript {
}
