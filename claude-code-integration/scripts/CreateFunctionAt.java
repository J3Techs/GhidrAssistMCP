// Create a function at a given address
// @category Analysis
// @keybinding
// @menupath
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class CreateFunctionAt extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("Usage: CreateFunctionAt <address>");
            return;
        }
        String addrStr = args[0].startsWith("0x") ? args[0].substring(2) : args[0];
        Address addr = toAddr(Long.parseUnsignedLong(addrStr, 16));
        CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
        boolean success = cmd.applyTo(currentProgram, monitor);
        if (success) {
            println("Created function at " + addr);
        } else {
            println("Failed to create function at " + addr + ": " + cmd.getStatusMsg());
        }
    }
}
