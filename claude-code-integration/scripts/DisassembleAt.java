// Disassemble at address provided as script argument
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;

public class DisassembleAt extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            println("Usage: provide address as argument");
            return;
        }
        Address addr = currentProgram.getAddressFactory().getAddress(args[0]);

        // Clear any existing code units first
        currentProgram.getListing().clearCodeUnits(addr, addr.add(5), false);

        // Disassemble
        DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
        cmd.applyTo(currentProgram);

        // Print results
        Address curAddr = addr;
        for (int i = 0; i < 6; i++) {
            Instruction instr = currentProgram.getListing().getInstructionAt(curAddr);
            if (instr == null) break;
            println(String.format("0x%s: %s  [%d bytes]", curAddr, instr, instr.getLength()));
            curAddr = curAddr.add(instr.getLength());
        }
    }
}
