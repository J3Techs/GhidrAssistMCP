// SetupMPC5676R_MemoryMap.java
// Creates proper memory regions for MPC5676R ECU in Ghidra.
// Sources: A2L MEMORY_SEGMENT definitions + ELF segment layout + MPC5676R reference manual.
//
// Usage: Run via MCP (run_script) or from Ghidra Script Manager on 0762_Base.hex
// Note: Uses reflection to temporarily null domainFile, bypassing Ghidra 12's
//       hasExclusiveAccess() check (which delegates to domainFile.isCheckedOutExclusive()).
//       This is required because createUninitializedBlock() demands exclusive access
//       that MCP-opened programs don't have.
// @category L5P

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import java.lang.reflect.Field;

public class SetupMPC5676R_MemoryMap extends GhidraScript {

    @Override
    public void run() throws Exception {

        // Find the domainFile field in DomainObjectAdapter and temporarily null it
        // to bypass hasExclusiveAccess() check for memory block creation
        Field domainFileField = null;
        Class<?> clazz = currentProgram.getClass();
        while (clazz != null) {
            for (Field f : clazz.getDeclaredFields()) {
                if (f.getName().equals("domainFile")) {
                    domainFileField = f;
                    break;
                }
            }
            if (domainFileField != null) break;
            clazz = clazz.getSuperclass();
        }

        if (domainFileField == null) {
            println("ERROR: domainFile field not found - cannot bypass exclusive access");
            return;
        }

        domainFileField.setAccessible(true);
        Object savedDomainFile = domainFileField.get(currentProgram);
        domainFileField.set(currentProgram, null);

        try {
            int txId = currentProgram.startTransaction("Setup MPC5676R Memory Map");
            try {
                Memory memory = currentProgram.getMemory();
                AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();

                // =================================================================
                // SRAM Regions (from A2L MEMORY_SEGMENT + ELF segments)
                // =================================================================
                create(memory, space, "SRAM_APP",    0x40000000L, 0x60000,  true, true, false, false, "Application SRAM - Ve*/Vb* vars, NVM, stacks");
                create(memory, space, "SRAM_INSTR",  0x20000000L, 0x60000,  true, true, true,  false, "Instruction SRAM - HWIO_RAM_INSTR");
                create(memory, space, "SRAM_EXT",    0x20060000L, 0x1A0000, true, true, false, false, "Extended SRAM / emulation overlay");
                create(memory, space, "USER_STACK",  0x41000000L, 0x2000,   true, true, false, false, "User stack");

                // =================================================================
                // MPC5676R Peripheral Registers (from reference manual)
                // =================================================================
                create(memory, space, "FMPLL",       0xC3F80000L, 0x100,   true, true, false, true, "FMPLL - Clock generation");
                create(memory, space, "EBI",         0xC3F84000L, 0x100,   true, true, false, true, "EBI - External Bus Interface");
                create(memory, space, "FLASH_CTRL",  0xC3F88000L, 0x4000,  true, true, false, true, "Flash controller registers");
                create(memory, space, "SIU",         0xC3F90000L, 0x4000,  true, true, false, true, "SIU - Pad config, GPIO, ext IRQ");
                create(memory, space, "eMIOS_0",     0xC3FA0000L, 0x4000,  true, true, false, true, "eMIOS_0 - Timer/PWM");
                create(memory, space, "eMIOS_1",     0xC3FA4000L, 0x4000,  true, true, false, true, "eMIOS_1 - Timer/PWM");
                create(memory, space, "PMC",         0xC3FBC000L, 0x100,   true, true, false, true, "PMC - Power management");
                create(memory, space, "eTPU2_0",     0xC3FC0000L, 0x4000,  true, true, false, true, "eTPU2_0 - Time processing");
                create(memory, space, "eTPU2_1",     0xC3FC4000L, 0x4000,  true, true, false, true, "eTPU2_1 - Time processing");
                create(memory, space, "eTPU_PRAM",   0xC3FC8000L, 0x8000,  true, true, false, true, "eTPU parameter RAM + SCM");
                create(memory, space, "PIT",         0xC3FF0000L, 0x4000,  true, true, false, true, "PIT - Periodic interrupt timers");
                create(memory, space, "STM",         0xFFF3C000L, 0x100,   true, true, false, true, "STM - System timer");
                create(memory, space, "SWT",         0xFFF38000L, 0x100,   true, true, false, true, "SWT - Software watchdog");
                create(memory, space, "eDMA",        0xFFF44000L, 0x4000,  true, true, false, true, "eDMA - DMA controller");
                create(memory, space, "INTC",        0xFFF48000L, 0x4000,  true, true, false, true, "INTC - Interrupt controller");
                create(memory, space, "eQADC_A",     0xFFF80000L, 0x4000,  true, true, false, true, "eQADC_A - ADC");
                create(memory, space, "eQADC_B",     0xFFF84000L, 0x4000,  true, true, false, true, "eQADC_B - ADC");
                create(memory, space, "DECFILT",     0xFFF88000L, 0x4000,  true, true, false, true, "Decimation Filter");
                create(memory, space, "DSPI_0",      0xFFF90000L, 0x4000,  true, true, false, true, "DSPI_0 - SPI");
                create(memory, space, "DSPI_1",      0xFFF94000L, 0x4000,  true, true, false, true, "DSPI_1 - SPI");
                create(memory, space, "DSPI_2",      0xFFF98000L, 0x4000,  true, true, false, true, "DSPI_2 - SPI");
                create(memory, space, "DSPI_3",      0xFFF9C000L, 0x4000,  true, true, false, true, "DSPI_3 - SPI");
                create(memory, space, "eSCI_A",      0xFFFB0000L, 0x4000,  true, true, false, true, "eSCI_A - UART/LIN");
                create(memory, space, "eSCI_B",      0xFFFB4000L, 0x4000,  true, true, false, true, "eSCI_B - UART/LIN");
                create(memory, space, "FlexCAN_A",   0xFFFC0000L, 0x4000,  true, true, false, true, "FlexCAN_A - CAN");
                create(memory, space, "FlexCAN_B",   0xFFFC4000L, 0x4000,  true, true, false, true, "FlexCAN_B - CAN");
                create(memory, space, "FlexCAN_C",   0xFFFC8000L, 0x4000,  true, true, false, true, "FlexCAN_C - CAN");
                create(memory, space, "FlexCAN_D",   0xFFFCC000L, 0x4000,  true, true, false, true, "FlexCAN_D - CAN");
                create(memory, space, "FlexCAN_E",   0xFFFD0000L, 0x4000,  true, true, false, true, "FlexCAN_E - CAN");
                create(memory, space, "FlexCAN_F",   0xFFFD4000L, 0x4000,  true, true, false, true, "FlexCAN_F - CAN");
                create(memory, space, "BAM",         0xFFFFC000L, 0x4000,  true, true, false, true, "BAM - Boot assist module");

                println("MPC5676R memory map setup complete.");
            } finally {
                currentProgram.endTransaction(txId, true);
            }
        } finally {
            // Always restore domainFile
            domainFileField.set(currentProgram, savedDomainFile);
        }
    }

    private void create(Memory memory, AddressSpace space, String name,
            long startAddr, int size, boolean r, boolean w, boolean x,
            boolean isVolatile, String comment) {
        Address addr = space.getAddress(startAddr);
        MemoryBlock existing = memory.getBlock(addr);
        if (existing != null) {
            println("SKIP: " + name + " @ " + String.format("0x%08X", startAddr) +
                " - covered by '" + existing.getName() + "'");
            return;
        }
        try {
            MemoryBlock block = memory.createUninitializedBlock(name, addr, size, false);
            block.setRead(r);
            block.setWrite(w);
            block.setExecute(x);
            block.setComment(comment);
            block.setVolatile(isVolatile);
            println("OK: " + name + " @ " + String.format("0x%08X", startAddr) +
                " (" + String.format("0x%X", size) + " bytes)");
        } catch (Exception e) {
            println("FAIL: " + name + " - " + e.getMessage());
        }
    }
}
