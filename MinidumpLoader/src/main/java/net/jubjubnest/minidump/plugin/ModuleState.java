package net.jubjubnest.minidump.plugin;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramUserData;
import net.jubjubnest.minidump.shared.ModuleData;

public class ModuleState {
	
	public String name;
	public Address baseAddress;
	public String loadedSymbols;
	
	public ModuleState(Program program, ModuleData data) {
		this.name = data.name;
		this.loadedSymbols = data.loadedSymbols;
		this.baseAddress = program.getImageBase().getNewAddress(data.baseAddress);
	}
	
	public void setLoadedSymbols(Program program, String symbols) {
		this.loadedSymbols = symbols;

		ProgramUserData userData = program.getProgramUserData();
		int transaction = userData.startTransaction();
		try {
			ModuleData data = ModuleData.getContainingModuleData(program, baseAddress);
			data.loadedSymbols = symbols;
			ModuleData.setModuleData(userData, baseAddress, data);
		} finally {
			userData.endTransaction(transaction);
		}
	}
}
