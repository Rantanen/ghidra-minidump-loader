package net.jubjubnest.minidump.plugin;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import net.jubjubnest.minidump.shared.ModuleData;

public class ModuleState {
	
	public String name;
	public Address baseAddress;
	public String symbolPath;
	public boolean symbolsLoaded;
	
	public ModuleState(Program program, ModuleData data) {
		this.name = data.name;
		this.symbolPath = data.loadedSymbols;
		this.symbolsLoaded = data.loadedSymbols != null;
		this.baseAddress = data.baseAddress;
	}
}
