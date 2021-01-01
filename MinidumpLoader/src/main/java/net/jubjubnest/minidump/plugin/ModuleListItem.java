package net.jubjubnest.minidump.plugin;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import net.jubjubnest.minidump.data.ModuleData;

class ModuleListItem {
	
	public String name;
	public Address baseAddress;
	public String symbolPath;
	public boolean symbolsLoaded;
	
	public ModuleListItem(Program program, ModuleData data) {
		this.name = data.name;
		this.symbolPath = data.loadedSymbols;
		this.symbolsLoaded = data.loadedSymbols != null;
		this.baseAddress = data.baseAddress;
	}
}
