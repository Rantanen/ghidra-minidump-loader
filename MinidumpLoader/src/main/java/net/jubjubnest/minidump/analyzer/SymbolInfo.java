package net.jubjubnest.minidump.analyzer;

import ghidra.app.util.pdb.PdbProgramAttributes;
import net.jubjubnest.minidump.plugin.PdbResolver.PdbResult;
import net.jubjubnest.minidump.shared.ModuleData;

class SymbolInfo {
	SymbolInfo(ModuleData m, PdbProgramAttributes attributes, PdbResult result) {
		if (m == null || attributes == null) {
			throw new IllegalArgumentException();
		}

		module = m;
		this.attributes = attributes;
		if (result != null) {
			this.result = result;
		}
	}

	ModuleData module;
	PdbProgramAttributes attributes;
	PdbResult result;
}