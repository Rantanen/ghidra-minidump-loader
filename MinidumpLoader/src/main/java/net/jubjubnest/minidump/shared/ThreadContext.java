package net.jubjubnest.minidump.shared;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public interface ThreadContext {

	public int getType();
	public byte[] toBytes();
	
	public void apply(Program program, PluginTool tool);
}
