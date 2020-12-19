package net.jubjubnest.minidump.shared;

import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;

public class ThreadData {
	
	public int id;
	public long stackBase;
	public long stackLimit;
	public long stackPointer;
	public long sp;
	public long ip;
}
