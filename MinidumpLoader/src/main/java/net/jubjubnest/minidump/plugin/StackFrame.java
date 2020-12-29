package net.jubjubnest.minidump.plugin;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

class StackFrame {
	Address stackPointer;
	Address instructionPointer;
	Address returnPointer;
	long functionOffset;
	String module;
	
	public StackFrame(
			Address stackPointer,
			Address instructionPointer,
			Address returnPointer,
			long functionOffset,
			String module) {
		this.stackPointer = stackPointer;
		this.instructionPointer = instructionPointer;
		this.returnPointer = returnPointer;
		this.functionOffset = functionOffset;
		this.module = module;
	}
	
	public Address getReturnAddress(Program program) {
		var langDesc = program.getLanguage().getLanguageDescription();
		var ptrSize = langDesc.getSize();
		var buffer = new byte[ptrSize / 8];
		try {
			program.getMemory().getBytes(this.returnPointer, buffer);
		} catch (MemoryAccessException e) {
			return null;
		}
		
		long addr = 0;
		var bb = ByteBuffer.wrap(buffer);
		bb.order(ByteOrder.LITTLE_ENDIAN);
		if (buffer.length == 8) {
			addr = bb.getLong();
		} else {
			addr = bb.getInt();
		}
		return this.returnPointer.getNewAddress(addr);
	}
}