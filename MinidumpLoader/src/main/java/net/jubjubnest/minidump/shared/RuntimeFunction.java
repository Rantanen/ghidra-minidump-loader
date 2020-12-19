package net.jubjubnest.minidump.shared;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.address.Address;

public class RuntimeFunction {
	
	public Address imageBase;
	public Address startOfFunction;
	public Address endOfFunction;
	public Address runtimeInfo;

	public static RuntimeFunction parse(Address imageBase, BinaryReader reader) throws IOException {
		return new RuntimeFunction(
			imageBase,
			imageBase.add(reader.readNextInt()),
			imageBase.add(reader.readNextInt()),
			imageBase.add(reader.readNextInt()));
	}
	
	public RuntimeFunction(Address base, Address startFn, Address endFn, Address rtInfo) {
		imageBase = base;
		startOfFunction = startFn;
		endOfFunction = endFn;
		runtimeInfo = rtInfo;
	}
	
	public RuntimeInfo readRuntimeInfo(ByteProvider bytes) throws IOException {
		BinaryReader reader = new BinaryReader(bytes, true);
		reader.setPointerIndex(runtimeInfo.getOffset());
		return RuntimeInfo.parse(imageBase, reader);
	}
}
