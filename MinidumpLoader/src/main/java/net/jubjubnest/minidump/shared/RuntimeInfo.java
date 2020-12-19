package net.jubjubnest.minidump.shared;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.address.Address;

public class RuntimeInfo {

	public static final long HEADER_SIZE = 4;

	public static RuntimeInfo parse(Address baseAddress, BinaryReader reader) throws IOException {

		var ri = new RuntimeInfo();
		int versionAndFlags = reader.readNextByte();
		ri.version = (byte)(versionAndFlags & 0x03);
		ri.flags = (byte)((versionAndFlags & 0xf4) >> 3);

		ri.prolog = reader.readNextByte();
		ri.unwindCodesCount = reader.readNextByte();

		int frameRegisterData = reader.readNextByte();
		ri.frameRegister = (byte)(frameRegisterData & 0x0f);
		ri.frameRegisterOffset = (byte)((frameRegisterData & 0xf0) >> 4);
		
		List<UnwindCode> unwindCodes = new ArrayList<>();
		for (byte i = 0; i < ri.unwindCodesCount; ) {
			var code = UnwindCode.parse(reader, ri.frameRegisterOffset);
			if (code == null)
				break;
			unwindCodes.add(code);
			i += code.opcodeSize;
			if (i > ri.unwindCodesCount)
				throw new IOException("Too many unwind codes");
		}
		ri.unwindCodes = unwindCodes;
		
		// Check for chained unwind info.
		if ((ri.flags & 0x04) != 0) {
			ri.parentFunction = RuntimeFunction.parse(baseAddress, reader);
		}
		
		return ri;
	}

	public byte version;
	public byte flags;
	public byte prolog;
	public byte unwindCodesCount;
	public byte frameRegister;
	public byte frameRegisterOffset;
	public RuntimeFunction parentFunction;
	
	public List<UnwindCode> unwindCodes;
}
