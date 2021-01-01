package net.jubjubnest.minidump.analyzer;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.datatype.microsoft.GuidUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

class ModuleParser {
	public static class PdbInfo {
		String guid;
		int age;
		String pdbName;
	}
	
	public static PdbInfo getPdbInfo(Program program, Address moduleBase) throws IOException {
		Address codeviewAddress = optionalHeader(program, moduleBase);
		if (codeviewAddress == null) {
			return null;
		}

		String guid = GuidUtil.getGuidString(program, codeviewAddress.add(4), false);

		ByteProvider provider = new MemoryByteProvider(program.getMemory(), moduleBase);
		BinaryReader reader = new BinaryReader(provider, true);
		
		long offset = codeviewAddress.subtract(moduleBase);
		int age = reader.readInt(offset + 0x14);
		String pdbName = reader.readAsciiString(offset + 0x18);
		
		PdbInfo info = new PdbInfo();
		info.guid = guid;
		info.age = age;
		info.pdbName = pdbName;
		return info;
	}

	private static Address optionalHeader(Program program, Address moduleBase) throws IOException {
		ByteProvider provider = new MemoryByteProvider(program.getMemory(), moduleBase);
		BinaryReader reader = new BinaryReader(provider, true);
		
		// Validate magic bytes at the start of the PE image.
		if (!reader.readAsciiString(0, 2).equals("MZ")) {
			return null;
		}

		// Validate magic bytes at the start of the PE portion of the image.
		int peOffset = reader.readInt(0x3C);
		if (!reader.readAsciiString(peOffset, 4).equals("PE")) {
			return null;
		}
		
		int optOffset = peOffset + 0x18;
		if (reader.readShort(optOffset) != 0x020b) {
			return null;
		}

		int directoryCount = reader.readInt(optOffset + 0x6c);
		if (directoryCount < 7) {
			return null;
		}
		
		int debugStart = optOffset + 0x70 + 8 * 6;
		reader.setPointerIndex(debugStart);
		int debugRva = reader.readNextInt();
		int debugSize = reader.readNextInt();
		
		int codeviewAddress = 0;
		for (int debugCursor = debugRva; debugCursor < debugRva + debugSize; debugCursor += 0x1C) {
			int type = reader.readInt(debugCursor + 0xC);
			if (type != 2) {
				continue;
			}

			codeviewAddress = reader.readInt(debugCursor + 0x14);
			break;
		}
		
		if (codeviewAddress == 0) {
			return null;
		}
		
		return moduleBase.add(codeviewAddress);
	}
}
