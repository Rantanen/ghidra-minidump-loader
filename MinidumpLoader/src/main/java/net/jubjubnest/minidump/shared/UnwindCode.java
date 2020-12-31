package net.jubjubnest.minidump.shared;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.exception.NotYetImplementedException;

public class UnwindCode {
	public static UnwindCode parse(BinaryReader reader, byte fpreg) throws IOException {
		var code = new UnwindCode();
		code.prologOffset = reader.readNextByte();
		var op = reader.readNextByte();
		byte opcode = (byte)(op & 0x0f);
		byte opinfo = (byte)((op & 0xf0) >> 4);
		
		switch (opcode) {
		case 0:
			// UWOP_PUSH_NONVOL
			code.spEffect = 8;
			code.opcodeSize = 1;
			break;
		case 1:
			// UWPO_ALLOC_LARGE
			if (opinfo == 0) {
				// Single scaled uint16le
				code.spEffect = (reader.readNextByte() & 0xff) + ((reader.readNextByte() & 0xff) << 8);
				code.spEffect *= 8;
				code.opcodeSize = 2;
			} else {
				// Single unscaled uint32le
				code.spEffect =
						reader.readNextByte() +
						(reader.readNextByte() << 8) +
						(reader.readNextByte() << 16) +
						(reader.readNextByte() << 24);
				code.opcodeSize = 3;
			}
			break;
		case 2:
			// UWPO_ALLOC_SMALL
			code.spEffect = opinfo * 8 + 8;
			code.opcodeSize = 1;
			break;
		case 3:
			code.spEffect = fpreg * 16;
			code.opcodeSize = 1;
			break;
		case 4:
			// Save register into previously allocated stack space.
			code.spEffect = 0;
			code.opcodeSize = 2;
			break;
		case 5:
			// Save register into previously allocated stack space.
			code.spEffect = 0;
			code.opcodeSize = 3;
			break;
		case 6:
			// Save register into previously allocated stack space.
			code.spEffect = 0;
			code.opcodeSize = 2;
			break;
		case 7:
			// Save register into previously allocated stack space.
			code.spEffect = 0;
			code.opcodeSize = 3;
			break;
		case 8:
			// Save register into previously allocated stack space.
			code.spEffect = 0;
			code.opcodeSize = 2;
			break;
		case 9:
			// Save register into previously allocated stack space.
			code.spEffect = 0;
			code.opcodeSize = 3;
			break;
		case 10:
			if (opcode == 0) {
				code.spEffect = 5 * 8;
			} else if (opinfo == 1) {
				code.spEffect = 6 * 8;
			} else {
				throw new NotYetImplementedException("Machine frame " + opinfo);
			}
			code.opcodeSize = 1;
			break;
			
		default:
			return null;
		}
		
		return code;
	}
	
	public byte prologOffset;
	public int spEffect;
	public byte opcodeSize;
}
