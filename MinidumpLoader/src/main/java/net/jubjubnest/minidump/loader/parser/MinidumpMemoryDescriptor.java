package net.jubjubnest.minidump.loader.parser;

import java.nio.ByteBuffer;

public class MinidumpMemoryDescriptor {

	public static final int RECORD_SIZE = 8 + MinidumpLocationDescriptor.RECORD_SIZE;

	public static MinidumpMemoryDescriptor parse(ByteBuffer byteBuffer) {
		var mem = new MinidumpMemoryDescriptor();
		
		mem.startOfMemoryRange = byteBuffer.getLong();
		mem.memory = MinidumpLocationDescriptor.parse(byteBuffer);

		return mem;
	}

	public long startOfMemoryRange;
	public MinidumpLocationDescriptor memory;
}
