package net.jubjubnest.minidump.loader.parser;

import java.nio.ByteBuffer;

public class MemoryDescriptor {

	public static final int RECORD_SIZE = 8 + LocationDescriptor.RECORD_SIZE;

	public static MemoryDescriptor parse(ByteBuffer byteBuffer) {
		var mem = new MemoryDescriptor();
		
		mem.startOfMemoryRange = byteBuffer.getLong();
		mem.memory = LocationDescriptor.parse(byteBuffer);

		return mem;
	}

	public long startOfMemoryRange;
	public LocationDescriptor memory;
}
