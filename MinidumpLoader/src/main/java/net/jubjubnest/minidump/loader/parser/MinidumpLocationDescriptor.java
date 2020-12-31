package net.jubjubnest.minidump.loader.parser;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.app.util.bin.ByteProvider;

public class MinidumpLocationDescriptor {
	public static final int RECORD_SIZE = 4 + 4;

	public static MinidumpLocationDescriptor parse(long offset, ByteProvider provider) throws IOException {
		var bytes = provider.readBytes(offset, RECORD_SIZE);
		var byteBuffer = ByteBuffer.wrap(bytes);
		byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
		return parse(byteBuffer);
	}

	public static MinidumpLocationDescriptor parse(ByteBuffer byteBuffer) {
		var descriptor = new MinidumpLocationDescriptor();
		descriptor.size = byteBuffer.getInt();
		descriptor.offset = byteBuffer.getInt();
		return descriptor;
	}

	public int size;
	public int offset;
}
