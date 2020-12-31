package net.jubjubnest.minidump.loader.parser;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;

public class MinidumpMemory64List {

	public static final int DESCRIPTOR_SIZE = 8 + 8;

	public static MinidumpMemory64List parse(long offset, ByteProvider provider) throws IOException {
		var bytes = provider.readBytes(offset, DESCRIPTOR_SIZE);
		var byteBuffer = ByteBuffer.wrap(bytes);
		byteBuffer.order(ByteOrder.LITTLE_ENDIAN);

		var list = new MinidumpMemory64List();
		list.memoryRangeCount = byteBuffer.getLong();
		list.dataOffset = byteBuffer.getLong();

		list.descriptors = new ArrayList<MinidumpMemory64Descriptor>((int) list.memoryRangeCount);
		var segmentBytes = provider.readBytes(offset + DESCRIPTOR_SIZE,
				list.memoryRangeCount * MinidumpMemory64Descriptor.RECORD_SIZE);
		var segmentBuffer = ByteBuffer.wrap(segmentBytes);
		segmentBuffer.order(ByteOrder.LITTLE_ENDIAN);

		var dataOffset = list.dataOffset;
		for (int i = 0; i < list.memoryRangeCount; i++) {
			var descriptor = MinidumpMemory64Descriptor.parse(segmentBuffer, dataOffset);
			dataOffset += descriptor.segmentSize;
			list.descriptors.add(descriptor);
		}

		return list;
	}

	public long memoryRangeCount;
	public long dataOffset;

	public List<MinidumpMemory64Descriptor> descriptors;
}