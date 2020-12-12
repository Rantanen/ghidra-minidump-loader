package net.jubjubnest.minidump.parser;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;

public class MemoryInfoList {

	// Memory info list doesn't have fixed size, instead it carries size information
	// as part of the data.

	public static MemoryInfoList parse(long offset, ByteProvider provider) throws IOException {
		var bytes = provider.readBytes(offset, 4 + 4 + 8);
		var byteBuffer = ByteBuffer.wrap(bytes);
		byteBuffer.order(ByteOrder.LITTLE_ENDIAN);

		var list = new MemoryInfoList();
		list.headerSize = byteBuffer.getInt();
		list.entrySize = byteBuffer.getInt();
		list.entryCount = byteBuffer.getLong();

		var descriptors = new ArrayList<MemoryInfo>((int) list.entryCount);
		long entriesStart = offset + list.headerSize;
		for (int i = 0; i < list.entryCount; i++) {

			var segmentBytes = provider.readBytes(entriesStart + list.entrySize * i, list.entrySize);
			var segmentBuffer = ByteBuffer.wrap(segmentBytes);
			segmentBuffer.order(ByteOrder.LITTLE_ENDIAN);

			descriptors.add(MemoryInfo.parse(segmentBuffer));
		}
		list.descriptors = descriptors;

		return list;
	}

	public int headerSize;
	public int entrySize;
	public long entryCount;

	public List<MemoryInfo> descriptors;
}
