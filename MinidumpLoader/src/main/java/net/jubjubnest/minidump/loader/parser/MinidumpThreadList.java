package net.jubjubnest.minidump.loader.parser;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;

public class MinidumpThreadList {

	public static final int DESCRIPTOR_SIZE = 4;

	public static MinidumpThreadList parse(long offset, ByteProvider provider) throws IOException {
		var bytes = provider.readBytes(offset, DESCRIPTOR_SIZE);
		var byteBuffer = ByteBuffer.wrap(bytes);
		byteBuffer.order(ByteOrder.LITTLE_ENDIAN);

		var list = new MinidumpThreadList();
		list.numberOfThreads = byteBuffer.getInt();

		long entriesStart = offset + DESCRIPTOR_SIZE;
		var segmentBytes = provider.readBytes(entriesStart, list.numberOfThreads * MinidumpThread.RECORD_SIZE);
		var segmentBuffer = ByteBuffer.wrap(segmentBytes);
		segmentBuffer.order(ByteOrder.LITTLE_ENDIAN);

		list.threads = new ArrayList<MinidumpThread>(list.numberOfThreads);
		for (int i = 0; i < list.numberOfThreads; i++) {
			list.threads.add(MinidumpThread.parse(segmentBuffer));
		}

		return list;
	}

	public int numberOfThreads;
	public List<MinidumpThread> threads;
}
