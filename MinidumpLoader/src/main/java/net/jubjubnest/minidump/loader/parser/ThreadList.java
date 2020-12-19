package net.jubjubnest.minidump.loader.parser;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;

public class ThreadList {

	public static final int DESCRIPTOR_SIZE = 4;

	public static ThreadList parse(long offset, ByteProvider provider) throws IOException {
		var bytes = provider.readBytes(offset, DESCRIPTOR_SIZE);
		var byteBuffer = ByteBuffer.wrap(bytes);
		byteBuffer.order(ByteOrder.LITTLE_ENDIAN);

		var list = new ThreadList();
		list.numberOfThreads = byteBuffer.getInt();

		long entriesStart = offset + DESCRIPTOR_SIZE;
		var segmentBytes = provider.readBytes(entriesStart, list.numberOfThreads * Thread.RECORD_SIZE);
		var segmentBuffer = ByteBuffer.wrap(segmentBytes);
		segmentBuffer.order(ByteOrder.LITTLE_ENDIAN);

		list.threads = new ArrayList<Thread>(list.numberOfThreads);
		for (int i = 0; i < list.numberOfThreads; i++) {
			list.threads.add(Thread.parse(segmentBuffer));
		}

		return list;
	}

	public int numberOfThreads;
	public List<Thread> threads;
}
