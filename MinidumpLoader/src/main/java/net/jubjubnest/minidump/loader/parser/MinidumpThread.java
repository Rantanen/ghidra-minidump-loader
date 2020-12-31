package net.jubjubnest.minidump.loader.parser;

import java.nio.ByteBuffer;

public class MinidumpThread {

	public static final int RECORD_SIZE = 4 + 4 + 4 + 4 + 8 + MinidumpMemoryDescriptor.RECORD_SIZE
			+ MinidumpLocationDescriptor.RECORD_SIZE;

	public static MinidumpThread parse(ByteBuffer byteBuffer) {
		var thread = new MinidumpThread();
		
		thread.threadId = byteBuffer.getInt();
		thread.suspendCount = byteBuffer.getInt();
		thread.priorityClass = byteBuffer.getInt();
		thread.priority = byteBuffer.getInt();
		thread.teb = byteBuffer.getLong();
		thread.stack = MinidumpMemoryDescriptor.parse(byteBuffer);
		thread.threadContext = MinidumpLocationDescriptor.parse(byteBuffer);

		return thread;
	}

	public int threadId;
	public int suspendCount;
	public int priorityClass;
	public int priority;
	public long teb;
	public MinidumpMemoryDescriptor stack;
	public MinidumpLocationDescriptor threadContext;
}
