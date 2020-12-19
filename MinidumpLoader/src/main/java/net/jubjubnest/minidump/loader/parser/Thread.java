package net.jubjubnest.minidump.loader.parser;

import java.nio.ByteBuffer;

public class Thread {

	public static final int RECORD_SIZE = 4 + 4 + 4 + 4 + 8 + MemoryDescriptor.RECORD_SIZE
			+ LocationDescriptor.RECORD_SIZE;

	public static Thread parse(ByteBuffer byteBuffer) {
		var thread = new Thread();
		
		thread.threadId = byteBuffer.getInt();
		thread.suspendCount = byteBuffer.getInt();
		thread.priorityClass = byteBuffer.getInt();
		thread.priority = byteBuffer.getInt();
		thread.teb = byteBuffer.getLong();
		thread.stack = MemoryDescriptor.parse(byteBuffer);
		thread.threadContext = LocationDescriptor.parse(byteBuffer);

		return thread;
	}

	public int threadId;
	public int suspendCount;
	public int priorityClass;
	public int priority;
	public long teb;
	public MemoryDescriptor stack;
	public LocationDescriptor threadContext;
}
