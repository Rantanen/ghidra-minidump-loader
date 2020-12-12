package net.jubjubnest.minidump.parser;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.app.util.bin.ByteProvider;

public class Header {
	public static final long RECORD_SIZE = 4 + 2 + 2 + 4 + 4 + 4 + 4 + 8;

	public static Header parse(long offset, ByteProvider provider) throws IOException {
		var bytes = provider.readBytes(offset, RECORD_SIZE);
		var byteBuffer = ByteBuffer.wrap(bytes);
		byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
		return parse(byteBuffer);
	}

	public static Header parse(ByteBuffer byteBuffer) {
		@SuppressWarnings("unused")
		int _signature = byteBuffer.getInt();
		@SuppressWarnings("unused")
		short _internalVersion = byteBuffer.getShort();

		var header = new Header();
		header.version = byteBuffer.getShort();
		header.streamsCount = byteBuffer.getInt();
		header.streamsOffset = byteBuffer.getInt();
		header.checksum = byteBuffer.getInt();
		header.timestamp = byteBuffer.getInt();
		header.flags = byteBuffer.getLong();
		return header;
	}

	public int version;
	public int streamsCount;
	public int streamsOffset;
	public int checksum;
	public int timestamp;
	public long flags;
}
