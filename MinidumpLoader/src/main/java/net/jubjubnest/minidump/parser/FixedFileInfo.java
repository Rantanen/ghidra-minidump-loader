package net.jubjubnest.minidump.parser;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.app.util.bin.ByteProvider;

public class FixedFileInfo {

	public static final int RECORD_SIZE = 4 + 4 + 8 + 8 + 4 + 4 + 4 + 4 + 4 + 8;

	public static FixedFileInfo parse(long offset, ByteProvider provider) throws IOException {
		var bytes = provider.readBytes(offset, RECORD_SIZE);
		var byteBuffer = ByteBuffer.wrap(bytes);
		byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
		return parse(byteBuffer);
	}

	public static FixedFileInfo parse(ByteBuffer byteBuffer) {
		var info = new FixedFileInfo();
		info.signature = byteBuffer.getInt();
		info.structVersion = byteBuffer.getInt();
		info.fileVersion = byteBuffer.getLong();
		info.productVersion = byteBuffer.getLong();
		info.flagsMask = byteBuffer.getInt();
		info.flags = byteBuffer.getInt();
		info.fileOs = byteBuffer.getInt();
		info.fileType = byteBuffer.getInt();
		info.fileSubtype = byteBuffer.getInt();
		info.fileDate = byteBuffer.getLong();
		return info;
	}

	public int signature;
	public int structVersion;
	public long fileVersion;
	public long productVersion;
	public int flagsMask;
	public int flags;
	public int fileOs;
	public int fileType;
	public int fileSubtype;
	public long fileDate;
}
