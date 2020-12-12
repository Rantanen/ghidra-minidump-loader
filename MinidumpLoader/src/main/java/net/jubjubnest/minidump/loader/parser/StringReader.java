package net.jubjubnest.minidump.loader.parser;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;

import ghidra.app.util.bin.ByteProvider;

public class StringReader {
	public static String readString(long offset, ByteProvider provider) throws IOException {
		var headerBytes = provider.readBytes(offset, 4);
		var byteBuffer = ByteBuffer.wrap(headerBytes);
		byteBuffer.order(ByteOrder.LITTLE_ENDIAN);

		var size = byteBuffer.getInt();
		if (size % 2 == 1)
			throw new IOException("Invalid string data");
		var length = size / 2;

		var dataBytes = provider.readBytes(offset + 4, size);
		var charset = Charset.forName("UTF-16LE");
		var dataBuffer = ByteBuffer.wrap(dataBytes);
		return charset.decode(dataBuffer).toString();
	}
}
