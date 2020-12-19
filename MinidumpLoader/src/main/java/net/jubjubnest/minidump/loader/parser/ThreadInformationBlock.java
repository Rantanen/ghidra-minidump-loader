package net.jubjubnest.minidump.loader.parser;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.lang.LanguageNotFoundException;

public class ThreadInformationBlock {

	public static final int RECORD_SIZE = 8 + 8 + 8;

	public static ThreadInformationBlock parse(LoadSpec loadSpec, long offset, ByteProvider provider) throws IOException {
		var bytes = provider.readBytes(offset, RECORD_SIZE);
		var byteBuffer = ByteBuffer.wrap(bytes);
		byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
		return parse(loadSpec, byteBuffer);
	}

	public static ThreadInformationBlock parse(LoadSpec loadSpec, ByteBuffer byteBuffer) {
		boolean is64 = true;
		try {
			is64 = loadSpec.getLanguageCompilerSpec().getLanguage().getLanguageDescription().getSize() == 64;
		} catch (LanguageNotFoundException e) {
			// Assume 64.
		}

		var info = new ThreadInformationBlock();
		if(is64) {
			info.sehFrame = byteBuffer.getLong();
			info.stackBase = byteBuffer.getLong();
			info.stackLimit = byteBuffer.getLong();
		} else {
			info.sehFrame = byteBuffer.getInt();
			info.stackBase = byteBuffer.getInt();
			info.stackLimit = byteBuffer.getInt();
		}
		return info;
	}

	public long sehFrame;
	public long stackBase;
	public long stackLimit;
	// ... and more. The stack limits are what we are interested in.
}
