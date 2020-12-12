package net.jubjubnest.minidump.loader.parser;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;

import ghidra.app.util.bin.ByteProvider;

public class Module {

	public static final int RECORD_SIZE = 8 + 4 + 4 + 4 + 4 + FixedFileInfo.RECORD_SIZE + LocationDescriptor.RECORD_SIZE
			+ LocationDescriptor.RECORD_SIZE + 8 + 8;

	public static Module parse(ByteBuffer byteBuffer, ByteProvider provider) throws IOException {
		var module = new Module();
		module.imageBase = byteBuffer.getLong();
		module.imageSize = byteBuffer.getInt();
		module.checksum = byteBuffer.getInt();
		module.timestamp = byteBuffer.getInt();
		module.moduleNameRva = byteBuffer.getInt();
		module.versionInfo = FixedFileInfo.parse(byteBuffer);
		module.cvRecord = LocationDescriptor.parse(byteBuffer);
		module.miscRecord = LocationDescriptor.parse(byteBuffer);
		module.reserved0 = byteBuffer.getLong();
		module.reserved1 = byteBuffer.getLong();

		module.name = StringReader.readString(module.moduleNameRva, provider);

		return module;
	}

	public String getBaseName() {
		return new File(this.name).getName();
	}

	public long imageBase;
	public int imageSize;
	public int checksum;
	public int timestamp;
	public int moduleNameRva;
	public FixedFileInfo versionInfo;
	public LocationDescriptor cvRecord;
	public LocationDescriptor miscRecord;
	public long reserved0;
	public long reserved1;

	public String name;
}
