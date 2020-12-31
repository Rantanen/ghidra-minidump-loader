package net.jubjubnest.minidump.loader.parser;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;

import ghidra.app.util.bin.ByteProvider;

public class MinidumpModule {

	public static final int RECORD_SIZE = 8 + 4 + 4 + 4 + 4 + VsFixedFileInfo.RECORD_SIZE + MinidumpLocationDescriptor.RECORD_SIZE
			+ MinidumpLocationDescriptor.RECORD_SIZE + 8 + 8;

	public static MinidumpModule parse(ByteBuffer byteBuffer, ByteProvider provider) throws IOException {
		var module = new MinidumpModule();
		module.imageBase = byteBuffer.getLong();
		module.imageSize = byteBuffer.getInt();
		module.checksum = byteBuffer.getInt();
		module.timestamp = byteBuffer.getInt();
		module.moduleNameRva = byteBuffer.getInt();
		module.versionInfo = VsFixedFileInfo.parse(byteBuffer);
		module.cvRecord = MinidumpLocationDescriptor.parse(byteBuffer);
		module.miscRecord = MinidumpLocationDescriptor.parse(byteBuffer);
		module.reserved0 = byteBuffer.getLong();
		module.reserved1 = byteBuffer.getLong();

		module.name = StringReader.readString(module.moduleNameRva, provider);

		return module;
	}

	public String getBaseName() {
		return getFilename(new File(this.name).getPath());
	}

	private String getFilename(String fullPath) {
		// Remove any trailing slashes
		String editedPath = fullPath;
		editedPath = editedPath.replaceAll("[\\/]$", "");

		int lastIndexForwardSlash = editedPath.lastIndexOf('/');
		int lastIndexBackSlash = editedPath.lastIndexOf('\\');

		if (lastIndexForwardSlash == -1 && lastIndexBackSlash == -1) {
			return editedPath;
		}

		int indexToUse = (lastIndexForwardSlash > lastIndexBackSlash) ? lastIndexForwardSlash
				: lastIndexBackSlash;

		return editedPath.substring(indexToUse + 1);
	}
	

	public long imageBase;
	public int imageSize;
	public int checksum;
	public int timestamp;
	public int moduleNameRva;
	public VsFixedFileInfo versionInfo;
	public MinidumpLocationDescriptor cvRecord;
	public MinidumpLocationDescriptor miscRecord;
	public long reserved0;
	public long reserved1;

	public String name;
}
