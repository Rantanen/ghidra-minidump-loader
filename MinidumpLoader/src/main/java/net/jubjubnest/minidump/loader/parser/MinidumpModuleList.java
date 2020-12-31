package net.jubjubnest.minidump.loader.parser;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;

public class MinidumpModuleList {

	public static final int DESCRIPTOR_SIZE = 4;

	public static MinidumpModuleList parse(long offset, ByteProvider provider) throws IOException {
		var bytes = provider.readBytes(offset, DESCRIPTOR_SIZE);
		var byteBuffer = ByteBuffer.wrap(bytes);
		byteBuffer.order(ByteOrder.LITTLE_ENDIAN);

		var list = new MinidumpModuleList();
		list.moduleCount = byteBuffer.getInt();

		var moduleBytes = provider.readBytes(offset + DESCRIPTOR_SIZE, MinidumpModule.RECORD_SIZE * list.moduleCount);
		var moduleBuffer = ByteBuffer.wrap(moduleBytes);
		moduleBuffer.order(ByteOrder.LITTLE_ENDIAN);

		var modules = new ArrayList<MinidumpModule>();
		for (int i = 0; i < list.moduleCount; i++) {
			modules.add(MinidumpModule.parse(moduleBuffer, provider));
		}
		list.modules = modules;

		return list;
	}

	public int moduleCount;
	public List<MinidumpModule> modules;
}
