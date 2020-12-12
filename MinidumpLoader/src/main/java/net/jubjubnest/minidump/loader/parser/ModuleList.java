package net.jubjubnest.minidump.loader.parser;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;

public class ModuleList {

	public static final int DESCRIPTOR_SIZE = 4;

	public static ModuleList parse(long offset, ByteProvider provider) throws IOException {
		var bytes = provider.readBytes(offset, DESCRIPTOR_SIZE);
		var byteBuffer = ByteBuffer.wrap(bytes);
		byteBuffer.order(ByteOrder.LITTLE_ENDIAN);

		var list = new ModuleList();
		list.moduleCount = byteBuffer.getInt();

		var moduleBytes = provider.readBytes(offset + DESCRIPTOR_SIZE, Module.RECORD_SIZE * list.moduleCount);
		var moduleBuffer = ByteBuffer.wrap(moduleBytes);
		moduleBuffer.order(ByteOrder.LITTLE_ENDIAN);

		var modules = new ArrayList<Module>();
		for (int i = 0; i < list.moduleCount; i++) {
			modules.add(Module.parse(moduleBuffer, provider));
		}
		list.modules = modules;

		return list;
	}

	public int moduleCount;
	public List<Module> modules;
}
