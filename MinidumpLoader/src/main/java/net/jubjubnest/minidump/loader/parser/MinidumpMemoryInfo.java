package net.jubjubnest.minidump.loader.parser;

import java.nio.ByteBuffer;

public class MinidumpMemoryInfo {

	// Memory info doesn't have definite record size, instead the module info struct
	// specifies the size of the entries.

	public static MinidumpMemoryInfo parse(ByteBuffer byteBuffer) {
		var module = new MinidumpMemoryInfo();

		module.baseAddress = byteBuffer.getLong();
		module.allocationBase = byteBuffer.getLong();
		module.allocationProtect = byteBuffer.getInt();
		module.__alignment1 = byteBuffer.getInt();
		module.regionSize = byteBuffer.getLong();
		module.state = byteBuffer.getInt();
		module.protect = byteBuffer.getInt();
		module.type = byteBuffer.getInt();
		module.__alignment2 = byteBuffer.getInt();

		return module;
	}

	public long baseAddress;
	public long allocationBase;
	public int allocationProtect;
	public int __alignment1;
	public long regionSize;
	public int state;
	public int protect;
	public int type;
	public int __alignment2;

	public final static int MEM_STATE_COMMIT = 0x1000;
	public final static int MEM_STATE_FREE = 0x10000;
	public final static int MEM_STATE_RESERVE = 0x2000;

	public final static int MEM_TYPE_IMAGE = 0x1000000;
	public final static int MEM_TYPE_MAPPED = 0x40000;
	public final static int MEM_TYPE_PRIVATE = 0x20000;

	public final static int PAGE_EXECUTE = 0x10;
	public final static int PAGE_EXECUTE_READ = 0x20;
	public final static int PAGE_EXECUTE_READWRITE = 0x40;
	public final static int PAGE_EXECUTE_WRITECOPY = 0x80;
	public final static int PAGE_NOACCESS = 0x01;
	public final static int PAGE_READONLY = 0x02;
	public final static int PAGE_READWRITE = 0x04;
	public final static int PAGE_WRITECOPY = 0x08;
	public final static int PAGE_TARGETS_INVALID = 0x40000000;
	public final static int PAGE_TARGETS_NO_UPDATE = 0x40000000;
	public final static int PAGE_GUARD = 0x100;
	public final static int PAGE_NOCACHE = 0x200;
	public final static int PAGE_WRITECOMBINE = 0x400;
}
