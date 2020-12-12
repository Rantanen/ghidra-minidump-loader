package net.jubjubnest.minidump.parser;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.app.util.bin.ByteProvider;

public class Directory {
	public static final int RECORD_SIZE = 4 + LocationDescriptor.RECORD_SIZE;

	public static Directory parse(long offset, ByteProvider provider) throws IOException {
		var bytes = provider.readBytes(offset, RECORD_SIZE);
		var byteBuffer = ByteBuffer.wrap(bytes);
		byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
		return parse(byteBuffer);
	}

	public static Directory parse(ByteBuffer byteBuffer) {
		var directory = new Directory();
		directory.streamType = byteBuffer.getInt();
		directory.location = LocationDescriptor.parse(byteBuffer);
		return directory;
	}

	public int streamType;
	public LocationDescriptor location;

	public static final int TYPE_UNUSED = 0;
	public static final int TYPE_RESERVED0 = 1;
	public static final int TYPE_RESERVED1 = 2;
	public static final int TYPE_THREADLISTSTREAM = 3;
	public static final int TYPE_MODULELISTSTREAM = 4;
	public static final int TYPE_MEMORYLISTSTREAM = 5;
	public static final int TYPE_EXCEPTIONSTREAM = 6;
	public static final int TYPE_SYSTEMINFOSTREAM = 7;
	public static final int TYPE_THREADEXLISTSTREAM = 8;
	public static final int TYPE_MEMORY64LISTSTREAM = 9;
	public static final int TYPE_COMMENTSTREAMA = 10;
	public static final int TYPE_COMMENTSTREAMW = 11;
	public static final int TYPE_HANDLEDATASTREAM = 12;
	public static final int TYPE_FUNCTIONTABLESTREAM = 13;
	public static final int TYPE_UNLOADEDMODULELISTSTREAM = 14;
	public static final int TYPE_MISCINFOSTREAM = 15;
	public static final int TYPE_MEMORYINFOLISTSTREAM = 16;
	public static final int TYPE_THREADINFOLISTSTREAM = 17;
	public static final int TYPE_HANDLEOPERATIONLISTSTREAM = 18;
	public static final int TYPE_TOKENSTREAM = 19;
	public static final int TYPE_JAVASCRIPTDATASTREAM = 20;
	public static final int TYPE_SYSTEMMEMROYINFOSTREAM = 21;
	public static final int TYPE_PROCESSVMCOUNTERSTREAM = 22;
	public static final int TYPE_IPTTRACESTREAM = 23;
	public static final int TYPE_THREADNAMESTREAM = 24;
	public static final int TYPE_CESTREAMNULL = 25;
	public static final int TYPE_CESTREAMSYSTEMINFO = 26;
	public static final int TYPE_CESTREAMEXCEPTION = 27;
	public static final int TYPE_CESTREAMMODULELIST = 28;
	public static final int TYPE_CESTREAMPROCESSLIST = 29;
	public static final int TYPE_CESTREAMTHREADLIST = 30;
	public static final int TYPE_CESTREAMTHREADCONTEXTLIST = 31;
	public static final int TYPE_CESTREAMTHREADCALLSTACKLIST = 32;
	public static final int TYPE_CESTREAMMEMORYVIRTUALLIST = 33;
	public static final int TYPE_CESTREAMMEMROYPHYSICALLIST = 34;
	public static final int TYPE_CESTREAMBUCKETPARAMETERS = 35;
	public static final int TYPE_CESTREAMPROCESSMODULEMAP = 36;
	public static final int TYPE_CESTREAMDIAGNOSISLIST = 37;
	public static final int TYPE_LASTRESERVEDSTREAM = 38;
}
