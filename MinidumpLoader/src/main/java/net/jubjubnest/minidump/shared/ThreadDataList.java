package net.jubjubnest.minidump.shared;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.util.ObjectStorage;
import ghidra.util.PrivateSaveable;

public class ThreadDataList extends PrivateSaveable {
	
	static private final String USER_DATA_KEY = "THREAD_DATA";
	
	public List<ThreadData> threads = new ArrayList<ThreadData>();

	@Override
	public Class<?>[] getObjectStorageFields() {
		return new Class[] {
			int[].class,
			long[].class,
			long[].class,
			long[].class,
			long[].class,
			long[].class,
		};
	}
	
	public static ThreadDataList getThreadDataList(Program program, ProgramUserData userData) {
		var objectMap = userData.getObjectProperty(ThreadDataList.class.getName(), USER_DATA_KEY, ThreadDataList.class, false);
		if (objectMap == null)
			return null;
		
		var threadData = (ThreadDataList)objectMap.getObject(program.getImageBase());
		return threadData;
	}

	public static void setThreadDataList(Program program, ProgramUserData userData, ThreadDataList data) {
		var objectMap = userData.getObjectProperty(ThreadDataList.class.getName(), USER_DATA_KEY, ThreadDataList.class, true);
		objectMap.add(program.getImageBase(), data);
	}

	@Override
	public void save(ObjectStorage objStorage) {
		int[] ids = new int[threads.size()];
		long[] stackBases = new long[threads.size()];
		long[] stackLimits = new long[threads.size()];
		long[] stackPointers = new long[threads.size()];
		long[] sps = new long[threads.size()];
		long[] ips = new long[threads.size()];
		
		for (int i = 0; i < threads.size(); i++)
		{
			var thread = threads.get(i);
			ids[i] = thread.id;
			stackBases[i] = thread.stackBase;
			stackLimits[i] = thread.stackLimit;
			stackPointers[i] = thread.stackPointer;
			sps[i] = thread.sp;
			ips[i] = thread.ip;
		}
		
		objStorage.putInts(ids);
		objStorage.putLongs(stackBases);
		objStorage.putLongs(stackLimits);
		objStorage.putLongs(stackPointers);
		objStorage.putLongs(sps);
		objStorage.putLongs(ips);
	}

	@Override
	public void restore(ObjectStorage objStorage) {
		int[] ids = objStorage.getInts();
		long[] stackBases = objStorage.getLongs();
		long[] stackLimits = objStorage.getLongs();
		long[] stackPointers = objStorage.getLongs();
		long[] sps = objStorage.getLongs();
		long[] ips = objStorage.getLongs();
		
		this.threads = new ArrayList<>();
		for (int i = 0; i < stackBases.length; i++) {
			var thread = new ThreadData();
			thread.id = ids[i];
			thread.stackBase = stackBases[i];
			thread.stackLimit = stackLimits[i];
			thread.stackPointer = stackPointers[i];
			thread.sp = sps[i];
			thread.ip = ips[i];
			this.threads.add(thread);
		}
	}

	@Override
	public int getSchemaVersion() {
		return 0;
	}

	@Override
	public boolean isUpgradeable(int oldSchemaVersion) {
		return false;
	}

	@Override
	public boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion, ObjectStorage currentObjStorage) {
		return false;
	}
}
