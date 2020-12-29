package net.jubjubnest.minidump.shared;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;

public class ThreadData {
	
	public int id;
	public Address stackBase;
	public Address stackLimit;
	public Address stackPointer;
	public Address sp;
	public Address ip;
	
	private static final String OBJECT_MAP_KEY = ThreadData.class.getCanonicalName();
	
	// Address with which the thread data is associated.
	// stackLimit should be at "top" which makes more sense if this is ever visible in the UI.
	// The program is given as a parameter in the case this ever needs to take stack direction into account.
	private Address key(Program program) { return this.stackLimit; }
	
	public ThreadData(int id, Address stackBase, Address stackLimit, Address stackPointer, Address sp, Address ip) {
		this.id = id;
		this.stackBase = stackBase;
		this.stackLimit = stackLimit;
		this.stackPointer = stackPointer;
		this.sp = sp;
		this.ip = ip;
	}
	
	private ThreadData(Program program, Record record) {
		id = record.id;
		stackBase = program.getImageBase().getNewAddress(record.stackBase);
		stackLimit = stackBase.getNewAddress(record.stackLimit);
		stackPointer = stackBase.getNewAddress(record.stackPointer);
		sp = stackBase.getNewAddress(record.sp);
		ip = stackBase.getNewAddress(record.ip);
	}
	
	public static List<ThreadData> getAllThreadData(Program program) {
		List<ThreadData> list = new ArrayList<>();

		ObjectPropertyMap map = getObjectMap(program, false);
		if (map != null) {
			for (Address addr : map.getPropertyIterator()) {
				list.add(new ThreadData(program, (Record)map.getObject(addr)));
			}
		}
		
		return list;
	}

	public static void storeThreadData(Program program, ThreadData data) {
		ObjectPropertyMap map = getObjectMap(program, true);
		map.add(data.key(program), new Record(data));
	}

	private static ObjectPropertyMap getObjectMap(Program program, boolean create) {
		return ObjectMapResolver.getModuleDataMap(program, OBJECT_MAP_KEY, Record.class, create);
	}
	
	public static class Record implements Saveable {
		
		public int id;
		public long stackBase;
		public long stackLimit;
		public long stackPointer;
		public long sp;
		public long ip;
		
		public Record(ThreadData data) {
			id = data.id;
			stackBase = data.stackBase.getOffset();
			stackLimit = data.stackLimit.getOffset();
			stackPointer = data.stackPointer.getOffset();
			sp = data.sp.getOffset();
			ip = data.ip.getOffset();
		}
		
		public Record() {}

		@Override
		public Class<?>[] getObjectStorageFields() {
			return new Class[] {
				int.class,
				long.class,
				long.class,
				long.class,
				long.class,
				long.class,
			};
		}

		@Override
		public void save(ObjectStorage objStorage) {
			objStorage.putInt(id);
			objStorage.putLong(stackBase);
			objStorage.putLong(stackLimit);
			objStorage.putLong(stackPointer);
			objStorage.putLong(sp);
			objStorage.putLong(ip);
		}

		@Override
		public void restore(ObjectStorage objStorage) {
			id = objStorage.getInt();
			stackBase = objStorage.getLong();
			stackLimit = objStorage.getLong();
			stackPointer = objStorage.getLong();
			sp = objStorage.getLong();
			ip = objStorage.getLong();
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

		@Override
		public boolean isPrivate() {
			return false;
		}
	}
}
