package net.jubjubnest.minidump.data;

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

	public ThreadContext context;
	
	private static final String OBJECT_MAP_KEY = ThreadData.class.getCanonicalName();
	
	// Address with which the thread data is associated.
	// stackLimit should be at "top" which makes more sense if this is ever visible in the UI.
	// The program is given as a parameter in the case this ever needs to take stack direction into account.
	private Address key(Program program) { return this.stackLimit; }
	
	public ThreadData(int id, Address stackBase, Address stackLimit, Address stackPointer,
			Address sp, Address ip, ThreadContext context) {

		this.id = id;
		this.stackBase = stackBase;
		this.stackLimit = stackLimit;
		this.stackPointer = stackPointer;
		this.sp = sp;
		this.ip = ip;
		this.context = context;
	}
	
	private ThreadData(Program program, Record record) {
		id = record.id;
		stackBase = program.getImageBase().getNewAddress(record.stackBase);
		stackLimit = stackBase.getNewAddress(record.stackLimit);
		stackPointer = stackBase.getNewAddress(record.stackPointer);
		sp = stackBase.getNewAddress(record.sp);
		ip = stackBase.getNewAddress(record.ip);
		
		switch (record.contextType) {
		case Context64.CONTEXT_TYPE:
			context = Context64.fromBytes(record.context);
			break;
		}
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
		
		// Version 0
		public int id;
		public long stackBase;
		public long stackLimit;
		public long stackPointer;
		public long sp;
		public long ip;
		
		// Version 1
		public int contextType;
		public byte[] context;
		
		public Record(ThreadData data) {
			id = data.id;
			stackBase = data.stackBase.getOffset();
			stackLimit = data.stackLimit.getOffset();
			stackPointer = data.stackPointer.getOffset();
			sp = data.sp.getOffset();
			ip = data.ip.getOffset();
			
			if (data.context == null) {
				contextType = 0;
				context = new byte[0];
			} else {
				contextType = data.context.getType();
				context = data.context.toBytes();
			}
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

				int.class,
				String.class,
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
			
			objStorage.putInt(contextType);
			objStorage.putBytes(context);
		}

		@Override
		public void restore(ObjectStorage objStorage) {
			id = objStorage.getInt();
			stackBase = objStorage.getLong();
			stackLimit = objStorage.getLong();
			stackPointer = objStorage.getLong();
			sp = objStorage.getLong();
			ip = objStorage.getLong();
			
			contextType = objStorage.getInt();
			context = objStorage.getBytes();
		}

		@Override
		public int getSchemaVersion() {
			return 1;
		}

		@Override
		public boolean isUpgradeable(int oldSchemaVersion) {
			return true;
		}

		@Override
		public boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion, ObjectStorage currentObjStorage) {

			currentObjStorage.putInt(oldObjStorage.getInt());
			currentObjStorage.putLong(oldObjStorage.getLong());
			currentObjStorage.putLong(oldObjStorage.getLong());
			currentObjStorage.putLong(oldObjStorage.getLong());
			currentObjStorage.putLong(oldObjStorage.getLong());
			currentObjStorage.putLong(oldObjStorage.getLong());

			if (oldSchemaVersion < 1) {
				currentObjStorage.putInt(0);
				currentObjStorage.putBytes(new byte[0]);
			} else {
				currentObjStorage.putInt(oldObjStorage.getInt());
				currentObjStorage.putBytes(oldObjStorage.getBytes());
			}
			
			return true;
		}

		@Override
		public boolean isPrivate() {
			return false;
		}
	}
}
