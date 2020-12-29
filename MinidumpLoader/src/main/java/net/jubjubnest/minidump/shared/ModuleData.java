package net.jubjubnest.minidump.shared;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;

public class ModuleData {
	
	public static final String PROPERTY_NAME = "MODULE_DATA";
	
	public String name;
	public String loadedSymbols;
	public Address baseAddress;
	public Address rtiStartAddress;
	public Address rtiEndAddress;
	
	public ModuleData(String name, Address baseAddress, Address rtiStart, Address rtiEnd) {
		this.name = name;
		this.loadedSymbols = null;
		this.baseAddress = baseAddress;
		this.rtiStartAddress = rtiStart;
		this.rtiEndAddress = rtiEnd;
	}
	
	private ModuleData(Program program, Record record) {
		this.name = record.name;
		this.loadedSymbols = record.loadedSymbols;
		this.baseAddress = program.getImageBase().getNewAddress(record.baseAddress);
		this.rtiStartAddress = baseAddress.getNewAddress(record.rtiStartAddress);
		this.rtiEndAddress = baseAddress.getNewAddress(record.rtiEndAddress);
	}
	
	public static ModuleData getContainingModuleData(Program program, Address address) {
		ObjectPropertyMap objectMap = getModuleDataMap(program,  false);
		if (objectMap == null)
			return null;
		
		// The modules shouldn't be interleaved and the data is set at the start of the module so we'll first try the specific
		// address but when that eventually fails we'll find the previous address that has data and trust that's the data for this module.
		Record record = (Record)objectMap.getObject(address);
		if (record == null) {
			Address previousAddress = objectMap.getPreviousPropertyAddress(address);
			if (previousAddress == null) {
				return null;
			}

			record = (Record)objectMap.getObject(previousAddress);
		}

		return new ModuleData(program, record);

	}
	
	public static List<ModuleData> getAllModules(Program program) {
		ObjectPropertyMap objectMap = getModuleDataMap(program, false);
		if (objectMap == null)
			return null;
		
		List<ModuleData> modules = new ArrayList<>();
		AddressIterator iterator = objectMap.getPropertyIterator();
		for (Address addr = iterator.next(); addr != null; addr = iterator.next()) {
			ModuleData moduleData = new ModuleData(program, (Record)objectMap.getObject(addr));
			modules.add(moduleData);
		}

		return modules;
	}
	
	public static ModuleData getModuleData(Program program, Address address) {
		ObjectPropertyMap objectMap = getModuleDataMap(program, false);
		Record record = (Record)objectMap.getObject(address);
		return record == null ? null : new ModuleData(program, record);
	}

	public static void setModuleData(Program program, ModuleData data) {
		ObjectPropertyMap objectMap = getModuleDataMap(program, true);
		objectMap.add(data.baseAddress, new Record(data));
	}

	private static ObjectPropertyMap getModuleDataMap(Program program, boolean create) {
		return ObjectMapResolver.getModuleDataMap(program, PROPERTY_NAME, Record.class, create);
	}
	
	public static class Record implements Saveable {
		
		private String name;
		private String loadedSymbols;
		private long baseAddress;
		private long rtiStartAddress;
		private long rtiEndAddress;
		
		public Record(ModuleData data) {
			this.name = data.name;
			this.loadedSymbols = data.loadedSymbols;
			this.baseAddress = data.baseAddress.getOffset();
			this.rtiStartAddress = data.rtiStartAddress.getOffset();
			this.rtiEndAddress = data.rtiEndAddress.getOffset();
		}
		
		public Record() {}

		@Override
		public Class<?>[] getObjectStorageFields() {
			return new Class[] {
				String.class,
				String.class,
				long.class,
				long.class,
				long.class,
			};
		}

		@Override
		public void save(ObjectStorage objStorage) {
			objStorage.putString(name);
			objStorage.putString(loadedSymbols);
			objStorage.putLong(baseAddress);
			objStorage.putLong(rtiStartAddress);
			objStorage.putLong(rtiEndAddress);
		}

		@Override
		public void restore(ObjectStorage objStorage) {
			name = objStorage.getString();
			loadedSymbols = objStorage.getString();
			baseAddress = objStorage.getLong();
			rtiStartAddress = objStorage.getLong();
			rtiEndAddress = objStorage.getLong();
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
