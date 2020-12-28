package net.jubjubnest.minidump.shared;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;

public class ModuleData implements Saveable {
	
	static private final String USER_DATA_KEY = "MODULE_DATA";
	
	public String name;
	public String loadedSymbols;
	public long baseAddress;
	public long rtiStartAddress;
	public long rtiEndAddress;
	
	public ModuleData(String name, long baseAddress, long rtiStart, long rtiEnd) {
		this.name = name;
		this.loadedSymbols = null;
		this.baseAddress = baseAddress;
		this.rtiStartAddress = rtiStart;
		this.rtiEndAddress = rtiEnd;
	}
	
	public ModuleData() {}
	
	public static Address getContainingModuleBase(Program program, Address address) {
		ProgramUserData userData = program.getProgramUserData();
		int transaction = userData.startTransaction();
		try {

			ObjectPropertyMap objectMap = userData.getObjectProperty(ModuleData.class.getName(), USER_DATA_KEY, ModuleData.class, false);
			if (objectMap == null)
				return null;
			
			AddressIterator iterator = objectMap.getPropertyIterator(program.getMinAddress(), address, false);
			return iterator.next();

		} finally {
			userData.endTransaction(transaction);
		}
	}

	public static ModuleData getContainingModuleData(Program program, Address address) {
		ProgramUserData userData = program.getProgramUserData();
		int transaction = userData.startTransaction();
		try {
			return getContainingModuleData(userData, address);
		} finally {
			userData.endTransaction(transaction);
		}
	}

	public static ModuleData getContainingModuleData(ProgramUserData userData, Address address) {
		ObjectPropertyMap objectMap = userData.getObjectProperty(ModuleData.class.getName(), USER_DATA_KEY, ModuleData.class, false);
		if (objectMap == null)
			return null;
		
		// The modules shouldn't be interleaved and the data is set at the start of the module so we'll first try the specific
		// address but when that eventually fails we'll find the previous address that has data and trust that's the data for this module.
		ModuleData moduleData = (ModuleData)objectMap.getObject(address);
		if (moduleData != null) {
			return moduleData;
		}

		Address previousAddress = objectMap.getPreviousPropertyAddress(address);
		if (previousAddress == null) {
			return null;
		}

		return (ModuleData)objectMap.getObject(previousAddress);
	}
	
	public static List<ModuleData> getAllModules(Program program) {
		ProgramUserData userData = program.getProgramUserData();
		int transaction = userData.startTransaction();
		try {
			ObjectPropertyMap objectMap = userData.getObjectProperty(ModuleData.class.getName(), USER_DATA_KEY, ModuleData.class, false);
			if (objectMap == null)
				return null;
			
			List<ModuleData> modules = new ArrayList<>();
			AddressIterator iterator = objectMap.getPropertyIterator();
			for (Address addr = iterator.next(); addr != null; addr = iterator.next()) {
				
				// The modules shouldn't be interleaved and the data is set at the start of the module so we'll first try the specific
				// address but when that eventually fails we'll find the previous address that has data and trust that's the data for this module.
				ModuleData moduleData = (ModuleData)objectMap.getObject(addr);
				if (moduleData != null) {
					modules.add(moduleData);
				}
			}

			return modules;

		} finally {
			userData.endTransaction(transaction);
		}
	}

	public static void setModuleData(ProgramUserData userData, Address address, ModuleData data) {
		if (address.getOffset() != data.baseAddress)
			throw new IllegalArgumentException("Address mismatch");
		
		ObjectPropertyMap objectMap = userData.getObjectProperty(ModuleData.class.getName(), USER_DATA_KEY, ModuleData.class, true);
		objectMap.add(address, data);
	}

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
