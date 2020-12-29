package net.jubjubnest.minidump.contrib.new_;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.IntPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NoValueException;

public class ModuleBaseMap {

	static final String MODULE_LIMITS_MAP_NAME = "MODULEBASEOFFSET_MODULE_LIMITS";
	static final int MODULE_START = 1;
	static final int MODULE_END = 0;
	
	public static void markModule(Program program, Address start, Address end) {
		PropertyMapManager manager = program.getUsrPropertyManager();

		IntPropertyMap map = manager.getIntPropertyMap(MODULE_LIMITS_MAP_NAME);
		if (map == null) {
			try {
				map = manager.createIntPropertyMap(MODULE_LIMITS_MAP_NAME);
			} catch (DuplicateNameException e) {
				map = manager.getIntPropertyMap(MODULE_LIMITS_MAP_NAME);
			}
		}
		
		map.add(start, MODULE_START);
		map.add(end, MODULE_END);
	}
	
	public static Address getModuleBase(Program program, Address addr) {
		PropertyMapManager manager = program.getUsrPropertyManager();

		IntPropertyMap map = manager.getIntPropertyMap(MODULE_LIMITS_MAP_NAME);
		if (map == null) {
			return null;
		}

		AddressIterator iter = map.getPropertyIterator(addr, false);
		Address closest = iter.next();

		int flag;
		try {
			flag = map.getInt(closest);
		} catch (NoValueException e) {
			// The address used in lookup should have value according to the map.
			throw new RuntimeException(e);
		}
		
		// If the previous record is start of module we'll return that.
		if (flag == MODULE_START) {
			return closest;
		}

		// No start of module record found.
		
		// There's a chance the user queried the exact end-of-module address, which is still
		// inclusive to the current module. If this happened, we'll continue iterating backwards
		// to acquire the start-of-module address.
		if (closest.equals(addr)) {
			return iter.next();
		}

		return null;
	}
}
