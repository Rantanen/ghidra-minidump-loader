package net.jubjubnest.minidump.shared;

import ghidra.program.model.listing.Program;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.util.Saveable;
import ghidra.util.exception.DuplicateNameException;

public class ObjectMapResolver {
	
	public static ObjectPropertyMap getModuleDataMap(Program program, String name, Class<? extends Saveable> recordClass, boolean create) {
		PropertyMapManager manager = program.getUsrPropertyManager();
		ObjectPropertyMap map = manager.getObjectPropertyMap(name);
		if (map != null || !create) {
			return map;
		}
		
		try {
			return manager.createObjectPropertyMap(name, recordClass);
		} catch (DuplicateNameException e) {
			return manager.getObjectPropertyMap(name);
		}
	}
	
}
