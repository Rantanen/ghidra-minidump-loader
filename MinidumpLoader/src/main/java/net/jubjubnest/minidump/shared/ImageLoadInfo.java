package net.jubjubnest.minidump.shared;

import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import net.jubjubnest.minidump.contrib.pe.PortableExecutable.SectionLayout;

public class ImageLoadInfo {
	public String imageName;
	public long imageBase;
	public boolean sharedProgram;
	public SectionLayout sectionLayout;
	
	public ImageLoadInfo() {
		imageName = null;
		imageBase = 0;
		sharedProgram = false;
		sectionLayout = SectionLayout.FILE;
	}
	
	public ImageLoadInfo(String moduleName, long moduleOffset) {
		imageName = moduleName;
		imageBase = moduleOffset;
		sharedProgram = true;
		sectionLayout = SectionLayout.MEMORY;
	}
	
	public String prefixName(String name) {
		return name;
		
		/*
		if (sharedProgram == false)
			return name;
		return imageName.toUpperCase() + "::" + name;
		*/
	}
	
	public Options getModuleOptions(Program program) {
		Options programOptions = program.getOptions(Program.PROGRAM_INFO);
		if (sharedProgram == false) {
			return programOptions;
		}
		
		Options moduleOptions = programOptions.getOptions("Module Information");
		return moduleOptions.getOptions(imageName.replace('.', '_'));
	}
}
