/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.jubjubnest.minidump.loader;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.bin.format.pdb.PdbParserConstants;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.DuplicateGroupException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotEmptyException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;
import net.jubjubnest.minidump.contrib.new_.ImageLoadInfo;
import net.jubjubnest.minidump.contrib.new_.ModuleBaseMap;
import net.jubjubnest.minidump.contrib.opinion.PeLoader;
import net.jubjubnest.minidump.contrib.pe.DataDirectory;
import net.jubjubnest.minidump.contrib.pe.ExceptionDataDirectory;
import net.jubjubnest.minidump.contrib.pe.NTHeader;
import net.jubjubnest.minidump.contrib.pe.OptionalHeader;
import net.jubjubnest.minidump.contrib.pe.PortableExecutable;
import net.jubjubnest.minidump.contrib.pe.PortableExecutable.SectionLayout;
import net.jubjubnest.minidump.data.Context64;
import net.jubjubnest.minidump.data.ModuleData;
import net.jubjubnest.minidump.data.ThreadData;
import net.jubjubnest.minidump.loader.parser.MinidumpDirectory;
import net.jubjubnest.minidump.loader.parser.MinidumpHeader;
import net.jubjubnest.minidump.loader.parser.MinidumpLocationDescriptor;
import net.jubjubnest.minidump.loader.parser.MinidumpMemory64List;
import net.jubjubnest.minidump.loader.parser.MinidumpMemoryInfo;
import net.jubjubnest.minidump.loader.parser.MinidumpMemoryInfoList;
import net.jubjubnest.minidump.loader.parser.MinidumpModule;
import net.jubjubnest.minidump.loader.parser.MinidumpModuleList;
import net.jubjubnest.minidump.loader.parser.ThreadInformationBlock;
import net.jubjubnest.minidump.loader.parser.MinidumpThreadList;

/**
 * Loads Windows Minidump files into Ghidra
 */
public class MinidumpLoader extends AbstractLibrarySupportLoader {
	
	public final static String NAME = "Windows Minidump";

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		var bytes = provider.readBytes(0, 4);
		if (bytes[0] != 'M' || bytes[1] != 'D' || bytes[2] != 'M' || bytes[3] != 'P')
			return loadSpecs;

		loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("x86:LE:64:default", "windows"), true));
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {

		log.appendMsg(this.getClass().getName(), String.format("Loading minidump: %s", provider.getAbsolutePath()));
		var header = MinidumpHeader.parse(0, provider);
		log.appendMsg(this.getClass().getName(), String.format("Total streams: %s", header.streamsCount));

		// Index all streams. We'll need to be a bit careful in what order we process
		// these so we'll first figure out what we have.
		var directories = new HashMap<Integer, List<MinidumpDirectory>>();
		for (int i = 0; i < header.streamsCount; i++) {
			var offset = header.streamsOffset + MinidumpDirectory.RECORD_SIZE * i;
			var directory = MinidumpDirectory.parse(offset, provider);
			var list = directories.computeIfAbsent(directory.streamType, (key) -> new ArrayList<MinidumpDirectory>());
			list.add(directory);

			log.appendMsg(this.getClass().getName(),
					String.format("- Stream %s: %s (location: %s)", i, directory.streamType, directory.location));
		}

		// First load the memory in the program. More or less everything else depends on memory addresses
		// for which we'll want a byte provider that can access the bytes based on in-memory addresses.
		var memoryList = directories.get(MinidumpDirectory.TYPE_MEMORY64LISTSTREAM);
		if (memoryList == null)
			throw new IllegalArgumentException("Minidump contains no memory segments");
		if (memoryList.size() != 1)
			throw new IllegalArgumentException("Minidump contains multiple memory lists");

		var memory = readMemory64(provider, memoryList.get(0).location, program, monitor, log);
		var memoryProvider = new MinidumpMemoryProvider(provider, memory);

		// The modules and private memory are somewhat well defined and should not overlap
		// so the order in which they are loaded doesn't really matter.
		var moduleList = directories.get(MinidumpDirectory.TYPE_MODULELISTSTREAM);
		if (moduleList != null) {
			for (var m : moduleList) {
				loadModules(provider, loadSpec, memoryProvider, m.location, program, monitor, log);
			}
		}
		
		var memoryInfoList = directories.get(MinidumpDirectory.TYPE_MEMORYINFOLISTSTREAM);
		if (memoryInfoList != null) {
			for (var m : memoryInfoList)
				loadPrivateMemory(provider, memoryProvider, m.location, program, monitor, log);
		}

		// The thread list must be processed after the private memory is loaded. The memory loading
		// can't tell stack apart from the heap so instead loading the threads assumes the stack
		// memory has been loaded already and 'steals' it away from the heap.
		var threadList = directories.get(MinidumpDirectory.TYPE_THREADLISTSTREAM);
		if (threadList != null) {
			for (var m : threadList) {
				loadThreads(provider, memoryProvider, loadSpec, m.location, program, monitor, log);
			}
		}
	}

	private MinidumpMemory64List readMemory64(ByteProvider provider, MinidumpLocationDescriptor location, Program program,
			TaskMonitor monitor, MessageLog log) throws IOException {
		if (monitor.isCancelled())
			return new MinidumpMemory64List();

		var list = MinidumpMemory64List.parse(location.offset, provider);
		log.appendMsg(this.getClass().getName(), String.format("  -> Memory segments: %s", list.memoryRangeCount));
		return list;
	}

	private void loadPrivateMemory(ByteProvider provider, ByteProvider memoryProvider, MinidumpLocationDescriptor location,
			Program program, TaskMonitor monitor, MessageLog log) throws IOException, CancelledException {
		if (monitor.isCancelled())
			return;

		AddressFactory af = program.getAddressFactory();
		AddressSpace space = af.getDefaultAddressSpace();

		var list = MinidumpMemoryInfoList.parse(location.offset, provider);
		for (var memoryInfo : list.descriptors) {
			if (memoryInfo.type != MinidumpMemoryInfo.MEM_TYPE_PRIVATE)
				continue;
			if (memoryInfo.state != MinidumpMemoryInfo.MEM_STATE_COMMIT)
				continue;

			FileBytes regionBytes = MemoryBlockUtils.createFileBytes(program, memoryProvider, memoryInfo.baseAddress,
					memoryInfo.regionSize, monitor);

			boolean r = memoryInfo.protect == MinidumpMemoryInfo.PAGE_EXECUTE_READ
					|| memoryInfo.protect == MinidumpMemoryInfo.PAGE_EXECUTE_READWRITE
					|| memoryInfo.protect == MinidumpMemoryInfo.PAGE_EXECUTE_WRITECOPY
					|| memoryInfo.protect == MinidumpMemoryInfo.PAGE_READONLY || memoryInfo.protect == MinidumpMemoryInfo.PAGE_READWRITE
					|| memoryInfo.protect == MinidumpMemoryInfo.PAGE_WRITECOPY;
			boolean w = memoryInfo.protect == MinidumpMemoryInfo.PAGE_EXECUTE_READWRITE
					|| memoryInfo.protect == MinidumpMemoryInfo.PAGE_EXECUTE_WRITECOPY
					|| memoryInfo.protect == MinidumpMemoryInfo.PAGE_READWRITE
					|| memoryInfo.protect == MinidumpMemoryInfo.PAGE_WRITECOPY;
			boolean x = memoryInfo.protect == MinidumpMemoryInfo.PAGE_EXECUTE_READ
					|| memoryInfo.protect == MinidumpMemoryInfo.PAGE_EXECUTE_READWRITE
					|| memoryInfo.protect == MinidumpMemoryInfo.PAGE_EXECUTE_WRITECOPY;
			Address baseAddress = space.getAddress(memoryInfo.baseAddress);
			try {
				MemoryBlockUtils.createInitializedBlock(program, false, "private_memory", baseAddress, regionBytes, 0,
						memoryInfo.regionSize, "", "", r, w, x, log);
			} catch (AddressOverflowException e) {
				throw new IOException(e);
			}
		}
	}

	class PeImageData {
		PeLoader loader;
		PeLoader.ImageInfo info;
		ByteProvider peBytes;
		MinidumpModule module;
	}

	private void loadModules(ByteProvider provider, LoadSpec loadSpec, ByteProvider memoryProvider, MinidumpLocationDescriptor location,
			Program program, TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
		if (monitor.isCancelled())
			return;

		var list = MinidumpModuleList.parse(location.offset, provider);
		var progress = 0;
		var images = new ArrayList<PeImageData>();
		for (var module : list.modules) {
			if (monitor.isCancelled())
				return;
			
			log.appendMsg(this.getClass().getName(), String.format("- Module %s", module.name));

			var baseName = module.getBaseName();

			var root = program.getListing().getDefaultRootModule();
			ProgramModule programModule = null;
			var fileName = baseName;
			int counter = 0;
			while (true) {
				try {
					programModule = root.createModule(fileName);
					break;
				} catch (DuplicateNameException e) {
					counter += 1;
					fileName = String.format("%s (%s)", baseName, counter);
				}
			}

			monitor.setMessage(
					String.format("[%s]: Loading PE image: %s...", program.getName(), module.getBaseName()));
			monitor.setProgress(progress * 100 / list.moduleCount);
			var peBytes = new ByteProviderWrapper(memoryProvider, module.imageBase, module.imageSize);
			images.add(loadPeImage(peBytes, loadSpec, programModule, module, program, monitor, log));
			progress++;
		}
		
		for (var image : images)
			processPeImage(image, program, monitor, log);
	}
	
	private PeImageData loadPeImage(ByteProvider peBytes, LoadSpec loadSpec, ProgramModule programModule, MinidumpModule module,
			Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {

		if (monitor.isCancelled())
			return null;

		var loadInfo = new ImageLoadInfo();
		loadInfo.imageBase = module.imageBase;
		loadInfo.imageName = module.getBaseName();
		loadInfo.sharedProgram = true;
		loadInfo.sectionLayout = SectionLayout.MEMORY;
		var peLoader = new PeLoader(loadInfo);
		var image = peLoader.loadImage(peBytes, loadSpec, new ArrayList<>(), program, monitor, log);
		if (monitor.isCancelled())
			return null;
		
		Address moduleStart = program.getImageBase().getNewAddress(module.imageBase);
		Address moduleEnd = moduleStart.add(module.imageSize - 1);
		ModuleBaseMap.markModule(program, moduleStart, moduleEnd);
		
		// Move the sections to the module folder.
		var baseAddr = module.imageBase;
		AddressFactory af = program.getAddressFactory();
		AddressSpace space = af.getDefaultAddressSpace();
		var imageAddr = space.getAddress(baseAddr);
		moveFragment(program, imageAddr, programModule);
		for (var s : image.pe.getNTHeader().getFileHeader().getSectionHeaders()) {
			moveFragment(program, space.getAddress(baseAddr + s.getVirtualAddress()), programModule);
		}
		moveFragment(program, "Debug Data", programModule);

		var result = new PeImageData();
		result.loader = peLoader;
		result.info = image;
		result.peBytes = peBytes;
		result.module = module;

		return result;
	}

	private void moveProgramOptions(MinidumpModule module, Program program) {
		Options programOptions = program.getOptions(Program.PROGRAM_INFO);
		Options allModuleOptions = programOptions.getOptions("Module Information");
		Options moduleOptions = allModuleOptions.getOptions(module.getBaseName().replace('.', '_'));
		
		for (String opt : new String[] {
			PdbParserConstants.PDB_AGE,
			PdbParserConstants.PDB_FILE,
			PdbParserConstants.PDB_GUID,
			PdbParserConstants.PDB_SIGNATURE,
			PdbParserConstants.PDB_VERSION,
			"Debug Misc",
			"Debug Misc Datatype",
		}) {
			if (!programOptions.contains(opt))
				continue;
			
			moduleOptions.setString(opt, programOptions.getString(opt, null));
			programOptions.removeOption(opt);
		}
		
		for (String opt : new String[] {
			"SectionAlignment"
		}) {
			if (!programOptions.contains(opt))
				continue;
			
			moduleOptions.setInt(opt, programOptions.getInt(opt, 0));
			programOptions.removeOption(opt);
		}
		
		for (String opt : new String[] {
			PdbParserConstants.PDB_LOADED,
			RelocationTable.RELOCATABLE_PROP_NAME,
		}) {
			if (!programOptions.contains(opt))
				continue;
			
			moduleOptions.setBoolean(opt, programOptions.getBoolean(opt, false));
			programOptions.removeOption(opt);
		}
	}
	
	private void storeModuleData(PeImageData data, Program program) {

		AddressFactory af = program.getAddressFactory();
		AddressSpace space = af.getDefaultAddressSpace();
		
		var image = data.info;
		var baseAddr = data.module.imageBase;
		
		var rti = getRuntimeInfoAddress(baseAddr, image.pe);
		if (rti == null)
			return;
		var moduleData = new ModuleData(data.module.getBaseName(),
				space.getAddress(baseAddr),
				space.getAddress(rti.start),
				space.getAddress(rti.end));
		ModuleData.setModuleData(program, moduleData);
	}
	
	class AddressRange { long start; long end; }
	private AddressRange getRuntimeInfoAddress(long baseAddress, PortableExecutable pe) {
		NTHeader ntHeader = pe.getNTHeader();
		if (ntHeader == null) {
			return null;
		}
		
		OptionalHeader optionalHeader = ntHeader.getOptionalHeader();
		if (optionalHeader == null) {
			return null;
		}

		DataDirectory[] dataDirectories = optionalHeader.getDataDirectories();
		if (dataDirectories == null) {
			
		}
		if (dataDirectories.length <= OptionalHeader.IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
			return null;
		}
		ExceptionDataDirectory idd =
			(ExceptionDataDirectory) dataDirectories[OptionalHeader.IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (idd == null) {
			return null;
		}
		
		AddressRange range = new AddressRange();
		range.start = baseAddress + idd.getVirtualAddress();
		range.end = range.start + idd.getSize();
		return range;
	}
		
	private void processPeImage(PeImageData image, Program program, TaskMonitor monitor, MessageLog log)
			throws IOException {
		
		image.loader.processImage(image.peBytes, image.info, new ArrayList<>(), program, monitor, log);
		moveProgramOptions(image.module, program);
		storeModuleData(image, program);
	}
	
	private void loadThreads(ByteProvider provider, ByteProvider memoryProvider, LoadSpec loadSpec, MinidumpLocationDescriptor location,
			Program program, TaskMonitor monitor, MessageLog log) throws IOException {
		if (monitor.isCancelled())
			return;

		AddressFactory af = program.getAddressFactory();
		AddressSpace space = af.getDefaultAddressSpace();
		
		var threadList = MinidumpThreadList.parse(location.offset, provider);
		for (var thread : threadList.threads) {
			var tib = ThreadInformationBlock.parse(loadSpec, thread.teb, memoryProvider);
			
			var ctx = Context64.parse(thread.threadContext.offset, provider);
			
			var threadData = new ThreadData(
				thread.threadId,
				space.getAddress(tib.stackBase - 1),
				space.getAddress(tib.stackLimit),
				space.getAddress(thread.stack.startOfMemoryRange),
				space.getAddress(ctx.rsp),
				space.getAddress(ctx.rip),
				ctx
			);
			ThreadData.storeThreadData(program, threadData);
			
			var listing = program.getListing();
			var root = listing.getDefaultRootModule();
			ProgramFragment threadStack;
			try {
				threadStack = root.createFragment(String.format("Stack:t%s", thread.threadId));
			} catch (DuplicateNameException e) {
				Msg.warn(this, "Duplicate thread ID: " + thread.threadId);
				continue;
			}
			
			long stackStart = tib.stackLimit;
			long stackEnd = tib.stackBase - 1;
			try {
				threadStack.move(space.getAddress(stackStart), space.getAddress(stackEnd));
			} catch (AddressOutOfBoundsException | NotFoundException e) {
				Msg.warn(this, String.format("Stack for thread %s was not part of the dump.", thread.threadId));
			}
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}

	private void moveFragment(Program program, Address addr, ProgramModule module) {
		var listing = program.getListing();
		for (String tree : listing.getTreeNames()) {
			ProgramFragment fragment = listing.getFragment(tree, addr);
			if (fragment == null)
				continue;

			moveFragment(program, fragment, module);
		}
	}

	private void moveFragment(Program program, String name, ProgramModule module) {
		var listing = program.getListing();
		for (String tree : listing.getTreeNames()) {
			ProgramFragment fragment = listing.getFragment(tree, name);
			if (fragment == null)
				continue;
			
			moveFragment(program, fragment, module);
		}
	}

	private void moveFragment(Program program, ProgramFragment fragment, ProgramModule module) {
		ProgramModule[] oldParents = fragment.getParents();
		try {
			module.add(fragment);
		} catch (DuplicateGroupException e) {
			// Log error and continue, the fragment will remain in the old place.
			Msg.error(this, e);
			return;
		}

		for (var p : oldParents) {
			try {
				p.removeChild(fragment.getName());
			} catch (NotEmptyException e) {
				throw new IllegalStateException("Fragment could not be moved", e);
			}
		}
		
		try {
			fragment.setName(String.format("%s (%s)", fragment.getName(), module.getName()));
		} catch (DuplicateNameException e) {
			throw new IllegalStateException("Fragment name wasn't unique to begin with", e);
		}
	}
}