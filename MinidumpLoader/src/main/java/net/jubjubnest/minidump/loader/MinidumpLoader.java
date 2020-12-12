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
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.DuplicateGroupException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotEmptyException;
import ghidra.util.task.TaskMonitor;
import net.jubjubnest.minidump.contrib.opinion.PeLoader;
import net.jubjubnest.minidump.contrib.pe.PortableExecutable.SectionLayout;
import net.jubjubnest.minidump.loader.parser.Directory;
import net.jubjubnest.minidump.loader.parser.Header;
import net.jubjubnest.minidump.loader.parser.LocationDescriptor;
import net.jubjubnest.minidump.loader.parser.Memory64List;
import net.jubjubnest.minidump.loader.parser.MemoryInfo;
import net.jubjubnest.minidump.loader.parser.MemoryInfoList;
import net.jubjubnest.minidump.loader.parser.Module;
import net.jubjubnest.minidump.loader.parser.ModuleList;

/**
 * Loads Windows Minidump files into Ghidra
 */
public class MinidumpLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {

		// TODO: Name the loader. This name must match the name of the loader in the
		// .opinion
		// files.

		return "Minidump Loader";
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
		var header = Header.parse(0, provider);
		log.appendMsg(this.getClass().getName(), String.format("Total streams: %s", header.streamsCount));

		// Index all streams. We'll need to be a bit careful in what order we process
		// these so we'll first figure out what we have.
		var directories = new HashMap<Integer, List<Directory>>();
		for (int i = 0; i < header.streamsCount; i++) {
			var offset = header.streamsOffset + Directory.RECORD_SIZE * i;
			var directory = Directory.parse(offset, provider);
			var list = directories.computeIfAbsent(directory.streamType, (key) -> new ArrayList<Directory>());
			list.add(directory);

			log.appendMsg(this.getClass().getName(),
					String.format("- Stream %s: %s (location: %s)", i, directory.streamType, directory.location));
		}

		// First load the memory in the program.
		var memoryList = directories.get(Directory.TYPE_MEMORY64LISTSTREAM);
		if (memoryList == null)
			throw new IllegalArgumentException("Minidump contains no memory segments");
		if (memoryList.size() != 1)
			throw new IllegalArgumentException("Minidump contains multiple memory lists");

		var memory = loadMemory64(provider, memoryList.get(0).location, program, monitor, log);
		var memoryProvider = new MinidumpMemoryProvider(provider, memory);

		var memoryInfoList = directories.get(Directory.TYPE_MEMORYINFOLISTSTREAM);
		if (memoryInfoList != null) {
			for (var m : memoryInfoList)
				loadPrivateMemory(provider, memoryProvider, m.location, program, monitor, log);
		}

		// Next load the modules if they exist.
		var moduleList = directories.get(Directory.TYPE_MODULELISTSTREAM);
		if (moduleList != null) {
			for (var m : moduleList) {
				loadModule(provider, loadSpec, memoryProvider, m.location, program, monitor, log);
			}
		}
	}

	private Memory64List loadMemory64(ByteProvider provider, LocationDescriptor location, Program program,
			TaskMonitor monitor, MessageLog log) throws IOException {

		var list = Memory64List.parse(location.offset, provider);
		log.appendMsg(this.getClass().getName(), String.format("  -> Memory segments: %s", list.memoryRangeCount));
		return list;
	}

	private void loadPrivateMemory(ByteProvider provider, ByteProvider memoryProvider, LocationDescriptor location,
			Program program, TaskMonitor monitor, MessageLog log) throws IOException, CancelledException {

		AddressFactory af = program.getAddressFactory();
		AddressSpace space = af.getDefaultAddressSpace();

		var list = MemoryInfoList.parse(location.offset, provider);
		for (var memoryInfo : list.descriptors) {
			if (memoryInfo.type != MemoryInfo.MEM_TYPE_PRIVATE)
				continue;
			if (memoryInfo.state != MemoryInfo.MEM_STATE_COMMIT)
				continue;

			FileBytes regionBytes = MemoryBlockUtils.createFileBytes(program, memoryProvider, memoryInfo.baseAddress,
					memoryInfo.regionSize, monitor);

			boolean r = memoryInfo.protect == MemoryInfo.PAGE_EXECUTE_READ
					|| memoryInfo.protect == MemoryInfo.PAGE_EXECUTE_READWRITE
					|| memoryInfo.protect == MemoryInfo.PAGE_EXECUTE_WRITECOPY
					|| memoryInfo.protect == MemoryInfo.PAGE_READONLY || memoryInfo.protect == MemoryInfo.PAGE_READWRITE
					|| memoryInfo.protect == MemoryInfo.PAGE_WRITECOPY;
			boolean w = memoryInfo.protect == MemoryInfo.PAGE_EXECUTE_READWRITE
					|| memoryInfo.protect == MemoryInfo.PAGE_EXECUTE_WRITECOPY
					|| memoryInfo.protect == MemoryInfo.PAGE_READWRITE
					|| memoryInfo.protect == MemoryInfo.PAGE_WRITECOPY;
			boolean x = memoryInfo.protect == MemoryInfo.PAGE_EXECUTE_READ
					|| memoryInfo.protect == MemoryInfo.PAGE_EXECUTE_READWRITE
					|| memoryInfo.protect == MemoryInfo.PAGE_EXECUTE_WRITECOPY;
			Address baseAddress = space.getAddress(memoryInfo.baseAddress);
			try {
				MemoryBlockUtils.createInitializedBlock(program, false, "private_memory", baseAddress, regionBytes, 0,
						memoryInfo.regionSize, "", "", r, w, x, log);
			} catch (AddressOverflowException e) {
				throw new IOException(e);
			}
		}
	}

	private void loadModule(ByteProvider provider, LoadSpec loadSpec, ByteProvider memoryProvider, LocationDescriptor location,
			Program program, TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {

		var list = ModuleList.parse(location.offset, provider);
		var progress = 0;
		for (var module : list.modules) {
			log.appendMsg(this.getClass().getName(), String.format("- Module %s", module.name));

			var baseName = module.getBaseName();
			var root = program.getListing().getDefaultRootModule();

			int counter = 0;
			var fileName = baseName;
			ProgramModule programModule = null;
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
			loadPe(module.imageBase, loadSpec, memoryProvider, programModule, module, program, monitor, log);
			progress++;
		}
	}

	private void loadPe(long baseAddr, LoadSpec loadSpec, ByteProvider memoryBytes, ProgramModule programModule, Module module,
			Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {

		var peBytes = new ByteProviderWrapper(memoryBytes, module.imageBase, module.imageSize);
		var peLoader = new PeLoader(module.imageBase, SectionLayout.MEMORY);
		var pe = peLoader.loadPortableExecutable(peBytes, loadSpec, new ArrayList<>(), program, monitor, log);
		
		// Move the sections to the module folder.
		AddressFactory af = program.getAddressFactory();
		AddressSpace space = af.getDefaultAddressSpace();
		moveFragment(program, space.getAddress(baseAddr), programModule);
		for (var s : pe.getNTHeader().getFileHeader().getSectionHeaders()) {
			moveFragment(program, space.getAddress(baseAddr + s.getVirtualAddress()), programModule);
		}
		moveFragment(program, "Debug Data", programModule);
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
			moveFragment(program, fragment, module);
		}
	}

	private void moveFragment(Program program, String name, ProgramModule module) {
		var listing = program.getListing();
		for (String tree : listing.getTreeNames()) {
			ProgramFragment fragment = listing.getFragment(tree, name);
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