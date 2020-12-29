package net.jubjubnest.minidump.plugin;

import java.io.File;
import java.io.IOException;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbParser;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions;
import ghidra.app.util.pdb.PdbProgramAttributes;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class LocatePdbTask extends Task {

	Program program;
	ModuleState module;
	ModulesProvider provider;

	public LocatePdbTask(Program program, ModuleState module, ModulesProvider provider) {
		super("Locate PDB");
		this.program = program;
		this.module = module;
		this.provider = provider;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {

		AbstractPdb pdb = null;
		File pdbFile = null;
		try {
			PdbProgramAttributes pdbAttributes = PdbResolver.getAttributes(program, module);
			if (pdbAttributes.getPdbFile() != null) {
				pdbFile = new File(pdbAttributes.getPdbFile());
				pdb = validatePdbCandidate(pdbFile, true, pdbAttributes, monitor);
			}
			
			if (pdb == null) {
				PdbResolver.SymbolPath symbolPath = PdbResolver.parseSymbolPath(
						"srv*C:\\symbols*\\\\localhost\\NetworkSymCache*https://msdl.microsoft.com/download/symbols");
				pdbFile = PdbResolver.loadSymbols(symbolPath, pdbAttributes);
				if (pdbFile != null) {
					pdb = PdbParser.parse(pdbFile.getAbsolutePath(), new PdbReaderOptions(), monitor);
				}
			}
			
			if (pdb == null) {
				
				GhidraFileChooser pdbChooser = new GhidraFileChooser(provider.getComponent());
				pdbChooser.setTitle("Select PDB file to load:");
				pdbChooser.setApproveButtonText("Select PDB");
				pdbChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
				pdbChooser.setFileFilter(new ExtensionFileFilter(new String[] { "pdb" },
					"Program Database Files"));

				if (pdbFile != null) {
					pdbChooser.setSelectedFile(pdbFile.getParentFile());
				}

				pdbFile = pdbChooser.getSelectedFile();

				pdb = validatePdbCandidate(pdbFile, true, pdbAttributes, monitor);PdbParser.parse(pdbFile.getAbsolutePath(), new PdbReaderOptions(), TaskMonitor.DUMMY);
			}
			
			module.symbolPath = pdbFile.getAbsolutePath();
			provider.refreshModules(false);

		} catch (CancelledException | IOException | PdbException | MemoryAccessException e) {
			pdb = null;
		}
		
	}

	AbstractPdb validatePdbCandidate(File candidate, boolean verifyGuidAge, PdbProgramAttributes pdbAttributes, TaskMonitor monitor) throws CancelledException, IOException, PdbException {

		if (!candidate.exists()) {
			return null;
		}

		AbstractPdb pdb = PdbParser.parse(candidate.getAbsolutePath(), new PdbReaderOptions(), monitor);
		if (verifyGuidAge) {
			if (!pdbAttributes.getPdbGuid().equals(pdb.getGuid().toString())) {
				return null;
			}

			if (!pdbAttributes.getPdbAge().equals(Integer.toHexString(pdb.getAge()))) {
				return null;
			}
		}
		
		return pdb;
	}
}
