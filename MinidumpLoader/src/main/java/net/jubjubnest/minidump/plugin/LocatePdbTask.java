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
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import net.jubjubnest.minidump.shared.ModuleData;

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

		try {
			File pdbFile = locatePdb(monitor);
			if (pdbFile == null) {
				return;
			}

			module.symbolPath = pdbFile.getAbsolutePath();
			if (provider != null) {
				provider.refreshModules(false);
			}
		} catch (CancelledException e) {
			// Ignore.
		} catch (IOException | PdbException | MemoryAccessException e) {
			Msg.showError(this, null, "Error", e.toString(), e);
		}
	}
	
	private File locatePdb(TaskMonitor monitor) throws CancelledException, IOException, PdbException, MemoryAccessException {

		PdbProgramAttributes pdbAttributes = PdbResolver.getAttributes(program, module.baseAddress);
		PdbResolver.PdbResult pdbResult = PdbResolver.locatePdb(pdbAttributes, monitor);
		if (pdbResult != null) {
			return pdbResult.file;
		}
		
		if (provider != null) {
			
			GhidraFileChooser pdbChooser = new GhidraFileChooser(provider.getComponent());
			pdbChooser.setTitle("Select PDB file to load:");
			pdbChooser.setApproveButtonText("Select PDB");
			pdbChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
			pdbChooser.setFileFilter(new ExtensionFileFilter(new String[] { "pdb" },
				"Program Database Files"));

			File pdbFile = pdbChooser.getSelectedFile();
			PdbResolver.PdbResult result = PdbResolver.validatePdbCandidate(pdbFile, true, pdbAttributes, monitor);PdbParser.parse(pdbFile.getAbsolutePath(), new PdbReaderOptions(), TaskMonitor.DUMMY);
			if (result != null) {
				return result.file;
			}
		}
		
		return null;
	}
}
