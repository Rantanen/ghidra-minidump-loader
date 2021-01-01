package net.jubjubnest.minidump.analyzer;

import java.awt.Component;
import java.io.File;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.util.pdb.PdbProgramAttributes;
import ghidra.util.SystemUtilities;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.task.TaskMonitor;
import ghidra.util.worker.Job;
import ghidra.util.worker.Worker;
import net.jubjubnest.minidump.analyzer.PdbResolver.PdbResult;

class FindSymbolsFileChooser extends GhidraFileChooser {
	
	private final PdbProgramAttributes pdbAttributes;
	private Worker worker = Worker.createGuiWorker();

	private File rootDirectory;
	private PdbResult result;
	
	public FindSymbolsFileChooser(Component parent, PdbProgramAttributes pdbAttributes) {
		super(parent);
		this.pdbAttributes = pdbAttributes;

		setTitle("Locate " + pdbAttributes.getPdbFile());
		setApproveButtonText("Select PDB");
		setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		setFileFilter(new ExtensionFileFilter(new String[] { "pdb" }, "Program Database Files"));
	}
	
	@Override
	public void setCurrentDirectory(File directory) {
		super.setCurrentDirectory(directory);
		worker.schedule(new CheckPdbPath(directory));
	}
	
	public PdbResult getValidatedResult() {
		return result;
	}
	
	public File getValidatedRoot() {
		return rootDirectory;
	}

	private class CheckPdbPath extends Job {
		
		private File currentDirectory;
		public CheckPdbPath(File currentDirectory) {
			this.currentDirectory = currentDirectory;
		}

		@Override
		public void run(TaskMonitor monitor) {
			
			PdbResult candidateResult = PdbResolver.tryFindSymbols(currentDirectory, pdbAttributes, monitor);
			if (candidateResult != null) {
				SystemUtilities.runSwingLater(() -> {
					rootDirectory = currentDirectory;
					result = candidateResult;
					setSelectedFile(result.file);
					close();
				});
			}
		}
	}

}
