package net.jubjubnest.minidump.plugin;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbParser;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import net.jubjubnest.minidump.shared.ModuleData;

public class LoadPdbsTask extends Task {
	
	private Program program;
	private ModulesProvider provider;
	
	public LoadPdbsTask(Program program, ModulesProvider provider) {
		super("Load PDB");
		this.program = program;
		this.provider = provider;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		
		AnalysisWorker worker = new AnalysisWorker() {

			@Override
			public String getWorkerName() {
				return "Load PDBs";
			}

			@Override
			public boolean analysisWorkerCallback(Program program, Object workerContext, TaskMonitor monitor)
					throws Exception, CancelledException {
				
				for (ModuleState module : provider.getModules()) {
					try {
						loadPdb(module, monitor);
					} catch (CancelledException | IOException | PdbException e) {
						Msg.showError(this, null, "Error", e.getMessage(), e);
					} catch (RuntimeException e) {
						throw e;
					}

					monitor.setMessage(module.name + " done.");
					provider.refreshModules(false);
				}

				return true;
			}
		};

		AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(program);
		try {
			aam.scheduleWorker(worker, null, true, monitor);
		} catch (CancelledException | InterruptedException e) {
			// Ignore.
		} catch (InvocationTargetException e) {
			Msg.showError(this, null, "Error", e.toString(), e);
		}
	}
	
	private void loadPdb(ModuleState module, TaskMonitor monitor) throws CancelledException, IOException, PdbException {
	
		if (module.symbolPath == null || module.symbolsLoaded == true) {
			return;
		}

		File pdbFile = new File(module.symbolPath);
		monitor.setMessage("Parsing " + pdbFile.getName() + "...");
		AbstractPdb pdb = PdbParser.parse(pdbFile.getAbsolutePath(), new PdbReaderOptions(), monitor);
		pdb.deserialize(monitor);

		int tx = program.startTransaction("PDB");
		try {
			monitor.setMessage("Applying " + pdbFile.getName() + "...");
			PdbApplicator applicator = new PdbApplicator(pdbFile.getAbsolutePath(), pdb);
			applicator.applyTo(program, null, module.baseAddress, null,
					TaskMonitor.DUMMY, new MessageLog());

			monitor.setMessage("Committing " + pdbFile.getName() + "...");
			ModuleData moduleData = ModuleData.getModuleData(program, module.baseAddress);
			moduleData.loadedSymbols = pdbFile.getAbsolutePath();
			ModuleData.setModuleData(program, moduleData);

			program.endTransaction(tx, true);

		} catch (Exception e) {
			program.endTransaction(tx, false);
			throw e;
		}
	}
}
