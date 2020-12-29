package net.jubjubnest.minidump.analyzer;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.PdbProgramAttributes;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicator;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicatorOptions;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;
import net.jubjubnest.minidump.loader.MinidumpLoader;
import net.jubjubnest.minidump.plugin.LocatePdbTask;
import net.jubjubnest.minidump.plugin.PdbResolver;
import net.jubjubnest.minidump.shared.ModuleData;
import net.jubjubnest.minidump.shared.SubTaskMonitor;

public class ModulePdbAnalyzer extends AbstractAnalyzer {
	
	public final static String NAME = "Module PDB Analyzer";
	public final static String DESCRIPTION = "Attempts to locate and apply PDBs for individual modules in a Minidump.";
	static final boolean DEFAULT_ENABLEMENT = true;
	
	PdbReaderOptions pdbReaderOptions = new PdbReaderOptions();
	PdbApplicatorOptions pdbApplicatorOptions = new PdbApplicatorOptions();
	long lastTransactionId = -1;

	public ModulePdbAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(DEFAULT_ENABLEMENT);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
		setSupportsOneTimeAnalysis();
	}
	
	static boolean isEnabled(Program program) {
		Options analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
		return analysisOptions.getBoolean(NAME, DEFAULT_ENABLEMENT);
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		// Avoid repeating for the same transaction.
		long txId = program.getCurrentTransaction().getID();
		if (txId == lastTransactionId) {
			return false;
		}
		lastTransactionId = txId;
		
		List<ModuleData> modules = ModuleData.getAllModules(program);
		Map<ModuleData, PdbResolver.PdbResult> modulePdbs = new HashMap<>();
		monitor.setProgress(0);
		monitor.setMaximum(modules.size());
		for (ModuleData md : ModuleData.getAllModules(program) ) {
			PdbResolver.PdbResult result = locateModulePdb(program, md, log, monitor);
			if (result == null) {
				continue;
			}
			
			loadModulePdb(program, md, result, log, monitor);
			monitor.incrementProgress(1);
		}
		
		return true;
	}
	
	public PdbResolver.PdbResult locateModulePdb(Program program, ModuleData md, MessageLog log, TaskMonitor monitor) throws CancelledException {
		PdbProgramAttributes pdbAttributes;
		try {
			pdbAttributes = PdbResolver.getAttributes(program, md.baseAddress);
		} catch (MemoryAccessException | IOException e) {
			log.appendMsg(getName(), "Exception parsing PDB information from the module: " + md.name);
			log.appendException(e);
			return null;
		}

		try {
			return PdbResolver.locatePdb(pdbAttributes, monitor);
		} catch (MemoryAccessException | IOException | PdbException e) {
			log.appendMsg(getName(), "Error locating PDB for " + md.name);
			log.appendException(e);
			return null;
		}
	}
	
	public void loadModulePdb(Program program, ModuleData md, PdbResolver.PdbResult pdbResult, MessageLog log, TaskMonitor monitor) throws CancelledException {

		try {

			String pdbName = pdbResult.file.getName();

			SubTaskMonitor subMonitor = new SubTaskMonitor(pdbName, "Parsing...", monitor);
			pdbResult.pdb.deserialize(subMonitor);

			subMonitor = new SubTaskMonitor(pdbName, "Applying...", monitor);
			subMonitor.setStripPrefix("PDB: ");
			PdbApplicator applicator = new PdbApplicator(pdbResult.file.getAbsolutePath(), pdbResult.pdb);
			applicator.applyTo(program, null, md.baseAddress, null, subMonitor, new MessageLog());

			monitor.setMessage(pdbName + ": Committing...");
			ModuleData moduleData = ModuleData.getModuleData(program, md.baseAddress);
			moduleData.loadedSymbols = pdbResult.file.getAbsolutePath();
			ModuleData.setModuleData(program, moduleData);

		} catch (IOException | PdbException e) {
			log.appendMsg(getName(), "Error applying PDB " + pdbResult.file.getName());
			log.appendException(e);
		}
	}

	@Override
	public boolean canAnalyze(Program program) {
		String executableFormat = program.getExecutableFormat();
		return executableFormat != null && executableFormat.equals(MinidumpLoader.NAME);
	}
}