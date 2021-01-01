package net.jubjubnest.minidump.analyzer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

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
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import net.jubjubnest.minidump.data.ModuleData;
import net.jubjubnest.minidump.loader.MinidumpLoader;

public class ModulePdbAnalyzer extends AbstractAnalyzer {
	
	public final static String NAME = "Module PDB Loader";
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
		
		List<SymbolInfo> symbols = new ArrayList<>();
		boolean missingSymbols = false;
		for (ModuleData md : ModuleData.getAllModules(program) ) {
			if (md.loadedSymbols != null) {
				continue;
			}

			monitor.setMessage(md.name + ": Locating PDB...");
			SymbolInfo info = locateModulePdb(program, md, log, monitor);
			if (info != null) {
				missingSymbols = missingSymbols || (info.result == null);
				symbols.add(info);
			}
		}
		
		// If we're not in a headless mode, ask the user for input if there are missing symbols.
		if (!SystemUtilities.isInHeadlessMode() && missingSymbols) {
			monitor.setMessage("Waiting for user confirmation...");
			SymbolLocationDialog locationDialog = new SymbolLocationDialog(symbols);
			if (!locationDialog.confirm()) {
				return false;
			}
		}
		
		for (SymbolInfo info : symbols) {
			if (info.result == null) {
				continue;
			}

			monitor.setMessage(info.module.name + ": Loading PDB...");
			loadModulePdb(program, info.module, info.result, log, monitor);
		}
		
		return true;
	}
	
	public SymbolInfo locateModulePdb(Program program, ModuleData md, MessageLog log, TaskMonitor monitor) throws CancelledException {
		PdbProgramAttributes pdbAttributes;
		try {
			pdbAttributes = PdbResolver.getAttributes(program, md.baseAddress);
			if (pdbAttributes == null) {
				return null;
			}
		} catch (IOException e) {
			log.appendMsg(getName(), "Exception parsing PDB information from the module: " + md.name);
			log.appendException(e);
			return null;
		}
		
		SymbolInfo info = new SymbolInfo(md, pdbAttributes, null);

		// Attempt to locate the PDB via non-interactive means.
		try {
			info.result = PdbResolver.locatePdb(pdbAttributes, monitor);
		} catch (IOException | PdbException e) {
			log.appendMsg(getName(), "Error locating PDB for " + md.name);
			log.appendException(e);
		}
		
		return info;
	}
	
	public void loadModulePdb(Program program, ModuleData md, PdbResolver.PdbResult pdbResult, MessageLog log, TaskMonitor monitor) throws CancelledException {

		try {

			String pdbName = pdbResult.file.getName();

			SubTaskMonitor subMonitor = new SubTaskMonitor(pdbName, "Parsing...", monitor);
			pdbResult.pdb.deserialize(subMonitor);

			subMonitor = new SubTaskMonitor(pdbName, "Applying...", monitor);
			subMonitor.addReplaceRule("^PDB: ", "");
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