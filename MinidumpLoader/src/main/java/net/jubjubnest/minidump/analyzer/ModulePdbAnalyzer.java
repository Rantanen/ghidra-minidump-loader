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
import ghidra.app.util.pdb.PdbLocator;
import ghidra.app.util.pdb.PdbProgramAttributes;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicator;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicatorOptions;
import ghidra.framework.options.OptionType;
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
	
	private static final String INTERACTIVE_OPTION_NAME = "Interactive";
	private static final String INTERACTIVE_OPTION_DESCRIPTION = "Confirm missing symbols using an interactive dialog.";
	
	private static final String SYMBOLPATH_OPTION_NAME = "Symbol Server";
	private static final String SYMBOLPATH_OPTION_DESCRIPTION = "Symbol path in the symbol server format: srv*..*...";
	
	private static final String USEPDBPATH_OPTION_NAME = "Unsafe: Use PDB path from modules";
	private static final String USEPDBPATH_OPTION_DESCRIPTION = "Use the PDB path embedded in the modules when searching PDB files.";

	PdbReaderOptions pdbReaderOptions = new PdbReaderOptions();
	PdbApplicatorOptions pdbApplicatorOptions = new PdbApplicatorOptions();
	long lastTransactionId = -1;
	
	String symbolPath;
	boolean isInteractive;
	boolean useModulePdbPath;

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
		if (isInteractive && !SystemUtilities.isInHeadlessMode() && missingSymbols) {
			monitor.setMessage("Waiting for user confirmation...");
			SymbolLocationDialog locationDialog = new SymbolLocationDialog(symbols, useModulePdbPath);
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
			info.result = PdbResolver.locatePdb(pdbAttributes, symbolPath, useModulePdbPath, monitor);
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
	
	@Override
	public void registerOptions(Options options, Program program) {
		symbolPath = System.getenv("_NT_SYMBOL_PATH");
		if (symbolPath == null || symbolPath.isEmpty()) {
			symbolPath = "srv*~/symbolcache*https://msdl.microsoft.com/download/symbols";
		}

		options.registerOption(SYMBOLPATH_OPTION_NAME,
				symbolPath,
				null,
				SYMBOLPATH_OPTION_DESCRIPTION);

		isInteractive = true;
		options.registerOption(INTERACTIVE_OPTION_NAME,
				OptionType.BOOLEAN_TYPE,
				isInteractive,
				null,
				INTERACTIVE_OPTION_DESCRIPTION);

		useModulePdbPath = false;
		options.registerOption(USEPDBPATH_OPTION_NAME,
				OptionType.BOOLEAN_TYPE,
				useModulePdbPath,
				null,
				USEPDBPATH_OPTION_NAME);
	}
	
	@Override
	public void optionsChanged(Options options, Program program) {
		symbolPath = options.getString(SYMBOLPATH_OPTION_NAME, symbolPath);
		isInteractive = options.getBoolean(INTERACTIVE_OPTION_NAME, isInteractive);
		useModulePdbPath = options.getBoolean(USEPDBPATH_OPTION_NAME, useModulePdbPath);
	}
}