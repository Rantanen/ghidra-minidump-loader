package net.jubjubnest.minidump.analyzer;

import java.io.File;
import java.io.IOException;
import java.util.List;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
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
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.task.TaskMonitor;
import net.jubjubnest.minidump.loader.MinidumpLoader;
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
		
		for (ModuleData md : ModuleData.getAllModules(program) ) {
			if (md.loadedSymbols != null) {
				continue;
			}

			monitor.setMessage(md.name + ": Locating PDB...");
			PdbResolver.PdbResult result = locateModulePdb(program, md, log, monitor);

			monitor.setMessage(md.name + ": Loading PDB...");
			loadModulePdb(program, md, result, log, monitor);
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

		// Attempt to locate the PDB via non-interactive means.
		try {
			PdbResolver.PdbResult result = PdbResolver.locatePdb(pdbAttributes, monitor);
			if (result != null) {
				return result;
			}
		} catch (MemoryAccessException | IOException | PdbException e) {
			log.appendMsg(getName(), "Error locating PDB for " + md.name);
			log.appendException(e);
		}

		// If we're not in a headless mode, ask the user for input.
		if (!SystemUtilities.isInHeadlessMode()) {
				
			GhidraFileChooser pdbChooser = new GhidraFileChooser(null);
			pdbChooser.setTitle("Select " + md.name + " PDB file");
			pdbChooser.setApproveButtonText("Select PDB");
			pdbChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
			pdbChooser.setFileFilter(new ExtensionFileFilter(new String[] { "pdb" }, "Program Database Files"));
			
			if (pdbAttributes.getPdbFile() != null) {
				File expected = new File(pdbAttributes.getPdbFile());
				pdbChooser.setCurrentDirectory(expected.getParentFile());
			}

			File pdbFile = pdbChooser.getSelectedFile();
			PdbResolver.PdbResult result;
			try {
				result = PdbResolver.validatePdbCandidate(pdbFile, true, pdbAttributes, monitor);
				if (result != null) {
					return result;
				}
			} catch (IOException | PdbException e) {
				log.appendMsg(getName(), "Error locating PDB for " + md.name);
				log.appendException(e);
			}
		}
		
		return null;
	}
	
	public void loadModulePdb(Program program, ModuleData md, PdbResolver.PdbResult pdbResult, MessageLog log, TaskMonitor monitor) throws CancelledException {

		try {

			String pdbName = pdbResult.file.getName();

			SubTaskMonitor subMonitor = new SubTaskMonitor(pdbName, "Parsing...", monitor);
			pdbResult.pdb.deserialize(subMonitor);

			subMonitor = new SubTaskMonitor(pdbName, "Applying...", monitor);
			subMonitor.addReplaceRule("^PDB: ", "");
			subMonitor.addReplaceRule("^Applying \\d+ ", "Applying ");
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