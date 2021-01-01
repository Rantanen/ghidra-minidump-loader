package net.jubjubnest.minidump.analyzer;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbParser;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions;
import ghidra.app.util.pdb.PdbProgramAttributes;
import ghidra.net.http.HttpUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotYetImplementedException;
import ghidra.util.task.TaskMonitor;

class PdbResolver {

	public static PdbProgramAttributes getAttributes(Program program, Address moduleBase) throws IOException {

		boolean analyzed = program.getOptions(Program.PROGRAM_INFO).getBoolean(Program.ANALYZED, false);
		ModuleParser.PdbInfo pdbInfo = ModuleParser.getPdbInfo(program, moduleBase);
		if (pdbInfo == null) {
			return null;
		}

		PdbProgramAttributes pdbAttributes = new PdbProgramAttributes(
				pdbInfo.guid, Integer.toString(pdbInfo.age),
				false, analyzed, null, pdbInfo.pdbName, "RSDS");

		return pdbAttributes;
	}

	public static class PdbResult {
		public PdbResult(File file, AbstractPdb pdb) {
			this.file = file;
			this.pdb = pdb;
		}

		public File file;
		public AbstractPdb pdb;
	}

	public static PdbResult locatePdb(PdbProgramAttributes pdbAttributes, String symbolServer, boolean useModulePdbPath, TaskMonitor monitor)
			throws IOException, CancelledException, PdbException {

		if (symbolServer == null || symbolServer.isEmpty()) {
			return null;
		}

		if (useModulePdbPath && pdbAttributes.getPdbFile() != null) {
			File candidate = new File(pdbAttributes.getPdbFile());
			PdbResult result = validatePdbCandidate(candidate, true, pdbAttributes, monitor);
			if (result != null) {
				return result;
			}
		}
		
		PdbResolver.SymbolPath symbolPath = PdbResolver.parseSymbolPath(symbolServer);
		File symbolServerMatch = PdbResolver.loadSymbols(symbolPath, pdbAttributes);
		if (symbolServerMatch != null) {
			return new PdbResult(
				symbolServerMatch, 
				PdbParser.parse(symbolServerMatch.getAbsolutePath(), new PdbReaderOptions(), monitor)
			);
		}

		return null;
	}

	public static PdbResult validatePdbCandidate(File candidate, boolean verifyGuidAge, PdbProgramAttributes pdbAttributes, TaskMonitor monitor) throws CancelledException, IOException, PdbException {

		if (candidate == null || !candidate.exists()) {
			return null;
		}

		AbstractPdb pdb = PdbParser.parse(candidate.getAbsolutePath(), new PdbReaderOptions(), monitor);
		if (verifyGuidAge) {
			if (!pdbAttributes.getPdbGuid().equals(pdb.getGuid().toString())) {
				throw new PdbException("PDB GUID mismatch");
			}

			if (!pdbAttributes.getPdbAge().equals(Integer.toHexString(pdb.getAge()))) {
				throw new PdbException("PDB age mismatch");
			}
		}
		
		return new PdbResult(candidate, pdb);
	}
	
	public static class SymbolServerResult {
		File file;
		String path;
	}
	
	public static File loadSymbols(SymbolPath path, PdbProgramAttributes pdbAttributes) throws IOException {

		for (SymbolPathItem item : path.items) {
			switch (item.type) { 
			case SymbolServer:
				String[] servers = item.path.split("\\*");
				return loadSymbolsFromSymbolServers(servers, pdbAttributes);
			default:
				throw new NotYetImplementedException();
			}
		}
		
		return null;
	}
	
	public static PdbResult tryFindSymbols(File root, PdbProgramAttributes pdbAttributes, TaskMonitor monitor) {

		String candidate = pdbAttributes.getPdbFile().replace('\\', '/');
		for (int nextDir = candidate.indexOf('/'); monitor.isCancelled() == false && nextDir != -1; nextDir = candidate.indexOf('/')) {
			candidate = candidate.substring(nextDir + 1);
			Path p = root.toPath().resolve(candidate);
			if (!Files.exists(p)) {
				continue;
			}
			
			try {
				PdbResult candidateResult = PdbResolver.validatePdbCandidate(p.toFile(), true, pdbAttributes, monitor);
				if (candidateResult == null) {
					continue;
				}

				return candidateResult;
			} catch (CancelledException | IOException | PdbException e) {
				// Ignore the candidate on errors.
				continue;
			}
		}
		
		return null;
	}

	private static File loadSymbolsFromSymbolServers(String[] servers, PdbProgramAttributes pdbAttributes) throws IOException {
		List<String> cascadeServers = new ArrayList<>();
		SymbolServerResult result = null;
		String tempPath = null;
		for (String server : servers) {

			// Support home directories.
			server = server.replaceFirst("^~\\B", Matcher.quoteReplacement(System.getProperty("user.home")));

			result = loadSymbolsFromSymbolServer(server, tempPath, pdbAttributes);

			if (result != null) break;
			cascadeServers.add(server);

			// Use the previous physical server as the temp path to avoid having to make a temporary copy of possible downloads.
			// We'll end up extracting the files anyway later.
			if (!server.startsWith("http:") && !server.startsWith("https:")) {
				tempPath = server;
			}
		}
		
		if (result == null) {
			return null;
		}
		
		for (String cascade : cascadeServers) {
			Path cascadedFile = Paths.get(cascade, result.path);
			if (!Files.exists(cascadedFile)) {
				Files.createDirectories(cascadedFile.getParent());
				Files.copy(result.file.toPath(), cascadedFile);
				result.file = cascadedFile.toFile();
			}
		}
		
		return result.file;
	}

	private static SymbolServerResult loadSymbolsFromSymbolServer(String server, String tempPath, PdbProgramAttributes pdbAttributes) throws IOException {

		for (String candidate : pdbAttributes.getPotentialPdbFilenames()) {
			return loadSymbolsFromSymbolServerForCandidate(server, candidate, tempPath, pdbAttributes);
		}
		
		return null;
	}
	
	private static SymbolServerResult loadSymbolsFromSymbolServerForCandidate(String server, String candidate, String tempPath, PdbProgramAttributes pdbAttributes) throws IOException {

		if (!server.endsWith("/")) {
			server += "/";
		}
		String path = candidate + "/" + pdbAttributes.getGuidAgeCombo() + "/" + candidate;
		
		if (server.startsWith("http:") || server.startsWith("https:")) {
			return downloadFile(server, path, tempPath);
		}

		File file = new File(server, path);
		if (file.exists()) {
			SymbolServerResult result = new SymbolServerResult();
			result.file = file;
			result.path = path;
			return result;
		}
		
		return null;
	}
	
	private static SymbolServerResult downloadFile(String server, String path, String target) throws IOException {
		if (target == null) {
			File tmp = File.createTempFile("symbol", "pdb");
			tmp.delete();
			tmp.mkdirs();
			target = tmp.getAbsolutePath() + "/";
		}
		
		File targetFile = new File(target, path);
		targetFile.getParentFile().mkdirs();

		String url = server + path;
		try {
			HttpUtil.getFile(url, null, true, targetFile);
		} catch (IOException e) {
			return null;
		}
		
		if (targetFile.exists()) {
			SymbolServerResult result = new SymbolServerResult();
			result.file = targetFile;
			result.path = path;
			return result;
		}
		return null;
	}
	
	public static SymbolPath parseSymbolPath(String path) {

		String currentCache = null;
		List<SymbolPathItem> items = new ArrayList<>();
		for (String segment : path.split(";")) {
			if (segment.toLowerCase().startsWith("cache*")) {
				currentCache = segment.substring("cache*".length());
				continue;
			}
			
			items.add(parseSegment(segment, currentCache));
		}
		
		return new SymbolPath(items);
	}
	
	private static SymbolPathItem parseSegment(String segment, String globalCache) {

		SymbolPathType type = SymbolPathType.Directory;
		if (segment.toLowerCase().startsWith("srv*")) {
			type = SymbolPathType.SymbolServer;
			segment = segment.substring("srv*".length());
		}
		
		SymbolPathItem item = new SymbolPathItem();
		item.path = segment;
		item.type = type;
		item.cache = globalCache;
		return item;
	}
	
	static class SymbolPath {
		public SymbolPath(List<SymbolPathItem> items) {
			this.items = items;
		}

		public List<SymbolPathItem> items;
	}
	
	static class SymbolPathItem {
		public String path;
		public SymbolPathType type;
		public String cache;
	}
	
	enum SymbolPathType { SymbolServer, Directory }
}
