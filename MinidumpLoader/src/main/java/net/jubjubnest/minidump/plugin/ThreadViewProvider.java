package net.jubjubnest.minidump.plugin;

import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;

import org.apache.logging.log4j.LogManager;

import javax.swing.JScrollPane;
import javax.swing.JSplitPane;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.GoToService;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbParser;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.PdbProgramAttributes;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicator;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;
import net.jubjubnest.minidump.loader.MinidumpLoader;
import net.jubjubnest.minidump.shared.ModuleData;
import net.jubjubnest.minidump.shared.RuntimeFunction;
import net.jubjubnest.minidump.shared.RuntimeInfo;
import net.jubjubnest.minidump.shared.ThreadData;
import net.jubjubnest.minidump.shared.ThreadDataList;
import resources.Icons;

// TODO: If provider is desired, it is recommended to move it to its own file
class ThreadViewProvider extends ComponentProvider implements DomainObjectListener {
	
	public static final String NAME = "Memory Dump Threads";

	private JPanel panel;
	private JTable threadTable;
	private StackList stackList;
	private DockingAction action;
	private Program program;
	private ThreadDataList threadList;
	private ArrayList<Address> offsets;
	private ThreadViewPlugin plugin;
	private ThreadData activeThread;

	public ThreadViewProvider(ThreadViewPlugin plugin, String owner) {
		super(plugin.getTool(), NAME, owner);
		this.plugin = plugin;
		buildPanel();
		createActions();
	}
	
	// Customize GUI
	private void buildPanel() {

		threadTable = new JTable() {
			@Override
			public boolean isCellEditable(int row, int column) {
				return false;
			}	
		};
		threadTable.setColumnSelectionAllowed(false);
		threadTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		threadTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
			public void valueChanged(ListSelectionEvent event) {
				if( event.getValueIsAdjusting())
					return;
				
				threadActivated(threadTable.getSelectionModel().getAnchorSelectionIndex());
			}
		});

		stackList = new StackList(this.plugin);

		panel = new JPanel(new BorderLayout());
		panel.add(new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(threadTable), new JScrollPane(stackList)));
		setVisible(true);
	}

	// TODO: Customize actions
	private void createActions() {
		action = new DockingAction("My Action", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				int tx = program.startTransaction("PDB");
				try {
					var pdb = PdbParser.parse("C:\\Users\\Rantanen\\source\\repos\\MinidumpTarget\\x64\\Release\\MinidumpTarget.pdb",
							new PdbReaderOptions(),
							TaskMonitorAdapter.DUMMY);
					pdb.deserialize(TaskMonitorAdapter.DUMMY);
					// pdb.getIdentifiers();
					PdbApplicator applicator = new PdbApplicator(
							"C:\\Users\\Rantanen\\source\\repos\\MinidumpTarget\\x64\\Release\\MinidumpTarget.pdb",
							pdb);
					applicator.applyTo(program, null, program.getImageBase().getNewAddress(0x7ff6a4930000l), null, TaskMonitorAdapter.DUMMY, new MessageLog());
					/*
					PdbProgramAttributes attribs = new PdbProgramAttributes(
							"4c7a5390-6613-4653-9a75-c06d855d8ff1",
							"2",
							false,
							false,
							null,
							"target.pdb",
							"none.exe");
					*/
					program.endTransaction(tx, true);
				} catch (CancelledException | PdbException | IOException e) {
					program.endTransaction(tx, false);
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		};
		action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);
	}
	
	public void programActivated(Program newProgram)
	{
		if (program != null) {
			program.removeListener(this);
			program = null;
		}

		if( newProgram == null )
			return;

		program = newProgram;
		program.addListener(this);
		
		var userData = program.getProgramUserData();
		var transaction = userData.startTransaction();
		try {
			threadList = ThreadDataList.getThreadDataList(program, userData);
			if (threadList == null)
				return;
		} finally {
			userData.endTransaction(transaction);
		}
		
		String[] headers = { "Thread ID", "StackP.", "InstP." };
		String[][] data = new String[threadList.threads.size()][headers.length];
		for (int i = 0; i < threadList.threads.size(); i++) {
			var thread = threadList.threads.get(i);
			data[i][0] = Integer.toString(thread.id);
			data[i][1] = Long.toHexString(thread.sp);
			data[i][2] = Long.toHexString(thread.ip);
		}
		var model = new DefaultTableModel(data, headers);
		threadTable.setModel(model);
		threadTable.setRowSelectionInterval(0, 0);
	}
	
	public void threadActivated(int threadIdx) {
		activeThread = threadList.threads.get(threadIdx);
		refreshStack();
	}
	
	private void refreshStack() {
		var frames = new ArrayList<StackFrame>();

		var af = program.getAddressFactory();
		var space = af.getDefaultAddressSpace();

		// Set up a pointer-sized byte buffer for re-using when reading addresses.
		var pointerSize = program.getLanguage().getLanguageDescription().getSize();
		byte[] ptr = new byte[pointerSize / 8];
		var buffer = ByteBuffer.wrap(ptr);
		buffer.order(ByteOrder.LITTLE_ENDIAN);

		// Thread info will give us the top-of-the-stack register values so we'll start with those.
		var addrIp = space.getAddress(activeThread.ip);
		var addrSp = space.getAddress(activeThread.sp);
		try {
			var firstFrame = getCaller(addrSp, addrIp, buffer);
			while (firstFrame != null) {
				frames.add(firstFrame);
				
				var rip =  firstFrame.getReturnAddress(program);
				if (rip == null)
					break;
				firstFrame = getCaller(firstFrame.returnPointer.add(ptr.length), rip, buffer);
			}
		} catch (IOException e1) {
			// In case of an IO err,r we'll log it but don't do anything else.
			// Show as much of the stack as we managed to gather.
			Msg.warn(this, "Memory violation when resolving the call stack");
		}
		
		stackList.setFrames(frames, program);
	}
	
	StackFrame getCaller(Address stackPtr, Address instructionPtr, ByteBuffer buffer) throws IOException {

		var memoryProvider = new MemoryByteProvider(program.getMemory(), instructionPtr.getAddressSpace());
		var data = new byte[4*3];
		var rtBuffer = ByteBuffer.wrap(data);
		rtBuffer.order(ByteOrder.LITTLE_ENDIAN);
		
		ModuleData moduleData = ModuleData.getContainingModuleData(program, instructionPtr);
		if (moduleData == null) {
			return null;
		}

		RuntimeFunction runtimeFunction = getRuntimeFunction(instructionPtr, moduleData, memoryProvider);
		if (runtimeFunction == null)
			return null;
		
		UnwindResult unwind = unwindStackPtr(stackPtr, instructionPtr, runtimeFunction, memoryProvider);
		long functionOffset = instructionPtr.subtract(unwind.finalFunction.startOfFunction);
		
		return new StackFrame(stackPtr, instructionPtr, unwind.finalStack, functionOffset, moduleData.name);
	}
	
	static class UnwindResult { Address finalStack; RuntimeFunction finalFunction; }
	UnwindResult unwindStackPtr(Address current, Address instructionPtr, RuntimeFunction rtFunction, ByteProvider memory) throws IOException {

		RuntimeInfo runtimeInfo = rtFunction.readRuntimeInfo(memory);
		RuntimeFunction finalFunction = rtFunction;
		while (runtimeInfo != null) {

			var functionOffset = instructionPtr.subtract(rtFunction.startOfFunction);
			for (var unwindCode : runtimeInfo.unwindCodes ) {
				if (unwindCode.prologOffset <= functionOffset) {
					current = current.add(unwindCode.spEffect);
				}
			}
			
			if (runtimeInfo.parentFunction == null)
				break;

			finalFunction = runtimeInfo.parentFunction;
			runtimeInfo = finalFunction.readRuntimeInfo(memory);
		}
		
		UnwindResult result = new UnwindResult();
		result.finalStack = current;
		result.finalFunction = finalFunction;
		return result;
	}
	
	RuntimeFunction getRuntimeFunction(Address instructionPtr, ModuleData moduleData, ByteProvider memoryProvider) throws IOException {

		Address moduleBaseAddress = instructionPtr.getNewAddress(moduleData.baseAddress);
		BinaryReader reader = new BinaryReader(memoryProvider, true);
		reader.setPointerIndex(moduleData.rtiStartAddress);
		for (;reader.getPointerIndex() < moduleData.rtiEndAddress;) {
			
			RuntimeFunction rf = RuntimeFunction.parse(moduleBaseAddress, reader);

			if (rf.startOfFunction.compareTo(instructionPtr) > 0)
				continue;
			if (rf.endOfFunction.compareTo(instructionPtr) < 0)
				continue;
			
			return rf;
		}
		
		return null;
	}
	
	void navigateStack(int idx) {
		var offset = offsets.get(idx);
		if (offset == null)
			return;
		plugin.goToService.goTo(offset);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		this.stackList.updateAnalysis(program);
	}
}