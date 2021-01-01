package net.jubjubnest.minidump.plugin;

import java.awt.BorderLayout;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;

import javax.swing.JScrollPane;
import javax.swing.JSplitPane;

import docking.ComponentProvider;
import docking.widgets.table.GTable;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import net.jubjubnest.minidump.shared.ModuleData;
import net.jubjubnest.minidump.shared.RuntimeFunction;
import net.jubjubnest.minidump.shared.RuntimeInfo;
import net.jubjubnest.minidump.shared.ThreadData;

// TODO: If provider is desired, it is recommended to move it to its own file
class ThreadViewProvider extends ComponentProvider implements DomainObjectListener {
	
	public static final String NAME = "Memory Dump Threads";

	private JPanel panel;
	private GTable threadTable;
	private StackList stackList;
	private Program program;
	private List<ThreadData> threadList;
	private ThreadViewPlugin plugin;
	private ThreadData activeThread;
	
	private JSplitPane activePanel;

	public ThreadViewProvider(ThreadViewPlugin plugin, String owner) {
		super(plugin.getTool(), NAME, owner);
		this.plugin = plugin;
		buildPanel();
	}
	
	// Customize GUI
	private void buildPanel() {

		threadTable = new GTable() {
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

		activePanel = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(threadTable), new JScrollPane(stackList));
		panel = new JPanel(new BorderLayout());
		
		addToTool();
		programActivated(null);
	}
	
	public void programActivated(Program newProgram)
	{
		if (program != null) {
			program.removeListener(this);
			program = null;
		}

		if( newProgram == null ) {
			setInactive("No program loaded");
			return;
		}

		program = newProgram;
		program.addListener(this);
	
		threadList = ThreadData.getAllThreadData(program);
		if (threadList == null || threadList.size() == 0) {
			setInactive("No thread information present in the loaded program");
			return;
		}
		
		setActive();
		
		String[] headers = { "Thread ID", "StackP.", "InstP." };
		String[][] data = new String[threadList.size()][headers.length];
		for (int i = 0; i < threadList.size(); i++) {
			var thread = threadList.get(i);
			data[i][0] = Integer.toString(thread.id);
			data[i][1] = thread.sp.toString();
			data[i][2] = thread.ip.toString();
		}
		var model = new DefaultTableModel(data, headers);
		threadTable.setModel(model);
		threadTable.setRowSelectionInterval(0, 0);
	}
	
	public void threadActivated(int threadIdx) {
		if (threadIdx == -1) {
			activeThread = null;
		} else {
			activeThread = threadList.get(threadIdx);
		}

		refreshStack();
	}
	
	private void refreshStack() {
		var frames = new ArrayList<StackFrame>();
		if (activeThread == null) {
			stackList.setFrames(frames, program);
			return;
		}

		// Set up a pointer-sized byte buffer for re-using when reading addresses.
		var pointerSize = program.getLanguage().getLanguageDescription().getSize();
		byte[] ptr = new byte[pointerSize / 8];
		var buffer = ByteBuffer.wrap(ptr);
		buffer.order(ByteOrder.LITTLE_ENDIAN);

		// Thread info will give us the top-of-the-stack register values so we'll start with those and then
		// attempt to walk the stack back from there.
		try {
			var firstFrame = getCaller(activeThread.sp, activeThread.ip, buffer);
			while (firstFrame != null) {
				frames.add(firstFrame);
				
				var rip =  firstFrame.getReturnAddress(program);
				if (rip == null)
					break;
				firstFrame = getCaller(firstFrame.returnPointer.add(ptr.length), rip, buffer);
			}
		} catch (IOException e1) {
			// In case of an IO error we'll log it but don't do anything else.
			// Show as much of the stack as we managed to gather.
			Msg.warn(this, "Memory violation when resolving the call stack");
		}
		
		stackList.setFrames(frames, program);
	}
	
	private void setInactive(String message) {
		panel.removeAll();
		panel.add(new JLabel(message, SwingConstants.CENTER));

		threadTable.setModel(new DefaultTableModel());
		threadTable.clearSelection();

		return;
	}
	
	private void setActive() {
		panel.removeAll();
		panel.add(activePanel);
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

			var functionOffset = instructionPtr.subtract(finalFunction.startOfFunction);
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

		Address moduleBaseAddress = moduleData.baseAddress;
		BinaryReader reader = new BinaryReader(memoryProvider, true);
		reader.setPointerIndex(moduleData.rtiStartAddress.getOffset());
		for (;reader.getPointerIndex() < moduleData.rtiEndAddress.getOffset();) {
			
			RuntimeFunction rf = RuntimeFunction.parse(moduleBaseAddress, reader);

			if (rf.startOfFunction.compareTo(instructionPtr) > 0)
				continue;
			if (rf.endOfFunction.compareTo(instructionPtr) < 0)
				continue;
			
			return rf;
		}
		
		return null;
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