package net.jubjubnest.minidump.analyzer;

import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.table.AbstractGTableModel;
import docking.widgets.table.GTable;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotYetImplementedException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import ghidra.util.worker.Job;
import ghidra.util.worker.Worker;

class SymbolLocationDialog extends DialogComponentProvider {
	
	GTable table;
	List<SymbolInfo> allRows;
	List<SymbolInfo> incompleteRows = new ArrayList<>();
	boolean useModulePdbPath;
	
	boolean wasCancelled;
	Worker worker = Worker.createGuiWorker();
	
	static final String[] COLUMN_NAMES = new String[] {
		"Module", "Symbols"
	};

	public SymbolLocationDialog(List<SymbolInfo> symbols, boolean useModulePdbPath) {
		super("Confirm Symbols", true, false, true, true);
		setPreferredSize(600, 300);

		this.useModulePdbPath = useModulePdbPath;
		allRows = symbols;
		for (SymbolInfo info : symbols) {
			if (info.result == null) {
				incompleteRows.add(info);
			}
		}
		
		table = new GTable(new AbstractGTableModel<SymbolInfo>() {

			@Override
			public String getName() {
				return "Symbols";
			}
			
			@Override
			public String getColumnName(int column) {
				return COLUMN_NAMES[column];
			}

			@Override
			public List<SymbolInfo> getModelData() {
				return incompleteRows;
			}

			@Override
			public Object getColumnValueForRow(SymbolInfo row, int columnIndex) {
				switch (columnIndex) {
					case 0:
						return row.module.name;
					case 1:
						if (row.result != null) {
							return row.result.file.getAbsolutePath();
						}
						if (row.message != null) {
							return row.message;
						}
						return "Double-click to specify symbols";
					default:
						throw new NotYetImplementedException();
				}
			}

			@Override
			public int getColumnCount() {
				return 2;
			}
		});
		table.getColumnModel().getColumn(0).setPreferredWidth(75);
		table.getColumnModel().getColumn(1).setPreferredWidth(175);

		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					changeSymbols(table.getSelectedRow());
				}
			}
		});
		
		JLabel label = new JLabel("No symbols were found for the following modules:");
		label.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		JPanel panel = new JPanel(new BorderLayout(10, 10));
		panel.add(label, BorderLayout.NORTH);
		panel.add(new JScrollPane(table));

		this.addWorkPanel(panel);
		this.addOKButton();
		this.addCancelButton();
	}
	
	public void changeSymbols(int idx) {
		SymbolInfo row = this.incompleteRows.get(idx);

		FindSymbolsFileChooser pdbChooser = new FindSymbolsFileChooser(null, row.attributes, useModulePdbPath);
		
		if (useModulePdbPath && row.attributes != null) {
			pdbChooser.setCurrentDirectory(new File(row.attributes.getPdbFile()));
		}

		File pdbFile = pdbChooser.getSelectedFile();
		if (pdbChooser.getValidatedResult() != null) {
			row.result = pdbChooser.getValidatedResult();
			worker.schedule(new TryFindMissingSymbols(pdbChooser.getValidatedRoot()));
			return;
		}
		
		if (pdbFile == null) {
			return;
		}

		executeProgressTask(new Task("Processing PDB") {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				try {
					row.result = PdbResolver.validatePdbCandidate(pdbFile, true, row.attributes, monitor);
				} catch (IOException | PdbException e) {
					row.message = "Error: " + e.getMessage() + " (" + pdbFile.getPath() + ")";
				}
				table.repaint();
			}
		}, 0);
	}
	
	class TryFindMissingSymbols extends Job {
		
		private File root;
		public TryFindMissingSymbols(File root) {
			this.root = root;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			for (SymbolInfo row : incompleteRows) {
				if (row.result != null) {
					continue;
				}

				row.result = PdbResolver.tryFindSymbols(root, row.attributes, monitor);
				table.repaint();
			}
		}
	}
	
	@Override
	protected void cancelCallback() {
		wasCancelled = true;
		super.cancelCallback();
	}
	
	@Override
	protected void okCallback() {
		super.okCallback();
		close();
	}

	public boolean confirm() {
		DockingWindowManager.showDialog(null, this);
		return !wasCancelled;
	}

}
