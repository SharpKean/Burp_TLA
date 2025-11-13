package ui;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URL;

import burp.BurpExtender; // 确保 BurpExtender 存在

public class RightDownUI extends JPanel {
    private JTable resultTable, bugResultTable;
    private DefaultTableModel resultTableModel, bugResultTableModel;
    private JPanel resultPanel, bugResultPanel;
    private JPopupMenu popupMenuForScan, popupMenuForBug;
    public static int repeaterCounter = 1;

    public RightDownUI() {
        setLayout(new BorderLayout());
        resultPanel = new JPanel(new BorderLayout());
        bugResultPanel = new JPanel(new BorderLayout());

        resultTableModel = new DefaultTableModel(new Object[]{"URL", "Status", "Length"}, 0);
        resultTable = new JTable(resultTableModel);
        TableColumnModel scanColumnModel = resultTable.getColumnModel();
        scanColumnModel.getColumn(0).setPreferredWidth(500); // URL
        scanColumnModel.getColumn(1).setPreferredWidth(50);  // Status
        scanColumnModel.getColumn(2).setPreferredWidth(50);  // Length

        TableRowSorter<DefaultTableModel> scanSorter = new TableRowSorter<>(resultTableModel);
        resultTable.setRowSorter(scanSorter);
        popupMenuForScan = createScanPopupMenu();
        resultTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    popupMenuForScan.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        JScrollPane scanScrollPane = new JScrollPane(resultTable);
        resultPanel.add(scanScrollPane, BorderLayout.CENTER);
        bugResultTableModel = new DefaultTableModel(
                new Object[]{"Bug", "Parameter", "URL", "Method", "Status", "Length", "RequestBytes"}, 0
        );
        bugResultTable = new JTable(bugResultTableModel);
        TableColumnModel bugColumnModel = bugResultTable.getColumnModel();
        bugColumnModel.getColumn(0).setPreferredWidth(100);
        bugColumnModel.getColumn(1).setPreferredWidth(100);
        bugColumnModel.getColumn(2).setPreferredWidth(300);
        bugColumnModel.getColumn(3).setPreferredWidth(60);
        bugColumnModel.getColumn(4).setPreferredWidth(50);
        bugColumnModel.getColumn(5).setPreferredWidth(50);
        bugColumnModel.getColumn(6).setMinWidth(0); 
        bugColumnModel.getColumn(6).setMaxWidth(0);
        bugColumnModel.getColumn(6).setWidth(0);

        TableRowSorter<DefaultTableModel> bugSorter = new TableRowSorter<>(bugResultTableModel);
        bugResultTable.setRowSorter(bugSorter);

        popupMenuForBug = createBugPopupMenu();
        bugResultTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    popupMenuForBug.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
        JScrollPane bugScrollPane = new JScrollPane(bugResultTable);
        bugResultPanel.add(bugScrollPane, BorderLayout.CENTER);
        JButton resultBtn = new JButton("目录扫描汇总");
        JButton bugResultBtn = new JButton("综合检测汇总");
        resultBtn.setBorderPainted(false);
        bugResultBtn.setBorderPainted(false);
        resultBtn.addActionListener(e -> switchToScanResult());
        bugResultBtn.addActionListener(e -> switchToBugResult());
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        topPanel.add(resultBtn);
        topPanel.add(bugResultBtn);
        add(topPanel, BorderLayout.NORTH);
        add(bugResultPanel, BorderLayout.CENTER);
        bugResultBtn.setBackground(new Color(240, 240, 240));
        add(resultPanel, BorderLayout.CENTER);
        add(bugResultPanel, BorderLayout.CENTER);
        remove(resultPanel); // 初始隐藏漏扫结果面板
    }
    private JPopupMenu createBugPopupMenu() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem sendToRepeaterItem = new JMenuItem("Send to Repeater");
        sendToRepeaterItem.addActionListener(e -> {
            int[] selectedRows = bugResultTable.getSelectedRows();
            for (int i = 0; i < selectedRows.length; i++) {
                int modelRow = bugResultTable.convertRowIndexToModel(selectedRows[i]);
                try {
                    byte[] request = (byte[]) bugResultTableModel.getValueAt(modelRow, 6);
                    String urlStr = (String) bugResultTableModel.getValueAt(modelRow, 2);

                    URL url = new URL(urlStr);
                    String host = url.getHost();
                    int port = url.getPort() != -1 ? url.getPort() : ("https".equals(url.getProtocol()) ? 443 : 80);
                    boolean useHttps = "https".equals(url.getProtocol());
                    BurpExtender.callbacks.sendToRepeater(
                            host,
                            port,
                            useHttps,
                            request,
                            "TLA_" + (repeaterCounter++)
                    );
                } catch (Exception ex) {
                }
            }
        });

        JMenuItem copyUrlItem = new JMenuItem("复制 URL");
        copyUrlItem.addActionListener(e -> {
            int[] selectedRows = bugResultTable.getSelectedRows();
            StringBuilder sb = new StringBuilder();
            for (int row : selectedRows) {
                Object urlValue = bugResultTableModel.getValueAt(bugResultTable.convertRowIndexToModel(row), 2);
                if (urlValue != 1) {
                    sb.append(urlValue.toString()).append("\n");
                }
            }
            if (sb.length() > 1) {
                StringSelection selection = new StringSelection(sb.toString());
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(selection, null);
            }
        });

        JMenuItem deleteSelectedItem = new JMenuItem("删除数据");
        deleteSelectedItem.addActionListener(e -> {
            int[] selectedRows = bugResultTable.getSelectedRows();
            for (int i = selectedRows.length - 1; i >= 0; i--) {
                int modelRow = bugResultTable.convertRowIndexToModel(selectedRows[i]);
                bugResultTableModel.removeRow(modelRow);
            }
        });

        menu.add(sendToRepeaterItem);
        menu.add(copyUrlItem);
        menu.add(deleteSelectedItem);

        return menu;
    }

    private void switchToScanResult() {
        remove(bugResultPanel);
        add(resultPanel, BorderLayout.CENTER);
        revalidate();
        repaint();
        JButton[] buttons = getComponentsInTopPanel();
        buttons[2].setBackground(new Color(240, 240, 240));
        buttons[1].setBackground(null);
    }
    private void switchToBugResult() {
        remove(resultPanel);
        add(bugResultPanel, BorderLayout.CENTER);
        revalidate();
        repaint();
        JButton[] buttons = getComponentsInTopPanel();
        buttons[1].setBackground(new Color(240, 240, 240));
        buttons[0].setBackground(null);
    }
    private JButton[] getComponentsInTopPanel() {
        JPanel topPanel = (JPanel) getComponent(0);
        Component[] components = topPanel.getComponents();
        JButton[] buttons = new JButton[2];
        for (int i = 0; i < components.length; i++) {
            if (components[i] instanceof JButton) {
                buttons[i] = (JButton) components[i];
            }
        }
        return buttons;
    }
    private JPopupMenu createScanPopupMenu() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem copyItem = new JMenuItem("复制 URL");
        copyItem.addActionListener(e -> {
            int[] rows = resultTable.getSelectedRows();
            StringBuilder sb = new StringBuilder();
            for (int row : rows) {
                sb.append(resultTable.getValueAt(row, 0)).append("\n");
            }
            StringSelection selection = new StringSelection(sb.toString());
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selection, null);
        });

        JMenuItem deleteItem = new JMenuItem("删除数据");
        deleteItem.addActionListener(e -> {
            int[] selectedRows = resultTable.getSelectedRows();
            for (int i = selectedRows.length - 1; i >= 0; i--) {
                resultTableModel.removeRow(selectedRows[i]);
            }
        });

        menu.add(copyItem);
        menu.add(deleteItem);
        return menu;
    }
    public void addResult(String url, String status, int length) {
        resultTableModel.addRow(new Object[]{url, status, length});
    }
    public void addBugResult(String bug, String parameter, String url, String method, String status, int length, byte[] request) {
        bugResultTableModel.addRow(new Object[]{bug, parameter, url, method, status, length, request});
    }
}