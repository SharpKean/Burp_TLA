package ui;

import burp.BurpExtender;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.sql.*;
import java.util.*;
import java.util.List;

public class MainUI {
    public JPanel root;
    private JTable table;
    private JLabel filePathLabel;
    private RightUI rightPanel;
    private RightDownUI rightDownPanel;

    public MainUI() {
        JPanel jPanelMain = new JPanel(new BorderLayout());
        JPanel leftPanel = new JPanel(new BorderLayout());
        rightPanel = new RightUI();
        JPanel leftDownPanel = new LeftDownUI();
        rightDownPanel = new RightDownUI();

        JSplitPane verticalSplitPane = createSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                createSplitPane(JSplitPane.VERTICAL_SPLIT, leftPanel, leftDownPanel, 0),
                createSplitPane(JSplitPane.VERTICAL_SPLIT, rightPanel, rightDownPanel, 0), 0.65);

        jPanelMain.add(verticalSplitPane, BorderLayout.CENTER);
        root = jPanelMain;

        JPanel upPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        String[] searchFields = {"Remarks", "ID", "Url", "Port", "Method", "Route", "Request", "Response"};
        JComboBox<String> fieldComboBox = new JComboBox<>(searchFields);
        JTextField searchField = new JTextField(30);
        JButton searchButton = new JButton("Search");
        JButton importButton = new JButton("导入路径");
        filePathLabel = new JLabel("请导入数据库db文件");

        upPanel.add(fieldComboBox);
        upPanel.add(searchField);
        upPanel.add(searchButton);
        upPanel.add(importButton);
        upPanel.add(filePathLabel);

        String[] columnNames = {"ID", "Url", "Port", "Method", "Route", "Remarks"};
        DefaultTableModel model = new DefaultTableModel(columnNames, 0);
        table = new JTable(model);
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        JScrollPane scrollPane = new JScrollPane(table);

        leftPanel.add(upPanel, BorderLayout.NORTH);
        leftPanel.add(scrollPane, BorderLayout.CENTER);

        JPopupMenu popupMenu = new JPopupMenu();

        JMenuItem main_sendToRepeaterItem = new JMenuItem("Send to Repeater");
        JMenuItem main_copyUrlItem = new JMenuItem("复制 URL");
        JMenuItem main_deleteItem = new JMenuItem("删除数据");
        popupMenu.add(main_sendToRepeaterItem);
        popupMenu.add(main_copyUrlItem);
        popupMenu.add(main_deleteItem);

        table.setComponentPopupMenu(popupMenu);

        table.getColumnModel().getColumn(0).setPreferredWidth(60);
        table.getColumnModel().getColumn(1).setPreferredWidth(300);
        table.getColumnModel().getColumn(2).setPreferredWidth(80);
        table.getColumnModel().getColumn(3).setPreferredWidth(80);
        table.getColumnModel().getColumn(4).setPreferredWidth(400);
        table.getColumnModel().getColumn(5).setPreferredWidth(500);

        SwingUtilities.invokeLater(() -> {
            Config.createConfigFile();
            String dbFile = Config.getDBFile("db_file");
            String dirFile = Config.getDBFile("dir_file");
            String filterUrl = Config.getDBFile("filter_url");
            String threadNum = Config.getDBFile("thread_num");
            String typeScan = Config.getDBFile("type_scan");
            String xssEnable = Config.getDBFile("xss_enable");

            if (!dbFile.equals("null")) {
                filePathLabel.setText("文件路径：" + dbFile);
                loadDataFromDB(dbFile, "remarks", null);
            }

            if (!dirFile.equals("null")) {
                rightPanel.setPathFieldText(dirFile);
                rightPanel.readTxtFileAndStoreContent(dirFile);
            } else {
                rightPanel.setPathFieldText("请导入txt字典【注：必须为txt文件】");
            }

            if (!filterUrl.equals("null")) {
                rightPanel.setfilterField(filterUrl);
            }
            if (!threadNum.equals("null")) {
                rightPanel.setThreadField(threadNum);
            }
            if (!typeScan.equals("null")) {
                rightPanel.settypeScan(typeScan);
            }
            if (!xssEnable.equals("null")) {
                rightPanel.setXssField(xssEnable);
            }
        });

        searchButton.addActionListener(e -> {
            String searchText = searchField.getText();
            String selectedField = (String) fieldComboBox.getSelectedItem();
            performSearch(searchText, selectedField);
        });

        importButton.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            int result = fc.showOpenDialog(root);
            if (result == JFileChooser.APPROVE_OPTION) {
                File file = fc.getSelectedFile();
                String path = file.getAbsolutePath();
                filePathLabel.setText("文件路径：" + path);
                loadDataFromDB(path, "remarks", null);
                Config.updateConfig(path, null, null, null, null, null);
            }
        });

        main_deleteItem.addActionListener(e -> {
            int[] viewRows = table.getSelectedRows();
            if (viewRows.length == 0) {
                JOptionPane.showMessageDialog(root, "请至少选择一行数据。", "温馨提示", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            DefaultTableModel del_model = (DefaultTableModel) table.getModel();
            List<Integer> idsToDelete = new ArrayList<>();
            List<Integer> modelRowsToDelete = new ArrayList<>();
            for (int viewRow : viewRows) {
                int modelRow = table.convertRowIndexToModel(viewRow);
                modelRowsToDelete.add(modelRow);
                int id = (int) del_model.getValueAt(modelRow, 0);
                idsToDelete.add(id);
            }
            Collections.sort(modelRowsToDelete, Comparator.reverseOrder());
            for (int modelRow : modelRowsToDelete) {
                del_model.removeRow(modelRow);
            }
            for (int id : idsToDelete) {
                deleteDataFromDB(id);
            }
        });

        main_copyUrlItem.addActionListener(e -> {
            int[] selectedRows = table.getSelectedRows();
            StringBuilder sb = new StringBuilder();
            for (int row : selectedRows) {
                Object urlValue = table.getModel().getValueAt(table.convertRowIndexToModel(row), 1);
                if (urlValue != null) {
                    sb.append(urlValue.toString()).append("\n");
                }
            }
            if (sb.length() > 0) {
                StringSelection selection = new StringSelection(sb.toString());
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(selection, null);
            }
        });

        main_sendToRepeaterItem.addActionListener(e -> {
            int[] selectedRows = table.getSelectedRows();
            if (selectedRows.length == 0) {
                JOptionPane.showMessageDialog(root, "请至少选择一行数据。", "提示", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            for (int row : selectedRows) {
                int modelRow = table.convertRowIndexToModel(row);
                int id = (int) model.getValueAt(modelRow, 0);
                String urlStr = (String) model.getValueAt(modelRow, 1);
                String portStr = (String) model.getValueAt(modelRow, 2);
                int port = Integer.parseInt(portStr);

                String sql_request = queryRequestAndResponse(id, 2);

                if (sql_request == null || sql_request.isEmpty()) {
                    JOptionPane.showMessageDialog(root, "（ID: " + id + "）的请求包为空", "温馨提示", JOptionPane.WARNING_MESSAGE);
                    continue;
                }

                byte[] requestBytes;
                try {
                    requestBytes = sql_request.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(root, "请求编码转换失败（ID: " + id + "）", "错误", JOptionPane.ERROR_MESSAGE);
                    ex.printStackTrace();
                    continue;
                }

                String host;
                boolean useHttps = false;

                if (urlStr.startsWith("https://")) {
                    useHttps = true;
                    host = urlStr.substring(8);
                } else if (urlStr.startsWith("http://")) {
                    host = urlStr.substring(7);
                } else {
                    host = urlStr;
                }
                int pathIndex = host.indexOf('/');
                if (pathIndex != -1) {
                    host = host.substring(0, pathIndex);
                }
                int colonIndex = host.indexOf(':');
                if (colonIndex != -1) {
                    host = host.substring(0, colonIndex);
                }

                try {
                    BurpExtender.callbacks.sendToRepeater(
                            host,
                            port,
                            useHttps,
                            requestBytes,
                            "TLA_" + rightDownPanel.repeaterCounter++
                    );
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(root, "发送到 Repeater 失败: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                    ex.printStackTrace();
                }
            }
        });

        model.addTableModelListener(e -> {
            if (e.getType() == TableModelEvent.UPDATE) {
                int row = e.getFirstRow();
                int col = e.getColumn();
                String value = model.getValueAt(row, col).toString();

                int id = Integer.parseInt(model.getValueAt(row, 0).toString());
                String columnName = model.getColumnName(col);

                String dbColumn = mapDisplayToDBColumn(columnName);

                updateDataInDB(id, dbColumn, value);
            }
        });

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = table.getSelectedRow();
                if (selectedRow != -1) {
                    int id = (int) table.getValueAt(selectedRow, 0);
                    queryRequestAndResponse(id, 1);
                }
            }
        });
    }

    private void performSearch(String searchText, String selectedField) {
        String filePath = getFilePath();
        if (filePath == null || filePath.isEmpty()) {
            JOptionPane.showMessageDialog(root, "请先导入数据库文件", "提示", JOptionPane.WARNING_MESSAGE);
            return;
        }

        if ("Request".equals(selectedField) || "Response".equals(selectedField)) {
            String actualColumn = mapDisplayToDBColumn(selectedField);
            loadSpecialFieldFromDB(filePath, actualColumn, searchText);
        } else {
            String actualColumn = mapDisplayToDBColumn(selectedField);
            loadDataFromDB(filePath, actualColumn, searchText);
        }
    }

    public void loadSpecialFieldFromDB(String filePath, String column, String searchText) {
        List<Object[]> dataList = new ArrayList<>();
        try {
            Class.forName("org.sqlite.JDBC");
            String url = "jdbc:sqlite:" + filePath;
            String sql = "SELECT id, url, port, method, route, remarks FROM TLA WHERE " + column + " LIKE ?";

            try (Connection connection = DriverManager.getConnection(url);
                 PreparedStatement statement = connection.prepareStatement(sql)) {

                statement.setString(1, "%" + searchText + "%");

                try (ResultSet rs = statement.executeQuery()) {
                    while (rs.next()) {
                        Object[] row = new Object[6];
                        row[0] = rs.getInt("id");
                        row[1] = rs.getString("url");
                        row[2] = rs.getString("port");
                        row[3] = rs.getString("method");
                        row[4] = rs.getString("route");
                        row[5] = rs.getString("remarks");
                        dataList.add(row);
                    }
                }
            }
            updateTableData(dataList);
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(root, "数据库查询出错：" + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    public void loadDataFromDB(String filePath, String column, String searchText) {
        List<Object[]> dataList = new ArrayList<>();
        try {
            Class.forName("org.sqlite.JDBC");
            String url = "jdbc:sqlite:" + filePath;
            String sql = "SELECT id, url, port, method, route, remarks FROM TLA";

            if (searchText != null && !searchText.isEmpty()) {
                sql += " WHERE " + column + " LIKE ?";
            }

            try (Connection connection = DriverManager.getConnection(url);
                 PreparedStatement statement = connection.prepareStatement(sql)) {

                if (searchText != null && !searchText.isEmpty()) {
                    statement.setString(1, "%" + searchText + "%");
                }

                try (ResultSet rs = statement.executeQuery()) {
                    while (rs.next()) {
                        Object[] row = new Object[6];
                        row[0] = rs.getInt("id");
                        row[1] = rs.getString("url");
                        row[2] = rs.getString("port");
                        row[3] = rs.getString("method");
                        row[4] = rs.getString("route");
                        row[5] = rs.getString("remarks");
                        dataList.add(row);
                    }
                }
            }
            updateTableData(dataList);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void updateTableData(List<Object[]> dataList) {
        DefaultTableModel model = (DefaultTableModel) table.getModel();
        model.setRowCount(0);
        for (Object[] row : dataList) {
            model.addRow(row);
        }

        TableRowSorter<DefaultTableModel> sorter = (TableRowSorter<DefaultTableModel>) table.getRowSorter();
        if (sorter == null) {
            sorter = new TableRowSorter<>(model);
            table.setRowSorter(sorter);
        }

        sorter.setComparator(0, (o1, o2) -> {
            Integer id1 = Integer.parseInt(o1.toString());
            Integer id2 = Integer.parseInt(o2.toString());
            return id1.compareTo(id2);
        });
    }

    public String getFilePath() {
        String text = filePathLabel.getText();
        if (text.startsWith("文件路径：")) {
            return text.replace("文件路径：", "");
        }
        return null;
    }

    public void insertDataToDatabase(String url, int port, String method, String route, String request, String response, String remarks) {
        try {
            Class.forName("org.sqlite.JDBC");
            String jdbcUrl = "jdbc:sqlite:" + getFilePath();
            try (Connection conn = DriverManager.getConnection(jdbcUrl)) {
                String sql = "INSERT INTO TLA (url, port, method, route, request, response, remarks) VALUES (?, ?, ?, ?, ?, ?, ?)";
                PreparedStatement pstmt = conn.prepareStatement(sql);
                pstmt.setString(1, url);
                pstmt.setInt(2, port);
                pstmt.setString(3, method);
                pstmt.setString(4, route);
                pstmt.setString(5, request);
                pstmt.setString(6, response);
                pstmt.setString(7, remarks);
                pstmt.executeUpdate();
                loadDataFromDB(getFilePath(), "remarks", null);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void deleteDataFromDB(int id) {
        try {
            Class.forName("org.sqlite.JDBC");
            String url = "jdbc:sqlite:" + getFilePath();
            try (Connection conn = DriverManager.getConnection(url)) {
                String sql = "DELETE FROM TLA WHERE id = ?";
                PreparedStatement stmt = conn.prepareStatement(sql);
                stmt.setInt(1, id);
                stmt.executeUpdate();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void updateDataInDB(int id, String column, String value) {
        try {
            Class.forName("org.sqlite.JDBC");
            String url = "jdbc:sqlite:" + getFilePath();
            try (Connection conn = DriverManager.getConnection(url)) {
                String sql = "UPDATE TLA SET " + column + " = ? WHERE id = ?";
                PreparedStatement stmt = conn.prepareStatement(sql);
                stmt.setString(1, value);
                stmt.setInt(2, id);
                stmt.executeUpdate();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String queryRequestAndResponse(int id, int type_mode) {
        try {
            Class.forName("org.sqlite.JDBC");
            String filePath = getFilePath();
            String url = "jdbc:sqlite:" + filePath;
            try (Connection connection = DriverManager.getConnection(url)) {
                String sql = "SELECT request, response FROM TLA WHERE id = ?";
                PreparedStatement stmt = connection.prepareStatement(sql);
                stmt.setInt(1, id);
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    String req = rs.getString("request");
                    String res = rs.getString("response");
                    if (type_mode == 1) {
                        SwingUtilities.invokeLater(() -> {
                            LeftDownUI.setEditorMessage(LeftDownUI.getLeftEditor(), req);
                            LeftDownUI.setEditorMessage(LeftDownUI.getRightEditor(), res);
                        });
                    } else if (type_mode == 2) {
                        return req;
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private String mapDisplayToDBColumn(String displayColumn) {
        switch (displayColumn) {
            case "ID": return "id";
            case "Url": return "url";
            case "Port": return "port";
            case "Method": return "method";
            case "Route": return "route";
            case "Request": return "request";
            case "Response": return "response";
            default: return "remarks";
        }
    }

    private JSplitPane createSplitPane(int orientation, JComponent left, JComponent right, double resizeWeight) {
        JSplitPane sp = new JSplitPane(orientation, left, right);
        sp.setResizeWeight(resizeWeight);
        return sp;
    }

    public RightUI getRightPanel() {
        return rightPanel;
    }

    public RightDownUI getRightDownPanel() {
        return rightDownPanel;
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("MainUI");
            MainUI mainUI = new MainUI();
            frame.setContentPane(mainUI.root);
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setSize(1200, 800);
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
        });
    }
}