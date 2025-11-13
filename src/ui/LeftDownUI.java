package ui;

import burp.BurpExtender;
import burp.IMessageEditor;
import burp.IContextMenuInvocation;
import burp.IContextMenuFactory;


import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

public class LeftDownUI extends JPanel {
    private static IMessageEditor leftEditor;
    private static IMessageEditor rightEditor;


    public LeftDownUI() {
        setLayout(new BorderLayout());

        JPanel leftPanel = new JPanel(new BorderLayout());
        JPanel rightPanel = new JPanel(new BorderLayout());

        JLabel leftTopLabel = new JLabel("Request");
        leftTopLabel.setForeground(new Color(255, 140, 0));
        Font font = new Font("SansSerif", Font.BOLD, 14);
        leftTopLabel.setFont(font);
        leftPanel.add(leftTopLabel, BorderLayout.NORTH);
        JLabel rightTopLabel = new JLabel("Response");
        rightTopLabel.setForeground(new Color(255, 140, 0));
        rightTopLabel.setFont(font);
        rightPanel.add(rightTopLabel, BorderLayout.NORTH);
        JSplitPane lowerPanel = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);
        lowerPanel.setResizeWeight(0.5);
        lowerPanel.setDividerLocation(0.5);
        leftEditor = BurpExtender.createMessageEditor(false);
        leftPanel.add(leftEditor.getComponent(), BorderLayout.CENTER);
        JPanel leftContainerPanel = new JPanel(new BorderLayout());
        leftContainerPanel.setPreferredSize(new Dimension(300, 400));
        leftContainerPanel.add(leftTopLabel, BorderLayout.NORTH);
        leftContainerPanel.add(leftEditor.getComponent(), BorderLayout.CENTER);
        leftPanel.add(Box.createHorizontalStrut(-10), BorderLayout.EAST);
        leftPanel.add(leftContainerPanel, BorderLayout.CENTER);


        rightEditor = BurpExtender.createMessageEditor(false);
        rightPanel.add(rightEditor.getComponent(), BorderLayout.CENTER);
        JPanel rightContainerPanel = new JPanel(new BorderLayout());
        rightContainerPanel.setPreferredSize(new Dimension(300, 400));
        rightContainerPanel.add(rightTopLabel, BorderLayout.NORTH);
        rightContainerPanel.add(rightEditor.getComponent(), BorderLayout.CENTER);
        rightPanel.add(Box.createHorizontalStrut(-15), BorderLayout.EAST);
        rightPanel.add(rightContainerPanel, BorderLayout.CENTER);
        JPanel upperPanel = new JPanel(new BorderLayout());
        upperPanel.add(lowerPanel, BorderLayout.CENTER);
        upperPanel.setBorder(BorderFactory.createEmptyBorder());
        add(upperPanel, BorderLayout.CENTER);
    }


    public static void setEditorMessage(IMessageEditor editor, String message) {
        editor.setMessage(message.getBytes(), false);
    }

    public static IMessageEditor getLeftEditor() {
        return leftEditor;
    }

    public static IMessageEditor getRightEditor() {
        return rightEditor;
    }
}

