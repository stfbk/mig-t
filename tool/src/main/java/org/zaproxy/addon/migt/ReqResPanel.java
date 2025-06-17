package org.zaproxy.addon.migt;

import java.awt.*;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import org.parosproxy.paros.network.HttpMalformedHeaderException;

public class ReqResPanel extends JPanel {
    private final JTextPane textPane;
    private static final int MAX_LINE_LENGTH = 100;
    private boolean isHexView = false;
    private HTTPReqRes displayedMsg;
    public JButton toggleButton;

    public ReqResPanel() {
        this.setName("ReqResPanel");
        this.setLayout(new BorderLayout());

        textPane = new JTextPane();
        textPane.setEditable(false);
        textPane.setContentType("text/html");
        textPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, true);
        textPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        textPane.setBackground(Color.WHITE);

        JScrollPane scrollPane = new JScrollPane(
                textPane,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        toggleButton = new JButton("MSG > HEX");
        toggleButton.addActionListener(e -> toggleView());

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(toggleButton);

        this.add(scrollPane, BorderLayout.CENTER);
        this.add(buttonPanel, BorderLayout.SOUTH);
    }

    public void setMessage(HTTPReqRes message, boolean isRequest) throws HttpMalformedHeaderException {
        isHexView = true;
        displayedMsg = message;
        toggleView();
    }

    private String wrapText(String text, int maxLineLength) {
        if (text == null) return "";
        StringBuilder wrappedText = new StringBuilder();
        String[] lines = text.split("\r?\n");

        for (String line : lines) {
            while (line.length() > maxLineLength) {
                wrappedText.append(line, 0, maxLineLength).append("\n");
                line = line.substring(maxLineLength);
            }
            wrappedText.append(line).append("\n");
        }

        return wrappedText.toString();
    }


    private String highlightKeywords(String text) {
        String[] keywords = {"Host", "User-Agent", "Accept", "Connection", "Upgrade-Insecure-Requests", "Priority", "Accept-Language",
                "Date",
                "Server",
                "Content-Type",
                "Location", "X-Frame-Options",
                "Content-Length",
                "X-Content-Type-Options",
                "Referrer-Policy", "Vary",
                "Cross-Origin-Opener-Policy"};

        for (String keyword : keywords) {
            text = text.replaceAll("(?m)^(" + keyword + "):", "<span style='color:red; font-weight:bold;'>$1:</span>");
        }

        return text;
    }

    private void toggleView() {
        isHexView = !isHexView;
        SwingUtilities.invokeLater(() -> {
            StringBuilder sb = new StringBuilder("<html><body style='font-family:monospace;'>");

            // Request
            sb.append("<b>Request:</b><br><pre>");
            sb.append(isHexView
                    ? wrapHexText(convertToHex(displayedMsg.Req_header), 100)
                    : highlightKeywords(wrapText(displayedMsg.Req_header, MAX_LINE_LENGTH)));
            if (displayedMsg.Req_body != null) {
                sb.append(isHexView
                        ? wrapHexText(convertToHex(displayedMsg.Req_body), 100)
                        : wrapText(displayedMsg.Req_body, MAX_LINE_LENGTH));
            }
            sb.append("</pre><br>");

            // Response Section
            sb.append("<b>Response:</b><br><pre>");
            sb.append(isHexView
                    ? wrapHexText(convertToHex(displayedMsg.Res_header), 100)
                    : highlightKeywords(wrapText(displayedMsg.Res_header, MAX_LINE_LENGTH)));
            if (displayedMsg.Res_body != null) {
                sb.append(isHexView
                        ? wrapHexText(convertToHex(displayedMsg.Res_body), 100)
                        : wrapText(displayedMsg.Res_body, MAX_LINE_LENGTH));
            }
            sb.append("</pre>");

            sb.append("</body></html>");
            textPane.setText(sb.toString());
            textPane.setCaretPosition(0);
            toggleButton.setText(isHexView ? "HEX > MSG" : "MSG > HEX");
        });
    }


    private String wrapHexText(String hexText, int maxLineLength) {
        StringBuilder wrappedText = new StringBuilder();
        int currentLineLength = 0;

        String[] hexBytes = hexText.split(" ");

        for (String hexByte : hexBytes) {
            int byteLength = hexByte.length() + 1;
            if (currentLineLength + byteLength > maxLineLength) {
                wrappedText.append("\n");
                currentLineLength = 0;
            }
            wrappedText.append(hexByte).append(" ");
            currentLineLength += byteLength;
        }

        return wrappedText.toString();
    }

    private String convertToHex(String text) {
        StringBuilder hexText = new StringBuilder();
        for (char c : text.toCharArray()) {
            hexText.append(String.format("%02X ", (int) c));
        }
        return hexText.toString();
    }
}
