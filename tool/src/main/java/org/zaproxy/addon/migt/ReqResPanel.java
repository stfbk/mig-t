package org.zaproxy.addon.migt;

import java.awt.*;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import org.parosproxy.paros.network.HttpMalformedHeaderException;

public class ReqResPanel extends JPanel {
    private final JTextPane textPane;
    private static final int MAX_LINE_LENGTH = 500;
    private boolean isHexView = false; // Stato per alternare la vista
    private HTTPReqRes displayedMsg;
    public JButton toggleButton;

    public ReqResPanel() {
        this.setName("ReqResPanel");
        this.setLayout(new BorderLayout());

        // Creazione del JTextPane per la visualizzazione del messaggio
        textPane = new JTextPane();
        textPane.setEditable(false);
        textPane.setContentType("text/html");
        textPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, true);
        textPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        textPane.setBackground(Color.WHITE); // Imposta il background bianco

        JScrollPane scrollPane = new JScrollPane(
                textPane,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        // Pulsante per alternare la vista tra normale e esadecimale
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
        int start = 0;
        while (start < text.length()) {
            int end = Math.min(start + maxLineLength, text.length());
            wrappedText.append(text, start, end).append("\n");
            start = end;
        }
        return wrappedText.toString();
    }

    private String highlightKeywords(String text) {
        // Parole chiave da evidenziare in rosso
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

            // Visualizzazione dei dati in base alla richiesta o risposta
            if (displayedMsg.isRequest) {
                sb.append("<b>Request Header:</b><br><pre>");
                // Se la visualizzazione è in esadecimale, converte l'header in esadecimale
                sb.append(isHexView ? wrapHexText(convertToHex(displayedMsg.Req_header), 100) : highlightKeywords(wrapText(displayedMsg.Req_header, MAX_LINE_LENGTH)));
                sb.append("</pre>");

                if (displayedMsg.Req_body != null) {
                    sb.append("<br><b>Request Body:</b><br><pre>");
                    sb.append(isHexView ? wrapHexText(convertToHex(displayedMsg.Req_body), 100) : wrapText(displayedMsg.Req_body, MAX_LINE_LENGTH));
                    sb.append("</pre>");
                }
            } else {
                sb.append("<b>Response Header:</b><br><pre>");
                // Se la visualizzazione è in esadecimale, converte l'header in esadecimale
                sb.append(isHexView ? wrapHexText(convertToHex(displayedMsg.Res_header), 100) : highlightKeywords(wrapText(displayedMsg.Res_header, MAX_LINE_LENGTH)));
                sb.append("</pre>");

                if (displayedMsg.Res_body != null) {
                    sb.append("<br><b>Response Body:</b><br><pre>");
                    sb.append(isHexView ? wrapHexText(convertToHex(displayedMsg.Res_body), 100) : wrapText(displayedMsg.Res_body, MAX_LINE_LENGTH));
                    sb.append("</pre>");
                }
            }

            sb.append("</body></html>");
            textPane.setText(sb.toString());
            textPane.setCaretPosition(0);

            // Cambia il testo del pulsante in base allo stato
            toggleButton.setText(isHexView ? "HEX > MSG" : "MSG > HEX");
        });
    }

    private String wrapHexText(String hexText, int maxLineLength) {
        StringBuilder wrappedText = new StringBuilder();
        int currentLineLength = 0;

        // Separiamo i byte esadecimali
        String[] hexBytes = hexText.split(" ");

        for (String hexByte : hexBytes) {
            int byteLength = hexByte.length() + 1; // +1 per lo spazio
            // Se aggiungiamo questo byte e spazio superiamo la lunghezza della riga
            if (currentLineLength + byteLength > maxLineLength) {
                // Aggiungi un ritorno a capo e resetta la lunghezza della riga
                wrappedText.append("\n");
                currentLineLength = 0;
            }

            // Aggiungi il byte esadecimale e uno spazio
            wrappedText.append(hexByte).append(" ");
            currentLineLength += byteLength; // Aumenta la lunghezza della riga
        }

        return wrappedText.toString();
    }

    // Metodo per convertire il testo in esadecimale
    private String convertToHex(String text) {
        StringBuilder hexText = new StringBuilder();
        for (char c : text.toCharArray()) {
            hexText.append(String.format("%02X ", (int) c));
        }
        return hexText.toString();
    }
}
