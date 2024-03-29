/*
 * https://github.com/CompassSecurity/SAMLRaider
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Roland Bischofberger and Emanuel Duss
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package samlraider.gui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

public class XSWHelpWindow extends JFrame {

    private static final long serialVersionUID = 1L;
    private final JPanel contentPane;

    public XSWHelpWindow() {
        setTitle("XML Signature Wrapping Help");
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setBounds(100, 100, 600, 400);
        setMinimumSize(new Dimension(600, 400));
        contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        setContentPane(contentPane);
        contentPane.setLayout(new BorderLayout(0, 0));

        JLabel lblDescription = new JLabel("<html>With xml wrapping attacks you try to trick the xml signature validator into validating an "
                + "signature of an element while evaluating an other element. The XSWs in the image are supported." + "<br/>The blue element represents the signature."
                + "<br/>The green one represents the original element, which is correctly signed. "
                + "<br/>The red one represents the falsly evaluated element, if the validating is not correctly implemented."
                + "<br/>Mind that the first two XSWs can be used for signed responses only whereas the other ones can be used for signed assertions only."
                + "<br/> These XSW are taken from this paper: <br/> Somorovsky, Juraj, et al. \"On Breaking SAML: Be Whoever You Want to Be.\" USENIX Security Symposium. 2012."
                + "<br/> Please check out this paper for further information." + "</html>");
        contentPane.add(lblDescription, BorderLayout.NORTH);

        JScrollPane scrollPane = new JScrollPane();
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
        contentPane.add(scrollPane, BorderLayout.CENTER);

        ImagePanel panel;
        String className = getClass().getName().replace('.', '/');
        String classJar = getClass().getResource("/" + className + ".class").toString();
        if (classJar.startsWith("jar:")) {
            panel = new ImagePanel("xswlist.png");
        } else {
            panel = new ImagePanel("src/main/resources/xswlist.png");
        }

        scrollPane.setViewportView(panel);
    }
}
