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

import samlraider.application.SamlTabController;
import burp.ITextEditor;

import javax.swing.*;
import java.awt.*;

public class SamlMain extends javax.swing.JPanel {

    private static final long serialVersionUID = 1L;
    private ITextEditor textEditorAction;
    private ITextEditor textEditorInformation;
    private SamlTabController controller;
    private SamlPanelAction panelAction;
    private SamlPanelInfo panelInformation;

    public SamlMain() {
        super();
        initializeUI();
    }

    public SamlMain(SamlTabController controller) {
        super();
        this.controller = controller;
        initializeUI();
    }

    private void initializeUI() {
        setLayout(new BorderLayout(0, 0));

        JSplitPane splitPaneAction = new JSplitPane();
        splitPaneAction.setOrientation(JSplitPane.VERTICAL_SPLIT);
        splitPaneAction.setDividerSize(5);
        add(splitPaneAction, BorderLayout.CENTER);

        JPanel panelActionTop = new JPanel();
        splitPaneAction.setLeftComponent(panelActionTop);
        panelActionTop.setLayout(new BorderLayout(0, 0));
        panelAction = new SamlPanelAction(controller);
        panelActionTop.add(panelAction);

        JPanel panelActionBottom = new JPanel();
        splitPaneAction.setRightComponent(panelActionBottom);
        panelActionBottom.setLayout(new BorderLayout(0, 0));
        textEditorAction = controller.getCallbacks().createTextEditor();
        textEditorAction.setText("<SAMLRaiderFailureInInitialization></SAMLRaiderFailureInInitialization>".getBytes());
        panelActionBottom.add(textEditorAction.getComponent(), BorderLayout.CENTER);

        JSplitPane splitPaneInformation = new JSplitPane();
        splitPaneInformation.setOrientation(JSplitPane.VERTICAL_SPLIT);
        splitPaneAction.setDividerSize(5);
        add(splitPaneInformation, BorderLayout.CENTER);

        JPanel panelInformationTop = new JPanel();
        splitPaneInformation.setLeftComponent((panelInformationTop));
        panelInformationTop.setLayout(new BorderLayout(0, 0));
        panelInformation = new SamlPanelInfo();
        panelInformationTop.add(panelInformation);

        JPanel panelInformationBottom = new JPanel();
        splitPaneInformation.setRightComponent(panelInformationBottom);
        panelInformationBottom.setLayout(new BorderLayout(0, 0));
        textEditorInformation = controller.getCallbacks().createTextEditor();
        textEditorInformation.setText("".getBytes());
        textEditorAction.setEditable(false);
        panelInformationBottom.add(textEditorInformation.getComponent(), BorderLayout.CENTER);

        JTabbedPane tabbedPane = new JTabbedPane();
        add(tabbedPane);
        tabbedPane.addTab("SAML Attacks", null, splitPaneAction, "SAML Attacks");
        tabbedPane.addTab("SAML Message Info", null, splitPaneInformation, "SAML Message Info");

        this.invalidate();
        this.updateUI();
    }

    public ITextEditor getTextEditorAction() {
        return textEditorAction;
    }

    public ITextEditor getTextEditorInformation() {
        return textEditorInformation;
    }

    public SamlPanelAction getActionPanel() {
        return panelAction;
    }

    public SamlPanelInfo getInfoPanel() {
        return panelInformation;
    }

}
