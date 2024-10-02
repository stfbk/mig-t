/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.migt.samlraider.gui;

import javax.swing.JPanel;
import org.zaproxy.addon.migt.samlraider.application.SamlTabController;

public class SamlMain extends JPanel {

    private static final long serialVersionUID = 1L;
    //  private ITextEditor textEditorAction;
    //  private ITextEditor textEditorInformation;
    private transient SamlTabController controller;
    private SamlPanelAction panelAction;
    private SamlPanelInfo panelInformation;

    //    public SamlMain() {
    //        super();
    //        initializeUI();
    //    }
    //
    //    public SamlMain(SamlTabController controller) {
    //        super();
    //        this.controller = controller;
    //        initializeUI();
    //    }
    //
    //    private void initializeUI() {
    //        setLayout(new BorderLayout(0, 0));
    //
    //        JSplitPane splitPaneAction = new JSplitPane();
    //        splitPaneAction.setOrientation(JSplitPane.VERTICAL_SPLIT);
    //        splitPaneAction.setDividerSize(5);
    //        add(splitPaneAction, BorderLayout.CENTER);
    //
    //        JPanel panelActionTop = new JPanel();
    //        splitPaneAction.setLeftComponent(panelActionTop);
    //        panelActionTop.setLayout(new BorderLayout(0, 0));
    //        panelAction = new SamlPanelAction(controller);
    //        panelActionTop.add(panelAction);
    //
    //        JPanel panelActionBottom = new JPanel();
    //        splitPaneAction.setRightComponent(panelActionBottom);
    //        panelActionBottom.setLayout(new BorderLayout(0, 0));
    //        textEditorAction = controller.getCallbacks().createTextEditor();
    //
    // textEditorAction.setText("<SAMLRaiderFailureInInitialization></SAMLRaiderFailureInInitialization>".getBytes());
    //        panelActionBottom.add(textEditorAction.getComponent(), BorderLayout.CENTER);
    //
    //        JSplitPane splitPaneInformation = new JSplitPane();
    //        splitPaneInformation.setOrientation(JSplitPane.VERTICAL_SPLIT);
    //        splitPaneAction.setDividerSize(5);
    //        add(splitPaneInformation, BorderLayout.CENTER);
    //
    //        JPanel panelInformationTop = new JPanel();
    //        splitPaneInformation.setLeftComponent((panelInformationTop));
    //        panelInformationTop.setLayout(new BorderLayout(0, 0));
    //        panelInformation = new SamlPanelInfo();
    //        panelInformationTop.add(panelInformation);
    //
    //        JPanel panelInformationBottom = new JPanel();
    //        splitPaneInformation.setRightComponent(panelInformationBottom);
    //        panelInformationBottom.setLayout(new BorderLayout(0, 0));
    //        textEditorInformation = controller.getCallbacks().createTextEditor();
    //        textEditorInformation.setText("".getBytes());
    //        textEditorAction.setEditable(false);
    //        panelInformationBottom.add(textEditorInformation.getComponent(), BorderLayout.CENTER);
    //
    //        JTabbedPane tabbedPane = new JTabbedPane();
    //        add(tabbedPane);
    //        tabbedPane.addTab("SAML Attacks", null, splitPaneAction, "SAML Attacks");
    //        tabbedPane.addTab("SAML Message Info", null, splitPaneInformation, "SAML Message
    // Info");
    //
    //        this.invalidate();
    //        this.updateUI();
    //    }
    //
    //    public ITextEditor getTextEditorAction() {
    //        return textEditorAction;
    //    }
    //
    //    public ITextEditor getTextEditorInformation() {
    //        return textEditorInformation;
    //    }

    public SamlPanelAction getActionPanel() {
        return panelAction;
    }

    public SamlPanelInfo getInfoPanel() {
        return panelInformation;
    }
}
