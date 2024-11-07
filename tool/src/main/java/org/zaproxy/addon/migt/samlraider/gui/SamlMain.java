
package org.zaproxy.addon.migt.samlraider.gui;

import javax.swing.JPanel;
import org.zaproxy.addon.migt.samlraider.application.SamlTabController;

public class SamlMain extends JPanel {

    private static final long serialVersionUID = 1L;
    private transient SamlTabController controller;
    private SamlPanelAction panelAction;
    private SamlPanelInfo panelInformation;

    public SamlPanelAction getActionPanel() {
        return panelAction;
    }

    public SamlPanelInfo getInfoPanel() {
        return panelInformation;
    }
}
