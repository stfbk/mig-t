
package org.zaproxy.addon.migt.samlraider.gui;

import java.util.List;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import org.zaproxy.addon.migt.samlraider.application.SamlTabController;
import org.zaproxy.addon.migt.samlraider.model.BurpCertificate;

public class SamlPanelAction extends JPanel {

    private static final long serialVersionUID = 1L;
    private transient SamlTabController controller;
    private JLabel lblMessage;
    private JComboBox<BurpCertificate> cmbboxCertificate;
    private JComboBox<String> cmbboxXSW;
    private JButton btnXSWHelp;
    private JButton btnXSWPreview;
    private JButton btnSignatureReset;
    private JButton btnXSWApply;
    private JButton btnMatchAndReplace;
    private JButton btnTestXXE;
    private JButton btnTestXSLT;
    private JButton btnSignatureHelp;
    private JButton btnSignatureRemove;
    private JButton btnSignatureReplace;
    private JButton btnSendCertificate;
    private JButton btnSignatureAdd;
    private JTextField txtSearch;
    private JCheckBox chkRawMode;

    public JLabel getInfoMessageLabel() {
        return lblMessage;
    }

    public void setCertificateList(List<BurpCertificate> list) {
        DefaultComboBoxModel<BurpCertificate> model = new DefaultComboBoxModel<BurpCertificate>();

        for (BurpCertificate cert : list) {
            model.addElement(cert);
        }
        cmbboxCertificate.setModel(model);
    }

    public BurpCertificate getSelectedCertificate() {
        return (BurpCertificate) cmbboxCertificate.getSelectedItem();
    }

    public void setXSWList(String[] xswTypes) {
        DefaultComboBoxModel<String> model = new DefaultComboBoxModel<String>(xswTypes);
        cmbboxXSW.setModel(model);
    }

    public String getSelectedXSW() {
        return (String) cmbboxXSW.getSelectedItem();
    }

    public String getSearchText() {
        return txtSearch.getText();
    }

    public boolean isRawModeEnabled() {
        return chkRawMode.isSelected();
    }

    public void setRawModeEnabled(boolean rawModeEnabled) {
        chkRawMode.setSelected(rawModeEnabled);
    }

    public void disableControls() {
        cmbboxCertificate.setEnabled(false);
        cmbboxXSW.setEnabled(false);
        btnXSWHelp.setEnabled(false);
        btnXSWPreview.setEnabled(false);
        btnSignatureReset.setEnabled(false);
        btnXSWApply.setEnabled(false);
        btnSignatureHelp.setEnabled(false);
        btnSignatureRemove.setEnabled(false);
        btnSignatureReplace.setEnabled(false);
        btnSendCertificate.setEnabled(false);
        btnSignatureAdd.setEnabled(false);
        btnMatchAndReplace.setEnabled(false);
        btnTestXXE.setEnabled(false);
        btnTestXSLT.setEnabled(false);
        chkRawMode.setEnabled(false);
        this.revalidate();
    }

    public void enableControls() {
        cmbboxCertificate.setEnabled(true);
        cmbboxXSW.setEnabled(true);
        btnXSWHelp.setEnabled(true);
        btnXSWPreview.setEnabled(true);
        btnSignatureReset.setEnabled(true);
        btnXSWApply.setEnabled(true);
        btnSignatureHelp.setEnabled(true);
        btnSignatureRemove.setEnabled(true);
        btnSignatureReplace.setEnabled(true);
        btnSendCertificate.setEnabled(true);
        btnSignatureAdd.setEnabled(true);
        btnMatchAndReplace.setEnabled(true);
        btnTestXXE.setEnabled(true);
        btnTestXSLT.setEnabled(true);
        chkRawMode.setEnabled(true);
        this.revalidate();
    }
}
