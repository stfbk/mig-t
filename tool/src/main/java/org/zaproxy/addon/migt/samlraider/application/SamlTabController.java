package org.zaproxy.addon.migt.samlraider.application;

import java.io.IOException;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import org.zaproxy.addon.migt.samlraider.helpers.XMLHelpers;
import org.zaproxy.addon.migt.samlraider.model.BurpCertificate;

public class SamlTabController {

    private static final String XML_CERTIFICATE_NOT_FOUND = "X509 Certificate not found";
    private static final String XSW_ATTACK_APPLIED = "XSW Attack applied";
    private static final String XXE_CONTENT_APPLIED = "XXE content applied";
    private static final String XML_NOT_SUITABLE_FOR_XXE =
            "This XML Message is not suitable for this particular XXE attack";
    private static final String XSLT_CONTENT_APPLIED = "XSLT content applied";
    private static final String XML_NOT_SUITABLE_FOR_XLST =
            "This XML Message is not suitable for this particular XLST attack";
    private static final String XML_COULD_NOT_SIGN = "Could not sign XML";
    private static final String XML_COULD_NOT_SERIALIZE = "Could not serialize XML";
    private static final String XML_NOT_WELL_FORMED =
            "XML isn't well formed or binding is not supported";
    private static final String XML_NOT_SUITABLE_FOR_XSW =
            "This XML Message is not suitable for this particular XSW, is there a signature?";
    private static final String NO_BROWSER =
            "Could not open diff in Browser. Path to file was copied to clipboard";
    private static final String NO_DIFF_TEMP_FILE = "Could not create diff temp file.";

    public static String removeSignature_edit(String input) {
        XMLHelpers xmlHelpers = new XMLHelpers();
        String res = "";
        try {
            Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(input);

            int sign = xmlHelpers.removeAllSignatures(document);
            if (sign > 0) {

                res = xmlHelpers.getStringOfDocument(document, 2, true);
            } else {
                // setInfoMessageText("No Signatures available to remove");
            }

        } catch (SAXException e1) {
            e1.printStackTrace();
            // setInfoMessageText(XML_NOT_WELL_FORMED);
        } catch (IOException e) {
            e.printStackTrace();
            // setInfoMessageText(XML_COULD_NOT_SERIALIZE);
        }
        return res;
    }

    public static String resignAssertion_edit(String input, String input_cert) {
        XMLHelpers xmlHelpers = new XMLHelpers();
        try {
            BurpCertificate original_cert =
                    CertificateTabController.importCertificateFromString_edit(input_cert);

            BurpCertificate cert =
                    CertificateTabController.cloneAndSignCertificate_edit(original_cert);

            if (cert != null) {
                Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(input);
                NodeList assertions = xmlHelpers.getAssertions(document);
                String signAlgorithm = xmlHelpers.getSignatureAlgorithm(assertions.item(0));
                String digestAlgorithm = xmlHelpers.getDigestAlgorithm(assertions.item(0));

                xmlHelpers.removeAllSignatures(document);
                String string = xmlHelpers.getString(document);
                Document doc = xmlHelpers.getXMLDocumentOfSAMLMessage(string);
                xmlHelpers.removeEmptyTags(doc);
                xmlHelpers.signAssertion(
                        doc,
                        signAlgorithm,
                        digestAlgorithm,
                        cert.getCertificate(),
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
}
