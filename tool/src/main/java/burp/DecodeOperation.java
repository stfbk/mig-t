package burp;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import samlraider.application.SamlTabController;
import samlraider.helpers.XMLHelpers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import static burp.Utils.getVariableByName;

/**
 * This class stores a decode operation
 */
public class DecodeOperation extends Module {
    String decoded_content; // the decoded content
    String decode_target; // aka decode_param how to decode the raw content
    Utils.MessageSection from; // where the raw content is
    List<Utils.Encoding> encodings; // the list of encoding to decode and rencode
    // TODO: change this to DecodeOperationType, and riassign it from the parser
    Utils.DecodeOpType type; // the type of the decoded param
    API api;

    String save_as; // TODO add in parsing
    String use; //TODO add in parsing

    // TODO: move this variables in parser
    String what;
    // XML
    Utils.XmlAction xml_action;
    String xml_action_name;
    String xml_tag;
    String xml_attr;
    String value;
    Integer xml_occurrency;
    Boolean self_sign;
    Boolean remove_signature;

    // TXT
    Utils.TxtAction txt_action;
    String txt_action_name;

    // JWT
    boolean isRawJWT = false;
    Utils.Jwt_section jwt_section;
    Utils.Jwt_action jwt_action;
    boolean sign = false;
    JWT jwt;

    XMLHelpers xmlHelpers = new XMLHelpers();
    String saml_original_cert;

    public DecodeOperation() {

    }

    public DecodeOperation(
            Utils.MessageSection from,
            String decode_target,
            List<Utils.Encoding> encodings,
            Utils.DecodeOpType type) {
        this.from = from;
        this.decode_target = decode_target;
        this.encodings = encodings;
        this.type = type;
    }

    /**
     * Decodes a parameter from a message, given the message section and the list of encodings to be applied during
     * decoding
     *
     * @param helpers      IExtensionHelpers helpers object from Burp
     * @param ms           The message section that contains the parameter to be decoded
     * @param encodings    The list of encodings to be applied to decode the parameter
     * @param messageInfo  The message to be decoded
     * @param isRequest    True if the message containing the parameter is a request
     * @param decode_param The name of the parameter to be decoded
     * @return The decoded parameter as a string
     * @throws ParsingException If problems are encountered during decoding
     */
    public static String decodeParam(IExtensionHelpers helpers,
                                     Utils.MessageSection ms,
                                     List<Utils.Encoding> encodings,
                                     HTTPReqRes messageInfo,
                                     Boolean isRequest,
                                     String decode_param) throws ParsingException {
        String decoded_param = "";
        switch (ms) {
            case HEAD:
                decoded_param = decode(
                        encodings, messageInfo.getHeadParam(isRequest, decode_param), helpers);
                break;
            case BODY:
                decoded_param = decode(
                        encodings, messageInfo.getBodyRegex(isRequest, decode_param), helpers);
                break;
            case URL:
                decoded_param = decode(
                        encodings, messageInfo.getUrlParam(decode_param), helpers);
                break;
        }

        decoded_param = Utils.removeNewline(decoded_param);

        return decoded_param;
    }

    /**
     * Decode the given string, with the given ordered encodings
     * Example taken from
     * <a href="https://github.com/CompassSecurity/SAMLRaider/blob/master/src/main/java/application/SamlTabController.java">Saml Raider</a>
     *
     * @param encodings the ordered list of encodings to be applied
     * @param encoded   the string to be decoded
     * @return the decoded string
     * @throws ParsingException if the decoding fails
     */
    public static String decode(List<Utils.Encoding> encodings, String encoded, IExtensionHelpers helpers) throws ParsingException {
        String actual = encoded;
        byte[] actual_b = null;
        boolean isActualString = true;

        if (encoded.length() == 0) {
            return "";
        }

        for (Utils.Encoding e : encodings) {
            switch (e) {
                case BASE64:
                    if (isActualString) {
                        actual_b = helpers.base64Decode(actual);
                        isActualString = false;
                    } else {
                        actual_b = helpers.base64Decode(actual_b);
                    }
                    break;
                case URL:

                    if (isActualString) {
                        actual = helpers.urlDecode(actual);
                    } else {
                        actual = helpers.urlDecode(new String(actual_b));
                        isActualString = true;
                    }
                    break;
                case JWT:
                    if (!isActualString) {
                        actual = new String(actual_b);
                        isActualString = true;
                    }
                    actual = burp.JWT.decode_raw_jwt(actual);

                    break;
                case DEFLATE:
                    boolean done = false;
                    if (isActualString) {
                        byte[] data = actual.getBytes();

                        try {
                            actual_b = decompress(data, true);
                            done = true;
                            isActualString = false;
                        } catch (IOException | DataFormatException ioException) {
                            ioException.printStackTrace();
                            //ioException.printStackTrace();
                        }

                        try {
                            if (!done) {
                                actual_b = decompress(data, false);
                                done = true;
                                isActualString = false;
                            }
                        } catch (IOException | DataFormatException ioException) {
                            //ioException.printStackTrace();

                        }
                    } else {
                        try {
                            actual_b = decompress(actual_b, true);
                            done = true;
                        } catch (IOException | DataFormatException ioException) {

                            //ioException.printStackTrace();
                        }

                        try {
                            if (!done) {
                                actual_b = decompress(actual_b, false);
                                done = true;
                            }
                        } catch (IOException | DataFormatException ioException) {

                        }
                    }
                    break;
            }
        }
        if (isActualString) {
            return actual;
        } else {
            return new String(actual_b, StandardCharsets.UTF_8);
        }
    }

    /**
     * Encode the given string, with the given encodings (in the specified order)
     * Example taken from
     * <a href="https://github.com/CompassSecurity/SAMLRaider/blob/master/src/main/java/application/SamlTabController.java">Saml Raider</a>
     *
     * @param encodings the ordered list of encodings to be applied
     * @param decoded   the string to be encoded
     * @return the encoded string
     */
    public static String encode(List<Utils.Encoding> encodings, String decoded, IExtensionHelpers helpers) {
        String actual = decoded;
        byte[] actual_b = null;
        boolean isActualString = true;
        for (Utils.Encoding e : encodings) {
            switch (e) {
                case BASE64:

                    if (isActualString) {
                        actual = helpers.base64Encode(actual);
                    } else {
                        actual = helpers.base64Encode(actual_b);
                        isActualString = true;
                    }
                    break;

                case URL:

                    if (isActualString) {
                        actual = URLEncoder.encode(actual);
                    } else {
                        actual = new String(actual_b);
                        actual = URLEncoder.encode(actual);
                        isActualString = true;
                    }
                    break;

                case JWT:
                    //TBD
                    break;

                case DEFLATE:

                    if (isActualString) {
                        try {
                            actual_b = compress(actual.getBytes(StandardCharsets.UTF_8), true);
                        } catch (IOException ioException) {

                            //ioException.printStackTrace();
                        }
                        isActualString = false;
                    } else {
                        try {
                            actual_b = compress(actual_b, true);
                        } catch (IOException ioException) {

                            //ioException.printStackTrace();
                        }
                        isActualString = false;
                    }
            }
        }

        if (isActualString) {
            return actual;
        } else {
            return new String(actual_b, StandardCharsets.UTF_8);
        }
    }

    /**
     * Also named Inflate, taken from
     * <a href="http://qupera.blogspot.ch/2013/02/howto-compress-and-uncompress-java-byte.html">here</a>
     *
     * @param data the data to be decompressed (inflated)
     * @param gzip true to use gzip
     * @return returns the decompressed data
     * @throws IOException         if something goes wrong
     * @throws DataFormatException if something goes wrong
     */
    public static byte[] decompress(byte[] data, boolean gzip) throws IOException, DataFormatException {
        Inflater inflater = new Inflater(true);
        inflater.setInput(data);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
        byte[] buffer = new byte[1024];
        while (!inflater.finished()) {
            int count = inflater.inflate(buffer);
            outputStream.write(buffer, 0, count);
        }
        outputStream.close();
        byte[] output = outputStream.toByteArray();

        inflater.end();

        return output;
    }

    /**
     * Also named Deflate, taken from
     * <a href="http://qupera.blogspot.ch/2013/02/howto-compress-and-uncompress-java-byte.html">here</a>
     *
     * @param data data to be compressed (deflated)
     * @param gzip true to use gzip
     * @return the compressed data
     * @throws IOException if the compression goes wrong
     */
    public static byte[] compress(byte[] data, boolean gzip) throws IOException {
        Deflater deflater = new Deflater(5, gzip);
        deflater.setInput(data);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);

        deflater.finish();
        byte[] buffer = new byte[1024];
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            outputStream.write(buffer, 0, count);
        }
        outputStream.close();
        byte[] output = outputStream.toByteArray();

        deflater.end();

        return output;
    }

    public void loader(Operation_API api, IExtensionHelpers helpers) throws ParsingException {
        // load api, extract needed things
        this.helpers = helpers;
        this.api = api;

        decoded_content = decodeParam(
                helpers, from, encodings, api.message, api.is_request, decode_target);
    }

    @Override
    public Operation_API exporter() throws ParsingException {
        Collections.reverse(encodings); // Set the right order for encoding
        String encoded = encode(encodings, decoded_content, helpers);

        byte[] edited_message = Utils.editMessageParam(
                helpers,
                decoded_content,
                from,
                ((Operation_API) api).message,
                ((Operation_API) api).is_request,
                encoded,
                true);

        if (edited_message != null) {
            if (((Operation_API) api).is_request) {
                ((Operation_API) api).message.setRequest(edited_message);
            } else {
                ((Operation_API) api).message.setResponse(edited_message);
            }
            /*
            if (op.processed_message_service != null) {
                messageInfo.setHttpService(op.processed_message_service);
            }
            */
        }

        return ((Operation_API) api);
    }

    public void execute(GUI mainPane) throws ParsingException {
        // If a variable value has to be used, read the value of the variable at execution time
        if (!use.equals("")) {
            Var v = getVariableByName(use, mainPane);
            if (!v.isMessage) {
                value = v.value;
            } else {
                throw new ParsingException("Error while using variable, expected text var, got message var");
            }
        }

        //SAML Remove signatures
        if (self_sign | remove_signature) {
            Document document = null;
            try {
                document = xmlHelpers.getXMLDocumentOfSAMLMessage(decoded_content);
                saml_original_cert = xmlHelpers.getCertificate(document.getDocumentElement());
                if (saml_original_cert == null) {
                    System.out.println("SAML Certificate not found in decoded parameter \"" + decode_target + "\"");
                    applicable = false;
                }
                decoded_content = SamlTabController.removeSignature_edit(decoded_content);

            } catch (SAXException e) {
                e.printStackTrace();
            }
        }

        switch (type) {
            case XML: {
                switch (xml_action) {
                    case ADD_TAG:
                        decoded_content = XML.addTag(decoded_content,
                                xml_tag,
                                xml_action_name,
                                value,
                                xml_occurrency);
                        break;
                    case ADD_ATTR:
                        decoded_content = XML.addTagAttribute(decoded_content,
                                xml_tag,
                                xml_action_name,
                                value,
                                xml_occurrency);
                        break;
                    case EDIT_TAG:
                        decoded_content = XML.editTagValue(decoded_content,
                                xml_action_name,
                                value,
                                xml_occurrency);
                        break;
                    case EDIT_ATTR:
                        decoded_content = XML.editTagAttributes(decoded_content,
                                xml_tag,
                                xml_action_name,
                                value,
                                xml_occurrency);
                        break;
                    case REMOVE_TAG:
                        decoded_content = XML.removeTag(decoded_content,
                                xml_action_name,
                                xml_occurrency);
                        break;
                    case REMOVE_ATTR:
                        decoded_content = XML.removeTagAttribute(decoded_content,
                                xml_tag,
                                xml_action_name,
                                xml_occurrency);
                        break;
                    case SAVE_TAG: {
                        String to_save = XML.getTagValaue(decoded_content,
                                xml_action_name,
                                xml_occurrency);
                        Var v = new Var();
                        v.name = save_as;
                        v.isMessage = false;
                        v.value = to_save;
                        synchronized (mainPane.lock) {
                            mainPane.act_test_vars.add(v);
                        }

                        break;
                    }
                    case SAVE_ATTR:
                        String to_save = XML.getTagAttributeValue(decoded_content,
                                xml_tag, xml_action_name,
                                xml_occurrency);
                        Var v = new Var();
                        v.name = save_as;
                        v.isMessage = false;
                        v.value = to_save;
                        synchronized (mainPane.lock) {
                            mainPane.act_test_vars.add(v);
                        }
                        break;
                }
                break;
            }
            case JWT: {
                jwt = new JWT();
                if (isRawJWT) {
                    jwt.parseJWT_string(decoded_content);
                } else {
                    jwt.parseJWT(decoded_content);
                }

                // TODO: Move edit to json
                switch (jwt_action) {
                    case REMOVE:
                        //TODO: Change with JSON
                        //jwt.removeClaim(jwt_section, what);
                        break;
                    case EDIT:
                    case ADD:
                        //TODO: Change with JSON
                        //jwt.editAddClaim(jwt_section, what, value);
                        break;
                    case SAVE:
                        Var v = new Var();
                        v.name = save_as;
                        v.isMessage = false;
                        //TODO: Change with JSON
                        //v.value = jwt.getClaim(jwt_section, what);
                        synchronized (mainPane.lock) {
                            mainPane.act_test_vars.add(v);
                        }
                        break;
                }

                decoded_content = isRawJWT ?
                        jwt.buildJWT_string() :
                        jwt.buildJWT();
                break;
            }
            case TXT: {
                Pattern p = Pattern.compile(txt_action_name);
                Matcher m = p.matcher(decoded_content);

                if (txt_action == null) {
                    throw new ParsingException("txt action not specified");
                }

                switch (txt_action) {
                    case REMOVE:
                        decoded_content = m.replaceAll("");

                        break;
                    case EDIT:
                        decoded_content = m.replaceAll(value);

                        break;
                    case ADD:
                        while (m.find()) {
                            int index = m.end();
                            String before = decoded_content.substring(0, index);
                            String after = decoded_content.substring(index);
                            decoded_content = before + value + after;
                            break;
                        }
                        break;
                    case SAVE:
                        String val = "";
                        while (m.find()) {
                            val = m.group();
                            break;
                        }

                        Var v = new Var();
                        v.name = save_as;
                        v.isMessage = false;
                        v.value = val;
                        synchronized (mainPane.lock) {
                            mainPane.act_test_vars.add(v);
                        }
                        break;
                }
                break;
            }
        }

        // SAML re-sign
        if (self_sign && !decoded_content.equals("")) {
            // SAML re-sign

            decoded_content = SamlTabController.resignAssertion_edit(decoded_content, saml_original_cert);
            //decoded_param = SamlTabController.resignMessage_edit(decoded_param, original_cert);
        }
    }
}
