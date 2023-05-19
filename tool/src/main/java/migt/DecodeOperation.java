package migt;

import burp.IExtensionHelpers;
import com.jayway.jsonpath.JsonPath;
import org.json.JSONArray;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import samlraider.application.SamlTabController;
import samlraider.helpers.XMLHelpers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import static migt.Tools.executeDecodeOps;
import static migt.Utils.getVariableByName;

/**
 * This class stores a decode operation
 */
public class DecodeOperation extends Module {
    public String decoded_content; // the decoded content
    public String decode_target; // aka decode_param how to decode the raw content
    public Utils.DecodeOperationFrom from; // where the raw content is. Depending on the containing module, can be other things
    public List<Utils.Encoding> encodings = new ArrayList<>(); // the list of encoding to decode and rencode
    // TODO: change this to DecodeOperationType, and riassign it from the parser
    public Utils.DecodeOpType type; // the type of the decoded param
    public List<Check> checks; // the list of checks to be executed
    public List<DecodeOperation> decodeOperations = new ArrayList<>(); // a list of decode operations to execute them recursevly

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

    /**
     * Instantiate a decode operation object parsing a json object
     *
     * @param decode_op_json the json object
     * @throws ParsingException
     */
    public DecodeOperation(JSONObject decode_op_json) throws ParsingException {
        java.util.Iterator<String> keys = decode_op_json.keys();
        while (keys.hasNext()) {
            String key = keys.next();

            switch (key) {
                case "use":
                    use = decode_op_json.getString("use");
                    break;
                case "as":
                    save_as = decode_op_json.getString("as");
                    break;
                case "decode param":
                    decode_target = decode_op_json.getString("decode param");
                    break;
                case "encodings":
                    JSONArray encodings = decode_op_json.getJSONArray("encodings");
                    Iterator<Object> it = encodings.iterator();

                    while (it.hasNext()) {
                        String act_enc = (String) it.next();
                        this.encodings.add(
                                Utils.Encoding.fromString(act_enc));
                    }
                    break;
                case "from":
                    String f = decode_op_json.getString("from");
                    from = Utils.DecodeOperationFrom.fromString(f);
                    break;
                case "value":
                    // value of xml or other edits
                    value = decode_op_json.getString("value");
                    break;
                case "add tag":
                    xml_action = Utils.XmlAction.ADD_TAG;
                    xml_action_name = decode_op_json.getString(key);
                    break;
                case "add attribute":
                    xml_action = Utils.XmlAction.ADD_ATTR;
                    xml_action_name = decode_op_json.getString(key);
                    break;
                case "edit tag":
                    xml_action = Utils.XmlAction.EDIT_TAG;
                    xml_action_name = decode_op_json.getString(key);
                    break;
                case "edit attribute":
                    xml_action = Utils.XmlAction.EDIT_ATTR;
                    xml_action_name = decode_op_json.getString(key);
                    break;
                case "remove tag":
                    xml_action = Utils.XmlAction.REMOVE_TAG;
                    xml_action_name = decode_op_json.getString(key);
                    break;
                case "remove attribute":
                    xml_action = Utils.XmlAction.REMOVE_ATTR;
                    xml_action_name = decode_op_json.getString(key);
                    break;
                case "save tag":
                    xml_action = Utils.XmlAction.SAVE_TAG;
                    xml_action_name = decode_op_json.getString(key);
                    break;
                case "save attribute":
                    xml_action = Utils.XmlAction.SAVE_ATTR;
                    xml_action_name = decode_op_json.getString(key);
                    break;
                case "self-sign":
                    self_sign = decode_op_json.getBoolean("self-sign");
                    break;
                case "remove signature":
                    remove_signature = decode_op_json.getBoolean("remove signature");
                    break;
                case "xml tag":
                    xml_tag = decode_op_json.getString("xml tag");
                    break;
                case "xml occurrency":
                    xml_occurrency = decode_op_json.getInt("xml occurrency");
                    break;
                case "xml attribute":
                    xml_attr = decode_op_json.getString("xml attribute");
                    break;
                case "txt remove":
                    txt_action = Utils.TxtAction.REMOVE;
                    txt_action_name = decode_op_json.getString("txt remove");
                    break;
                case "txt edit":
                    txt_action = Utils.TxtAction.EDIT;
                    txt_action_name = decode_op_json.getString("txt edit");
                    break;
                case "txt add":
                    txt_action = Utils.TxtAction.ADD;
                    txt_action_name = decode_op_json.getString("txt add");
                    break;
                case "txt save":
                    txt_action = Utils.TxtAction.SAVE;
                    txt_action_name = decode_op_json.getString("txt save");
                    break;
                case "jwt from":
                    jwt_section = Utils.Jwt_section.getFromString(
                            decode_op_json.getString("jwt from"));
                    if (decode_op_json.getString("jwt from").contains("raw")) {
                        isRawJWT = true;
                    }
                    break;
                case "jwt remove":
                    jwt_action = Utils.Jwt_action.REMOVE;
                    what = decode_op_json.getString("jwt remove");
                    break;
                case "jwt edit":
                    jwt_action = Utils.Jwt_action.EDIT;
                    what = decode_op_json.getString("jwt edit");
                    break;
                case "jwt add":
                    jwt_action = Utils.Jwt_action.ADD;
                    what = decode_op_json.getString("jwt add");
                    break;
                case "jwt save":
                    jwt_action = Utils.Jwt_action.SAVE;
                    what = decode_op_json.getString("jwt save");
                    break;
                case "jwt sign":
                    sign = decode_op_json.getBoolean("jwt sign");
                    break;
                case "decode operations":
                    // Recursion goes brr
                    JSONArray decode_ops = decode_op_json.getJSONArray("decode operations");
                    for (int k = 0; k < decode_ops.length(); k++) {
                        JSONObject act_decode_op = decode_ops.getJSONObject(k);
                        DecodeOperation decode_op = new DecodeOperation(act_decode_op);
                        decodeOperations.add(decode_op);
                    }
                    break;
            }
        }
    }

    public DecodeOperation(
            Utils.DecodeOperationFrom from,
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
                                     Utils.DecodeOperationFrom ms,
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
        // TODO: remove dependency from helpers
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
                    actual = JWT.decode_raw_jwt(actual);

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

    @Override
    public DecodeOperation_API getAPI() {
        return (DecodeOperation_API) api;
    }

    /**
     * Loads an Operation API
     *
     * @param api
     * @param helpers
     * @throws ParsingException
     */
    public void loader(Operation_API api, IExtensionHelpers helpers) {
        // load api, extract needed things
        this.helpers = helpers;
        this.imported_api = api;
    }

    /**
     * Loads a decode operation API
     *
     * @param api
     */
    public void loader(DecodeOperation_API api, IExtensionHelpers helpers) {
        this.imported_api = api;
        this.helpers = helpers;

    }

    /**
     * Exports the API of this decode operation to be used by another operation
     *
     * @return the API
     * @throws ParsingException
     */
    @Override
    public Operation_API exporter() throws ParsingException {
        Collections.reverse(encodings); // Set the right order for encoding
        String encoded = encode(encodings, decoded_content, helpers);

        Utils.editMessageParam(
                helpers,
                decode_target,
                from,
                ((Operation_API) imported_api).message,
                ((Operation_API) imported_api).is_request,
                encoded,
                true);

        // the previous function should already have updated the message inside api
        return ((Operation_API) imported_api);
    }

    /**
     * Executes this decode operation
     *
     * @param mainPane the mainpane is needed to access the variables
     * @throws ParsingException
     */
    public void execute(GUI mainPane) throws ParsingException {
        if (api instanceof Operation_API) {
            decoded_content = decodeParam(
                    helpers,
                    from,
                    encodings,
                    ((Operation_API) api).message,
                    ((Operation_API) api).is_request,
                    decode_target
            );
        } else if (api instanceof DecodeOperation_API) {
            switch (from) {
                case JWT_HEADER:
                case JWT_PAYLOAD:
                case JWT_SIGNATURE:
                    // recursevly decode from a jwt
                    String j = ((DecodeOperation_API) api).getDecodedContent(from);

                    String found = "";
                    // https://github.com/json-path/JsonPath
                    try {
                        found = JsonPath.read(j, what); // select what to decode
                    } catch (com.jayway.jsonpath.PathNotFoundException e) {
                        applicable = false;
                        result = false;
                        return;
                    }
                    decoded_content = decode(encodings, found, helpers);
                    break;
                default:
                    throw new UnsupportedOperationException(
                            "the from you selected in the recursive decode operation is not yet supported");
                    //TODO implement missing
            }
        }

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

        // Edit decoded content
        editDecodedContent(mainPane);

        // executes recursive decode operations
        if (decodeOperations.size() != 0) {
            executeDecodeOps(this, helpers, mainPane);
        }

        if (checks.size() != 0) {
            Tools.executeChecks(this);
        }

        // SAML re-sign
        if (self_sign && !decoded_content.equals("")) {
            // SAML re-sign

            decoded_content = SamlTabController.resignAssertion_edit(decoded_content, saml_original_cert);
            //decoded_param = SamlTabController.resignMessage_edit(decoded_param, original_cert);
        }
    }

    private void editDecodedContent(GUI mainPane) throws ParsingException {
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

                //edit
                switch (jwt_section) {
                    case HEADER:
                        jwt.header = Utils.editJson(jwt_action, jwt.header, what, mainPane, save_as);
                        break;
                    case PAYLOAD:
                        jwt.payload = Utils.editJson(jwt_action, jwt.payload, what, mainPane, save_as);
                        break;
                    case SIGNATURE:
                        jwt.signature = Utils.editJson(jwt_action, jwt.signature, what, mainPane, save_as);
                        break;
                    case RAW_HEADER:
                        //TODO
                        break;
                    case RAW_PAYLOAD:
                        //TODO
                        break;
                    case RAW_SIGNATURE:
                        //TODO
                        break;
                }

                //rebuild
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
    }
}
