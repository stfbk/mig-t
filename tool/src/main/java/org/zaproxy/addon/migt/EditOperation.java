package org.zaproxy.addon.migt;

import static org.zaproxy.addon.migt.Tools.getVariableByName;

import com.jayway.jsonpath.PathNotFoundException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import org.zaproxy.addon.migt.samlraider.application.SamlTabController;
import org.zaproxy.addon.migt.samlraider.helpers.XMLHelpers;

public class EditOperation extends Module {
    // XML
    XmlAction xml_action;
    String xml_action_name;
    String xml_tag;
    String xml_attr;
    String value;
    Integer xml_occurrency;
    Boolean self_sign;
    Boolean remove_signature;
    String saml_original_cert;
    String edited_xml;

    String use; // say which parameter use as value
    String save_as; // say the name of the parameter to save the value

    // JWT
    Jwt_section jwt_section;
    Jwt_action jwt_action;
    boolean sign;
    String jwt_private_key_pem;

    String what;
    String key_add;

    // TXT
    TxtAction txt_action;
    String txt_action_name;
    // Encode
    List<DecodeOperation.Encoding> encodings;

    // Http message
    MessageOperation.MessageOperationActions action;
    HTTPReqRes.MessageSection msg_from;

    public EditOperation(JSONObject eop_json) throws ParsingException {
        init();
        Iterator<String> keys = eop_json.keys();
        while (keys.hasNext()) {
            String key = keys.next();

            switch (key) {
                case "use":
                    use = eop_json.getString("use");
                    break;
                case "as":
                    save_as = eop_json.getString("as");
                    break;
                case "value":
                    // value of xml or other edits
                    value = eop_json.getString("value");
                    break;
                case "add tag":
                    xml_action = XmlAction.ADD_TAG;
                    xml_action_name = eop_json.getString(key);
                    break;
                case "add attribute":
                    xml_action = XmlAction.ADD_ATTR;
                    xml_action_name = eop_json.getString(key);
                    break;
                case "edit tag":
                    xml_action = XmlAction.EDIT_TAG;
                    xml_action_name = eop_json.getString(key);
                    break;
                case "edit attribute":
                    xml_action = XmlAction.EDIT_ATTR;
                    xml_action_name = eop_json.getString(key);
                    break;
                case "remove tag":
                    xml_action = XmlAction.REMOVE_TAG;
                    xml_action_name = eop_json.getString(key);
                    break;
                case "remove attribute":
                    xml_action = XmlAction.REMOVE_ATTR;
                    xml_action_name = eop_json.getString(key);
                    break;
                case "save tag":
                    xml_action = XmlAction.SAVE_TAG;
                    xml_action_name = eop_json.getString(key);
                    break;
                case "save attribute":
                    xml_action = XmlAction.SAVE_ATTR;
                    xml_action_name = eop_json.getString(key);
                    break;
                case "self-sign":
                    self_sign = eop_json.getBoolean("self-sign");
                    break;
                case "remove signature":
                    remove_signature = eop_json.getBoolean("remove signature");
                    break;
                case "xml tag":
                    xml_tag = eop_json.getString("xml tag");
                    break;
                case "xml occurrency":
                    xml_occurrency = eop_json.getInt("xml occurrency");
                    break;
                case "xml attribute":
                    xml_attr = eop_json.getString("xml attribute");
                    break;
                    // JWT
                case "jwt from":
                    jwt_section = Jwt_section.getFromString(eop_json.getString("jwt from"));
                    break;
                case "jwt remove":
                    jwt_action = Jwt_action.REMOVE;
                    what = eop_json.getString("jwt remove");
                    break;
                case "jwt edit":
                    jwt_action = Jwt_action.EDIT;
                    what = eop_json.getString("jwt edit");
                    break;
                case "jwt add":
                    jwt_action = Jwt_action.ADD;
                    what = eop_json.getString("jwt add");
                    break;
                case "jwt save":
                    jwt_action = Jwt_action.SAVE;
                    what = eop_json.getString("jwt save");
                    break;
                case "jwt sign":
                    sign = true;
                    jwt_private_key_pem = eop_json.getString("jwt sign");
                    break;

                case "txt remove":
                    txt_action = TxtAction.REMOVE;
                    txt_action_name = eop_json.getString("txt remove");
                    break;
                case "txt edit":
                    txt_action = TxtAction.EDIT;
                    txt_action_name = eop_json.getString("txt edit");
                    break;
                case "txt add":
                    txt_action = TxtAction.ADD;
                    txt_action_name = eop_json.getString("txt add");
                    break;
                case "txt save":
                    txt_action = TxtAction.SAVE;
                    txt_action_name = eop_json.getString("txt save");
                    break;
                case "encodings":
                    JSONArray encodings = eop_json.getJSONArray("encodings");
                    Iterator<Object> it = encodings.iterator();

                    while (it.hasNext()) {
                        String act_enc = (String) it.next();
                        this.encodings.add(DecodeOperation.Encoding.fromString(act_enc));
                    }
                    break;
                case "encode":
                    action = MessageOperation.MessageOperationActions.ENCODE;
                    what = eop_json.getString("encode");
                    break;
                case "from":
                    msg_from = HTTPReqRes.MessageSection.fromString(eop_json.getString("from"));
                    break;
                case "edit":
                    action = MessageOperation.MessageOperationActions.EDIT;
                    what = eop_json.getString("edit");
                    break;
                case "edit regex":
                    action = MessageOperation.MessageOperationActions.EDIT_REGEX;
                    what = eop_json.getString("edit regex");
                    break;
                case "add":
                    action = MessageOperation.MessageOperationActions.ADD;
                    what = eop_json.getString("add");
                    break;
                case "remove":
                    action = MessageOperation.MessageOperationActions.REMOVE_PARAMETER;
                    what = eop_json.getString("remove");
                    break;
                case "key":
                    key_add = eop_json.getString("key");
                    break;
                default:
                    throw new ParsingException("Invalid key \"" + key + "\" in Edit Operation");
            }
        }

        validate();
    }

    /** Validate this object's content. Used to check if the parsed tags are valid. */
    @Override
    public void validate() throws ParsingException {
        if (action == MessageOperation.MessageOperationActions.ENCODE) {
            if (encodings.isEmpty()) {
                throw new ParsingException(
                        "Using encode in Edit Operation, but not providing encodings");
            }
        }
    }

    public void init() {
        use = "";
        save_as = "";
        xml_action_name = "";
        xml_tag = "";
        xml_attr = "";
        value = "";
        self_sign = false;
        remove_signature = false;
        saml_original_cert = "";
        edited_xml = "";
        sign = false;
        txt_action_name = "";
        what = "";
        encodings = new ArrayList<>();
    }

    public void setAPI(Operation_API api) {
        imported_api = api;
    }

    public API exporter() {
        return imported_api;
    }

    public void execute_decodeOperation_API(List<Var> vars) throws ParsingException {
        // the edit operation is being executed inside a Decode Operation
        DecodeOperation_API tmp_imported_api = (DecodeOperation_API) imported_api;

        switch (((DecodeOperation_API) imported_api).type) {

                // ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo
            case XML:
                // SAML Remove signatures
                if (self_sign | remove_signature) {
                    Document document = null;
                    try {
                        XMLHelpers xmlHelpers = new XMLHelpers();
                        document =
                                xmlHelpers.getXMLDocumentOfSAMLMessage(
                                        ((DecodeOperation_API) imported_api).xml);
                        saml_original_cert =
                                xmlHelpers.getCertificate(document.getDocumentElement());
                        if (saml_original_cert == null) {
                            System.out.println("SAML Certificate not found in decoded parameter");
                            applicable = false;
                        }
                        edited_xml =
                                SamlTabController.removeSignature_edit(
                                        ((DecodeOperation_API) imported_api).xml);
                    } catch (SAXException e) {
                        e.printStackTrace();
                    }
                }

                switch (xml_action) {
                    case ADD_TAG:
                        edited_xml =
                                XML.addTag(
                                        edited_xml,
                                        xml_tag,
                                        xml_action_name,
                                        value,
                                        xml_occurrency);
                        break;
                    case ADD_ATTR:
                        edited_xml =
                                XML.addTagAttribute(
                                        edited_xml,
                                        xml_tag,
                                        xml_action_name,
                                        value,
                                        xml_occurrency);
                        break;
                    case EDIT_TAG:
                        edited_xml =
                                XML.editTagValue(
                                        edited_xml, xml_action_name, value, xml_occurrency);
                        break;
                    case EDIT_ATTR:
                        edited_xml =
                                XML.editTagAttributes(
                                        edited_xml,
                                        xml_tag,
                                        xml_action_name,
                                        value,
                                        xml_occurrency);
                        break;
                    case REMOVE_TAG:
                        edited_xml = XML.removeTag(edited_xml, xml_action_name, xml_occurrency);
                        break;
                    case REMOVE_ATTR:
                        edited_xml =
                                XML.removeTagAttribute(
                                        edited_xml, xml_tag, xml_action_name, xml_occurrency);
                        break;
                    case SAVE_TAG:
                        {
                            String to_save =
                                    XML.getTagValaue(edited_xml, xml_action_name, xml_occurrency);
                            Var v = new Var(save_as, to_save);
                            vars.add(v);
                            break;
                        }
                    case SAVE_ATTR:
                        String to_save =
                                XML.getTagAttributeValue(
                                        edited_xml, xml_tag, xml_action_name, xml_occurrency);
                        Var v = new Var(save_as, to_save);
                        vars.add(v);
                        break;
                }

                if (self_sign && !edited_xml.equals("")) {
                    // SAML re-sign
                    edited_xml =
                            SamlTabController.resignAssertion_edit(edited_xml, saml_original_cert);
                }

                tmp_imported_api.xml = edited_xml;
                applicable = true;
                break;
                // ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo
            case JWT:
                if (jwt_section != null) { // if only sign, there will be no jwt section
                    try {
                        switch (jwt_section) {
                            case HEADER:
                                tmp_imported_api.jwt.header =
                                        Tools.editJson(
                                                jwt_action,
                                                tmp_imported_api.jwt.header,
                                                what,
                                                vars,
                                                save_as,
                                                value,
                                                key_add);
                                break;
                            case PAYLOAD:
                                tmp_imported_api.jwt.payload =
                                        Tools.editJson(
                                                jwt_action,
                                                tmp_imported_api.jwt.payload,
                                                what,
                                                vars,
                                                save_as,
                                                value,
                                                key_add);
                                break;
                            case SIGNATURE:
                                tmp_imported_api.jwt.signature =
                                        Tools.editJson(
                                                jwt_action,
                                                tmp_imported_api.jwt.signature,
                                                what,
                                                vars,
                                                save_as,
                                                value,
                                                key_add);
                                break;
                        }
                    } catch (PathNotFoundException e) {
                        this.applicable = false;

                        this.result = false;
                        return;
                    }
                    applicable = true;
                } else if (sign) {
                    applicable = true;
                    tmp_imported_api.jwt.sign = true;
                    tmp_imported_api.jwt.private_key_pem = jwt_private_key_pem;
                } else {
                    throw new ParsingException("missing jwt section in Edit operation");
                }

                break;

            case NONE:
                Pattern p = Pattern.compile(Pattern.quote(txt_action_name));
                Matcher m = p.matcher(tmp_imported_api.txt);

                if (txt_action == null) {
                    throw new ParsingException("txt action not specified");
                }

                switch (txt_action) {
                    case REMOVE:
                        tmp_imported_api.txt = m.replaceAll("");

                        break;
                    case EDIT:
                        tmp_imported_api.txt = m.replaceAll(value);

                        break;
                    case ADD:
                        while (m.find()) {
                            int index = m.end();
                            String before = tmp_imported_api.txt.substring(0, index);
                            String after = tmp_imported_api.txt.substring(index);
                            tmp_imported_api.txt = before + value + after;
                            break;
                        }
                        break;
                    case SAVE:
                        String val = "";
                        while (m.find()) {
                            val = m.group();
                            break;
                        }

                        Var v = new Var(save_as, val);
                        vars.add(v);
                        break;
                }
                applicable = true;
                break;
        }
        imported_api = tmp_imported_api;
    }

    public void execute_Operation_API() throws ParsingException {
        HTTPReqRes message = ((Operation_API) imported_api).message;
        boolean is_request =
                ((Operation_API) imported_api).is_request; // if the message to edit is the request

        switch (msg_from) {
            case URL:
                {
                    if (!is_request) {
                        throw new RuntimeException(
                                "trying to access the URL of a response message");
                    }

                    switch (action) {
                        case REMOVE_PARAMETER:
                            message.removeUrlParam(what);
                            break;
                        case REMOVE_MATCH_WORD:
                            // TODO: remove, can be done with edit regex
                            break;
                        case EDIT:
                            message.editUrlParam(what, value);
                            break;
                        case EDIT_REGEX:
                            message.editUrlRegex(what, value);
                            break;
                        case ADD:
                            message.addUrlParam(what, value);
                            break;
                        case ENCODE:
                            String old_value = message.getUrlParam(what);
                            String new_value = DecodeOperation.encode(encodings, old_value);
                            message.editUrlParam(what, new_value);
                            break;
                    }
                    break;
                }

            case HEAD:
                {
                    switch (action) {
                        case REMOVE_PARAMETER:
                            message.removeHeadParameter(is_request, what);
                            break;
                        case REMOVE_MATCH_WORD:
                            // TODO: remove, can be done with edit regex
                            break;
                        case EDIT:
                            message.editHeadParam(is_request, what, value);
                            break;
                        case EDIT_REGEX:
                            // For each header applies regex
                            message.editHeadRegex(is_request, what, value);
                            break;
                        case ADD:
                            message.addHeadParameter(is_request, what, value);
                            break;
                        case ENCODE:
                            String old_value = message.getHeadParam(is_request, what);
                            String new_value = DecodeOperation.encode(encodings, old_value);
                            message.editHeadParam(is_request, what, new_value);
                            break;
                    }
                    break;
                }

            case BODY:
                {
                    switch (action) {
                            // TODO add also edits based on Content-Type?
                        case REMOVE_PARAMETER:
                            // nothing
                            break;
                        case REMOVE_MATCH_WORD:
                            // nothing
                            break;
                        case EDIT:
                            // nothing
                            break;
                        case EDIT_REGEX:
                            // edit matched value
                            message.editBodyRegex(is_request, what, value);
                            break;
                        case ADD:
                            // append value
                            message.addBody(is_request, value);
                            break;
                        case ENCODE:
                            // encode matched value
                            String old_value = message.getBodyRegex(is_request, what);
                            String new_value = DecodeOperation.encode(encodings, old_value);
                            message.editBodyRegex(is_request, what, new_value);
                            break;
                    }
                    break;
                }

            case RAW:
                {
                    switch (action) {
                            // TODO
                        case REMOVE_PARAMETER:
                            break;
                        case REMOVE_MATCH_WORD:
                            break;
                        case EDIT:
                            break;
                        case EDIT_REGEX:
                            // TODO
                            break;
                        case ADD:
                            break;
                        case ENCODE:
                            // TODO
                            break;
                    }
                    break;
                }
        }
        applicable = true; // check if there is a better place for this
        ((Operation_API) imported_api).message = message;
    }

    public void execute(List<Var> vars) throws ParsingException {
        // If a variable value has to be used, read the value of the variable at execution time
        if (!use.equals("")) {
            Var v = getVariableByName(use, vars);
            value = v.get_value_string();
        }

        if (imported_api instanceof DecodeOperation_API) {
            execute_decodeOperation_API(vars);
        } else if (imported_api instanceof Operation_API) {
            execute_Operation_API();
        }
    }

    /** The possible XML actions are the ones described in this enum */
    public enum XmlAction {
        ADD_TAG,
        ADD_ATTR,
        EDIT_TAG,
        EDIT_ATTR,
        REMOVE_TAG,
        REMOVE_ATTR,
        SAVE_TAG,
        SAVE_ATTR;

        /**
         * From a string get the corresponding value
         *
         * @param input the input string
         * @return the enum value
         * @throws ParsingException if the string does not correspond to any of the values
         */
        public static XmlAction fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "add tag":
                        return ADD_TAG;
                    case "add attribute":
                        return ADD_ATTR;
                    case "edit tag":
                        return EDIT_TAG;
                    case "edit attribute":
                        return EDIT_ATTR;
                    case "remove tag":
                        return REMOVE_TAG;
                    case "remove attribute":
                        return REMOVE_ATTR;
                    case "save tag":
                        return SAVE_TAG;
                    case "save attribute":
                        return SAVE_ATTR;
                    default:
                        throw new ParsingException("invalid xml action");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }

    /** Defines the possible actions to be done on a decoded parameter interpreted as plain text */
    public enum TxtAction {
        REMOVE,
        EDIT,
        ADD,
        SAVE;

        /**
         * From a string get the corresponding value
         *
         * @param input the input string
         * @return the enum value
         * @throws ParsingException if the string does not correspond to any of the values
         */
        public static TxtAction fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "txt remove":
                        return REMOVE;
                    case "txt edit":
                        return EDIT;
                    case "txt add":
                        return ADD;
                    case "txt save":
                        return SAVE;
                    default:
                        throw new ParsingException("invalid xml action");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }

    /** Defines the possible actions to be done on a JWT token */
    public enum Jwt_action {
        REMOVE,
        EDIT,
        ADD,
        SAVE
    }

    /** Defines the possible JWT token sections */
    public enum Jwt_section {
        HEADER,
        PAYLOAD,
        SIGNATURE;

        /**
         * Get the JWT section enum value from a string
         *
         * @param s the string to parse
         * @return the enum value
         * @throws ParsingException if the string is invalid
         */
        public static Jwt_section getFromString(String s) throws ParsingException {
            switch (s) {
                case "header":
                    return HEADER;
                case "payload":
                    return PAYLOAD;
                case "signature":
                    return SIGNATURE;
                default:
                    throw new ParsingException("Invalid jwt section");
            }
        }
    }
}
