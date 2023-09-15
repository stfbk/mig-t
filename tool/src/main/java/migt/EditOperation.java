package migt;

import com.jayway.jsonpath.PathNotFoundException;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import samlraider.application.SamlTabController;
import samlraider.helpers.XMLHelpers;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static migt.Tools.getVariableByName;

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

    // TXT
    TxtAction txt_action;
    String txt_action_name;

    public EditOperation(JSONObject eop_json) throws ParsingException {
        init();
        java.util.Iterator<String> keys = eop_json.keys();
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
                    jwt_section = Jwt_section.getFromString(
                            eop_json.getString("jwt from"));
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
    }

    public void loader(DecodeOperation_API dop_api) {
        // TODO
        if (dop_api == null) {
            throw new RuntimeException("loaded api is null");
        }
        this.imported_api = dop_api;
    }

    public DecodeOperation_API exporter() {
        return (DecodeOperation_API) imported_api;
    }

    public void execute(List<Var> vars) throws ParsingException {
        if (imported_api instanceof DecodeOperation_API) {
            // the edit operation is being executed inside a Decode Operation
            // If a variable value has to be used, read the value of the variable at execution time
            if (!use.equals("")) {
                Var v = getVariableByName(use, vars);
                if (!v.isMessage) {
                    value = v.value;
                } else {
                    throw new ParsingException("Error while using variable, expected text var, got message var");
                }
            }

            DecodeOperation_API tmp_imported_api = (DecodeOperation_API) imported_api;

            switch (((DecodeOperation_API) imported_api).type) {
                case XML:
                    //SAML Remove signatures
                    if (self_sign | remove_signature) {
                        Document document = null;
                        try {
                            XMLHelpers xmlHelpers = new XMLHelpers();
                            document = xmlHelpers.getXMLDocumentOfSAMLMessage(((DecodeOperation_API) imported_api).xml);
                            saml_original_cert = xmlHelpers.getCertificate(document.getDocumentElement());
                            if (saml_original_cert == null) {
                                System.out.println("SAML Certificate not found in decoded parameter");
                                applicable = false;
                            }
                            edited_xml = SamlTabController.removeSignature_edit(((DecodeOperation_API) imported_api).xml);
                        } catch (SAXException e) {
                            e.printStackTrace();
                        }
                    }

                    switch (xml_action) {
                        case ADD_TAG:
                            edited_xml = XML.addTag(edited_xml,
                                    xml_tag,
                                    xml_action_name,
                                    value,
                                    xml_occurrency);
                            break;
                        case ADD_ATTR:
                            edited_xml = XML.addTagAttribute(edited_xml,
                                    xml_tag,
                                    xml_action_name,
                                    value,
                                    xml_occurrency);
                            break;
                        case EDIT_TAG:
                            edited_xml = XML.editTagValue(edited_xml,
                                    xml_action_name,
                                    value,
                                    xml_occurrency);
                            break;
                        case EDIT_ATTR:
                            edited_xml = XML.editTagAttributes(edited_xml,
                                    xml_tag,
                                    xml_action_name,
                                    value,
                                    xml_occurrency);
                            break;
                        case REMOVE_TAG:
                            edited_xml = XML.removeTag(edited_xml,
                                    xml_action_name,
                                    xml_occurrency);
                            break;
                        case REMOVE_ATTR:
                            edited_xml = XML.removeTagAttribute(edited_xml,
                                    xml_tag,
                                    xml_action_name,
                                    xml_occurrency);
                            break;
                        case SAVE_TAG: {
                            String to_save = XML.getTagValaue(edited_xml,
                                    xml_action_name,
                                    xml_occurrency);
                            Var v = new Var();
                            v.name = save_as;
                            v.isMessage = false;
                            v.value = to_save;
                            vars.add(v);
                            break;
                        }
                        case SAVE_ATTR:
                            String to_save = XML.getTagAttributeValue(edited_xml,
                                    xml_tag, xml_action_name,
                                    xml_occurrency);
                            Var v = new Var();
                            v.name = save_as;
                            v.isMessage = false;
                            v.value = to_save;
                            vars.add(v);
                            break;
                    }

                    if (self_sign && !edited_xml.equals("")) {
                        // SAML re-sign
                        edited_xml = SamlTabController.resignAssertion_edit(edited_xml, saml_original_cert);
                    }

                    tmp_imported_api.xml = edited_xml;
                    applicable = true;
                    break;

                case JWT:
                    if (jwt_section != null) { // if only sign, there will be no jwt section
                        try {
                            switch (jwt_section) {
                                case HEADER:
                                    tmp_imported_api.jwt.header = Tools.editJson(
                                            jwt_action, tmp_imported_api.jwt.header, what, vars, save_as, value);
                                    break;
                                case PAYLOAD:
                                    // TODO: pass newvalue
                                    tmp_imported_api.jwt.payload = Tools.editJson(
                                            jwt_action, tmp_imported_api.jwt.payload, what, vars, save_as, value);
                                    break;
                                case SIGNATURE:
                                    tmp_imported_api.jwt.signature = Tools.editJson(
                                            jwt_action, tmp_imported_api.jwt.signature, what, vars, save_as, value);
                                    break;
                            }
                        } catch (PathNotFoundException e) {
                            this.applicable = false;
                            this.result = false;
                            return;
                        }
                    }
                    applicable = true;

                    if (sign) {
                        tmp_imported_api.jwt.sign = true;
                        tmp_imported_api.jwt.private_key_pem = jwt_private_key_pem;
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

                            Var v = new Var();
                            v.name = save_as;
                            v.isMessage = false;
                            v.value = val;
                            vars.add(v);
                            break;
                    }
                    applicable = true;
                    break;
            }
            imported_api = tmp_imported_api;
        }
    }

    /**
     * The possible XML actions are the ones described in this enum
     */
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

    /**
     * Defines the possible actions to be done on a decoded parameter interpreted as plain text
     */
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

    /**
     * Defines the possible actions to be done on a JWT token
     */
    public enum Jwt_action {
        REMOVE,
        EDIT,
        ADD,
        SAVE
    }

    /**
     * Defines the possible JWT token sections
     */
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
