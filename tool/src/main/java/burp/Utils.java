package burp;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * class containing useful methods and enums to be used in other classes
 *
 * @author Matteo Bitussi
 */
public class Utils {
    /**
     * Function that checks if a message's url is an authorization request
     *
     * @param url the url of the request message to be checked
     * @return true if the message is an authorization request
     */
    public static boolean isAuthRequest(String url) {
        boolean d = url.contains("response_type");
        return d;
    }

    /**
     * Function that parses checks from a JSON array
     *
     * @param checks_array the JSONarray that should contain checks
     * @return a List of Check elements
     * @throws ParsingException if the input is malformed
     */
    public static List<Check> parseChecksFromJSON(JSONArray checks_array) throws ParsingException {
        List<Check> res = new ArrayList<>();
        for (int k = 0; k < checks_array.length(); k++) {
            JSONObject act_check = checks_array.getJSONObject(k);
            Check check = new Check();
            Iterator<String> keys = act_check.keys();
            while (keys.hasNext()) {
                String key = keys.next();


                switch (key) {
                    case "in":
                        if (key.equals("in")) {
                            check.in = Utils.MessageSection.fromString(act_check.getString("in"));
                        }
                    case "check param":
                        if (key.equals("check param")) {
                            check.isParamCheck = true;
                            check.setWhat(act_check.getString("check param"));
                            break;
                        }
                    case "check":
                        if (key.equals("check")) {
                            check.setWhat(act_check.getString("check"));
                            break;
                        }
                    case "is":
                        if (key.equals("is")) {
                            check.setOp(Utils.CheckOps.IS);
                            check.op_val = act_check.getString("is");
                            break;
                        }
                    case "is not":
                        if (key.equals("is not")) {
                            check.setOp(Utils.CheckOps.IS_NOT);
                            check.op_val = act_check.getString("is not");
                            break;
                        }
                    case "contains":
                        if (key.equals("contains")) {
                            check.setOp(Utils.CheckOps.CONTAINS);
                            check.op_val = act_check.getString("contains");
                            break;
                        }
                    case "not contains":
                        if (key.equals("not contains")) {
                            check.setOp(Utils.CheckOps.NOT_CONTAINS);
                            check.op_val = act_check.getString("not contains");
                            break;
                        }
                    case "is present":
                        if (key.equals("is present")) {
                            check.op = act_check.getBoolean("is present") ? Utils.CheckOps.IS_PRESENT :
                                    Utils.CheckOps.IS_NOT_PRESENT;
                            check.op_val = act_check.getBoolean("is present") ?
                                    "is present" : "is not present";
                        }
                }
            }
            if (check.in == null) {
                throw new ParsingException("In tag cannot be empty");
            }
            res.add(check);
        }
        return res;
    }

    /**
     * Given a list of message parts url, head, body (in this order), build a message
     *
     * @param parts the list of the parts to build the message, has to be url, head, body
     * @return the builded message
     */
    public static byte[] buildMessage(List<String> parts, IExtensionHelpers helpers) {
        String tmp = parts.get(0) + parts.get(1) + parts.get(2);

        //return helpers.stringToBytes(tmp);
        return tmp.getBytes(StandardCharsets.UTF_8); // verify if is the same as burp
    }

    /**
     * Given a message, split it in 3 parts, url, head, body
     *
     * @param message   the message to be splitted
     * @param helpers   an istance of IExtensionHelpers
     * @param isRequest true if the message is a request
     * @return a List of Strings containing the three parts
     */
    public static List<String> splitMessage(IHttpRequestResponse message, IExtensionHelpers helpers, boolean isRequest) {
        int body_offset = isRequest ?
                helpers.analyzeRequest(message.getRequest()).getBodyOffset() :
                helpers.analyzeResponse(message.getResponse()).getBodyOffset();

        String head = new String(isRequest ?
                Arrays.copyOfRange(message.getRequest(), 0, body_offset) :
                Arrays.copyOfRange(message.getResponse(), 0, body_offset));
        String body = new String(isRequest ?
                Arrays.copyOfRange(message.getRequest(), body_offset, message.getRequest().length) :
                Arrays.copyOfRange(message.getResponse(), body_offset, message.getResponse().length));

        String url = head.split("\n")[0] + "\n";
        //String url = isRequest ? helpers.analyzeRequest(message).getUrl().toString() : "";
        String[] head_splitted = head.split("\n");
        String[] head_ok = Arrays.copyOfRange(head_splitted, 1, head_splitted.length);

        head = "";
        for (String act : head_ok) {
            head += act + "\n";
        }

        List<String> res = new ArrayList<>();
        res.add(url);
        res.add(head);
        res.add(body);

        return res;
    }

    /**
     * Given a message, split it in 3 parts, url, head, body
     *
     * @param message   the message to be splitted
     * @param helpers   an istance of IExtensionHelpers
     * @param isRequest true if the message is a request
     * @return a List of Strings containing the three parts
     */
    public static List<String> splitMessage(HTTPReqRes message, IExtensionHelpers helpers, boolean isRequest) {
        int body_offset = isRequest ?
                helpers.analyzeRequest(message.getRequest()).getBodyOffset() :
                helpers.analyzeResponse(message.getResponse()).getBodyOffset();

        String head = new String(isRequest ?
                Arrays.copyOfRange(message.getRequest(), 0, body_offset) :
                Arrays.copyOfRange(message.getResponse(), 0, body_offset));
        String body = new String(isRequest ?
                Arrays.copyOfRange(message.getRequest(), body_offset, message.getRequest().length) :
                Arrays.copyOfRange(message.getResponse(), body_offset, message.getResponse().length));

        String url = head.split("\n")[0] + "\n";
        //String url = isRequest ? helpers.analyzeRequest(message).getUrl().toString() : "";
        String[] head_splitted = head.split("\n");
        String[] head_ok = Arrays.copyOfRange(head_splitted, 1, head_splitted.length);

        head = "";
        for (String act : head_ok) {
            head += act + "\n";
        }

        List<String> res = new ArrayList<>();
        res.add(url);
        res.add(head);
        res.add(body);

        return res;
    }

    /**
     * Set an url to a message, note that
     * with url is intended the entire first row of the head (GET ...path... HTTP)
     *
     * @param url       the url to be substituted to the message
     * @param message   the message
     * @param helpers   the helpers
     * @param isRequest true if the message is a request
     * @return the edited message
     */
    public static byte[] setUrl(String url, IHttpRequestResponse message, IExtensionHelpers helpers, boolean isRequest) {
        List<String> mes_split = splitMessage(message, helpers, isRequest);

        if (!url.endsWith("\n")) url += "\n";
        mes_split.set(0, url);

        return buildMessage(mes_split, helpers);
    }

    /**
     * Function used to parse the message types from a string
     *
     * @param input a string containing the msg types in JSON
     * @return a List of messagetype objects
     * @throws ParsingException if the input is malformed
     */
    public static List<MessageType> readMsgTypeFromJson(String input) throws ParsingException {
        List<MessageType> msg_types = new ArrayList<>();

        JSONObject obj = new JSONObject(input);
        JSONArray message_types = obj.getJSONArray("message_types");

        for (int i = 0; i < message_types.length(); i++) {
            JSONObject act_msg_type = message_types.getJSONObject(i);

            String name = act_msg_type.getString("name");
            Boolean isRequest = act_msg_type.getBoolean("is request");

            MessageType msg_obj = new MessageType(name, isRequest);

            if (act_msg_type.has("response name")) {
                msg_obj.responseName = act_msg_type.getString("response name");
            }
            if (act_msg_type.has("request name")) {
                msg_obj.requestName = act_msg_type.getString("request name");
            }

            if (act_msg_type.has("checks")) {
                msg_obj.isRegex = false;
                msg_obj.checks = parseChecksFromJSON(act_msg_type.getJSONArray("checks"));
            } else if (act_msg_type.has("regex")) {
                msg_obj.isRegex = true;
                msg_obj.regex = act_msg_type.getString("regex");
                msg_obj.messageSection = Utils.MessageSection.fromString(act_msg_type.getString("message section"));
            } else {
                throw new ParsingException("message type definition is invalid, no checks or regex found");
            }
            msg_types.add(msg_obj);
        }

        return msg_types;
    }

    /**
     * Returns the default string that contains the default message types that fill a msg_def.json file
     *
     * @return the string
     */
    public static String getDefaultJSONMsgType() {
        return "{\n" +
                "    \"message_types\": [\n" +
                "        {\n" +
                "            \"name\": \"authorization request\",\n" +
                "            \"is request\": true,\n" +
                "            \"response name\": \"authorization response\",\n" +
                "            \"checks\": [\n" +
                "                {\n" +
                "                    \"in\": \"url\",\n" +
                "                    \"check param\": \"response_type\",\n" +
                "                    \"is present\": \"true\"\n" +
                "                }\n" +
                "            ]\n" +
                "        },\n" +
                "        {\n" +
                "            \"name\": \"token request\",\n" +
                "            \"is request\": true,\n" +
                "            \"response name\": \"token response\",\n" +
                "            \"checks\": [\n" +
                "                {\n" +
                "                    \"in\": \"url\",\n" +
                "                    \"check param\": \"code\",\n" +
                "                    \"is present\": \"true\"\n" +
                "                }\n" +
                "            ]\n" +
                "        },\n" +
                "        {\n" +
                "            \"name\": \"coda landing request\",\n" +
                "            \"is request\": true,\n" +
                "            \"response name\": \"coda landing response\",\n" +
                "            \"checks\": [\n" +
                "                {\n" +
                "                    \"in\": \"url\",\n" +
                "                    \"check\": \"/welcome\",\n" +
                "                    \"is present\": \"true\"\n" +
                "                },\n" +
                "                {\n" +
                "                    \"in\": \"head\",\n" +
                "                    \"check\": \"Host\",\n" +
                "                    \"is\": \"coda.io\"\n" +
                "                }\n" +
                "            ]\n" +
                "        },\n" +
                "        {\n" +
                "            \"name\": \"saml request\",\n" +
                "            \"is request\": true,\n" +
                "            \"checks\": [\n" +
                "                {\n" +
                "                    \"in\": \"url\",\n" +
                "                    \"check param\": \"SAMLRequest\",\n" +
                "                    \"is present\": true\n" +
                "                }\n" +
                "            ]\n" +
                "        },\n" +
                "        {\n" +
                "            \"name\": \"saml response\",\n" +
                "            \"is request\": true,\n" +
                "            \"checks\": [\n" +
                "                {\n" +
                "                    \"in\": \"body\",\n" +
                "                    \"check param\": \"SAMLResponse\",\n" +
                "                    \"is present\": true\n" +
                "                }\n" +
                "            ]\n" +
                "        }\n" +
                "    ]\n" +
                "}";
    }

    /**
     * Returns the default string that contains the default config for the config.json file
     *
     * @return the string
     */
    public static String getDefaultJSONConfig() {
        return "{\n" +
                "  \"last_driver_path\":\"\",\n" +
                "  \"last_browser_used\": \"\"\n" +
                "}";
    }

    /**
     * Set the body to a message
     *
     * @return the edited message
     */
    public static String removeNewline(String input) {
        Pattern p = Pattern.compile("\n");
        Matcher m = p.matcher(input);

        String out = m.replaceAll("");
        return out;
    }

    /**
     * Get the headers of an HTTP message
     * @param message the message
     * @param isRequest true if it is a request
     * @param helpers The Burp IExtensionHelpers
     * @return a list of Strings, each one is a header
     */
    public static List<String> getHeaders(IHttpRequestResponse message, boolean isRequest, IExtensionHelpers helpers) {
        if (isRequest) {
            return helpers.analyzeRequest(message.getRequest()).getHeaders();
        } else {
            return helpers.analyzeResponse(message.getResponse()).getHeaders();
        }
    }

    /**
     * Get the body of a message
     * @param message the message
     * @param isRequest true if the message is a request
     * @param helpers The Burp IExtensionHelpers
     * @return the body of the message as byte array
     */
    public static byte[] getBody(IHttpRequestResponse message, boolean isRequest, IExtensionHelpers helpers) {
        int body_offset = isRequest ?
                helpers.analyzeRequest(message.getRequest()).getBodyOffset() :
                helpers.analyzeResponse(message.getResponse()).getBodyOffset();

        byte[] body = isRequest ?
                Arrays.copyOfRange(message.getRequest(), body_offset, message.getRequest().length) :
                Arrays.copyOfRange(message.getResponse(), body_offset, message.getResponse().length);

        return body;
    }

    /**
     * Removes a head parameter from a list of headers
     * @param headers the list of headers
     * @param param_name the name of the header to remove
     * @return The list without the removed header
     */
    public static List<String> removeHeadParameter(List<String> headers, String param_name) {
        for (String s : headers) {
            if (s.contains(param_name)) {
                headers.remove(s);
                break;
            }
        }
        return headers;
    }

    /**
     * Add a header to a list of headers
     * @param headers the header list
     * @param param_name the name of the header to add
     * @param value the value of the header to add
     * @return the edited header list
     */
    public static List<String> addHeadParameter(List<String> headers, String param_name, String value) {
        if (value.equals("")) return headers;

        for (String s : headers) {
            if (s.contains(param_name)) {
                headers.set(headers.indexOf(s), param_name + ": " + value);
                return headers;
            }
        }
        headers.add(param_name + ": " + value);
        return headers;
    }

    /**
     * Edit a header ina a list of headers
     * @param headers the header list
     * @param param_name the name of the header to edit
     * @param value the value of the header to add
     * @return the edited header list
     */
    public static List<String> editHeadParameter(List<String> headers, String param_name, String value) {
        if (value.equals("")) return headers;

        for (String s : headers) {
            if (s.contains(param_name)) {
                headers.set(headers.indexOf(s), param_name + ": " + value);
                return headers;
            }
        }
        return headers;
    }

    /**
     * Get the value of a header from a header list
     * @param headers the list of headers
     * @param param_name the name of the header to get the value from
     * @return the value of the header
     */
    public static String getHeadParameterValue(List<String> headers, String param_name) {
        for (String s : headers) {
            if (s.contains(param_name)) {
                String[] splitted = s.split(":");

                String value = s.substring(s.indexOf(":") + 1);
                return value;
            }
        }
        return "";
    }

    /**
     * Builds a string, substituting variables names with values
     * @param vars the list of variables to use
     * @param s the string
     * @return the builded string
     * @throws ParsingException if a variable is not found
     */
    public static String buildStringWithVars(List<Var> vars, String s) throws ParsingException {
        Pattern p = Pattern.compile("\\$[^\\$]*\\$");
        Matcher m = p.matcher(s);

        String res = s;

        HashMap<String, String> req_var = new HashMap<>();

        while (m.find()) {
            String act_match = m.group();
            act_match = act_match.replaceAll("\\$", "");
            req_var.put(act_match, getVariableByName(act_match, vars).value);
        }

        if (req_var.size() == 0) {
            return s;
        }

        for (String key : req_var.keySet()) {
            res = res.replaceAll("\\$" + key + "\\$", Matcher.quoteReplacement(req_var.get(key)));
        }
        return res;
    }

    /**
     * Given a name, returns the corresponding variable
     *
     * @param name the name of the variable
     * @return the Var object
     * @throws ParsingException if the variable cannot be found
     */
    public static Var getVariableByName(String name, List<Var> vars) throws ParsingException {
        for (Var act : vars) {
            if (act.name.equals(name)) {
                return act;
            }
        }
        throw new ParsingException("variable \"" + name + "\" not defined");
    }

    /**
     * Used to process session operations of a given operation
     *
     * @param op the operation containing the session operation
     * @return An array of Object elements, the first is the edited operation, the second is the updated variables
     */
    public static Object[] executeSessionOps(Test t,
                                             Operation op,
                                             List<Var> vars) throws ParsingException {
        Object[] res = new Object[2];
        List<Var> updated_vars = vars;
        for (SessionOperation sop : op.session_operations) {
/*
            List<Var> vars_new = eal.onBeforeExSessionOps();

            for (Var v : vars_new) {
                if (!updated_vars.contains(v)) {
                    updated_vars.inse
                }
            }


 */
            Session session = t.getSession(sop.from_session);
            Track track = session.track;

            switch (sop.action) {
                case SAVE:
                    Var v = new Var();
                    v.name = sop.as;
                    v.isMessage = false;
                    v.value = "";
                    switch (sop.target) {
                        case TRACK:
                            for (SessionTrackAction sa : t.getSession(sop.from_session).track
                                    .getStasFromMarkers(sop.at, sop.to, sop.is_from_included, sop.is_to_included)) {
                                v.value += sa.toString() + "\n";
                            }
                            break;
                        case LAST_ACTION:
                            v.value = session.last_action.toString();
                            break;
                        case LAST_ACTION_ELEM:
                            v.value = session.last_action.elem;
                            break;
                        case LAST_ACTION_ELEM_PARENT:
                            v.value = findParentDiv(session.last_action.elem);
                            break;
                        case LAST_CLICK:
                            v.value = session.last_click.toString();
                            break;
                        case LAST_CLICK_ELEM:
                            v.value = session.last_click.elem;
                            break;
                        case LAST_CLICK_ELEM_PARENT:
                            v.value = findParentDiv(session.last_click.elem);
                            break;
                        case LAST_OPEN:
                            v.value = session.last_open.toString();
                            break;
                        case LAST_OPEN_ELEM:
                            v.value = session.last_open.elem;
                            break;
                        case LAST_URL:
                            v.value = session.last_url;
                            break;
                        case ALL_ASSERT:
                            for (SessionTrackAction sa : t.getSession(sop.from_session).track.getTrack()) {
                                if (sa.isAssert) {
                                    v.value += sa + "\n";
                                }
                            }
                            break;
                    }
                    updated_vars.add(v);
                    break;

                case INSERT:
                    String to_be_added = buildStringWithVars(updated_vars, sop.what);
                    track.insert(new Marker(sop.at), to_be_added);
                    break;

                case MARKER:
                    switch (sop.target) {
                        case LAST_ACTION:
                        case LAST_ACTION_ELEM:
                            track.mark(session.last_action, sop.mark_name);
                            break;
                        case LAST_CLICK:
                        case LAST_CLICK_ELEM:
                            track.mark(session.last_click, sop.mark_name);
                            break;
                        case LAST_OPEN:
                        case LAST_OPEN_ELEM:
                            track.mark(session.last_open, sop.mark_name);
                            break;
                        case ALL_ASSERT:
                            for (SessionTrackAction sa : t.getSession(sop.from_session).track.getTrack()) {
                                if (sa.isAssert) {
                                    track.mark(sa, sop.mark_name);
                                }
                            }
                            break;
                        case TRACK:
                        case LAST_URL:
                            throw new ParsingException("Invalid session operation target: " + sop.target);
                        default:
                            throw new ParsingException("Invalid session operation target");
                    }
                    break;
                case REMOVE:
                    if (sop.to != null && !sop.to.equals("")) {
                        // TODO: remove interval of indices instead of using the remove construct of lists, because it
                        // removes duplicated things

                        int[] range = t.getSession(sop.from_session).track.
                                getStasIndexFromRange(sop.at, sop.to, sop.is_from_included, sop.is_to_included);


                        t.getSession(sop.from_session).track.getTrack().subList(range[0], range[1]+1).clear();
                    } else {
                        track.remove(new Marker(sop.at));
                    }
                    break;
            }
        }
        res[0] = op;
        res[1] = updated_vars;
        return res;
    }

    /**
     * Finds the parent div of an http element
     * @param in the http element in xpath format
     * @return the xpath of the parent div
     * @throws ParsingException if no parent div present or input is malformed
     */
    public static String findParentDiv(String in) throws ParsingException {
        String[] split1 = in.split("=");
        if (split1.length != 2) {
            throw new ParsingException("invalid input \"" + in + "\" for finding parent div");
        }
        String[] split = split1[1].split("/");
        if (split.length == 0) {
            return in;
        }

        int cut_indx = -1;

        //-2 because if the last element is a div i don't take it, otherwise is not a div, so i don't take it
        for (int i = split.length - 2; i > 0; i--) {
            if (split[i].contains("div")) {
                cut_indx = i;
                break;
            }
        }
        if (cut_indx == -1) return in;

        String res = split1[0] + "=";

        for (int i = 1; i <= cut_indx; i++) {
            if (i == cut_indx) {
                // removes the index of the div element
                res += "/" + split[i].replaceAll("\\[.*\\]", "");
            } else {
                res += "/" + split[i];
            }
        }
        return res;
    }

    /**
     * An enum representing the possible message sections
     */
    public enum MessageSection {
        HEAD,
        BODY,
        URL,
        RAW;

        /**
         * Function that given a message section in form of String, returns the corresponding MessageSection enum value
         *
         * @param input the input string
         * @return the MessageSection enum value
         * @throws ParsingException if the input does not correspond to any of the possible messagesections
         */
        public static MessageSection fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "head":
                        return HEAD;
                    case "body":
                        return BODY;
                    case "url":
                        return URL;
                    case "raw":
                        return RAW;
                    default:
                        throw new ParsingException("message section not valid");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }

    /**
     * enum containing all the possible check operations
     */
    public enum CheckOps {
        IS,
        IS_NOT,
        CONTAINS,
        NOT_CONTAINS,
        IS_PRESENT,
        IS_NOT_PRESENT;

        /**
         * Function that given a String, returns the corresponding CheckOps enum's value
         *
         * @param input the input string
         * @return the CheckOps enum value
         * @throws ParsingException if the input string does not correspond to any of the possible check operations
         */
        public static CheckOps fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "is":
                        return IS;
                    case "is not":
                        return IS_NOT;
                    case "contains":
                        return CONTAINS;
                    case "not contains":
                        return NOT_CONTAINS;
                    default:
                        throw new ParsingException("invalid check operation");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }

    /**
     * Enum containing all the possible Active operation actions
     */
    public enum Action {
        INTERCEPT,
        VALIDATE;

        /**
         * From a string get the corresponding enum value
         *
         * @param input the string
         * @return the enum value
         * @throws ParsingException if the input is malformed
         */
        public static Action fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "intercept":
                        return INTERCEPT;
                    case "validate":
                        return VALIDATE;
                    default:
                        throw new ParsingException("invalid check operation");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }

    /**
     * Enum containing all the possible session operation actions
     */
    public enum SessionAction {
        START,
        PAUSE,
        RESUME,
        STOP,
        CLEAR_COOKIES;

        /**
         * From a string get the corresponding enum value
         *
         * @param input the string
         * @return the enum value
         * @throws ParsingException if the input is malformed
         */
        public static SessionAction fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "start":
                        return START;
                    case "pause":
                        return PAUSE;
                    case "resume":
                        return RESUME;
                    case "stop":
                        return STOP;
                    case "clear cookies":
                        return CLEAR_COOKIES;
                    default:
                        throw new ParsingException("invalid Session action");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }

    /**
     * Enum that contains all the possible action to do after a message is received
     */
    public enum Then {
        FORWARD,
        DROP;

        /**
         * From a string get the corresponding enum value
         *
         * @param input the string
         * @return the enum value
         * @throws ParsingException if the input is malformed
         */
        public static Then fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "forward":
                        return FORWARD;
                    case "drop":
                        return DROP;
                    default:
                        throw new ParsingException("invalid check operation");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }

    /**
     * All the possible actions of a MessageOperation
     */
    public enum MessageOperationActions {
        REMOVE_PARAMETER,
        REMOVE_MATCH_WORD,
        EDIT,
        EDIT_REGEX,
        ADD,
        SAVE,
        SAVE_MATCH;

        /**
         * From a string get the corresponding enum value
         *
         * @param input the string
         * @return the enum value
         * @throws ParsingException if the input is malformed
         */
        public static MessageOperationActions fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "remove parameter":
                        return REMOVE_PARAMETER;
                    case "remove match word":
                        return REMOVE_MATCH_WORD;
                    case "edit":
                        return EDIT;
                    case "edit regex":
                        return EDIT_REGEX;
                    case "add":
                        return ADD;
                    case "save":
                        return SAVE;
                    case "save match":
                        return SAVE_MATCH;
                    default:
                        throw new ParsingException("invalid check operation");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }

    /**
     * The result type of (also the oracle) of an Active test
     */
    public enum ResultType {
        CORRECT_FLOW,
        INCORRECT_FLOW,
        ASSERT_ONLY;

        /**
         * From a string get the corresponding enum value
         *
         * @param input the string
         * @return the enum value
         * @throws ParsingException if the input is malformed
         */
        public static ResultType fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "correct":
                        return CORRECT_FLOW;
                    case "incorrect":
                        return INCORRECT_FLOW;
                    case "assert_only":
                        return ASSERT_ONLY;
                    default:
                        throw new ParsingException("invalid result");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }

    /**
     * The possible encodings to be used
     */
    public enum Encoding {
        BASE64,
        URL,
        JWT,
        DEFLATE;

        /**
         * From a string get the corresponding enum value
         *
         * @param input the string
         * @return the enum value
         * @throws ParsingException if the input is malformed
         */
        public static Encoding fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "base64":
                        return BASE64;
                    case "url":
                        return URL;
                    case "jwt":
                        return JWT;
                    case "deflate":
                        return DEFLATE;
                    default:
                        throw new ParsingException("invalid encoding");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }

    /**
     * The possible types of messageOps
     */
    public enum MessageOpType {
        XML,
        JWT,
        HTTP,
        TXT,
        GENERATE_POC;

        /**
         * From a string get the corresponding enum value
         *
         * @param input the string
         * @return the enum value
         * @throws ParsingException if the input is malformed
         */
        public static MessageOpType fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "xml":
                        return XML;
                    case "jwt":
                        return JWT;
                    case "http":
                        return HTTP;
                    case "txt":
                        return TXT;
                    case "generate_poc":
                        return GENERATE_POC;
                    default:
                        throw new ParsingException("invalid message Op Type");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }

    public enum ContentType{
        JSON,
        HTTP;

        public static ContentType fromString(String input) throws ParsingException {
            if (input != null){
                switch (input){
                    case "json":
                        return JSON;
                    case "http":
                        return HTTP;
                    default:
                        throw new ParsingException("invalid content type " + input);
                }
            }
            throw new ParsingException("invalid content type");
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
     * Defines the possible JWT token sections
     */
    public enum Jwt_section {
        HEADER,
        PAYLOAD,
        SIGNATURE,
        RAW_HEADER,
        RAW_PAYLOAD,
        RAW_SIGNATURE;

        /**
         * Get the JWT section enum value from a string
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
                case "raw_header":
                    return RAW_HEADER;
                case "raw_payload":
                    return RAW_PAYLOAD;
                case "raw_signature":
                    return RAW_SIGNATURE;
                default:
                    throw new ParsingException("Invalid jwt section");
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
     * Defines the action of a session action
     */
    public enum SessAction {
        CLICK,
        OPEN,
        TYPE,
        SNAPSHOT,
        DIFF,
        EQUALS,
        WAIT,
        SET_VAR,
        CLEAR_COOKIES,
        ASSERT_CLICKABLE,
        ASSERT_NOT_CLICKABLE,
        ASSERT_VISIBLE,
        ASSERT_NOT_VISIBLE,
        ASSERT_ELEM_CONTENT_IS,
        ASSERT_ELEM_CONTENT_HAS,
        ASSERT_ELEM_CLASS_IS,
        ASSERT_ELEM_CLASS_HAS,
        ASSERT_ELEM_HAS_ATTRIBUTE,
        ASSERT_ELEM_NOT_HAS_ATTRIBUTE,
        ALERT;

        /**
         * Get a session action enum value from a string
         * @param s the string
         * @return the enum value
         * @throws ParsingException if the string is invalid
         */
        public static SessAction getFromString(String s) throws ParsingException {
            switch (s) {
                case "assert click":
                case "click":
                    return CLICK;
                case "open":
                case "assert open": // just an alias of open
                    return OPEN;
                case "type":
                    return TYPE;
                case "snapshot":
                    return SNAPSHOT;
                case "diff":
                    return DIFF;
                case "equals":
                    return EQUALS;
                case "wait":
                    return WAIT;
                case "set var":
                    return SET_VAR;
                case "clear cookies":
                    return CLEAR_COOKIES;
                case "assert clickable":
                    return ASSERT_CLICKABLE;
                case "assert not clickable":
                    return ASSERT_NOT_CLICKABLE;
                case "assert visible":
                    return ASSERT_VISIBLE;
                case "assert not visible":
                    return ASSERT_NOT_VISIBLE;
                case "assert element content is":
                    return ASSERT_ELEM_CONTENT_IS;
                case "assert element content has":
                    return ASSERT_ELEM_CONTENT_HAS;
                case "assert element class is":
                    return ASSERT_ELEM_CLASS_IS;
                case "assert element class has":
                    return ASSERT_ELEM_CLASS_HAS;
                case "assert element has attribute":
                    return ASSERT_ELEM_HAS_ATTRIBUTE;
                case "assert element not has attribute":
                    return ASSERT_ELEM_NOT_HAS_ATTRIBUTE;
                case "alert":
                    return ALERT;
                default:
                    throw new ParsingException("Invalid session action \"" + s + "\"");
            }
        }
    }

    /**
     * Defines the action of a session operation
     */
    public enum SessOperationAction {
        SAVE,
        INSERT,
        MARKER,
        REMOVE
    }

    /**
     * Defines the target of a session operation.
     * Is it better to use js or just build a form? if a form is used, body has to be interpreted
     */
    public enum SessOperationTarget {
        LAST_ACTION,
        LAST_ACTION_ELEM,
        LAST_ACTION_ELEM_PARENT,
        LAST_CLICK,
        LAST_CLICK_ELEM,
        LAST_CLICK_ELEM_PARENT,
        LAST_OPEN,
        LAST_OPEN_ELEM,
        LAST_URL,
        ALL_ASSERT,
        TRACK;

        /**
         * Parse a string containing a session operation target
         * @param s the string to parse
         * @throws ParsingException if the string is malformed, or no session operation target is found
         */
        public static SessOperationTarget getFromString(String s) throws ParsingException {

            if (s.contains(".")) {
                String[] splitted;
                splitted = s.split("\\.");
                String left = splitted[0];
                boolean parent = false;
                if (splitted.length == 3) {
                    if (splitted[2].equals("parent")) {
                        parent = true;
                    }
                }

                switch (s) {
                    case "last_action.elem":
                    case "last_action.elem.parent":
                        return parent ? LAST_ACTION_ELEM_PARENT : LAST_ACTION_ELEM;
                    case "last_click.elem":
                    case "last_click.elem.parent":
                        return parent ? LAST_CLICK_ELEM_PARENT : LAST_CLICK_ELEM;
                    case "last_open.elem":
                        return LAST_OPEN_ELEM;
                    case "last_url":
                        return LAST_URL;
                    case "all_assert":
                        return ALL_ASSERT;
                    default:
                        throw new ParsingException("invalid target in session operation");
                }
            } else {
                switch (s) {
                    case "track":
                        return TRACK;
                    case "last_action":
                        return LAST_ACTION;
                    case "last_click":
                        return LAST_CLICK;
                    case "last_open":
                        return LAST_OPEN;
                    case "last_url":
                        return LAST_URL;
                    case "all_assert":
                        return ALL_ASSERT;
                    default:
                        throw new ParsingException("invalid target in session operation");
                }
            }
        }
    }

    /**
     * Generates a CSRF POC from an HTTP request message
     * @param message the message to generate the POC from
     * @param helpers Burp's IExtensionHelper instance
     * @return the html poc as a string
     */
    public static String generate_CSRF_POC(IHttpRequestResponse message,
                                  IExtensionHelpers helpers){

        String CSFR_TEMPLATE= "<!DOCTYPE html>\n" +
                "<html>\n" +
                "  <body>\n" +
                "    <h2>Attack Page</h2>\n" +
                "    <p>Service Provider (SP) is your service.</p>\n" +
                "    <p>Identity Provider (IdP) is the provider with which the SP allows to associate the account.</p>\n" +
                "    <p>These are the steps to reproduce the attack:</p>\n" +
                "    <p>1. The victim clicks on button to initiate force-login to IdP and victim logs in as the attacker because IdP suffering of Pre-Authentication Login CSRF. To simulate this step, the victim logs in with the attacker's IdP credentials.</p>\n" +
                "    <p>2. The victim logins at SP with victim credentials.</p>\n" +
                "    <p>3. The victim clicks on following link which suffers of CSRF, to associate attacker IdP account with the Victim SP account.</p>\n" +
                "    $INSERT_HERE$\n" +
                "    <br>\n" +
                "    <p>4. If the IdP attacker account has been associated with the victim SP account then the vulnerability has been properly exploited.</p>\n" +
                "  </body>\n" +
                "</html>";

        String POST_TEMPLATE =
                "  <form enctype=\"$ENCODING_TYPE$\" method=\"$METHOD$\" action=\"$URL$\">\n" +
                "    <table>\n" +
                "        $BODY_PARAMETERS$\n" +
                "    </table>\n" +
                "    <input type=\"submit\" value=\"Link vulnerable to CSRF account association with IdP\">\n" +
                "  </form>\n";

        String TEMPLATE_BODY_PARAMS = "" +
                "       <tr>\n" +
                "        <td>$PARAM_NAME$</td>\n" +
                "        <td>\n" +
                "          <input type=\"text\" value=\"$PARAM_VALUE$\" name=\"$PARAM_NAME$\">\n" +
                "        </td>\n" +
                "      </tr>";

        List<String> headers = Utils.getHeaders(message, true, helpers);
        String encoding = getHeadParameterValue(headers, "Content-Type").strip();
        String body = splitMessage(message,helpers,true).get(2);
        String url = helpers.analyzeRequest(message).getUrl().toString();
        String method = splitMessage(message,helpers,true).get(0).split(" ")[0];

        Pattern p = Pattern.compile("");
        Matcher m = p.matcher(body);

        String res = "";

        res = POST_TEMPLATE;
        p = Pattern.compile("\\$ENCODING_TYPE\\$");
        m = p.matcher(res);
        res = m.replaceAll(encoding);

        p = Pattern.compile("\\$METHOD\\$");
        m = p.matcher(res);
        res = m.replaceAll(method);

        if (method.equals("POST")) {
            p = Pattern.compile("([^=]*)=([^&\\n$]*)(&|\\n|$)");
            m = p.matcher(body);
            String out_body_params = "";

            if (body.length() != 0) {
                Map<String, String> body_params = new HashMap<>();
                while (m.find()) {
                    String name = m.group(1);
                    String value = m.group(2);
                    if (name.length() != 0 ) {
                        body_params.put(name,
                                value.length() != 0 ? value : "");
                    }
                }
                for (String key : body_params.keySet()) {
                    String tmp = TEMPLATE_BODY_PARAMS;
                    p = Pattern.compile("\\$PARAM_NAME\\$");
                    m = p.matcher(tmp);

                    tmp = m.replaceAll(key);

                    p = Pattern.compile("\\$PARAM_VALUE\\$");
                    m = p.matcher(tmp);

                    tmp = m.replaceAll(body_params.get(key));

                    out_body_params += tmp;
                }
            }

            p = Pattern.compile("\\$URL\\$");
            m = p.matcher(res);
            res = m.replaceAll(url);

            p = Pattern.compile("\\$BODY_PARAMETERS\\$");
            m = p.matcher(res);
            res = m.replaceAll(out_body_params);
        } else {
            boolean has_query_params = url.split("\\?").length > 1;
            String out_query_params = "";

            if (has_query_params) {
                String raw_query_params = url.split("\\?")[1];

                p = Pattern.compile("([^=\\n&]*)=([^=\\n&]*)");
                m = p.matcher(raw_query_params);

                Map<String, String> query_params = new HashMap<>();
                while (m.find()) {
                    String name = m.group(1);
                    String value = m.group(2);
                    if (name.length() != 0) {
                        query_params.put(name, value.length() != 0 ? value : "");
                    }
                }
                for (String key : query_params.keySet()) {
                    String tmp = TEMPLATE_BODY_PARAMS;
                    p = Pattern.compile("\\$PARAM_NAME\\$");
                    m = p.matcher(tmp);

                    tmp = m.replaceAll(key);

                    p = Pattern.compile("\\$PARAM_VALUE\\$");
                    m = p.matcher(tmp);

                    tmp = m.replaceAll(query_params.get(key));

                    out_query_params += tmp;
                }
            }

            p = Pattern.compile("\\$URL\\$");
            m = p.matcher(res);
            res = m.replaceAll( has_query_params ? url.split("\\?")[0] : url);

            p = Pattern.compile("\\$BODY_PARAMETERS\\$");
            m = p.matcher(res);
            res = m.replaceAll(out_query_params);
        }

        String tmp = CSFR_TEMPLATE;
        p = Pattern.compile("\\$INSERT_HERE\\$");
        m = p.matcher(tmp);
        tmp = m.replaceAll(res);

        return tmp;
    }

    /**
     * Create batches of passive tests, grouping them by the session they need to execute.
     * @return An HashMap object having as keys, Strings representing the sessions names, and as value a list of tests
     * that need to execute that session
     */
    public static HashMap<String, List<Test>> batchPassivesFromSession(List<Test> testList) throws ParsingException {
        HashMap<String, List<Test>> batch = new HashMap<>();
        for (Test t : testList) {
            if (t.sessions.size() == 0) {
                throw new ParsingException("Undefined session in test " + t.name);
            }

            if(!batch.containsKey(t.sessions.get(0).name)){
                List<Test> n = new ArrayList<>();
                n.add(t);
                batch.put(t.sessions.get(0).name, n);
            } else {
                List<Test> tmp = batch.get(t.sessions.get(0).name);
                tmp.add(t);
                batch.put(t.sessions.get(0).name, tmp);
            }
        }
        return batch;
    }

    /**
     * From a batch of tests grouped by sessions, return a list containing all the tests
     * @param batch the batch of tests in the form of a MAP<String, List<Test>>
     * @return
     * @throws ParsingException
     */
    public static List<Test> debatchPassive(HashMap<String, List<Test>> batch) {
        List<Test> res = new ArrayList<>();
        for (String sessionName : batch.keySet()){
            for (Test t : batch.get(sessionName)) {
                res.add(t);
            }
        }
        return res;
    }

    /**
     * Given a message, get the given parameter value from the url
     *
     * @param message   the message to search into
     * @param isRequest if the message is a request
     * @param param     the parameter name to be searched
     * @return the value of the parameter
     */
    public static String getUrlParam(IExtensionHelpers helpers, IHttpRequestResponse message, Boolean isRequest, String param) {
        List<String> parts = Utils.splitMessage(message, helpers, isRequest);
        //Pattern pattern = Pattern.compile("(?=&?)" + param + "=[^& ]*((?=&)|(?= ))");

        Pattern pattern = Pattern.compile("(?<=" + param + "=)[^$\\n&\\s]*");
        Matcher matcher = pattern.matcher(parts.get(0));
        String res = "";
        while (matcher.find()) {
            res = matcher.group();
            break;
        }
        return res;
    }

    /**
     * Given a message, get the given parameter value from the url
     *
     * @param message   the message to search into
     * @param isRequest if the message is a request
     * @param param     the parameter name to be searched
     * @return the value of the parameter
     */
    public static String getUrlParam(IExtensionHelpers helpers, HTTPReqRes message, Boolean isRequest, String param) {
        List<String> parts = Utils.splitMessage(message, helpers, isRequest);
        //Pattern pattern = Pattern.compile("(?=&?)" + param + "=[^& ]*((?=&)|(?= ))");

        Pattern pattern = Pattern.compile("(?<=" + param + "=)[^$\\n&\\s]*");
        Matcher matcher = pattern.matcher(parts.get(0));
        String res = "";
        while (matcher.find()) {
            res = matcher.group();
            break;
        }
        return res;
    }

    /**
     * Given a message, get the given parameter value from the head
     *
     * @param message   the message to search into
     * @param isRequest if the message is a request
     * @param param     the parameter name to be searched
     * @return the value of the parameter
     */
    public static String getHeadParam(IExtensionHelpers helpers, IHttpRequestResponse message, Boolean isRequest, String param) {
        List<String> parts = Utils.splitMessage(message, helpers, isRequest);

        Pattern pattern = Pattern.compile("(?<=" + param + ":)[^$\\n]*", Pattern.MULTILINE);
        Matcher matcher = pattern.matcher(parts.get(1));
        String res = "";
        while (matcher.find()) {
            res = matcher.group();
            res = res;
            break;
        }
        return res;
    }

    /**
     * Given a message, get the given parameter value from the head
     *
     * @param message   the message to search into
     * @param isRequest if the message is a request
     * @param param     the parameter name to be searched
     * @return the value of the parameter
     */
    public static String getHeadParam(IExtensionHelpers helpers, HTTPReqRes message, Boolean isRequest, String param) {
        List<String> parts = Utils.splitMessage(message, helpers, isRequest);

        Pattern pattern = Pattern.compile("(?<=" + param + ":)[^$\\n]*", Pattern.MULTILINE);
        Matcher matcher = pattern.matcher(parts.get(1));
        String res = "";
        while (matcher.find()) {
            res = matcher.group();
            res = res;
            break;
        }
        return res;
    }

    /**
     * Given a message, get the given parameter value from the body, note that it accepts a regular expression, and
     * everything matched will be returned as a value
     *
     * @param message   the message to search into
     * @param isRequest if the message is a request
     * @param param     the parameter to be searched as a regex, everything matched by this will be returned as a value
     * @return the value of the parameter
     */
    public static String getBodyParam(IExtensionHelpers helpers, IHttpRequestResponse message, Boolean isRequest, String param) {
        List<String> parts = Utils.splitMessage(message, helpers, isRequest);

        //Pattern pattern = Pattern.compile("(?<=" + param + "=)[^$\\n&]*");
        Pattern pattern = Pattern.compile(param);
        Matcher matcher = pattern.matcher(parts.get(2));
        //parts.set(2, matcher.replaceAll(""));

        String res = "";
        while (matcher.find()) {
            res = matcher.group();
            break;
        }
        return res;
    }

    /**
     * Given a message, get the given parameter value from the body, note that it accepts a regular expression, and
     * everything matched will be returned as a value
     *
     * @param message   the message to search into
     * @param isRequest if the message is a request
     * @param param     the parameter to be searched as a regex, everything matched by this will be returned as a value
     * @return the value of the parameter
     */
    public static String getBodyParam(IExtensionHelpers helpers, HTTPReqRes message, Boolean isRequest, String param) {
        List<String> parts = Utils.splitMessage(message, helpers, isRequest);

        //Pattern pattern = Pattern.compile("(?<=" + param + "=)[^$\\n&]*");
        Pattern pattern = Pattern.compile(param);
        Matcher matcher = pattern.matcher(parts.get(2));
        //parts.set(2, matcher.replaceAll(""));

        String res = "";
        while (matcher.find()) {
            res = matcher.group();
            break;
        }
        return res;
    }

    /**
     * Edit a message treating it as a string using a regex
     * @param helpers an instance of Burp's IExtensionHelper
     * @param regex the regex used to match the things to change
     * @param mop the message operation containing information about the section to match the regex
     * @param messageInfo the message as IHttpRequestResponse object
     * @param isRequest specify if the message to consider is the request or response
     * @param new_value the new value to substitute to the message section
     * @param isBodyRegex not used, to remove
     * @return the edited message as byte array
     * @throws ParsingException if problems are encountered in editing the message
     */
    public static byte[] editMessage(IExtensionHelpers helpers,
                                     String regex,
                                     MessageOperation mop,
                                     IHttpRequestResponse messageInfo,
                                     boolean isRequest,
                                     String new_value,
                                     boolean isBodyRegex) throws ParsingException {
        List<String> splitted = null;
        Pattern pattern = null;
        Matcher matcher = null;
        switch (mop.from) {
            case HEAD:
                splitted = Utils.splitMessage(messageInfo, helpers, isRequest);

                pattern = Pattern.compile(regex);
                matcher = pattern.matcher(splitted.get(1));
                splitted.set(1, matcher.replaceAll(new_value));

                return Utils.buildMessage(splitted, helpers);

            case BODY:
                splitted = Utils.splitMessage(messageInfo, helpers, isRequest);

                pattern = Pattern.compile(regex);

                matcher = pattern.matcher(splitted.get(2));
                splitted.set(2, matcher.replaceAll(new_value));

                List<String> head = Utils.getHeaders(messageInfo, isRequest, helpers);
                //Automatically update content-lenght
                return helpers.buildHttpMessage(head, helpers.stringToBytes(splitted.get(2)));

            case URL:
                if (!isRequest) {
                    throw new ParsingException("Encoding URL in response");
                }
                splitted = Utils.splitMessage(messageInfo, helpers, isRequest);

                pattern = Pattern.compile(regex);
                matcher = pattern.matcher(splitted.get(0));

                String replaced = matcher.replaceAll(new_value);

                splitted.set(0, replaced); // problema

                return Utils.buildMessage(splitted, helpers);
        }

        return null;
    }

    /**
     * Edit a message parameter
     * @param helpers an instance of Burp's IExtensionHelper
     * @param param_name the name of the parameter to edit
     * @param message_section the message section to edit
     * @param messageInfo the message as IHttpRequestResponse object
     * @param isRequest specify if the message to consider is the request or response
     * @param new_value the new value of the parameter
     * @param isBodyRegex when the section is body, set it to true if you want to use a regex to substitute the value,
     *                    otherwise a parameter param=... is searched
     * @return the edited message as byte array
     * @throws ParsingException if problems are encountered in editing the message
     */
    public static byte[] editMessageParam(IExtensionHelpers helpers,
                                          String param_name,
                                          Utils.MessageSection message_section,
                                          IHttpRequestResponse messageInfo,
                                          boolean isRequest,
                                          String new_value,
                                          boolean isBodyRegex) throws ParsingException {
        List<String> splitted = null;
        Pattern pattern = null;
        Matcher matcher = null;
        switch (message_section) {
            case HEAD:
                List<String> headers = Utils.getHeaders(messageInfo, isRequest, helpers);
                headers = Utils.editHeadParameter(headers, param_name, new_value);
                byte[] message = helpers.buildHttpMessage(
                        headers,
                        Utils.getBody(messageInfo, isRequest, helpers));

                if (param_name.equals("Host")) {
                    messageInfo.setHttpService(
                            helpers.buildHttpService(
                                    new_value,
                                    messageInfo.getHttpService().getPort(),
                                    messageInfo.getHttpService().getProtocol()
                            )
                    );
                }

                return message;

            case BODY:
                splitted = Utils.splitMessage(messageInfo, helpers, isRequest);

                if (!isBodyRegex) {
                    pattern = Pattern.compile("(?<=" + param_name + "=)[^$\\n& ]*");
                } else {
                    pattern = Pattern.compile(param_name);
                }

                matcher = pattern.matcher(splitted.get(2));
                splitted.set(2, matcher.replaceAll(new_value));

                List<String> head = Utils.getHeaders(messageInfo, isRequest, helpers);
                //Automatically update content-lenght
                return helpers.buildHttpMessage(head, helpers.stringToBytes(splitted.get(2)));

            case URL:
                if (!isRequest) {
                    throw new ParsingException("Encoding URL in response");
                }
                splitted = Utils.splitMessage(messageInfo, helpers, isRequest);

                pattern = Pattern.compile(param_name + "=[^& ]*((?=&)|(?= ))");
                matcher = pattern.matcher(splitted.get(0));

                splitted.set(0, matcher.replaceAll(param_name + "=" + new_value)); // problema

                return Utils.buildMessage(splitted, helpers);
        }

        return null;
    }
}
