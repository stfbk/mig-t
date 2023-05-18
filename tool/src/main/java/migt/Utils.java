package migt;

import burp.IExtensionHelpers;
import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * class containing useful methods and enums to be used in other classes
 *
 * @author Matteo Bitussi
 */
public class Utils {
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
            Check check = new Check(act_check);

            if (check.in == null) {
                throw new ParsingException("In tag cannot be empty");
            }
            res.add(check);
        }
        return res;
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
     * Removes all the newlines from a string
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
     * Builds a string, substituting variables names with values
     *
     * @param vars the list of variables to use
     * @param s    the string
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
     * Generates a CSRF POC from an HTTP request message
     *
     * @param message the message to generate the POC from
     * @param helpers Burp's IExtensionHelper instance
     * @return the html poc as a string
     */
    public static String generate_CSRF_POC(HTTPReqRes message,
                                           IExtensionHelpers helpers) {

        String CSFR_TEMPLATE = "<!DOCTYPE html>\n" +
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

        String TEMPLATE_BODY_PARAMS = "       <tr>\n" +
                "        <td>$PARAM_NAME$</td>\n" +
                "        <td>\n" +
                "          <input type=\"text\" value=\"$PARAM_VALUE$\" name=\"$PARAM_NAME$\">\n" +
                "        </td>\n" +
                "      </tr>";

        List<String> headers = message.getHeaders(true);
        String encoding = message.getHeadParam(true, "Content-Type").strip();
        String body = new String(message.getBody(true), StandardCharsets.UTF_8); // splitMessage(message, helpers, true).get(2);
        String url = message.getUrl();
        String method = message.getUrlHeader().split(" ")[0];

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
                    if (name.length() != 0) {
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
            res = m.replaceAll(has_query_params ? url.split("\\?")[0] : url);

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
     *
     * @return An HashMap object having as keys, Strings representing the sessions names, and as value a list of tests
     * that need to execute that session
     */
    public static HashMap<String, List<Test>> batchPassivesFromSession(List<Test> testList) throws ParsingException {
        HashMap<String, List<Test>> batch = new HashMap<>();
        for (Test t : testList) {
            if (t.sessions.size() == 0) {
                throw new ParsingException("Undefined session in test " + t.name);
            }

            if (!batch.containsKey(t.sessions.get(0).name)) {
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
     *
     * @param batch the batch of tests in the form of a MAP<String, List<Test>>
     * @return
     * @throws ParsingException
     */
    public static List<Test> debatchPassive(HashMap<String, List<Test>> batch) {
        List<Test> res = new ArrayList<>();
        for (String sessionName : batch.keySet()) {
            for (Test t : batch.get(sessionName)) {
                res.add(t);
            }
        }
        return res;
    }

    /**
     * Edit a message treating it as a string using a regex
     *
     * @param helpers     an instance of Burp's IExtensionHelper
     * @param regex       the regex used to match the things to change
     * @param mop         the message operation containing information about the section to match the regex
     * @param messageInfo the message as IHttpRequestResponse object
     * @param isRequest   specify if the message to consider is the request or response
     * @param new_value   the new value to substitute to the message section
     * @return the edited message as byte array
     * @throws ParsingException if problems are encountered in editing the message
     */
    public static byte[] editMessage(IExtensionHelpers helpers,
                                     String regex,
                                     MessageOperation mop,
                                     HTTPReqRes messageInfo,
                                     boolean isRequest,
                                     String new_value) throws ParsingException {
        // TODO: remove dependency from Helpers
        Pattern pattern = null;
        Matcher matcher = null;
        switch (mop.from) {
            case HEAD:
                List<String> head = messageInfo.getHeaders(isRequest);
                pattern = Pattern.compile(regex);
                List<String> new_head = new ArrayList<>();

                for (String act_header : head) {
                    matcher = pattern.matcher(act_header);
                    new_head.add(matcher.replaceAll(new_value));
                }
                messageInfo.setHeaders(isRequest, new_head);
                return messageInfo.getMessage(isRequest, helpers);

            case BODY:
                pattern = Pattern.compile(regex);

                matcher = pattern.matcher(new String(messageInfo.getBody(isRequest)));
                messageInfo.setBody(isRequest, matcher.replaceAll(new_value));
                //Automatically update content-lenght
                return messageInfo.getMessage(isRequest, helpers);

            case URL:
                if (!isRequest) {
                    throw new ParsingException("Encoding URL in response");
                }

                pattern = Pattern.compile(regex);
                matcher = pattern.matcher(messageInfo.getUrlHeader());
                String replaced = matcher.replaceAll(new_value);
                messageInfo.setUrlHeader(replaced);

                return messageInfo.getMessage(isRequest, helpers);
        }

        return null;
    }

    /**
     * Edit a message parameter
     *
     * @param helpers         an instance of Burp's IExtensionHelper
     * @param param_name      the name of the parameter to edit
     * @param message_section the message section to edit
     * @param messageInfo     the message as IHttpRequestResponse object
     * @param isRequest       specify if the message to consider is the request or response
     * @param new_value       the new value of the parameter
     * @param isBodyRegex     when the section is body, set it to true if you want to use a regex to substitute the value,
     *                        otherwise a parameter param=... is searched
     * @return the edited message as byte array
     * @throws ParsingException if problems are encountered in editing the message
     */
    public static byte[] editMessageParam(IExtensionHelpers helpers,
                                          String param_name,
                                          Utils.MessageSection message_section,
                                          HTTPReqRes messageInfo,
                                          boolean isRequest,
                                          String new_value,
                                          boolean isBodyRegex) throws ParsingException {
        List<String> splitted = null;
        Pattern pattern = null;
        Matcher matcher = null;
        switch (message_section) {
            case HEAD:
                messageInfo.editHeadParam(isRequest, param_name, new_value);
                byte[] message = messageInfo.getMessage(isRequest, helpers);
                messageInfo.setHost(new_value); // this should be set when the message is converted to the burp class
                return message;

            case BODY:
                if (!isBodyRegex) {
                    pattern = Pattern.compile("(?<=" + param_name + "=)[^$\\n& ]*");
                } else {
                    pattern = Pattern.compile(param_name);
                }

                matcher = pattern.matcher(new String(messageInfo.getBody(isRequest)));
                messageInfo.setBody(isRequest, matcher.replaceAll(new_value));
                //Automatically update content-lenght
                return messageInfo.getMessage(isRequest, helpers);

            case URL:
                if (!isRequest) {
                    throw new ParsingException("Encoding URL in response");
                }
                String url_header = messageInfo.getUrlHeader();

                pattern = Pattern.compile(param_name + "=[^& ]*((?=&)|(?= ))");
                matcher = pattern.matcher(url_header);

                messageInfo.setUrlHeader(matcher.replaceAll(param_name + "=" + new_value)); // problema

                return messageInfo.getMessage(isRequest, helpers);
        }
        return null;
    }

    /**
     * Given a name, returns the corresponding variable
     *
     * @param name the name of the variable
     * @return the Var object
     * @throws ParsingException if the variable cannot be found
     */
    public static Var getVariableByName(String name, GUI mainPane) throws ParsingException {
        synchronized (mainPane.lock) {
            for (Var act : mainPane.act_test_vars) {
                if (act.name.equals(name)) {
                    return act;
                }
            }
        }
        throw new ParsingException("variable not defined");
    }

    /**
     * Executes the decode operations in an operation
     *
     * @param op
     * @param messageInfo
     * @param isRequest
     * @param helpers
     * @param mainPane
     * @return
     * @throws ParsingException
     */
    public static Operation executeDecodeOps(Operation op,
                                             HTTPReqRes messageInfo,
                                             boolean isRequest,
                                             IExtensionHelpers helpers,
                                             GUI mainPane) throws ParsingException {
        Operation_API api = new Operation_API(messageInfo, isRequest);
        for (DecodeOperation dop : op.getDecodeOperations()) {
            // TODO: add to parser the decode operations list
            dop.loader(api, helpers);
            dop.execute(mainPane);
            if (!op.setResult(dop))
                break;
            api = dop.exporter();
        }

        return op;
    }

    /**
     * Finds the parent div of an http element
     *
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
        HTTP,
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
                    case "http":
                        return HTTP;
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

    public enum DecodeOpType {
        JWT,
        TXT,
        XML;

        public static DecodeOpType fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "jwt":
                        return JWT;
                    case "txt":
                        return TXT;
                    case "xml":
                        return XML;
                    default:
                        throw new ParsingException("invalid message Op Type");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }

    public enum ContentType {
        JSON,
        HTTP;

        public static ContentType fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
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
         *
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
         *
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
}
