package migt;

import burp.IExtensionHelpers;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Class with methods to process messages and execute tests
 *
 * @author Matteo Bitussi
 */
public class Tools {
    /**
     * Function that execute the given passive test.
     *
     * @param test        a <Code>Test</Code> element, it has to be a passive test
     * @param messageList a list of <code>HTTPReqRes</code> messages
     * @param helpers     an istance of <code>IExtensionHelpers</code>
     * @param msg_types   the message types used by the test
     * @return true if a test is passed, false otherwise
     */
    public static boolean executePassiveTest(Test test,
                                             List<HTTPReqRes> messageList,
                                             IExtensionHelpers helpers,
                                             List<MessageType> msg_types) {
        int i, j;
        boolean res = true;
        boolean actisreq = false;
        boolean actisresp = false;

        for (i = 0; i < messageList.size(); i++) {
            j = 0;
            while (j < test.operations.size() && res) {
                actisreq = false;
                actisresp = false;

                Operation currentOP = test.operations.get(j);

                List<Boolean> result = null;
                try {
                    result = executePassiveOperation(currentOP, messageList.get(i), i, helpers, msg_types);
                } catch (ParsingException e) {
                    e.printStackTrace();
                    res = false;
                    currentOP.applicable = false;
                    break;
                }
                res = result.get(0);
                actisreq = result.get(1);
                actisresp = result.get(2);
                currentOP.applicable = result.get(3);
                j++;
            }
            if (!res) {
                test.operations.get(--j).matchedMessages.add(new Operation.MatchedMessage(messageList.get(i), i, actisreq, actisresp, true));
                break;
            }
        }

        for (Operation op : test.operations) {
            if (!op.applicable) {
                res = false;
                test.applicable = false;
                break;
            }
        }

        return res;
    }

    /**
     * Còass that executes a passive operation
     *
     * @param op           The operation to be executed
     * @param message      the message to be used in the execution
     * @param messageIndex the index of that message w.r.t. the list of messages ( if present ) otherwise write 0
     * @param helpers      An istance of the IExtensionHelpers
     * @param msg_types    the list of msg_types available
     * @return a list of booleans, containing in order: the result of the operation, if the actual message is a request,
     * if the actual message is a response, if the operation is applicable
     * <p>
     * Note that this function is used also to validate active checks.
     */
    public static List<Boolean> executePassiveOperation(Operation op,
                                                        HTTPReqRes message,
                                                        int messageIndex,
                                                        IExtensionHelpers helpers,
                                                        List<MessageType> msg_types) throws ParsingException {
        boolean res = true;
        boolean actisreq = false;
        boolean actisresp = false;
        switch (op.getMessageType()) {
            case "request":
                op.applicable = true;
                actisreq = true;
                res = processOperation(op, message, messageIndex, helpers, true);
                break;
            case "response":
                op.applicable = true;
                actisreq = true;
                res = processOperation(op, message, messageIndex, helpers, false);
                break;
            default:
                try {
                    MessageType msg_type = MessageType.getFromList(msg_types, op.getMessageType());

                    /* If the response message name is searched, the getByResponse will be true.
                     * so messageIndex have to search for the request, and then evaluate the response*/
                    Boolean matchedMessage = false;

                    if (msg_type.getByResponse) {
                        if (msg_type.isRegex) {
                            matchedMessage = Tools.findInMessage(msg_type.messageSection,
                                    msg_type.regex,
                                    message,
                                    helpers,
                                    true);
                        } else {
                            matchedMessage = Tools.executeChecks(msg_type.checks,
                                    message,
                                    helpers,
                                    true);
                        }
                        if (matchedMessage) {
                            op.applicable = true;
                            actisreq = false;
                            actisresp = true;

                            res = processOperation(op, message, messageIndex, helpers, false);
                        }
                    } else if (msg_type.getByRequest) {
                        if (msg_type.isRegex) {
                            matchedMessage = Tools.findInMessage(msg_type.messageSection,
                                    msg_type.regex,
                                    message,
                                    helpers, false);
                        } else {
                            matchedMessage = Tools.executeChecks(msg_type.checks,
                                    message,
                                    helpers, false);
                        }
                        if (matchedMessage) {
                            op.applicable = true;
                            actisreq = false;
                            actisresp = true;

                            res = processOperation(op, message, messageIndex, helpers, true);
                        }
                    } else {
                        if (msg_type.isRegex) {
                            matchedMessage = Tools.findInMessage(msg_type.messageSection,
                                    msg_type.regex,
                                    message,
                                    helpers,
                                    msg_type.isRequest);
                        } else {
                            matchedMessage = Tools.executeChecks(msg_type.checks,
                                    message,
                                    helpers,
                                    msg_type.isRequest);
                        }
                        if (matchedMessage) {
                            op.applicable = true;
                            actisreq = msg_type.isRequest;
                            actisresp = !msg_type.isRequest;

                            res = processOperation(op, message, messageIndex, helpers, msg_type.isRequest);
                        }
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
        }
        List<Boolean> tmp = new ArrayList<>();
        tmp.add(res);
        tmp.add(actisreq);
        tmp.add(actisresp);
        tmp.add(op.applicable);
        return tmp;
    }

    /**
     * Function that processes an operation over a message
     *
     * @param currentOP     the <code>Operation</code> to be processed
     * @param act_message   the message over which the operation has to be executed
     * @param message_index the index of the <code>act_message</code> in the messages list
     * @param helpers       An istance of the helpers
     * @param isRequest     set true if the request has to be processed
     * @return the result of the operation
     */
    public static boolean processOperation(Operation currentOP,
                                           HTTPReqRes act_message,
                                           int message_index,
                                           IExtensionHelpers helpers,
                                           boolean isRequest) throws ParsingException {
        currentOP.setAPI(new Operation_API(act_message, isRequest));
        HTTPReqRes message = null;
        boolean res = true;

        try {
            message = (HTTPReqRes) act_message.clone();
        } catch (CloneNotSupportedException e) {
            e.printStackTrace();
            currentOP.applicable = false;
            return false;
        }

        currentOP = executeDecodeOps(
                currentOP,
                helpers,
                null
        );

        if (currentOP.hasChecks()) {
            try {
                res = !isRequest || Tools.executeChecks(
                        currentOP.getChecks(), message, helpers, true);
                if (!res) {
                    if (isRequest)
                        currentOP.matchedMessages.add(
                                new Operation.MatchedMessage(
                                        message, message_index, true, false, true));
                    return false;
                }
                res = isRequest || Tools.executeChecks(
                        currentOP.getChecks(), message, helpers, false);
                if (!res) {
                    if (!isRequest)
                        currentOP.matchedMessages.add(
                                new Operation.MatchedMessage(
                                        message, message_index, false, true, true));
                    return false;
                }

                if (isRequest)
                    currentOP.matchedMessages.add(
                            new Operation.MatchedMessage(
                                    message, message_index, true, false, false));
                if (!isRequest)
                    currentOP.matchedMessages.add(
                            new Operation.MatchedMessage(
                                    message, message_index, false, true, false));
            } catch (ParsingException e) {
                currentOP.applicable = false;
                System.err.println(e);
            }
        }

        return res;
    }

    /**
     * Function that check a regex over a given message and section
     *
     * @param section the section of the message to be checked with the regex
     * @param regex   the regex
     * @param message the message to be checked
     * @param helpers an instance of the helpers
     * @return the result of the check, if the regex matches 1 or more time it returns true
     */
    public static boolean findInMessage(HTTPReqRes.MessageSection section,
                                        String regex,
                                        HTTPReqRes message,
                                        IExtensionHelpers helpers,
                                        boolean isRequest) throws ParsingException {
        int occ = 0;

        Pattern pattern;
        Matcher matcher;

        switch (section) {
            case URL:
                if (!isRequest) {
                    throw new ParsingException("Searching URL in response");
                }
                String url = message.getRequest_url();
                pattern = Pattern.compile(regex);
                matcher = pattern.matcher(url);

                while (matcher.find()) {
                    occ++;
                }
                break;

            case HEAD:
                pattern = Pattern.compile(regex);
                List<String> header = isRequest ? helpers.analyzeRequest(message.getRequest()).getHeaders() :
                        helpers.analyzeResponse(message.getResponse()).getHeaders();

                String headersString = getAllHeaders(header);

                matcher = pattern.matcher(headersString);

                while (matcher.find()) {
                    occ++;
                }
                break;

            case BODY:
                pattern = Pattern.compile(regex, Pattern.DOTALL);
                int index = isRequest ?
                        helpers.analyzeRequest(message.getRequest()).getBodyOffset()
                        : helpers.analyzeResponse(message.getResponse()).getBodyOffset();

                byte[] body = isRequest ?
                        Arrays.copyOfRange(message.getRequest(), index, message.getRequest().length)
                        : Arrays.copyOfRange(message.getResponse(), index, message.getResponse().length);

                String rawBody = new String(body);
                matcher = pattern.matcher(rawBody);

                while (matcher.find()) {
                    occ++;
                }
                break;

            case RAW:
                String raw_msg = isRequest ?
                        new String(message.getRequest(), StandardCharsets.UTF_8) :
                        new String(message.getResponse(), StandardCharsets.UTF_8);

                pattern = Pattern.compile(regex, Pattern.DOTALL);
                matcher = pattern.matcher(raw_msg);

                while (matcher.find()) {
                    occ++;
                }
                break;

            default:
                System.out.println("No right message section selected");
        }

        return (occ > 0);
    }

    /**
     * Function that given a list of headers, concatenates them in a single string
     *
     * @param headers the list of headers
     * @return the string
     */
    public static String getAllHeaders(List<String> headers) {
        StringBuilder out = new StringBuilder();
        for (Object o : headers) {
            out.append(o.toString());
            out.append("\n");
        }
        return out.toString();
    }

    /**
     * This function execute a list of checks over a message, returning true if all the checks are successful
     *
     * @param checks    a List of checks
     * @param message   the message to be checked
     * @param helpers   an istance of the helpers
     * @param isRequest set true if the request has to be checked, false for the response
     * @return returns the result of the checks (true if all the tests are successful)
     */
    public static boolean executeChecks(List<Check> checks,
                                        HTTPReqRes message,
                                        IExtensionHelpers helpers,
                                        boolean isRequest) throws ParsingException {
        //TODO: change to module in progress
        for (Check c : checks) {
            if (!c.execute(message, helpers, isRequest)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Execute a list of checks from an operation. Uses API.
     *
     * @param op
     * @return
     * @throws ParsingException
     */
    public static boolean executeChecks(Operation op) throws ParsingException {
        // TODO
        for (Check c : op.getChecks()) {
            c.loader(op.api); //TODO: change loader to an Operation api
            c.execute();
            if (!op.setResult(c)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Executes the decode operations in an operation. Uses APIs. Sets the result to the operation
     *
     * @param op       the operation to execute the decode operations from
     * @param helpers  the Burp helpers
     * @param mainPane reference to the mainPane object (contains the variables)
     * @return The operation (edited)
     * @throws ParsingException if something goes wrong
     */
    public static Operation executeDecodeOps(Operation op,
                                             IExtensionHelpers helpers,
                                             GUI mainPane) throws ParsingException {
        Operation_API api = op.getAPI();
        for (DecodeOperation dop : op.getDecodeOperations()) {
            dop.loader(api, helpers);
            dop.execute(mainPane);
            if (!op.setResult(dop))
                break;
            op.setAPI(dop.exporter());
        }

        return op;
    }

    /**
     * Executes a decode operation, from a decode operation. This is basically the recursive step.
     *
     * @param op       the decode operation executing its child decode operations
     * @param helpers  the burp helpers
     * @param mainPane reference to the mainPane object (contains the variables)
     * @return The operation (edited)
     * @throws ParsingException if something goes wrong
     */
    public static DecodeOperation executeDecodeOps(DecodeOperation op,
                                                   IExtensionHelpers helpers,
                                                   GUI mainPane) throws ParsingException {
        DecodeOperation_API api = op.getAPI();
        for (DecodeOperation dop : op.decodeOperations) {
            dop.loader(api, helpers);
            dop.execute(mainPane);
            if (!op.setResult(dop))
                break;
            op.setAPI(dop.exporter());
        }

        return op;
    }

    /**
     * Executes the edit operations inside of a decode operation
     *
     * @param op       the decode operation to run the edit operations from
     * @param mainPane reference to the mainPane object (contains the variables)
     * @return the Decode operation (edited)
     * @throws ParsingException if something goes wrong
     */
    public static DecodeOperation executeEditOps(DecodeOperation op,
                                                 GUI mainPane) throws ParsingException {
        DecodeOperation_API api = op.getAPI();
        for (EditOperation eop : op.editOperations) {
            eop.loader(api);
            eop.execute(mainPane);
            if (!op.setResult(eop))
                break;
            op.setAPI(eop.exporter());
        }

        return op;
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
            Check check = new Check(act_check);

            if (check.in == null) {
                throw new ParsingException("In tag cannot be empty");
            }
            res.add(check);
        }
        return res;
    }

    /**
     * Parses a list of Edit operations from a JSON array
     *
     * @param edits_array the input JSON array containing the edit operations
     * @return the parsed list of Edit operations
     * @throws ParsingException if there are problems parsing the JSON array
     */
    public static List<EditOperation> parseEditsFromJSON(JSONArray edits_array) throws ParsingException {
        List<EditOperation> res = new ArrayList<>();
        for (int i = 0; i < edits_array.length(); i++) {
            JSONObject act_edit = edits_array.getJSONObject(i);
            EditOperation edit = new EditOperation(act_edit);
            res.add(edit);
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
                msg_obj.messageSection = HTTPReqRes.MessageSection.fromString(act_msg_type.getString("message section"));
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
     * @return a list containing all the tests
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
                                          HTTPReqRes.MessageSection message_section,
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

    public static byte[] editMessageParam(IExtensionHelpers helpers,
                                          String param_name,
                                          DecodeOperation.DecodeOperationFrom decodeOperationFrom,
                                          HTTPReqRes messageInfo,
                                          boolean isRequest,
                                          String new_value,
                                          boolean isBodyRegex) throws ParsingException {

        HTTPReqRes.MessageSection ms = null;

        switch (decodeOperationFrom) {
            case HEAD:
                ms = HTTPReqRes.MessageSection.HEAD;
                break;
            case BODY:
                ms = HTTPReqRes.MessageSection.BODY;
                break;
            case URL:
                ms = HTTPReqRes.MessageSection.URL;
                break;
            case JWT_HEADER:
            case JWT_PAYLOAD:
            case JWT_SIGNATURE:
                throw new ParsingException("invalid from section in decode operation should be a message section");
        }

        return editMessageParam(
                helpers,
                param_name,
                ms,
                messageInfo,
                isRequest,
                new_value,
                isBodyRegex
        );
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
     * Given a json string and a json path, edit the json.
     *
     * @param action   the action to do, (edit, remove, add, or save)
     * @param content  the json content as string
     * @param j_path   the json path as string
     * @param mainPane the mainPane reference, to access the variables
     * @param save_as  the name of the variable if the action is save
     * @return the edited json
     * @throws PathNotFoundException if the path in the json is not found
     */
    public static String editJson(EditOperation.Jwt_action action,
                                  String content,
                                  String j_path,
                                  GUI mainPane,
                                  String save_as,
                                  String newValue) throws PathNotFoundException {
        Object document = Configuration.defaultConfiguration().jsonProvider().parse(content);
        JsonPath jsonPath = JsonPath.compile(j_path);

        switch (action) {
            case REMOVE:
                document = jsonPath.delete(document, Configuration.defaultConfiguration());
                break;
            case EDIT:
            case ADD:
                document = jsonPath.set(document, newValue, Configuration.defaultConfiguration());
                //TODO: check if set also adds in case it is not found
                break;
            case SAVE:
                Var v = new Var();
                v.name = save_as;
                v.isMessage = false;
                v.value = JsonPath.read(content, j_path); //TODO could rise errors
                synchronized (mainPane.lock) {
                    mainPane.act_test_vars.add(v);
                }
                break;
        }
        return Configuration.defaultConfiguration().jsonProvider().toJson(document); //basically converts to string
    }
}
