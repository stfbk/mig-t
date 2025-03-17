package org.zaproxy.addon.migt;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** Class with methods to process messages and execute tests */
public class Tools {

    /**
     * This function execute a list of checks over a message, returning true if all the checks are
     * successful
     *
     * @param checks a List of checks
     * @param message the message to be checked
     * @param isRequest set true if the request has to be checked, false for the response
     * @return returns the result of the checks (true if all the tests are successful)
     */
    public static boolean executeChecks(
            List<Check> checks, HTTPReqRes message, boolean isRequest, List<Var> vars)
            throws ParsingException {
        System.out.println("eseguito executeChecks");
        for (Check c : checks) {
            //TODO ----------------> IL PROBLEMA E' QUA
            if (!c.execute(message, isRequest, vars)) {
                System.out.println("executeChecks will return false");
                return false;
            }
        }
        System.out.println("executeChecks will return true");
        return true;
    }

    /**
     * Execute a list of checks in an operation. Uses API.
     *
     * @param op the operation to execute checks from
     * @return the result of the checks
     * @throws ParsingException if something goes wrong related to the definition of the test
     */
    public static Operation executeChecks(Operation op, List<Var> vars) throws ParsingException {
        for (Check c : op.getChecks()) {
            c.loader(op.api);
            c.execute(vars);
            if (!op.setResult(c)) break;
        }
        return op;
    }

    /**
     * Executes the decode operations in an operation. Uses APIs. Sets the result to the operation
     *
     * @param op the operation to execute the decode operations from
     * @return The operation (edited)
     * @throws ParsingException if something goes wrong
     */
    public static Operation executeDecodeOps(Operation op, List<Var> vars) throws ParsingException {
        for (DecodeOperation dop : op.getDecodeOperations()) {
            dop.loader(op.getAPI());
            dop.execute(vars);
            if (!op.setResult(dop)) break;
            op.setAPI((Operation_API) dop.exporter());
        }

        return op;
    }

    /**
     * Executes the decode operations in a decode operation. This is the recursive step.
     *
     * @param op the decode operation executing its child decode operations
     * @return The operation (edited)
     * @throws ParsingException if something goes wrong
     */
    public static DecodeOperation executeDecodeOps(DecodeOperation op, List<Var> vars)
            throws ParsingException {
        for (DecodeOperation dop : op.decodeOperations) {
            dop.loader(op.getAPI());
            dop.execute(vars);
            if (!op.setResult(dop)) break;
            op.setAPI((DecodeOperation_API) dop.exporter());
        }

        return op;
    }

    /**
     * Executes the edit operations inside a decode operation
     *
     * @param op the decode operation to run the edit operations from
     * @return the Decode operation (edited)
     * @throws ParsingException if something goes wrong
     */
    public static DecodeOperation executeEditOps(DecodeOperation op, List<Var> vars)
            throws ParsingException {
        for (EditOperation eop : op.editOperations) {
            eop.loader(op.getAPI());
            eop.execute(vars);
            if (!op.setResult(eop)) break;
            op.setAPI(eop.exporter());
        }

        return op;
    }

    /**
     * Executes the edit operations inside a standard Operation
     *
     * @param op the Operation to run the edit operations from
     * @return the Operation (edited)
     * @throws ParsingException if something goes wrong
     */
    public static Operation executeEditOps(Operation op, List<Var> vars) throws ParsingException {
        for (EditOperation eop : op.editOperations) {
            eop.loader(op.getAPI());
            eop.execute(vars);
            if (!op.setResult(eop)) break;
            op.setAPI((Operation_API) eop.exporter());
        }

        return op;
    }

    public static Operation executeMessageOperations(Operation op) throws ParsingException {
        for (MessageOperation mop : op.messageOperations) {
            mop.loader(op.api);
            mop.execute();
            op.setAPI(mop.exporter());
            if (!op.setResult(mop)) break;
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
    public static List<EditOperation> parseEditsFromJSON(JSONArray edits_array)
            throws ParsingException {
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
     * @return a List of MessageType objects
     * @throws ParsingException if the input is malformed
     */
    public static List<MessageType> readMsgTypesFromJson(String input) throws ParsingException {
        List<MessageType> msg_types = new ArrayList<>();

        JSONObject obj = null;

        try {
            obj = new JSONObject(input);
        } catch (JSONException e) {
            throw new ParsingException("Invalid JSON in message definition file: " + e);
        }
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
                msg_obj.checks = parseChecksFromJSON(act_msg_type.getJSONArray("checks"));
            } else {
                throw new ParsingException(
                        "message type definition is invalid, no checks or regex found");
            }
            msg_types.add(msg_obj);
        }

        return msg_types;
    }

    /**
     * Returns the default string that contains the default message types that fill a msg_def.json
     * file
     *
     * @return the string
     */
    public static String getDefaultJSONMsgType() {
        return "{\n"
                + "    \"message_types\": [\n"
                + "        {\n"
                + "            \"name\": \"authorization request\",\n"
                + "            \"is request\": true,\n"
                + "            \"response name\": \"authorization response\",\n"
                + "            \"checks\": [\n"
                + "                {\n"
                + "                    \"in\": \"url\",\n"
                + "                    \"check param\": \"response_type\",\n"
                + "                    \"is present\": \"true\"\n"
                + "                }\n"
                + "            ]\n"
                + "        },\n"
                + "        {\n"
                + "            \"name\": \"token request\",\n"
                + "            \"is request\": true,\n"
                + "            \"response name\": \"token response\",\n"
                + "            \"checks\": [\n"
                + "                {\n"
                + "                    \"in\": \"url\",\n"
                + "                    \"check param\": \"code\",\n"
                + "                    \"is present\": \"true\"\n"
                + "                }\n"
                + "            ]\n"
                + "        },\n"
                + "        {\n"
                + "            \"name\": \"coda landing request\",\n"
                + "            \"is request\": true,\n"
                + "            \"response name\": \"coda landing response\",\n"
                + "            \"checks\": [\n"
                + "                {\n"
                + "                    \"in\": \"url\",\n"
                + "                    \"check\": \"/welcome\",\n"
                + "                    \"is present\": \"true\"\n"
                + "                },\n"
                + "                {\n"
                + "                    \"in\": \"head\",\n"
                + "                    \"check\": \"Host\",\n"
                + "                    \"is\": \"coda.io\"\n"
                + "                }\n"
                + "            ]\n"
                + "        },\n"
                + "        {\n"
                + "            \"name\": \"saml request\",\n"
                + "            \"is request\": true,\n"
                + "            \"checks\": [\n"
                + "                {\n"
                + "                    \"in\": \"url\",\n"
                + "                    \"check param\": \"SAMLRequest\",\n"
                + "                    \"is present\": true\n"
                + "                }\n"
                + "            ]\n"
                + "        },\n"
                + "        {\n"
                + "            \"name\": \"saml response\",\n"
                + "            \"is request\": true,\n"
                + "            \"checks\": [\n"
                + "                {\n"
                + "                    \"in\": \"body\",\n"
                + "                    \"check param\": \"SAMLResponse\",\n"
                + "                    \"is present\": true\n"
                + "                }\n"
                + "            ]\n"
                + "        }\n"
                + "    ]\n"
                + "}";
    }

    /**
     * Returns the default string that contains the default config for the config.json file
     *
     * @return the string
     */
    public static String getDefaultJSONConfig() {
        return "{\n"
                + "  \"last_driver_path\":\"\",\n"
                + "  \"last_browser_used\": \"\"\n"
                + "  \"default_port\":8080\n"
                + "}";
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

            Var v = getVariableByName(act_match, vars);
            req_var.put(act_match, v.get_value_string());
        }

        if (req_var.isEmpty()) {
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
     * @return the html poc as a string
     */
    public static String generate_CSRF_POC(HTTPReqRes message) {

        String CSFR_TEMPLATE =
                "<!DOCTYPE html>\n"
                        + "<html>\n"
                        + "  <body>\n"
                        + "    <h2>Attack Page</h2>\n"
                        + "    <p>Service Provider (SP) is your service.</p>\n"
                        + "    <p>Identity Provider (IdP) is the provider with which the SP allows to associate the account.</p>\n"
                        + "    <p>These are the steps to reproduce the attack:</p>\n"
                        + "    <p>1. The victim clicks on button to initiate force-login to IdP and victim logs in as the attacker because IdP suffering of Pre-Authentication Login CSRF. To simulate this step, the victim logs in with the attacker's IdP credentials.</p>\n"
                        + "    <p>2. The victim logins at SP with victim credentials.</p>\n"
                        + "    <p>3. The victim clicks on following link which suffers of CSRF, to associate attacker IdP account with the Victim SP account.</p>\n"
                        + "    $INSERT_HERE$\n"
                        + "    <br>\n"
                        + "    <p>4. If the IdP attacker account has been associated with the victim SP account then the vulnerability has been properly exploited.</p>\n"
                        + "  </body>\n"
                        + "</html>";

        String POST_TEMPLATE =
                "  <form enctype=\"$ENCODING_TYPE$\" method=\"$METHOD$\" action=\"$URL$\">\n"
                        + "    <table>\n"
                        + "        $BODY_PARAMETERS$\n"
                        + "    </table>\n"
                        + "    <input type=\"submit\" value=\"Link vulnerable to CSRF account association with IdP\">\n"
                        + "  </form>\n";

        String TEMPLATE_BODY_PARAMS =
                "       <tr>\n"
                        + "        <td>$PARAM_NAME$</td>\n"
                        + "        <td>\n"
                        + "          <input type=\"text\" value=\"$PARAM_VALUE$\" name=\"$PARAM_NAME$\">\n"
                        + "        </td>\n"
                        + "      </tr>";

        String encoding = message.getHeadParam(true, "Content-Type").strip();
        String body =
                new String(
                        message.getBody(true),
                        StandardCharsets.UTF_8); // splitMessage(message, helpers, true).get(2);
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
                        body_params.put(name, value.length() != 0 ? value : "");
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
     * @return An HashMap object having as keys, Strings representing the sessions names, and as
     *     value a list of tests that need to execute that session
     */
    public static HashMap<String, List<Test>> batchPassivesFromSession(List<Test> testList)
            throws ParsingException {
        HashMap<String, List<Test>> batch = new HashMap<>();
        for (Test t : testList) {
            if (t.sessions.isEmpty()) {
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
     * @param regex the regex used to match the things to change
     * @param mop the message operation containing information about the section to match the regex
     * @param messageInfo the message as IHttpRequestResponse object
     * @param isRequest specify if the message to consider is the request or response
     * @param new_value the new value to substitute to the message section
     * @return the edited message as byte array
     * @throws ParsingException if problems are encountered in editing the message
     */
    public static byte[] editMessage(
            String regex,
            MessageOperation mop,
            HTTPReqRes messageInfo,
            boolean isRequest,
            String new_value)
            throws ParsingException {
        // TODO: remove in future versions
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
                return messageInfo.getMessage(isRequest);

            case BODY:
                pattern = Pattern.compile(regex);

                matcher = pattern.matcher(new String(messageInfo.getBody(isRequest)));
                messageInfo.setBody(isRequest, matcher.replaceAll(new_value));
                // Automatically update content-lenght
                return messageInfo.getMessage(isRequest);

            case URL:
                if (!isRequest) {
                    throw new ParsingException("Encoding URL in response");
                }

                pattern = Pattern.compile(regex);
                matcher = pattern.matcher(messageInfo.getUrlHeader());
                String replaced = matcher.replaceAll(new_value);
                messageInfo.setUrlHeader(replaced);

                return messageInfo.getMessage(isRequest);
        }
        return null;
    }

    /**
     * Edit a message parameter
     *
     * @param param_name the name of the parameter to edit
     * @param message_section the message section to edit
     * @param messageInfo the message as IHttpRequestResponse object
     * @param isRequest specify if the message to consider is the request or response
     * @param new_value the new value of the parameter
     * @param isBodyRegex when the section is body, set it to true if you want to use a regex to
     *     substitute the value, otherwise a parameter param=... is searched
     * @return the edited message as byte array
     * @throws ParsingException if problems are encountered in editing the message
     */
    public static byte[] editMessageParam(
            String param_name,
            HTTPReqRes.MessageSection message_section,
            HTTPReqRes messageInfo,
            boolean isRequest,
            String new_value,
            boolean isBodyRegex)
            throws ParsingException {
        // TODO: remove in future versions
        Pattern pattern = null;
        Matcher matcher = null;
        switch (message_section) {
            case HEAD:
                messageInfo.editHeadParam(isRequest, param_name, new_value);
                byte[] message = messageInfo.getMessage(isRequest);
                messageInfo.setHost(
                        new_value); // this should be set when the message is converted to the burp
                // class
                return message;

            case BODY:
                if (!isBodyRegex) {
                    pattern = Pattern.compile("(?<=" + Pattern.quote(param_name) + "=)[^$\\n& ]*");
                } else {
                    pattern = Pattern.compile(param_name);
                }

                matcher = pattern.matcher(new String(messageInfo.getBody(isRequest)));
                String new_body = matcher.replaceFirst(new_value);
                messageInfo.setBody(isRequest, new_body);
                // Automatically update content-lenght
                return messageInfo.getMessage(isRequest);

            case URL:
                if (!isRequest) {
                    throw new ParsingException("Encoding URL in response");
                }
                String url_header = messageInfo.getUrlHeader();
                System.err.println("ZZZZZZZZZZZZZZZZZ" + url_header);

                pattern = Pattern.compile(Pattern.quote(param_name) + "=[^& ]*((?=&)|(?= ))");
                matcher = pattern.matcher(url_header);

                messageInfo.setUrlHeader(
                        matcher.replaceAll(param_name + "=" + new_value)); // problema

                return messageInfo.getMessage(isRequest);
        }
        return null;
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

        // -2 because if the last element is a div i don't take it, otherwise is not a div, so i
        // don't take it
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
     * @param action the action to do, (edit, remove, add, or save)
     * @param content the json content as string
     * @param j_path the json path as string
     * @param save_as the name of the variable if the action is save
     * @return the edited json
     * @throws PathNotFoundException if the path in the json is not found
     */
    public static String editJson(
            EditOperation.Jwt_action action,
            String content,
            String j_path,
            List<Var> vars,
            String save_as,
            String newValue,
            String newKey)
            throws PathNotFoundException {
        // TODO: remove in future versions
        Object document = Configuration.defaultConfiguration().jsonProvider().parse(content);
        JsonPath jsonPath = JsonPath.compile(j_path);

        switch (action) {
            case REMOVE:
                document = jsonPath.delete(document, Configuration.defaultConfiguration());
                break;
            case EDIT:
                document = jsonPath.set(document, newValue, Configuration.defaultConfiguration());
                break;
            case ADD:
                document =
                        jsonPath.put(
                                document,
                                newKey,
                                newValue.isEmpty() ? null : newValue,
                                Configuration.defaultConfiguration());
                break;
            case SAVE:
                Object to_save = JsonPath.read(content, j_path);

                Var v = null;
                if (to_save instanceof String) {
                    v = new Var(save_as, (String) to_save);
                } else if (to_save instanceof Double) {
                    v = new Var(save_as, ((Double) to_save).toString());
                } else if (to_save instanceof Integer) {
                    v = new Var(save_as, ((Integer) to_save).toString());
                } else if (to_save instanceof net.minidev.json.JSONArray) {
                    v = new Var(save_as, ((net.minidev.json.JSONArray) to_save).toArray());
                } else {
                    throw new RuntimeException("Invalid type of saving variable");
                }

                vars.add(v);
                break;
        }

        // This difference has been added because the parsed documed removed backslashes from the
        // content even if it
        // was not modified (like if it was just a save)
        if (!(action == EditOperation.Jwt_action.SAVE)) {
            return Configuration.defaultConfiguration()
                    .jsonProvider()
                    .toJson(document); // basically converts to string
        } else {
            return content;
        }
    }

    /**
     * Checks that the json resulting by parsing the two strings is equals. Equals in this case
     * means that the same keys and values are present, but the order is ignored
     *
     * @param s1 the string 1
     * @param s2 the string 2
     * @return true or false depending if the json parsing of the two strings is the same or not
     */
    public static boolean check_json_strings_equals(String s1, String s2) {
        JsonElement o1 = JsonParser.parseString(s1);
        JsonElement o2 = JsonParser.parseString(s2);

        return o1.equals(o2);
    }
}
