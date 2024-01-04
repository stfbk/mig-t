package migt;

import org.json.JSONObject;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static migt.Tools.getVariableByName;

/**
 * The class storing a MessageOperation object
 */
public class MessageOperation extends Module {
    HTTPReqRes.MessageSection from;
    String what;
    String to;
    MessageOperationActions action;
    String save_as; // The name of the variable to save the parameter's value
    String use;
    MessageOpType type;

    // GENERATE POC
    String template;
    String output_path;

    /**
     * Used to Instantiate the class
     */
    public MessageOperation() {
        init();
    }

    public MessageOperation(JSONObject message_op_json) throws ParsingException {
        init();

        java.util.Iterator<String> keys = message_op_json.keys();
        while (keys.hasNext()) {
            String key = keys.next();

            switch (key) {
                case "from":
                    from = HTTPReqRes.MessageSection.fromString(message_op_json.getString("from"));
                    break;
                case "remove parameter":
                    what = message_op_json.getString("remove parameter");
                    action = MessageOperationActions.REMOVE_PARAMETER;
                    break;
                case "remove match word":
                    what = message_op_json.getString("remove match word");
                    action = MessageOperationActions.REMOVE_MATCH_WORD;
                    break;
                case "edit":
                    what = message_op_json.getString("edit");
                    action = MessageOperationActions.EDIT;
                    break;
                case "edit regex":
                    what = message_op_json.getString("edit regex");
                    action = MessageOperationActions.EDIT_REGEX;
                    break;
                case "in":
                    to = message_op_json.getString("in");
                    break;
                case "add":
                    what = message_op_json.getString("add");
                    action = MessageOperationActions.ADD;
                    break;
                case "this":
                    to = message_op_json.getString("this");
                    break;
                case "save":
                    what = message_op_json.getString("save");
                    action = MessageOperationActions.SAVE;
                    break;
                case "save match":
                    what = message_op_json.getString("save match");
                    action = MessageOperationActions.SAVE_MATCH;
                    break;
                case "as":
                    save_as = message_op_json.getString("as");
                    break;
                case "use":
                    use = message_op_json.getString("use");
                    break;
                case "type":
                    type = MessageOpType.fromString(
                            message_op_json.getString("type"));
                    break;
                case "template":
                    template = message_op_json.getString("template");
                    break;
                case "output_path":
                    output_path = message_op_json.getString("output_path");
                    break;
                default:
                    throw new ParsingException("Message operation key \" " + key + "\" not valid");
            }
        }
    }

    /**
     * Returns the adding of a message operation, decides if the value to be inserted/edited should be a variable or
     * a typed value and return it
     *
     * @param m the message operation which has to be examined
     * @return the adding to be used in add/edit
     * @throws ParsingException if the variable name is not valid or the variable has not been initiated
     */
    public static String getAdding(MessageOperation m, List<Var> vars) throws ParsingException {
        if (!m.use.isEmpty()) {
            Var v = getVariableByName(m.use, vars);
            return v.get_value_string();
        } else {

            return m.to;
        }
    }

    public void init() {
        this.what = "";
        this.to = "";
        this.save_as = "";
        this.use = "";
        this.type = MessageOpType.HTTP;
        this.template = "";
        this.output_path = "";
    }

    public void loader(Operation_API api) {
        this.imported_api = api;
    }

    public Operation_API exporter() {
        if (imported_api instanceof Operation_API) {
            return (Operation_API) this.imported_api;
        }
        return null;
    }

    /**
     * Given an operation, and a message, execute the Message operations contained in the operation
     *
     * @param op the operation containing the message operation
     * @return the updated Operation with the result
     * @throws ParsingException if parsing of names is not successfull
     */
    public Operation execute(Operation op) throws ParsingException {
        for (MessageOperation mop : op.getMessageOperations()) {
            Pattern pattern;
            Matcher matcher;
            try {
                if (mop.type == MessageOperation.MessageOpType.GENERATE_POC) {
                    if (!op.api.is_request) {
                        throw new ParsingException("Invalid POC generation, message should be a request");
                    }

                    if (!mop.template.equals("csrf")) {
                        continue; // other templates not supported yet
                    }

                    String poc = Tools.generate_CSRF_POC(op.api.message);

                    try {
                        File myObj = new File(mop.output_path);
                        myObj.createNewFile();
                    } catch (IOException e) {
                        throw new ParsingException("Invalid POC generation output path: "
                                + mop.output_path + " " + e.getMessage());
                    }
                    try {
                        FileWriter myWriter = new FileWriter(mop.output_path);
                        myWriter.write(poc);
                        myWriter.close();
                    } catch (IOException e) {
                        throw new ParsingException("Something went wrong while writing output file for POC generator: "
                                + mop.output_path + " " + e.getMessage());
                    }
                } else {
                    if (mop.action != null) {
                        switch (mop.action) {
                            case REMOVE_PARAMETER:
                                switch (mop.from) {
                                    case URL:
                                        // Works
                                        if (!op.api.is_request) {
                                            throw new ParsingException("Searching URL in response");
                                        }
                                        String url_header = op.api.message.getUrlHeader();
                                        pattern = Pattern.compile("&?" + Pattern.quote(mop.what) + "=[^& ]*((?=&)|(?= ))");
                                        matcher = pattern.matcher(url_header);
                                        String new_url = matcher.replaceFirst("");
                                        op.api.message.setUrlHeader(new_url);
                                        op.processed_message = op.api.message.getMessage(op.api.is_request);
                                        break;

                                    case HEAD:
                                        op.api.message.removeHeadParameter(op.api.is_request, mop.what);
                                        op.processed_message = op.api.message.getMessage(op.api.is_request);
                                        break;

                                    case BODY:
                                        String body = new String(op.api.message.getBody(op.api.is_request));
                                        pattern = Pattern.compile(Pattern.quote(mop.what));
                                        matcher = pattern.matcher(body);
                                        op.api.message.setBody(op.api.is_request, matcher.replaceAll(""));
                                        //Automatically update content-lenght
                                        op.processed_message = op.api.message.getMessage(op.api.is_request);
                                        break;
                                }
                                break;

                            case ADD:
                                if (getAdding(mop, op.api.vars) == null | getAdding(mop, op.api.vars).equals("")) {
                                    // TODO: should raise exception or set operation not applicable?
                                    break;
                                }
                                switch (mop.from) {
                                    case HEAD: {
                                        op.api.message.addHeadParameter(op.api.is_request, mop.what, getAdding(mop, op.api.vars));
                                        op.processed_message = op.api.message.getMessage(op.api.is_request);
                                        break;
                                    }
                                    case BODY: {
                                        String tmp = new String(op.api.message.getBody(op.api.is_request));
                                        tmp = tmp + getAdding(mop, op.api.vars);
                                        op.api.message.setBody(op.api.is_request, tmp);
                                        //Automatically update content-lenght
                                        op.processed_message = op.api.message.getMessage(op.api.is_request);
                                        break;
                                    }
                                    case URL:
                                        if (!op.api.is_request) {
                                            throw new ParsingException("Searching URL in response");
                                        }
                                        String header_0 = op.api.message.getUrlHeader();

                                        pattern = Pattern.compile("&?" + Pattern.quote(mop.what) + "=[^& ]*((?=&)|(?= ))");
                                        matcher = pattern.matcher(header_0);

                                        String newHeader_0 = "";
                                        boolean found = false;
                                        while (matcher.find() & !found) {
                                            String before = header_0.substring(0, matcher.end());
                                            String after = header_0.substring(matcher.end());
                                            newHeader_0 = before + getAdding(mop, op.api.vars) + after;
                                            found = true;
                                        }
                                        op.api.message.setUrlHeader(newHeader_0);
                                        op.processed_message = op.api.message.getMessage(op.api.is_request);
                                        break;
                                }
                                break;

                            case EDIT:
                                op.processed_message = Tools.editMessageParam(
                                        mop.what,
                                        mop.from,
                                        op.api.message,
                                        op.api.is_request,
                                        getAdding(mop, op.api.vars),
                                        true);
                                break;

                            case EDIT_REGEX:
                                op.processed_message = Tools.editMessage(
                                        mop.what,
                                        mop,
                                        op.api.message,
                                        op.api.is_request,
                                        getAdding(mop, op.api.vars));
                                break;

                            case REMOVE_MATCH_WORD:
                                switch (mop.from) {
                                    case HEAD: {
                                        List<String> headers = op.api.message.getHeaders(op.api.is_request);
                                        pattern = Pattern.compile(Pattern.quote(mop.what));
                                        List<String> new_headers = new ArrayList<>();

                                        for (String header : headers) {
                                            matcher = pattern.matcher(header);
                                            new_headers.add(matcher.replaceAll(""));
                                        }

                                        op.api.message.setHeaders(op.api.is_request, new_headers);
                                        op.processed_message = op.api.message.getMessage(op.api.is_request);
                                        break;
                                    }
                                    case BODY: {
                                        pattern = Pattern.compile(Pattern.quote(mop.what));
                                        matcher = pattern.matcher(new String(op.api.message.getBody(op.api.is_request)));
                                        op.api.message.setBody(op.api.is_request, matcher.replaceAll(""));

                                        //Automatically update content-lenght
                                        op.processed_message = op.api.message.getMessage(op.api.is_request);
                                        break;
                                    }
                                    case URL:
                                        // Works
                                        if (!op.api.is_request) {
                                            throw new ParsingException("Searching URL in response");
                                        }
                                        String header_0 = op.api.message.getUrlHeader();

                                        pattern = Pattern.compile(mop.what);
                                        matcher = pattern.matcher(header_0);
                                        String newHeader_0 = matcher.replaceFirst("");

                                        op.api.message.setUrlHeader(newHeader_0);
                                        op.processed_message = op.api.message.getMessage(op.api.is_request);
                                        break;
                                }
                                break;

                            case SAVE:
                            case SAVE_MATCH:
                                switch (mop.from) {
                                    case HEAD: {
                                        String value = "";
                                        if (mop.action == MessageOperation.MessageOperationActions.SAVE) {
                                            value = op.api.message.getHeadParam(op.api.is_request, mop.what).trim();
                                        } else {
                                            List<String> headers = op.api.message.getHeaders(op.api.is_request);
                                            pattern = Pattern.compile(mop.what);
                                            for (String h : headers) {
                                                matcher = pattern.matcher(h);
                                                value = "";
                                                while (matcher.find()) {
                                                    value = matcher.group();
                                                    break;
                                                }
                                            }
                                        }

                                        Var v = new Var(mop.save_as, value);
                                        op.api.vars.add(v);
                                        break;
                                    }
                                    case BODY: {
                                        String tmp = new String(op.api.message.getBody(op.api.is_request), StandardCharsets.UTF_8);
                                        pattern = Pattern.compile(mop.what);
                                        matcher = pattern.matcher(tmp);
                                        Var v = null;

                                        while (matcher.find()) {
                                            v = new Var(mop.save_as, matcher.group());
                                            break;
                                        }
                                        if (v != null)
                                            op.api.vars.add(v);
                                        break;
                                    }
                                    case URL: {
                                        // works
                                        if (!op.api.is_request) {
                                            throw new ParsingException("Searching URL in response");
                                        }
                                        String header_0 = op.api.message.getUrlHeader();

                                        pattern = mop.action == MessageOperation.MessageOperationActions.SAVE ?
                                                Pattern.compile(Pattern.quote(mop.what) + "=[^& ]*(?=(&| ))") :
                                                Pattern.compile(Pattern.quote(mop.what));

                                        matcher = pattern.matcher(header_0);
                                        String value = "";

                                        if (matcher.find()) {
                                            String matched = matcher.group();
                                            value = mop.action == MessageOperation.MessageOperationActions.SAVE ?
                                                    matched.split("=")[1] :
                                                    matched;

                                            Var v = new Var(mop.save_as, value);
                                            op.api.vars.add(v);
                                        }
                                        break;
                                    }
                                }
                                break;
                        }
                    }
                }

                applicable = true;

                if (op.processed_message != null) {
                    if (op.api.is_request) {
                        op.api.message.setRequest(op.processed_message);
                    } else {
                        op.api.message.setResponse(op.processed_message);
                    }
                }
            } catch (StackOverflowError e) {
                e.printStackTrace();
            }
        }
        return op;
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
        SAVE_MATCH,
        ENCODE;

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
                    case "encode":
                        return ENCODE;
                    default:
                        throw new ParsingException("invalid Message operation action \"" + input + "\"");
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
}
