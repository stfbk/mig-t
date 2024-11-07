package org.zaproxy.addon.migt;

import static org.zaproxy.addon.migt.Tools.getVariableByName;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONObject;

/** The class storing a MessageOperation object */
public class MessageOperation extends Module {
    HTTPReqRes.MessageSection from;
    String what;
    String to;
    MessageOperationActions action;
    String save_as; // The name of the variable to save the parameter's value
    String use;
    MessageOpType type;
    boolean url_decode = true; // enable or disable url decoding of url parameters

    // GENERATE POC
    String template;
    String output_path;

    /** Used to Instantiate the class */
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
                    type = MessageOpType.fromString(message_op_json.getString("type"));
                    break;
                case "template":
                    template = message_op_json.getString("template");
                    break;
                case "output_path":
                    output_path = message_op_json.getString("output_path");
                    break;
                case "url decode":
                    url_decode = message_op_json.getBoolean("url decode");
                    break;
                default:
                    throw new ParsingException("Message operation key \" " + key + "\" not valid");
            }
        }
    }

    /**
     * Returns the adding of a message operation, decides if the value to be inserted/edited should
     * be a variable or a typed value and return it
     *
     * @param m the message operation which has to be examined
     * @return the adding to be used in add/edit
     * @throws ParsingException if the variable name is not valid or the variable has not been
     *     initiated
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
     * @return the updated Operation with the result
     * @throws ParsingException if parsing of names is not successfull
     */
    public void execute() {
        Pattern pattern;
        Matcher matcher;
        try {
            if (type == MessageOpType.GENERATE_POC) {
                if (!((Operation_API) imported_api).is_request) {
                    throw new ParsingException(
                            "Invalid POC generation, message should be a request");
                }

                if (!template.equals("csrf")) {
                    System.out.println("CSRF template not supported");
                    return; // other templates not supported yet
                }

                String poc = Tools.generate_CSRF_POC(((Operation_API) imported_api).message);

                try {
                    File myObj = new File(output_path);
                    myObj.createNewFile();
                } catch (IOException e) {
                    throw new ParsingException(
                            "Invalid POC generation output path: "
                                    + output_path
                                    + " "
                                    + e.getMessage());
                }
                try {
                    FileWriter myWriter = new FileWriter(output_path);
                    myWriter.write(poc);
                    myWriter.close();
                } catch (IOException e) {
                    throw new ParsingException(
                            "Something went wrong while writing output file for POC generator: "
                                    + output_path
                                    + " "
                                    + e.getMessage());
                }
            } else {
                if (action == null) {
                    throw new ParsingException("Invalid action in message operation");
                }

                switch (action) {
                    case REMOVE_PARAMETER:
                        switch (from) {
                            case URL:
                                if (!((Operation_API) imported_api).is_request) {
                                    throw new ParsingException("Searching URL in response");
                                }
                                String url_header =
                                        ((Operation_API) imported_api).message.getUrlHeader();
                                pattern =
                                        Pattern.compile(
                                                "&?"
                                                        + Pattern.quote(what)
                                                        + "=[^& ]*((?=&)|(?= ))");
                                matcher = pattern.matcher(url_header);
                                String new_url = matcher.replaceFirst("");
                                ((Operation_API) imported_api).message.setUrlHeader(new_url);
                                break;

                            case HEAD:
                                ((Operation_API) imported_api)
                                        .message.removeHeadParameter(
                                                ((Operation_API) imported_api).is_request, what);
                                break;

                            case BODY:
                                String body =
                                        new String(
                                                ((Operation_API) imported_api)
                                                        .message.getBody(
                                                                ((Operation_API) imported_api)
                                                                        .is_request));
                                pattern = Pattern.compile(Pattern.quote(what));
                                matcher = pattern.matcher(body);
                                ((Operation_API) imported_api)
                                        .message.setBody(
                                                ((Operation_API) imported_api).is_request,
                                                matcher.replaceAll(""));
                                break;
                        }
                        break;

                    case ADD:
                        if (getAdding(this, ((Operation_API) imported_api).vars) == null
                                | getAdding(this, ((Operation_API) imported_api).vars).isEmpty()) {
                            // TODO: should raise exception or set operation not applicable?
                            break;
                        }
                        switch (from) {
                            case HEAD:
                                {
                                    ((Operation_API) imported_api)
                                            .message.addHeadParameter(
                                                    ((Operation_API) imported_api).is_request,
                                                    what,
                                                    getAdding(
                                                            this,
                                                            ((Operation_API) imported_api).vars));
                                    break;
                                }
                            case BODY:
                                {
                                    String tmp =
                                            new String(
                                                    ((Operation_API) imported_api)
                                                            .message.getBody(
                                                                    ((Operation_API) imported_api)
                                                                            .is_request));
                                    tmp =
                                            tmp
                                                    + getAdding(
                                                            this,
                                                            ((Operation_API) imported_api).vars);
                                    ((Operation_API) imported_api)
                                            .message.setBody(
                                                    ((Operation_API) imported_api).is_request, tmp);
                                    break;
                                }
                            case URL:
                                if (!((Operation_API) imported_api).is_request) {
                                    throw new ParsingException("Searching URL in response");
                                }
                                String header_0 =
                                        ((Operation_API) imported_api).message.getUrlHeader();

                                pattern =
                                        Pattern.compile(
                                                "&?"
                                                        + Pattern.quote(what)
                                                        + "=[^& ]*((?=&)|(?= ))");
                                matcher = pattern.matcher(header_0);

                                String newHeader_0 = "";
                                boolean found = false;
                                while (matcher.find() & !found) {
                                    String before = header_0.substring(0, matcher.end());
                                    String after = header_0.substring(matcher.end());
                                    newHeader_0 =
                                            before
                                                    + getAdding(
                                                            this,
                                                            ((Operation_API) imported_api).vars)
                                                    + after;
                                    found = true;
                                }
                                ((Operation_API) imported_api).message.setUrlHeader(newHeader_0);
                                break;
                        }
                        break;

                    case EDIT:
                        byte[] msg =
                                Tools.editMessageParam(
                                        what,
                                        from,
                                        ((Operation_API) imported_api).message,
                                        ((Operation_API) imported_api).is_request,
                                        getAdding(this, ((Operation_API) imported_api).vars),
                                        true);

                        if (((Operation_API) imported_api).message.isRequest) {
                            ((Operation_API) imported_api).message.setRequest(msg);
                        } else {
                            ((Operation_API) imported_api).message.setResponse(msg);
                        }
                        break;

                    case EDIT_REGEX:
                        msg =
                                Tools.editMessage(
                                        what,
                                        this,
                                        ((Operation_API) imported_api).message,
                                        ((Operation_API) imported_api).is_request,
                                        getAdding(this, ((Operation_API) imported_api).vars));

                        if (((Operation_API) imported_api).message.isRequest) {
                            ((Operation_API) imported_api).message.setRequest(msg);
                        } else {
                            ((Operation_API) imported_api).message.setResponse(msg);
                        }
                        break;

                    case REMOVE_MATCH_WORD:
                        switch (from) {
                            case HEAD:
                                {
                                    List<String> headers =
                                            ((Operation_API) imported_api)
                                                    .message.getHeaders(
                                                            ((Operation_API) imported_api)
                                                                    .is_request);
                                    pattern = Pattern.compile(Pattern.quote(what));
                                    List<String> new_headers = new ArrayList<>();

                                    for (String header : headers) {
                                        matcher = pattern.matcher(header);
                                        new_headers.add(matcher.replaceAll(""));
                                    }

                                    ((Operation_API) imported_api)
                                            .message.setHeaders(
                                                    ((Operation_API) imported_api).is_request,
                                                    new_headers);
                                    break;
                                }
                            case BODY:
                                {
                                    pattern = Pattern.compile(Pattern.quote(what));
                                    matcher =
                                            pattern.matcher(
                                                    new String(
                                                            ((Operation_API) imported_api)
                                                                    .message.getBody(
                                                                            ((Operation_API)
                                                                                            imported_api)
                                                                                    .is_request)));
                                    ((Operation_API) imported_api)
                                            .message.setBody(
                                                    ((Operation_API) imported_api).is_request,
                                                    matcher.replaceAll(""));
                                    break;
                                }
                            case URL:
                                if (!((Operation_API) imported_api).is_request) {
                                    throw new ParsingException("Searching URL in response");
                                }
                                String header_0 =
                                        ((Operation_API) imported_api).message.getUrlHeader();

                                pattern = Pattern.compile(what);
                                matcher = pattern.matcher(header_0);
                                String newHeader_0 = matcher.replaceFirst("");

                                ((Operation_API) imported_api).message.setUrlHeader(newHeader_0);
                                break;
                        }
                        break;

                    case SAVE:
                    case SAVE_MATCH:
                        switch (from) {
                            case HEAD:
                                {
                                    String value =
                                            action == MessageOperationActions.SAVE
                                                    ? ((Operation_API) imported_api)
                                                            .message.getHeadParam(
                                                                    ((Operation_API) imported_api)
                                                                            .is_request,
                                                                    what)
                                                    : ((Operation_API) imported_api)
                                                            .message.getHeadRegex(
                                                                    ((Operation_API) imported_api)
                                                                            .is_request,
                                                                    what);

                                    if (value.isEmpty()) {
                                        System.out.println(
                                                "Warning: saved head parameter \""
                                                        + what
                                                        + "\" that has an empty value");
                                    }

                                    Var v = new Var(save_as, value);
                                    ((Operation_API) imported_api).vars.add(v);
                                }
                                break;
                            case BODY:
                                {
                                    String value =
                                            ((Operation_API) imported_api)
                                                    .message.getBodyRegex(
                                                            ((Operation_API) imported_api)
                                                                    .is_request,
                                                            what);

                                    if (value.isEmpty()) {
                                        System.out.println(
                                                "Warning: saved body regex \""
                                                        + what
                                                        + "\" that matched an empty value");
                                    }

                                    Var v = new Var(save_as, value);
                                    ((Operation_API) imported_api).vars.add(v);
                                }
                                break;
                            case URL:
                                {
                                    if (!((Operation_API) imported_api).is_request) {
                                        throw new ParsingException(
                                                "Trying to acces the url of a response message");
                                    }

                                    String value =
                                            action == MessageOperationActions.SAVE
                                                    ? ((Operation_API) imported_api)
                                                            .message.getUrlParam(what, !url_decode)
                                                    : ((Operation_API) imported_api)
                                                            .message.getUrlRegex(what);

                                    if (value.isEmpty()) {
                                        System.out.println(
                                                "Warning: saved URL parameter \""
                                                        + what
                                                        + "\" that has an empty value");
                                    }

                                    Var v = new Var(save_as, value);
                                    ((Operation_API) imported_api).vars.add(v);
                                }
                                break;
                        }
                        break;
                }
            }
            applicable = true;
        } catch (StackOverflowError | ParsingException e) {
            e.printStackTrace();
            // applicable is already false
        }
    }

    /** All the possible actions of a MessageOperation */
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
                        throw new ParsingException(
                                "invalid Message operation action \"" + input + "\"");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }

    /** The possible types of messageOps */
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
