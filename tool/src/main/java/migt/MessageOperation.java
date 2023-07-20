package migt;

import org.json.JSONObject;

/**
 * The class storing a MessageOperation object
 *
 * @author Matteo Bitussi
 */
public class MessageOperation {
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
        this.what = "";
        this.to = "";
        this.save_as = "";
        this.use = "";
        this.type = MessageOpType.HTTP;
        this.template = "";
        this.output_path = "";
    }

    public MessageOperation(JSONObject message_op_json) throws ParsingException {
        this.what = "";
        this.to = "";
        this.save_as = "";
        this.use = "";
        this.type = MessageOpType.HTTP;
        this.template = "";
        this.output_path = "";

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
                    System.err.println(key);
                    throw new ParsingException("Message operation not valid");
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
