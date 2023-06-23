package migt;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * The class storing a MessageOperation object
 *
 * @author Matteo Bitussi
 */
public class MessageOperation {
    Utils.MessageSection from;
    String what;
    String to;
    Utils.MessageOperationActions action;
    String save_as; // The name of the variable to save the parameter's value
    String use;
    String decode_param;
    List<Utils.Encoding> encodings;
    Utils.MessageOpType type;

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
        this.decode_param = "";
        this.encodings = new ArrayList<>();
        this.type = Utils.MessageOpType.HTTP;
        this.template = "";
        this.output_path = "";
    }

    public MessageOperation(JSONObject message_op_json) throws ParsingException {
        this.what = "";
        this.to = "";
        this.save_as = "";
        this.use = "";
        this.decode_param = "";
        this.encodings = new ArrayList<>();
        this.type = Utils.MessageOpType.HTTP;
        this.template = "";
        this.output_path = "";

        java.util.Iterator<String> keys = message_op_json.keys();
        while (keys.hasNext()) {
            String key = keys.next();

            switch (key) {
                case "from":
                    from = Utils.MessageSection.fromString(message_op_json.getString("from"));
                    break;
                case "remove parameter":
                    what = message_op_json.getString("remove parameter");
                    action = Utils.MessageOperationActions.REMOVE_PARAMETER;
                    break;
                case "remove match word":
                    what = message_op_json.getString("remove match word");
                    action = Utils.MessageOperationActions.REMOVE_MATCH_WORD;
                    break;
                case "edit":
                    what = message_op_json.getString("edit");
                    action = Utils.MessageOperationActions.EDIT;
                    break;
                case "edit regex":
                    what = message_op_json.getString("edit regex");
                    action = Utils.MessageOperationActions.EDIT_REGEX;
                    break;
                case "in":
                    to = message_op_json.getString("in");
                    break;
                case "add":
                    what = message_op_json.getString("add");
                    action = Utils.MessageOperationActions.ADD;
                    break;
                case "this":
                    to = message_op_json.getString("this");
                    break;
                case "save":
                    what = message_op_json.getString("save");
                    action = Utils.MessageOperationActions.SAVE;
                    break;
                case "save match":
                    what = message_op_json.getString("save match");
                    action = Utils.MessageOperationActions.SAVE_MATCH;
                    break;
                case "as":
                    save_as = message_op_json.getString("as");
                    break;
                case "use":
                    use = message_op_json.getString("use");
                    break;
                case "type":
                    type = Utils.MessageOpType.fromString(
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
}
