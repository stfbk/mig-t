package burp;

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
}
