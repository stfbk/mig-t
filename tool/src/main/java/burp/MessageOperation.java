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

    // XML
    Utils.XmlAction xml_action;
    String xml_action_name;
    String xml_tag;
    String xml_attr;
    String value;
    Integer xml_occurrency;
    Boolean self_sign;
    Boolean remove_signature;

    // TXT
    Utils.TxtAction txt_action;
    String txt_action_name;

    // JWT
    boolean isRawJWT = false;
    Utils.Jwt_section jwt_section;
    Utils.Jwt_action jwt_action;
    boolean sign = false;

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
        this.value = "";
        this.xml_action_name = "";
        this.xml_tag = "";
        this.xml_attr = "";
        this.self_sign = false;
        this.txt_action_name = "";
        this.remove_signature = false;
        this.xml_occurrency = -1;
        this.jwt_action = null;
        this.jwt_section = null;
        this.template = "";
        this.output_path = "";
    }
}
