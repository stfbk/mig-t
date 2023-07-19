package migt;

import java.util.ArrayList;
import java.util.List;

/**
 * Class storing a MessageType
 *
 * @author Matteo Bitussi
 */
public class MessageType implements Cloneable {
    String name;
    Boolean isRequest;
    String regex;
    List<Check> checks;
    HTTPReqRes.MessageSection messageSection;
    String responseName;
    String requestName;

    Boolean getByResponse;
    Boolean getByRequest;
    Boolean isRegex;

    /**
     * Instantiate a MessageType
     *
     * @param name      the name of that message
     * @param isRequest if the message is a request
     */
    public MessageType(String name, Boolean isRequest) {
        this.name = name;
        this.isRequest = isRequest;
        this.regex = "";
        this.checks = new ArrayList<>();
        this.isRegex = false;
        this.responseName = "";
        this.requestName = "";
        this.getByResponse = false;
        this.getByRequest = false;
    }

    /**
     * From a list of message types, get the corresponding MessageType from the name
     *
     * @param list the list of message types
     * @param name the name of the message type
     * @return the corresponding MessageType (if found)
     * @throws Exception if the MessageType can not be found
     */
    public static MessageType getFromList(List<MessageType> list, String name) throws Exception {
        for (MessageType act : list) {
            if (act.name.equals(name)) {
                return act;
            } else if (act.responseName.equals(name)) {
                MessageType tmp = (MessageType) act.clone();
                tmp.getByResponse = true;
                return tmp;
            } else if (act.requestName.equals(name)) {
                MessageType tmp = (MessageType) act.clone();
                tmp.getByRequest = true;
                return tmp;
            }
        }
        throw new ParsingException("cannot find the specified message type");
    }
}
