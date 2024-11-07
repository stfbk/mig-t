package org.zaproxy.addon.migt;

import java.util.ArrayList;
import java.util.List;

/** Class storing a MessageType */
public class MessageType implements Cloneable {
    String name;
    Boolean isRequest; // this tells if the message where the checks are executed is a request or a
    // response
    List<Check> checks;
    String responseName;
    String requestName;

    Boolean getByResponse; // this tells if you are getting a response by checking a request
    Boolean getByRequest; // this tells if you are getting a request by checking a response

    boolean msg_to_process_is_request; // this tells whether the message to be intercepted is a

    // request or a response

    /**
     * Instantiate a MessageType
     *
     * @param name the name of that message
     * @param isRequest if the message is a request
     */
    public MessageType(String name, Boolean isRequest) {
        this.name = name;
        this.isRequest = isRequest;
        this.checks = new ArrayList<>();
        this.responseName = "";
        this.requestName = "";
        this.getByResponse = false;
        this.getByRequest = false;
        this.msg_to_process_is_request =
                isRequest; // init with this, if getByResponse or getByRequest, then change
        // accordingly
    }

    /**
     * From a list of message types, get the corresponding MessageType from the name
     *
     * @param list the list of message types
     * @param name the name of the message type
     * @return the corresponding MessageType (if found)
     * @throws Exception if the MessageType can not be found
     */
    public static MessageType getFromList(List<MessageType> list, String name)
            throws ParsingException {
        for (MessageType act : list) {
            try {
                if (act.name.equals(name)) {
                    return act;
                } else if (act.responseName.equals(name)) {
                    MessageType tmp = (MessageType) act.clone();
                    tmp.getByResponse = true;
                    tmp.msg_to_process_is_request = false;
                    return tmp;
                } else if (act.requestName.equals(name)) {
                    MessageType tmp = (MessageType) act.clone();
                    tmp.getByRequest = true;
                    tmp.msg_to_process_is_request = true;
                    return tmp;
                }
            } catch (CloneNotSupportedException e) {
                throw new ParsingException(e.getMessage());
            }
        }
        throw new ParsingException("cannot find the specified message type \" " + name + "\"");
    }
}
