package migt;

import burp.IHttpService;
import burp.IInterceptedProxyMessage;

import java.util.ArrayList;
import java.util.List;

import static migt.Utils.buildStringWithVars;
import static migt.Utils.findParentDiv;

/**
 * Class storing an Operation in a Test
 *
 * @author Matteo Bitussi
 */
public class Operation extends Module {
    public List<MessageOperation> messageOerations;
    public String from_session;
    public String to_session;
    public Utils.Then then;
    public String save_name;
    public int to_match;
    public int act_matched;
    public String session_port;
    public List<Check> preconditions;
    public String replace_request_name;
    public String replace_response_name;
    public boolean isSessionOp = false;
    public boolean isRegex = false;
    public List<MatchedMessage> matchedMessages;
    public byte[] processed_message;
    public IHttpService processed_message_service;  // null if it is not changed
    public String decode_param;
    public List<Utils.Encoding> encodings;
    public List<IInterceptedProxyMessage> log_messages;

    // Session operation

    public List<SessionOperation> session_operations;

    //boolean applicable = false; // if the operation can't find a matching message, is not applicable
    //boolean result = true; // defalult true
    private List<Check> checks;
    private String messageType;
    private String regex;
    private Utils.MessageSection messageSection;
    private Utils.Action action;
    private String session;
    private Utils.SessionAction sessionAction;

    // Decode operations
    private List<DecodeOperation> decodeOperations;

    /**
     * Instantiate an operation
     */
    public Operation() {
        this.messageOerations = new ArrayList<>();
        this.preconditions = new ArrayList<>();
        this.checks = new ArrayList<>();
        this.setChecks(new ArrayList<>());
        this.matchedMessages = new ArrayList<>();
        this.encodings = new ArrayList<>();
        this.session_operations = new ArrayList<>();
        this.log_messages = new ArrayList<>();
        this.decodeOperations = new ArrayList<>();
        this.to_match = 0;
        this.act_matched = 0;
        this.from_session = "";
        this.to_session = "";
        this.save_name = "";
        this.session_port = "";
        this.replace_response_name = "";
        this.replace_request_name = "";
        this.messageType = "";
        this.regex = "";
        this.session = "";
        this.decode_param = "";
        this.processed_message_service = null;
        this.processed_message = null;
    }

    public String getMessageType() {
        return messageType;
    }

    /**
     * Set the message type of the message the operation needs to deal with
     *
     * @param messageType the name of the message type
     * @param msg_types   the list of message types
     * @throws Exception Thrown if the message type is not found
     */
    public void setMessageType(String messageType, List<MessageType> msg_types) throws Exception {
        if (MessageType.getFromList(msg_types, messageType) != null) {
            this.messageType = messageType;
        } else {
            throw new ParsingException("Message type not found");
        }
        this.messageType = messageType;
    }

    public List<MessageOperation> getMessageOerations() {
        return messageOerations;
    }

    public List<Check> getChecks() {
        return checks;
    }

    public void setChecks(List<Check> checks) {
        this.checks = checks;
    }

    public String getRegex() {
        return regex;
    }

    public void setRegex(String regex) {
        this.regex = regex;
    }

    public Utils.MessageSection getMessageSection() {
        return messageSection;
    }

    public void setMessageSection(Utils.MessageSection messageSection) {
        this.messageSection = messageSection;
    }

    public Utils.Action getAction() {
        return action;
    }

    public void setAction(String action) throws ParsingException {
        this.setAction(Utils.Action.fromString(action));
    }

    public void setAction(Utils.Action action) {
        this.action = action;
    }

    public String getSession() {
        return session;
    }

    public void setSession(String sessionName) {
        this.session = sessionName;
    }

    public Utils.SessionAction getSessionAction() {
        return sessionAction;
    }

    public void setSessionAction(String sessionAction) throws ParsingException {
        this.setSessionAction(Utils.SessionAction.fromString(sessionAction));
    }

    public void setSessionAction(Utils.SessionAction sessionAction) {
        this.sessionAction = sessionAction;
    }

    public boolean hasChecks() {
        return this.checks.size() > 0;
    }

    public List<DecodeOperation> getDecodeOperations() {
        return decodeOperations;
    }

    public void setDecodeOperations(List<DecodeOperation> decodeOperations) {
        this.decodeOperations = decodeOperations;
    }

    /**
     * Used to process session operations of a given operation
     *
     * @return An array of Object elements, the first is the edited operation, the second is the updated variables
     */
    public List<Var> executeSessionOps(Test t,
                                       List<Var> vars) throws ParsingException {
        Object[] res = new Object[2];
        List<Var> updated_vars = vars;
        for (SessionOperation sop : this.session_operations) {
/*
            List<Var> vars_new = eal.onBeforeExSessionOps();

            for (Var v : vars_new) {
                if (!updated_vars.contains(v)) {
                    updated_vars.inse
                }
            }
 */
            Session session = t.getSession(sop.from_session);
            Track track = session.track;

            switch (sop.action) {
                case SAVE:
                    Var v = new Var();
                    v.name = sop.as;
                    v.isMessage = false;
                    v.value = "";
                    switch (sop.target) {
                        case TRACK:
                            for (SessionTrackAction sa : t.getSession(sop.from_session).track
                                    .getStasFromMarkers(sop.at, sop.to, sop.is_from_included, sop.is_to_included)) {
                                v.value += sa.toString() + "\n";
                            }
                            break;
                        case LAST_ACTION:
                            v.value = session.last_action.toString();
                            break;
                        case LAST_ACTION_ELEM:
                            v.value = session.last_action.elem;
                            break;
                        case LAST_ACTION_ELEM_PARENT:
                            v.value = findParentDiv(session.last_action.elem);
                            break;
                        case LAST_CLICK:
                            v.value = session.last_click.toString();
                            break;
                        case LAST_CLICK_ELEM:
                            v.value = session.last_click.elem;
                            break;
                        case LAST_CLICK_ELEM_PARENT:
                            v.value = findParentDiv(session.last_click.elem);
                            break;
                        case LAST_OPEN:
                            v.value = session.last_open.toString();
                            break;
                        case LAST_OPEN_ELEM:
                            v.value = session.last_open.elem;
                            break;
                        case LAST_URL:
                            v.value = session.last_url;
                            break;
                        case ALL_ASSERT:
                            for (SessionTrackAction sa : t.getSession(sop.from_session).track.getTrack()) {
                                if (sa.isAssert) {
                                    v.value += sa + "\n";
                                }
                            }
                            break;
                    }
                    updated_vars.add(v);
                    break;

                case INSERT:
                    String to_be_added = buildStringWithVars(updated_vars, sop.what);
                    track.insert(new Marker(sop.at), to_be_added);
                    break;

                case MARKER:
                    switch (sop.target) {
                        case LAST_ACTION:
                        case LAST_ACTION_ELEM:
                            track.mark(session.last_action, sop.mark_name);
                            break;
                        case LAST_CLICK:
                        case LAST_CLICK_ELEM:
                            track.mark(session.last_click, sop.mark_name);
                            break;
                        case LAST_OPEN:
                        case LAST_OPEN_ELEM:
                            track.mark(session.last_open, sop.mark_name);
                            break;
                        case ALL_ASSERT:
                            for (SessionTrackAction sa : t.getSession(sop.from_session).track.getTrack()) {
                                if (sa.isAssert) {
                                    track.mark(sa, sop.mark_name);
                                }
                            }
                            break;
                        case TRACK:
                        case LAST_URL:
                            throw new ParsingException("Invalid session operation target: " + sop.target);
                        default:
                            throw new ParsingException("Invalid session operation target");
                    }
                    break;
                case REMOVE:
                    if (sop.to != null && !sop.to.equals("")) {
                        // TODO: remove interval of indices instead of using the remove construct of lists, because it
                        // removes duplicated things

                        int[] range = t.getSession(sop.from_session).track.
                                getStasIndexFromRange(sop.at, sop.to, sop.is_from_included, sop.is_to_included);


                        t.getSession(sop.from_session).track.getTrack().subList(range[0], range[1] + 1).clear();
                    } else {
                        track.remove(new Marker(sop.at));
                    }
                    break;
            }
        }

        return updated_vars;
    }

    /**
     * Class to store the index and some information about matched messages (with regex or check) in an operation
     */
    public static class MatchedMessage {
        HTTPReqRes message;
        boolean isRequest = false;
        boolean isResponse = false;
        boolean isFail = false;
        Integer index;

        /**
         * Instantiates a MatchedMessage
         *
         * @param message    the message
         * @param index      the index in the message list
         * @param isRequest  if it is a request
         * @param isResponse if it is a response
         * @param isFail     if it maked the test fail
         */
        public MatchedMessage(HTTPReqRes message, Integer index, boolean isRequest, boolean isResponse, boolean isFail) {
            this.message = message;
            this.isResponse = isResponse;
            this.isRequest = isRequest;
            this.index = index;
            this.isFail = isFail;
        }
    }
}

