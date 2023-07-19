package migt;

import burp.IHttpService;
import burp.IInterceptedProxyMessage;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static migt.Tools.buildStringWithVars;
import static migt.Tools.findParentDiv;

/**
 * Class storing an Operation in a Test
 *
 * @author Matteo Bitussi
 */
public class Operation extends Module {
    public List<MessageOperation> messageOerations;
    public String from_session;
    public String to_session;
    public Then then;
    public String save_name;
    public int to_match;
    public int act_matched;
    public String session_port;
    public List<Check> preconditions;
    public String replace_request_name;
    public String replace_response_name;
    public boolean isSessionOp = false;
    public List<MatchedMessage> matchedMessages;
    public byte[] processed_message;
    public IHttpService processed_message_service;  // null if it is not changed
    public String decode_param;
    public List<DecodeOperation.Encoding> encodings;
    public List<IInterceptedProxyMessage> log_messages;
    public List<SessionOperation> session_operations;
    // Decode operations
    public List<DecodeOperation> decodeOperations;
    // Session operation
    // API
    Operation_API api;
    private List<Check> checks;
    private String messageType;
    private HTTPReqRes.MessageSection messageSection;
    private Action action;
    private String session;
    private SessionOperation.SessionAction sessionAction;

    /**
     * Instantiate an operation
     */
    public Operation() {
        init();
    }

    /**
     * Instantiate an Operation parsing a JSON object
     *
     * @param operation_json the operation defined in MIG-L as JSONObject
     * @param isActive       if the operation is used inside an active or passive test
     * @param messageTypes   All the message types imported
     * @throws Exception
     */
    public Operation(JSONObject operation_json,
                     boolean isActive,
                     List<MessageType> messageTypes) throws Exception {
        init();

        if (!isActive) {
            if (operation_json.has("decode param")) {
                decode_param = operation_json.getString("decode param");

                JSONArray encodings = operation_json.getJSONArray("encoding");
                Iterator<Object> it = encodings.iterator();

                while (it.hasNext()) {
                    String act_enc = (String) it.next();
                    this.encodings.add(
                            DecodeOperation.Encoding.fromString(act_enc));
                }
            }
            if (operation_json.has("checks")) {
                //non regex version
                JSONArray checks = operation_json.getJSONArray("checks");

                if (operation_json.has("message section")) {
                    setMessageSection(HTTPReqRes.MessageSection.fromString(operation_json.getString("message section")));
                }
                setChecks(Tools.parseChecksFromJSON(checks));
            }
        } else {
            // If the test is active
            if (operation_json.has("session")) {
                // If is a Session Operation
                String session = operation_json.getString("session");
                String action = operation_json.getString("action");

                List<SessionOperation> lsop = SessionOperation.parseFromJson(operation_json);
                if (lsop != null) {
                    for (SessionOperation sop : lsop) {
                        session_operations.add(sop);
                    }
                }

                setSession(session);
                setSessionAction(action);
                isSessionOp = true;
                return;
            }

            // If is a standard operation
            String action = operation_json.getString("action");
            setAction(action);

            // if it is a validate
            if (getAction() == Action.VALIDATE) {
                // TODO: to remove match?
                if (operation_json.has("match")) {
                    String toMatch = operation_json.getString("match");
                    if (toMatch.equals("all")) to_match = -1;
                    else to_match = Integer.parseInt(toMatch);
                } else {
                    to_match = 1;
                }
                //non regex version
                JSONArray checks = operation_json.getJSONArray("checks");
                setChecks(Tools.parseChecksFromJSON(checks));
            }

            if (operation_json.has("from session")) {
                from_session = operation_json.getString("from session");
            }
            if (operation_json.has("to session")) {
                to_session = operation_json.getString("to session");
            }
            if (operation_json.has("then")) {
                then = Then.fromString(operation_json.getString("then"));
            }
            if (operation_json.has("save")) {
                save_name = operation_json.getString("save");
            }
            if (operation_json.has("replace request")) {
                replace_request_name = operation_json.getString("replace request");
            } else if (operation_json.has("replace response")) {
                replace_response_name = operation_json.getString("replace response");
            }

            // Preconditions
            if (operation_json.has("preconditions")) {
                JSONArray checks = operation_json.getJSONArray("preconditions");
                preconditions = Tools.parseChecksFromJSON(checks);
            }

            // Message Operations
            if (operation_json.has("message operations")) {
                JSONArray message_ops = operation_json.getJSONArray("message operations");
                for (int k = 0; k < message_ops.length(); k++) {
                    JSONObject act_message_op = message_ops.getJSONObject(k);
                    MessageOperation message_op = new MessageOperation(act_message_op);
                    messageOerations.add(message_op);
                }
            }

            // Decode Operations
            if (operation_json.has("decode operations")) {
                JSONArray decode_ops = operation_json.getJSONArray("decode operations");
                for (int k = 0; k < decode_ops.length(); k++) {
                    JSONObject act_decode_op = decode_ops.getJSONObject(k);
                    // recursion managed inside
                    DecodeOperation decode_op = new DecodeOperation(act_decode_op);
                    decodeOperations.add(decode_op);
                }
            }
            setMessageType(operation_json.getString("message type"), messageTypes);
        }
    }

    private void init() {
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


    public HTTPReqRes.MessageSection getMessageSection() {
        return messageSection;
    }

    public void setMessageSection(HTTPReqRes.MessageSection messageSection) {
        this.messageSection = messageSection;
    }

    public Action getAction() {
        return action;
    }

    public void setAction(String action) throws ParsingException {
        this.setAction(Action.fromString(action));
    }

    public void setAction(Action action) {
        this.action = action;
    }

    public String getSession() {
        return session;
    }

    public void setSession(String sessionName) {
        this.session = sessionName;
    }

    public SessionOperation.SessionAction getSessionAction() {
        return sessionAction;
    }

    public void setSessionAction(String sessionAction) throws ParsingException {
        this.setSessionAction(SessionOperation.SessionAction.fromString(sessionAction));
    }

    public void setSessionAction(SessionOperation.SessionAction sessionAction) {
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

    public Operation_API getAPI() {
        return this.api;
        // TODO: check if the api should be updated with the processed message before returning it
        // TODO: the api should be updated i.e. if the message is edited before making it available
    }

    public void setAPI(Operation_API api) {
        this.api = api;
        // updates the processed message from the api
        this.processed_message = api.message.build_message(api.is_request);
    }

    public void execute() {
        // TODO
    }

    /**
     * Enum containing all the possible Active operation actions
     */
    public enum Action {
        INTERCEPT,
        VALIDATE;

        /**
         * From a string get the corresponding enum value
         *
         * @param input the string
         * @return the enum value
         * @throws ParsingException if the input is malformed
         */
        public static Action fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "intercept":
                        return INTERCEPT;
                    case "validate":
                        return VALIDATE;
                    default:
                        throw new ParsingException("invalid check operation");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }

    /**
     * Enum that contains all the possible action to do after a message is received
     */
    public enum Then {
        FORWARD,
        DROP;

        /**
         * From a string get the corresponding enum value
         *
         * @param input the string
         * @return the enum value
         * @throws ParsingException if the input is malformed
         */
        public static Then fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "forward":
                        return FORWARD;
                    case "drop":
                        return DROP;
                    default:
                        throw new ParsingException("invalid check operation");
                }
            } else {
                throw new NullPointerException();
            }
        }
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

