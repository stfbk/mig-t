package org.zaproxy.addon.migt;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONObject;

/** Class containing a session Operation */
public class SessionOperation {
    public String from_session;
    public SessOperationAction action;
    public String what;
    public String as;
    public String at;
    public String to; // until to which ession action save
    public boolean is_from_included = false;
    public boolean is_to_included = false;
    public SessOperationTarget target;
    public String mark_name;

    /**
     * Parses a list of session operations from json
     *
     * @param act_operation the session operations as JSON object
     * @return the list of tession operations
     * @throws ParsingException if the parsing goes wrong
     */
    public static List<SessionOperation> parseFromJson(JSONObject act_operation)
            throws ParsingException {
        List<SessionOperation> lsop = new ArrayList<>();
        if (act_operation.has("session operations")) {
            JSONArray session_ops = act_operation.getJSONArray("session operations");
            for (int l = 0; l < session_ops.length(); l++) {
                JSONObject act_session_op = session_ops.getJSONObject(l);
                SessionOperation sop = new SessionOperation();
                Iterator<String> keys = act_session_op.keys();
                while (keys.hasNext()) {
                    String key = keys.next();

                    switch (key) {
                        case "session":
                            sop.from_session = act_session_op.getString("session");
                            break;
                        case "save":
                            sop.action = SessOperationAction.SAVE;
                            sop.target =
                                    SessOperationTarget.getFromString(
                                            act_session_op.getString("save"));
                            break;
                        case "as":
                            sop.as = act_session_op.getString("as");
                            break;
                        case "insert":
                            sop.action = SessOperationAction.INSERT;
                            sop.what = act_session_op.getString("insert");
                            break;
                        case "at":
                            sop.at = act_session_op.getString("at");
                            break;
                        case "mark":
                            sop.action = SessOperationAction.MARKER;
                            sop.target =
                                    SessOperationTarget.getFromString(
                                            act_session_op.getString("mark"));
                            sop.mark_name = act_session_op.getString("name");
                            break;
                        case "name":
                            // Already processed in mark
                            break;
                        case "remove":
                            sop.action = SessOperationAction.REMOVE;
                            if (sop.at == null || sop.at.length() == 0) {
                                sop.at = act_session_op.getString("remove");
                            }
                            break;

                        case "range":
                            List<Object> res = parseRange(act_session_op.getString("range"));
                            sop.is_from_included = (boolean) res.get(0);
                            sop.is_to_included = (boolean) res.get(1);
                            sop.at = (String) res.get(2);
                            sop.to = (String) res.get(3);
                            break;

                        default:
                            throw new ParsingException(
                                    "Unexpected value: " + key + " in session operation");
                    }
                }
                lsop.add(sop);
            }
            return lsop;
        }
        return null;
    }

    /**
     * Parse a string containing a range in the form of [number, number] or (number,number], based
     * on the type of parenthesis you can say that the rance is included [ or excluded (
     *
     * @param range The string containing the range to parse
     * @return Position 0, true if from included. Position 1: true if to included. Position 2: from,
     *     Position 3: to
     */
    public static List<Object> parseRange(String range) throws ParsingException {
        Pattern p =
                Pattern.compile("^(\\(|\\[)\\s*([^\\[\\],]*)\\s*,\\s*([^\\[\\],]*)\\s*(\\)|\\])$");
        Matcher m = p.matcher(range);

        List<Object> l = new ArrayList<>();

        List<String> tmp = new ArrayList<>();

        int count = m.groupCount();

        if (count != 4)
            throw new ParsingException("invalid range in session operation: \"" + range + "\"");

        while (m.find()) {
            tmp.add(m.group(1));
            tmp.add(m.group(2));
            tmp.add(m.group(3));
            tmp.add(m.group(4));
        }

        if (tmp.size() != 4)
            throw new ParsingException("invalid range in session operation: \"" + range + "\"");

        l.add(tmp.get(0).equals("["));
        l.add(tmp.get(3).equals("]"));
        l.add(tmp.get(1));
        l.add(tmp.get(2));

        return l;
    }

    /** Enum containing all the possible session operation actions */
    public enum SessionAction {
        START,
        PAUSE,
        RESUME,
        STOP,
        CLEAR_COOKIES;

        /**
         * From a string get the corresponding enum value
         *
         * @param input the string
         * @return the enum value
         * @throws ParsingException if the input is malformed
         */
        public static SessionAction fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "start":
                        return START;
                    case "pause":
                        return PAUSE;
                    case "resume":
                        return RESUME;
                    case "stop":
                        return STOP;
                    case "clear cookies":
                        return CLEAR_COOKIES;
                    default:
                        throw new ParsingException("invalid Session action");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }

    /** Defines the action of a session action */
    public enum SessAction {
        CLICK,
        OPEN,
        TYPE,
        SNAPSHOT,
        DIFF,
        EQUALS,
        WAIT,
        SET_VAR,
        CLEAR_COOKIES,
        ASSERT_CLICKABLE,
        ASSERT_NOT_CLICKABLE,
        ASSERT_VISIBLE,
        ASSERT_NOT_VISIBLE,
        ASSERT_ELEM_CONTENT_IS,
        ASSERT_ELEM_CONTENT_HAS,
        ASSERT_ELEM_CLASS_IS,
        ASSERT_ELEM_CLASS_HAS,
        ASSERT_ELEM_HAS_ATTRIBUTE,
        ASSERT_ELEM_NOT_HAS_ATTRIBUTE,
        ALERT;

        /**
         * Get a session action enum value from a string
         *
         * @param s the string
         * @return the enum value
         * @throws ParsingException if the string is invalid
         */
        public static SessAction getFromString(String s) throws ParsingException {
            switch (s) {
                case "assert click":
                case "click":
                    return CLICK;
                case "open":
                case "assert open": // just an alias of open
                    return OPEN;
                case "type":
                    return TYPE;
                case "snapshot":
                    return SNAPSHOT;
                case "diff":
                    return DIFF;
                case "equals":
                    return EQUALS;
                case "wait":
                    return WAIT;
                case "set var":
                    return SET_VAR;
                case "clear cookies":
                    return CLEAR_COOKIES;
                case "assert clickable":
                    return ASSERT_CLICKABLE;
                case "assert not clickable":
                    return ASSERT_NOT_CLICKABLE;
                case "assert visible":
                    return ASSERT_VISIBLE;
                case "assert not visible":
                    return ASSERT_NOT_VISIBLE;
                case "assert element content is":
                    return ASSERT_ELEM_CONTENT_IS;
                case "assert element content has":
                    return ASSERT_ELEM_CONTENT_HAS;
                case "assert element class is":
                    return ASSERT_ELEM_CLASS_IS;
                case "assert element class has":
                    return ASSERT_ELEM_CLASS_HAS;
                case "assert element has attribute":
                    return ASSERT_ELEM_HAS_ATTRIBUTE;
                case "assert element not has attribute":
                    return ASSERT_ELEM_NOT_HAS_ATTRIBUTE;
                case "alert":
                    return ALERT;
                default:
                    throw new ParsingException("Invalid session action \"" + s + "\"");
            }
        }
    }

    /** Defines the action of a session operation */
    public enum SessOperationAction {
        SAVE,
        INSERT,
        MARKER,
        REMOVE
    }

    /**
     * Defines the target of a session operation. Is it better to use js or just build a form? if a
     * form is used, body has to be interpreted
     */
    public enum SessOperationTarget {
        LAST_ACTION,
        LAST_ACTION_ELEM,
        LAST_ACTION_ELEM_PARENT,
        LAST_CLICK,
        LAST_CLICK_ELEM,
        LAST_CLICK_ELEM_PARENT,
        LAST_OPEN,
        LAST_OPEN_ELEM,
        LAST_URL,
        ALL_ASSERT,
        TRACK;

        /**
         * Parse a string containing a session operation target
         *
         * @param s the string to parse
         * @throws ParsingException if the string is malformed, or no session operation target is
         *     found
         */
        public static SessOperationTarget getFromString(String s) throws ParsingException {

            if (s.contains(".")) {
                String[] splitted;
                splitted = s.split("\\.");
                boolean parent = false;
                if (splitted.length == 3) {
                    if (splitted[2].equals("parent")) {
                        parent = true;
                    }
                }

                switch (s) {
                    case "last_action.elem":
                    case "last_action.elem.parent":
                        return parent ? LAST_ACTION_ELEM_PARENT : LAST_ACTION_ELEM;
                    case "last_click.elem":
                    case "last_click.elem.parent":
                        return parent ? LAST_CLICK_ELEM_PARENT : LAST_CLICK_ELEM;
                    case "last_open.elem":
                        return LAST_OPEN_ELEM;
                    case "last_url":
                        return LAST_URL;
                    case "all_assert":
                        return ALL_ASSERT;
                    default:
                        throw new ParsingException("invalid target in session operation");
                }
            } else {
                switch (s) {
                    case "track":
                        return TRACK;
                    case "last_action":
                        return LAST_ACTION;
                    case "last_click":
                        return LAST_CLICK;
                    case "last_open":
                        return LAST_OPEN;
                    case "last_url":
                        return LAST_URL;
                    case "all_assert":
                        return ALL_ASSERT;
                    default:
                        throw new ParsingException("invalid target in session operation");
                }
            }
        }
    }
}
