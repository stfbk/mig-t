package org.zaproxy.addon.migt;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** This class represents an user action in a session */
public class SessionTrackAction {
    public SessionOperation.SessAction action;
    public String elem_type;
    public String elem_source;
    public String elem;
    public String content;
    public List<Marker> markers;
    public boolean isAssert;

    // "action | elem_type=elem_source | content"

    public int hashCode() {
        return Objects.hash(elem, elem_type, elem_source, content);
    }

    /** Constuctor used to instantiate the class */
    public SessionTrackAction() {
        action = null;
        elem_type = "";
        elem_source = "";
        elem = "";
        content = "";
        markers = new ArrayList<>();
        isAssert = false;
    }

    /**
     * Constructor parsing a raw action in string format
     *
     * @param raw_action The user action in string format
     * @throws ParsingException If the user action is written wrongly
     */
    public SessionTrackAction(String raw_action) throws ParsingException {
        markers = new ArrayList<>();
        parse_raw_action(raw_action);
    }

    /**
     * Function used to parse a string containing a raw user action in string format
     *
     * @param raw_action the user action in string format
     * @throws ParsingException if user action is not written properly
     */
    public void parse_raw_action(String raw_action) throws ParsingException {
        try {
            String[] splitted = raw_action.split("\\|");
            if (splitted.length < 2 || splitted.length > 3) {
                throw new ParsingException("invalid session action \"" + raw_action + "\"");
            }

            action = SessionOperation.SessAction.getFromString(splitted[0].trim());
            if (splitted[0].trim().contains("assert")) {
                isAssert = true;
            }

            if (action == SessionOperation.SessAction.CLEAR_COOKIES) return;

            elem = splitted[1].trim();
            if (!(action == SessionOperation.SessAction.OPEN)
                    && action != SessionOperation.SessAction.WAIT
                    && action != SessionOperation.SessAction.ALERT
                    && action != SessionOperation.SessAction.SET_VAR) {
                String[] tmp = elem.split("=");
                elem_type = tmp[0].trim();
                elem_source = tmp[1].trim();
            }
            if (splitted.length == 3) {
                content = splitted[2].trim();
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ParsingException("invalid session action \"" + raw_action + "\"");
        }
    }

    /**
     * Prints the user action as it was in string format. Compliant with the language.
     *
     * @return
     */
    @Override
    public String toString() {
        String res = "";
        switch (action) {
            case CLICK:
                res += "click";
                break;
            case OPEN:
                res += "open";
                break;
            case TYPE:
                res += "type";
                break;
            case SNAPSHOT:
                res += "snapshot";
                break;
            case DIFF:
                res += "diff";
                break;
            case EQUALS:
                res += "equals";
                break;
            case WAIT:
                res += "wait";
                break;
            case CLEAR_COOKIES:
                res += "cookies";
                break;
            case ASSERT_CLICKABLE:
                res += "assert clickable";
                break;
            case ASSERT_NOT_CLICKABLE:
                res += "assert not clickable";
                break;
            case ASSERT_VISIBLE:
                res += "assert visible";
                break;
            case ASSERT_NOT_VISIBLE:
                res += "assert not visible";
                break;
            case ALERT:
                res += "alert";
                break;
            case SET_VAR:
                res += "set var";
                break;
        }
        switch (action) {
            case OPEN:
            case WAIT:
            case ALERT:
                res += " | " + elem + " |";
                break;
            case SET_VAR:
                res += " | " + elem + " | " + content + " |";
                break;
            case TYPE:
            case CLICK:
            case SNAPSHOT:
            case DIFF:
            case EQUALS:
            case ASSERT_CLICKABLE:
            case ASSERT_VISIBLE:
            case ASSERT_NOT_VISIBLE:
            case ASSERT_NOT_CLICKABLE:
                res += " | " + elem_type + "=" + elem_source + " |";
                break;
            case CLEAR_COOKIES:
                break;
        }
        if (action == SessionOperation.SessAction.TYPE) {
            res += " " + content;
        }

        return res;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SessionTrackAction that = (SessionTrackAction) o;

        if (isAssert != that.isAssert) return false;
        if (action != that.action) return false;
        if (!Objects.equals(elem_type, that.elem_type)) return false;
        if (!Objects.equals(elem_source, that.elem_source)) return false;
        if (!Objects.equals(elem, that.elem)) return false;
        if (!Objects.equals(content, that.content)) return false;
        return Objects.equals(markers, that.markers);
    }
}
