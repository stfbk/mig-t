package org.zaproxy.addon.migt;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

/** Class to manage Sessions */
public class Session {
    // Session actions
    public SessionTrackAction last_action;
    public SessionTrackAction last_open;
    public SessionTrackAction last_click;
    public String last_url;
    public String name = "";
    String port;
    Track track;
    int index = 0;
    List<HTTPReqRes> messages;

    boolean isOffline = false;
    ExecuteTrack ex;

    /** Instantiate the session */
    public Session() {
        this.messages = new ArrayList<>();
        this.name = "";
        this.port = "";
        try {
            this.track = new Track("");
        } catch (ParsingException e) {
            e.printStackTrace();
        }
    }

    /**
     * Instantiate the session
     *
     * @param name the session name
     */
    public Session(String name) {
        this.messages = new ArrayList<>();
        this.name = name;
        this.port = "8080";
        try {
            this.track = new Track("");
        } catch (ParsingException e) {
            e.printStackTrace();
        }
    }

    /**
     * Instantiate the session
     *
     * @param name the name of the session
     * @param port the port of the session
     */
    public Session(String name, String port) {
        this.messages = new ArrayList<>();
        this.name = name;
        this.port = port;
        try {
            this.track = new Track("");
        } catch (ParsingException e) {
            e.printStackTrace();
        }
    }

    public Track getTrack() {
        return track;
    }

    /**
     * Tells if the session's track has an element
     *
     * @return true if the track has at least one more element
     */
    public boolean hasNext() {
        return track.getTrack().size() > index;
    }

    /**
     * Gets the next track element. Note that the function <code>hasNext()</code> could be called
     * before the execution of this function track
     *
     * @return the next track element
     */
    public SessionTrackAction next() {
        return track.getTrack().get(index++);
    }

    /**
     * Adds a message to the list of messages in this session. if the param filter is set to true
     * the message is checked against some common file extension and if it is matched it is
     * discarded
     *
     * @param msg the message to be added
     * @param filter specify if filtering is enabled
     * @return the added message
     */
    public HTTPReqRes addMessage(HttpMessage msg, boolean filter)
            throws URISyntaxException,
                    MalformedURLException,
                    HttpMalformedHeaderException,
                    DatabaseException {
        HTTPReqRes res = null;

        if (filter) {
//            String forURI = message.getRequestHeader().getURI().toString();
//            URI uri = new URI(forURI);
//            String url = uri.toURL().toString();
            String url = msg.getRequestHeader().getPrimeHeader();
            url = url.split("\\sHTTP")[0];
            Pattern pattern =
                    Pattern.compile(
                            "\\.gif$|\\.jpg$|\\.jpeg$|\\.svg$|\\.png$|\\.css$|\\.js$|\\.webp$|\\.ico$|"
                                    + "\\.tiff$|\\.bpm$|\\.ttf$|\\.otf$|\\.woff$|\\.woff2$|\\.eot$|\\.txt$");
            Matcher matcher = pattern.matcher(url);

            if (!matcher.find()) {
                res = new HTTPReqRes(msg);
                messages.add(res);
            }
        } else {
            res = new HTTPReqRes(msg);
            messages.add(res);
        }
        return res;
    }

    /**
     * Set the track of this session by parsing a string track
     *
     * @param raw_track the track in string format
     * @return the parsed track as a Track object
     * @throws ParsingException if the track is malformed
     */
    public Track setTrackFromString(String raw_track) throws ParsingException {
        track = new Track(raw_track);
        return track;
    }
}
