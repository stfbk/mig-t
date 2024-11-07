package org.zaproxy.addon.migt;

import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;
import java.util.Objects;

/**
 * This class represents the track of a session. The track is a list of all the user actions to be
 * done during a test
 */
public class Track {
    private final List<SessionTrackAction> track;

    public int hashCode() {
        return Objects.hash(track);
    }

    /**
     * Instantiate a new Track object, starting from a raw session track
     *
     * @param raw The raw session track to be parsed
     * @throws ParsingException Thrown if there are problems parsing the track
     */
    public Track(String raw) throws ParsingException {
        track = new ArrayList<>();
        if (raw.equals("")) {
            return;
        }

        String[] steps = raw.trim().split("\n");

        for (String row : steps) {
            track.add(new SessionTrackAction(row));
        }
        updateIndexes();
    }

    /**
     * Updates the indexes of the first and last element of the track. This function has to be
     * called each time the list is updated.
     */
    private void updateIndexes() {
        for (SessionTrackAction sta : track) {
            if (sta.markers.size() != 0) {
                sta.markers.remove(new Marker("M0"));
                sta.markers.remove(new Marker("ML"));
            }
        }

        track.get(0).markers.add(new Marker("M0"));
        track.get(track.size() - 1).markers.add(new Marker("ML"));
    }

    public List<SessionTrackAction> getTrack() {
        return track;
    }

    /**
     * Get the index of the first User Action having the given marker.
     *
     * @param marker_name The name of the marker to search
     * @param start_from_last true if you want to start searching from the last element
     * @return the index
     */
    public int indexOfStaFromMarker(String marker_name, boolean start_from_last) {
        if (track.size() == 0) {
            return -1;
        }

        Marker m = new Marker(marker_name);

        if (start_from_last) {
            int indx = track.size() - 1;
            ListIterator<SessionTrackAction> listIterator = track.listIterator(track.size());
            while (listIterator.hasPrevious()) {
                SessionTrackAction sta = listIterator.previous();
                if (sta.markers.size() != 0) {
                    if (sta.markers.contains(m)) {
                        return indx;
                    }
                }
                indx--;
            }
        } else {
            int indx = 0;
            for (SessionTrackAction sta : track) {
                if (sta.markers.size() != 0) {
                    if (sta.markers.contains(m)) {
                        return indx;
                    }
                }
                indx++;
            }
        }
        return -1;
    }

    /**
     * Return the index of the first user action which has the markerFrom, and the index of the
     * first user action having the marker to (searched from the end of the track)
     *
     * @param markerFrom The left range marker to search for
     * @param markerTo The right range marker to search for
     * @param is_from_included true if the left range element is included
     * @param is_to_included true if the right range element is included
     * @return an array of int of length 2, containing the left index in position 0, and right index
     *     in position 1
     * @throws ParsingException If the markers are not found
     */
    public int[] getStasIndexFromRange(
            String markerFrom, String markerTo, boolean is_from_included, boolean is_to_included)
            throws ParsingException {
        int indx_from =
                is_from_included
                        ? indexOfStaFromMarker(markerFrom, false)
                        : indexOfStaFromMarker(markerFrom, false) + 1;
        int indx_to =
                is_to_included
                        ? indexOfStaFromMarker(markerTo, true)
                        : indexOfStaFromMarker(markerTo, true) - 1;

        if (indx_from == -1) throw new ParsingException("Invalid from marker");

        int[] res = new int[2];
        res[0] = indx_from;
        res[1] = indx_to;

        return res;
    }

    /**
     * Given a range represented by two markers, return the User actions in that range from the
     * track.
     *
     * @param markerFrom the left range marker to search for
     * @param markerTo the right range marker to search for (starting from the end of the track
     *     backward)
     * @param is_from_included true if the left range element should be included
     * @param is_to_included true if the right range element should be included
     * @return a list of User Actions in that range
     * @throws ParsingException if markers are not found
     */
    public List<SessionTrackAction> getStasFromMarkers(
            String markerFrom, String markerTo, boolean is_from_included, boolean is_to_included)
            throws ParsingException {

        int[] range = getStasIndexFromRange(markerFrom, markerTo, is_from_included, is_to_included);

        int indx_from = range[0];
        int indx_to = range[1];

        List<SessionTrackAction> res = new ArrayList<>();

        int act_indx = indx_from;
        while (act_indx != indx_to + 1) {
            res.add(track.get(act_indx));
            act_indx++;
        }

        return res;
    }

    /**
     * Mark a given user action with a marker
     *
     * @param to_be_marked the User Action to be marked
     * @param marker_name the name of the marker
     * @throws ParsingException If the User Action is not found in the track
     */
    public void mark(SessionTrackAction to_be_marked, String marker_name) throws ParsingException {
        int indx = track.indexOf(to_be_marked);
        if (indx == -1)
            throw new ParsingException("Cannot find previous action, maybe not yet occurred?");
        SessionTrackAction sta = track.get(indx);
        sta.markers.add(new Marker(marker_name));
        track.set(indx, sta);
        updateIndexes();
    }

    /**
     * Insert an User Action in a given position of the track
     *
     * @param at the marker used as a reference to insert the user action to
     * @param to_be_inserted the User Action to insert in string format
     * @throws ParsingException if marker non present in track or action malformed
     */
    public void insert(Marker at, String to_be_inserted) throws ParsingException {
        int indx = indexOfStaFromMarker(at.name, false) + 1;

        if (at.name.equals("M0")) indx = 0;

        if (to_be_inserted.contains("\n")) {
            // If there are multiple actions in the String
            String[] split = to_be_inserted.split("\n");
            for (String s : split) {
                SessionTrackAction sa = new SessionTrackAction(s);
                track.add(indx, sa);
                indx++;
            }
        } else {
            // If there is just one action in the string
            SessionTrackAction sa = new SessionTrackAction(to_be_inserted);
            track.add(indx, sa); // Add shifts the list next the new element
        }
        updateIndexes();
    }

    /**
     * Removes all User Action in track having the specified marker
     *
     * @param at the marker telling which actions to remove
     * @throws ParsingException if no actions are found with that marker.
     */
    public void remove(Marker at) throws ParsingException {
        boolean done = false;
        while (!done) {
            int indx = indexOfStaFromMarker(at.name, false);

            if (indx == -1) {
                done = true;
                break;
            }

            track.remove(indx);
        }
        updateIndexes();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        return this.track.equals(((Track) o).getTrack());
    }

    /**
     * Return the track in string format complaint with the language.
     *
     * @return the track in string format
     */
    @Override
    public String toString() {
        String res = "";

        for (SessionTrackAction sa : track) {
            res += sa + "\n";
        }
        return res;
    }
}
