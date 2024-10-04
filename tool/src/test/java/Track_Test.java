/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.migt.Marker;
import org.zaproxy.addon.migt.ParsingException;
import org.zaproxy.addon.migt.SessionTrackAction;
import org.zaproxy.addon.migt.Track;

public class Track_Test {

    @Test
    @DisplayName("Test indexes")
    void testIndexes() throws ParsingException {
        Track t =
                new Track(
                        "open | https://www.google.com/ |\n"
                                + "open | https://www.youtube.com/ |\n"
                                + "wait | 3000");

        int indx_0 = t.indexOfStaFromMarker("M0", false);
        int indx_L = t.indexOfStaFromMarker("ML", true);

        assertEquals(0, indx_0);
        assertEquals(2, indx_L);

        t = new Track("");
        indx_0 = t.indexOfStaFromMarker("M0", false);
        indx_L = t.indexOfStaFromMarker("ML", true);

        assertEquals(-1, indx_0);
        assertEquals(-1, indx_L);
    }

    @Test
    @DisplayName("Test first and last indexes")
    void testFirstAndLAstIndexes() throws ParsingException {
        Track t =
                new Track(
                        "open | https://www.google.com/ |\n"
                                + "open | https://www.youtube.com/ |\n"
                                + "open | https://www.youtube.com/ |\n"
                                + "open | https://www.youtube.com/ |\n"
                                + "open | https://www.youtube.com/ |\n"
                                + "open | https://www.youtube.com/ |\n"
                                + "wait | 3000");

        int indx_0 = t.indexOfStaFromMarker("M0", false);
        int indx_L = t.indexOfStaFromMarker("ML", true);

        assertEquals(t.getTrack().get(0), t.getStasFromMarkers("M0", "M0", true, true).get(0));
        assertEquals(t.getTrack().get(indx_L), t.getStasFromMarkers("ML", "ML", true, true).get(0));
        assertEquals(t.getTrack(), t.getStasFromMarkers("M0", "ML", true, true));
    }

    @Test
    @DisplayName("Test insert")
    void testInsert() throws ParsingException {
        Track t =
                new Track(
                        "open | https://www.google.com/ |\n"
                                + "open | https://www.youtube.com/ |\n"
                                + "wait | 3000");

        t.insert(new Marker("M0"), "wait | 3000");

        assertEquals(
                t.getStasFromMarkers("M0", "M0", true, true).get(0).toString(),
                new SessionTrackAction("wait | 3000").toString());

        List<SessionTrackAction> l = new ArrayList<>();
        t.mark(t.getTrack().get(1), "M1");
        l.add(t.getTrack().get(1));
        t.mark(t.getTrack().get(2), "M2");
        l.add(t.getTrack().get(2));
        assertEquals(l, t.getStasFromMarkers("M1", "M2", true, true));

        t = new Track("");
        t.insert(new Marker("M0"), "wait | 3000");
        t.insert(new Marker("M0"), "wait | 4000");
        t.insert(new Marker("ML"), "wait | 5000");

        t = new Track("");
        String in =
                "open | https://www.google.com/ |\n"
                        + "open | https://www.youtube.com/ |\n"
                        + "wait | 3000 |";

        t.insert(new Marker("M0"), in);

        assertEquals(
                "open | https://www.google.com/ |\nopen | https://www.youtube.com/ |\nwait | 3000 |\n",
                t.toString());
    }

    @Test
    @DisplayName("Track equals")
    void testTrackEquals() throws ParsingException {
        Track t1 =
                new Track(
                        "open | https://www.google.com/ |\n"
                                + "open | https://www.youtube.com/ |\n"
                                + "wait | 3000");
        Track t2 =
                new Track(
                        "open | https://www.google.com/ |\n"
                                + "open | https://www.youtube.com/ |\n"
                                + "wait | 3000");

        assertEquals(t1, t2);
        assertEquals(t2, t1);

        t2 =
                new Track(
                        "open | https://www.google.com/ |\n"
                                + "open | https://www.youtube.com/ |\n");

        assertNotEquals(t1, t2);
        assertNotEquals(t2, t1);
    }

    @Test
    @DisplayName("Track remove test")
    void testTrackRemove() throws ParsingException {
        Track t =
                new Track(
                        "open | https://www.google.com/ |\n"
                                + "open | https://www.youtube.com/ |\n"
                                + "open | https://www.youtube.com/ |\n"
                                + "open | https://www.youtube.com/ |\n"
                                + "open | https://www.youtube.com/ |\n"
                                + "open | https://www.youtube.com/ |\n"
                                + "wait | 3000");

        t.remove(new Marker("ML"));
        assertEquals(
                "open | https://www.google.com/ |\n"
                        + "open | https://www.youtube.com/ |\n"
                        + "open | https://www.youtube.com/ |\n"
                        + "open | https://www.youtube.com/ |\n"
                        + "open | https://www.youtube.com/ |\n"
                        + "open | https://www.youtube.com/ |\n",
                t.toString());

        t.remove(new Marker("M0"));
        assertEquals(
                "open | https://www.youtube.com/ |\n"
                        + "open | https://www.youtube.com/ |\n"
                        + "open | https://www.youtube.com/ |\n"
                        + "open | https://www.youtube.com/ |\n"
                        + "open | https://www.youtube.com/ |\n",
                t.toString());
    }

    @Test
    @DisplayName("Test range")
    void rangeTest() throws ParsingException {
        Track t =
                new Track(
                        "open | https://www.google.com/ |\n"
                                + "open | https://www.youtube.com/ |\n"
                                + "wait | 3000");
        List<SessionTrackAction> sta = t.getStasFromMarkers("M0", "ML", false, true);
        assertEquals(t.getTrack().get(1), sta.get(0));
        assertEquals(t.getTrack().get(2), sta.get(1));

        sta = t.getStasFromMarkers("M0", "ML", true, false);
        assertEquals(2, sta.size());
        assertEquals(t.getTrack().get(0), sta.get(0));
        assertEquals(t.getTrack().get(1), sta.get(1));

        sta = t.getStasFromMarkers("M0", "M0", true, true);
        assertEquals(1, sta.size());
        assertEquals(t.getTrack().get(0), sta.get(0));
    }
}
