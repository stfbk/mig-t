package org.zaproxy.addon.migt;

import java.util.ArrayList;
import java.util.List;

/** Listener class for the ExecutePassive Object */
public interface ExecutePassiveListener {
    /**
     * This method is called when the ExecutePassive thread is started, it is used to tell when the
     * thread should start executing the passives test. if it returns true, the thread will start
     *
     * @return true if you want the thread to start
     */
    boolean onWaitToStart();

    /** Called when the ExecutePassives thread is started */
    void onExecuteStart();

    /**
     * Called when the ExecutePassives thread has ended
     *
     * @param passives_test The list of executed passive tests
     */
    void onExecuteDone(List<Test> passives_test);

    /**
     * Called when there is an error in the execution
     *
     * @param msg the error message
     */
    void onError(String msg);

    /**
     * When a new session has to be executed this method is called. This is thought to fill the
     * session with the right values from the GUI class.
     *
     * @param s the session to be initiated
     * @return the session with the filled values
     */
    Session onNewSession(Session s) throws ParsingException;

    /**
     * Called before the track of the session is executed. Usually used to start the recording of
     * the messages in the GUI class
     */
    void onBeforeExecuteTrack();

    /**
     * Called when a track ends its execution
     *
     * @return the list of intercepted messages
     */
    ArrayList<HTTPReqRes> onTrackExecuteDone();
}
