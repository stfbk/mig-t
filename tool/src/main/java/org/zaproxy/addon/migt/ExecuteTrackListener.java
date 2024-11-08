package org.zaproxy.addon.migt;

/** Listener for the ExectuteTrack Object */
public interface ExecuteTrackListener {

    /**
     * Called when the execution of the track is finished
     *
     * @param errors true if errors are found during execution of the track
     * @param current_url the url which the track execution stopped
     * @param sessionName The name of the session which was linked to the execution
     */
    void onExecuteDone(boolean errors, String current_url, String sessionName);

    /**
     * Called when the execution of the track is finished, and you want to force the result of the
     * test
     *
     * @param forceResult the final result the test will have, independently of correct or incorrect
     *     flow
     * @param sessionName The name of the session which was linked to the execution
     */
    void onExecuteDone(boolean forceResult, String sessionName);

    /**
     * Called when the Browser crashes or some error is present, it is different from the
     * onExecuteDone having the error parameter set to true, this method is called when an error not
     * related to the test, and that does not have to influence the result of the test is found.
     */
    void onError(String sessionName);

    /**
     * The caller asks if it has to pause, the listener responds
     *
     * @param sessionName the name of the session which is asking
     * @return true if the execution has to be paused, false otherwise
     */
    Boolean onAskPause(String sessionName);

    /**
     * The thread asks if it has to stop the execution, the listener responds
     *
     * @param sessionName The name of the session that is executing
     * @return true if the execution should stop
     */
    Boolean onAskStop(String sessionName);

    /**
     * The thread asks if it has to clear the cookies, the listener responds
     *
     * @param sessionName The name of the session that is executing
     * @return true if the browser that is executing should clear the cookies
     */
    Boolean onAskClearCookie(String sessionName);

    /**
     * Called whether a new session action is executed. This is used to update the listener on the
     * actions that are being executed
     *
     * @param last_action the last User action executed at this point
     * @param last_open the last open User action executed to this point
     * @param last_click the last click User action executed to this point
     * @param last_url the last url User action executed to this point
     * @param session_name the name of the session that is executing
     * @throws ParsingException If problems are encounter retrieving these parameters
     */
    void onNextSessionAction(
            SessionTrackAction last_action,
            SessionTrackAction last_open,
            SessionTrackAction last_click,
            String last_url,
            String session_name)
            throws ParsingException;

    /**
     * With this method is possible to update the Session track during execution
     *
     * @param sessionName the name of the session that is executing
     * @return the updated track
     * @throws ParsingException if problems are encountered in updating the session track
     */
    Track onUpdateTrack(String sessionName) throws ParsingException;

    /**
     * Called whether a variable is set using a User action
     *
     * @param v the variable that has been set
     */
    void onSetVar(Var v);
}
