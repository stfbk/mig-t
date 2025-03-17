package org.zaproxy.addon.migt;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Class used to execute passive tests, it implements Runnable, it should be executed as a Thread.
 * To communicate with the tread you can use the ExecutePassivesListener listener class.
 */
public class ExecutePassives implements Runnable {
    final Object lock = new Object();
    public List<Test> passives;
    ExecutePassiveListener listener;
    List<MessageType> messageTypes;
    boolean finished;
    boolean execution_error;

    /**
     * Used to instantiate an ExecutePassives object
     *
     * @param passiveTests The list of passive tests to execute
     * @param listener the listener for this ExecutePassives Object, used to communicate with the
     *     thread
     * @param msg_types the list of message types needed by the tests
     */
    public ExecutePassives(
            List<Test> passiveTests, ExecutePassiveListener listener, List<MessageType> msg_types) {
        this.passives = passiveTests;
        this.listener = listener;
        this.messageTypes = msg_types;
        this.finished = false;
        this.execution_error = false;
    }

    /** Starts the execution of the passive tests */
    @Override
    public void run() {
        // This first piece is thought to make the thread wait before start
        while (!listener.onWaitToStart()) {
            try {
                // TODO: fix busy waiting
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                return;
            }
        }

        listener.onExecuteStart();
        execution_error = false;

        HashMap<String, List<Test>> batch = null;
        try {
            batch = Tools.batchPassivesFromSession(passives);
        } catch (ParsingException e) {
            e.printStackTrace();
            // lblOutput.setText(e.getMessage());
            return;
        }

        for (String sessionName : batch.keySet()) {
            List<Test> actual_batch = batch.get(sessionName);

            Session act_session = actual_batch.get(0).sessions.get(0);
            try {
                if (act_session.messages.size() == 0) {
                    act_session = listener.onNewSession(act_session);
                }
            } catch (ParsingException e) {
                listener.onError("Error in retrieving session");
                return;
            }

            Session executedSession = act_session;
            // If sessions already executed, don't re-execute them
            if (act_session.messages.size() == 0) {
                executedSession = executePassiveTestSession(act_session);
                for (Test t : actual_batch) {
                    t.sessions.set(0, executedSession);
                }
                batch.put(sessionName, actual_batch);
                if (execution_error) {
                    return;
                }
            }

            // Execute all the tests for each session
            for (Test actual_test : actual_batch) {
                System.out.println("Actual test name: " + actual_test.getName());

                boolean res = false;
                try {
                    res = actual_test.execute(executedSession.messages, messageTypes);
                } catch (ParsingException e) {
                    actual_test.applicable = false;
                }

                System.out.println("Actual test result: " + res);
                actual_test.success = res;
            }
            // Remove used session
            executedSession = null;
        }
        passives = Tools.debatchPassive(batch);
        listener.onExecuteDone(passives);
    }

    /**
     * Executes a passive test's session, to gather messages needed to execute the passive tests.
     *
     * @param session the session to be executed
     * @return the same session, executed, that will contain the intercepted messages
     */
    public Session executePassiveTestSession(Session session) {
        // FIXME: session's track is assumed to be present

        System.out.println("Eseguito executePassiveTestSession");

        synchronized (lock) {
            finished = false;
        }

        ExecuteTrackListener track_listener =
                new ExecuteTrackListener() {
                    @Override
                    public void onExecuteDone(
                            boolean errors, String current_url, String sessionName) {
                        ArrayList<HTTPReqRes> intercepted_messages = listener.onTrackExecuteDone();
                        session.messages = intercepted_messages;

                        if (errors) {
                            listener.onError("Error in executing track for session " + sessionName);
                            execution_error = true;
                        }
                        synchronized (lock) {
                            lock.notify();
                            finished = true;
                        }
                    }

                    @Override
                    public void onExecuteDone(boolean forceResult, String sessionName) {
                        ArrayList<HTTPReqRes> intercepted_messages = listener.onTrackExecuteDone();
                        session.messages = intercepted_messages;

                        synchronized (lock) {
                            lock.notify();
                            finished = true;
                        }
                    }

                    @Override
                    public void onError(String sessionName) {
                        listener.onError("Error in executing track for session " + sessionName);
                        execution_error = true;
                        synchronized (lock) {
                            lock.notify();
                            finished = true;
                        }
                    }

                    @Override
                    public Boolean onAskPause(String sessionName) {
                        return false;
                    }

                    @Override
                    public Boolean onAskStop(String sessionName) {
                        return false;
                    }

                    @Override
                    public Boolean onAskClearCookie(String sessionName) {
                        return null;
                    }

                    @Override
                    public void onNextSessionAction(
                            SessionTrackAction last_action,
                            SessionTrackAction last_open,
                            SessionTrackAction last_click,
                            String last_url,
                            String session_name) {}

                    @Override
                    public Track onUpdateTrack(String sessionName) throws ParsingException {
                        return null;
                    }

                    @Override
                    public void onSetVar(Var v) {}
                };

        listener.onBeforeExecuteTrack();
        session.ex.registerExecuteTrackListener(track_listener);
        new Thread(session.ex).start(); // ex is assumed to be initialized

        // Waits execution to be finished
        synchronized (lock) {
            while (!finished) {
                try {
                    lock.wait();
                } catch (InterruptedException e) {
                    break;
                }
            }
        }

        return session;
    }
}
