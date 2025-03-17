package org.zaproxy.addon.migt;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.PatternSyntaxException;

/** Class which executes actives tests, has to be run as a thread */
public class ExecuteActives implements Runnable {
    final Object waiting; // the lock on which the thread will wait
    ExecuteActiveListener listener;
    List<Test> actives;

    /**
     * Instantiate the class
     *
     * @param actives the list of Active tests
     * @param waiting an object which will serve as a lock between this class and BurpExtender to
     *     stop and resume the execution
     */
    public ExecuteActives(List<Test> actives, Object waiting) {
        this.actives = actives;
        this.waiting = waiting;
    }

    /**
     * Method to register an ExecuteActiveListener, used to receive callbacks
     *
     * @param listener the listener
     */
    public void registerExecuteActivesListener(ExecuteActiveListener listener) {
        this.listener = listener;
    }

    /** The run method, which runs the Tests */
    @Override
    public void run() {
        listener.onExecuteStart();
        for (Test actual_test : actives) {
            listener.onNewTest(actual_test);

            Map<String, Boolean> isInPause = new HashMap<>();
            Map<String, Boolean> clearCookieAsked = new HashMap<>();

            for (Session s : actual_test.sessions) {
                s = listener.onNewSession(s);
                if (s == null) {
                    listener.onError(actual_test);
                }
                isInPause.put(s.name, false);
            }

            Map<String, Thread> executions = new HashMap<>();
            AtomicInteger alive_count = new AtomicInteger();

            for (Operation op : actual_test.operations) {
                try {
                    // if the operation is a session control operation
                    if (op.isSessionOp) {
                        actual_test.applicable = true;
                        switch (op.getSessionAction()) {
                            case START:
                                {
                                    Session selected = actual_test.getSession(op.getSession());
                                    if (selected == null) {
                                        actual_test.error_str =
                                                "Invalid session name, maybe you didn't declare it?";
                                        actual_test.error = true;
                                        break;
                                    }
                                    selected.ex.registerExecuteTrackListener(
                                            new ExecuteTrackListener() {
                                                @Override
                                                public void onExecuteDone(
                                                        boolean errors,
                                                        String current_url,
                                                        String sessionName) {
                                                    if (actual_test.resultSession.equals("")
                                                            || actual_test.resultSession.equals(
                                                                    sessionName)) {

                                                        if (actual_test.result
                                                                == Test.ResultType.CORRECT_FLOW) {
                                                            if (errors
                                                                    || current_url.contains(
                                                                            "error")) {
                                                                actual_test.success = false;
                                                            }
                                                        } else if (actual_test.result
                                                                == Test.ResultType.INCORRECT_FLOW) {
                                                            actual_test.success =
                                                                    errors; // Difficult to read
                                                        } else if (actual_test.result
                                                                == Test.ResultType.ASSERT_ONLY) {
                                                            // at this point, all the asserts have
                                                            // been executed, and if they failed
                                                            // they already returned a false result
                                                        }
                                                        synchronized (waiting) {
                                                            waiting.notify();
                                                        }
                                                    }
                                                    if (errors) {
                                                        synchronized (waiting) {
                                                            waiting.notify();
                                                        }
                                                    }
                                                    alive_count.getAndDecrement();
                                                }

                                                @Override
                                                public void onExecuteDone(
                                                        boolean forceResult, String sessionName) {
                                                    if (actual_test.resultSession.equals("")
                                                            || actual_test.resultSession.equals(
                                                                    sessionName)) {

                                                        actual_test.success = forceResult;
                                                        synchronized (waiting) {
                                                            waiting.notify();
                                                        }
                                                    }
                                                    alive_count.getAndDecrement();
                                                }

                                                @Override
                                                public void onError(String sessionName) {
                                                    if (actual_test.resultSession.equals("")
                                                            || actual_test.resultSession.equals(
                                                                    sessionName)) {
                                                        actual_test.applicable = false;
                                                        System.out.println(
                                                                "Error position is ExecuteActives 1");
                                                    }
                                                    synchronized (waiting) {
                                                        waiting.notify();
                                                    }
                                                    alive_count.getAndDecrement();
                                                }

                                                @Override
                                                public Boolean onAskPause(String sessionName) {
                                                    if (isInPause.get(sessionName) != null) {
                                                        return isInPause.get(sessionName);
                                                    } else {
                                                        return false;
                                                    }
                                                }

                                                @Override
                                                public Boolean onAskStop(String sessionName) {
                                                    return null;
                                                }

                                                @Override
                                                public Boolean onAskClearCookie(
                                                        String sessionName) {
                                                    if (clearCookieAsked.get(sessionName) != null) {
                                                        boolean tmp =
                                                                clearCookieAsked.get(sessionName);
                                                        clearCookieAsked.replace(
                                                                sessionName, false);
                                                        return tmp;
                                                    } else {
                                                        return false;
                                                    }
                                                }

                                                @Override
                                                public void onNextSessionAction(
                                                        SessionTrackAction last_action,
                                                        SessionTrackAction last_open,
                                                        SessionTrackAction last_click,
                                                        String last_url,
                                                        String session_name)
                                                        throws ParsingException {
                                                    Session s =
                                                            actual_test.getSession(session_name);
                                                    s.last_action = last_action;
                                                    s.last_open = last_open;
                                                    s.last_click = last_click;
                                                    s.last_url = last_url;
                                                }

                                                @Override
                                                public Track onUpdateTrack(String sessionName)
                                                        throws ParsingException {
                                                    return actual_test.getSession(sessionName)
                                                            .track;
                                                }

                                                @Override
                                                public void onSetVar(Var v) {
                                                    actual_test.vars.add(v);
                                                }
                                            });

                                    Thread t = new Thread(selected.ex);
                                    t.setName(op.getSession());
                                    executions.put(op.getSession(), t);
                                    alive_count.addAndGet(1);
                                    executions.get(op.getSession()).start();
                                    break;
                                }

                            case PAUSE:
                                isInPause.replace(op.getSession(), true);
                                break;

                            case RESUME:
                                isInPause.replace(op.getSession(), false);
                                break;

                            case STOP:
                                {
                                    Session selected = actual_test.getSession(op.getSession());
                                    if (selected == null) {
                                        actual_test.error_str =
                                                "Invalid session name, maybe you didn't declare it?";
                                        actual_test.error = true;
                                        break;
                                    }

                                    executions.get(op.getSession()).interrupt();
                                    break;
                                }
                            case CLEAR_COOKIES:
                                Session selected = actual_test.getSession(op.getSession());
                                if (selected == null) {
                                    actual_test.error_str =
                                            "Invalid session name, maybe you didn't declare it?";
                                    actual_test.error = true;
                                    break;
                                }
                                clearCookieAsked.put(selected.name, true);
                                break;
                        }

                        List<Var> act_vars = actual_test.vars;
                        List<Var> updated_vars = op.executeSessionOps(actual_test, act_vars);
                        actual_test.vars = updated_vars;

                    } else {
                        // if it is a normal operation

                        if (!op.from_session.equals("")) {
                            op.session_port = actual_test.getSession(op.from_session).port;
                        } else if (!op.to_session.equals("")) {
                            op.session_port = actual_test.getSession(op.to_session).port;
                        } else {
                            op.session_port = "8080";
                        }

                        if (op.api == null) {
                            op.api = new Operation_API(actual_test.vars);
                        } else {
                            op.api.vars = actual_test.vars;
                        }


                        //TODO nick
                        listener.onNewProcessOperation(op);

                        synchronized (this.waiting) {
                            try {
                                this.waiting.wait();
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                        }

                        op = listener.onOperationDone(); // Take the operation from the caller

                        actual_test.vars = op.api.vars;
                        actual_test.vars = op.executeSessionOps(actual_test, actual_test.vars);

                        if (op.applicable) {
                            actual_test.success = op.result;
                            actual_test.applicable = true;
                            if (!op.result) {
                                for (String key : executions.keySet()) {
                                    executions.get(key).interrupt();
                                }
                                break;
                            }
                        } else {
                            actual_test.applicable = false;
                            for (String key : executions.keySet()) {
                                executions.get(key).interrupt();
                            }
                            break;
                        }
                    }
                } catch (ParsingException | PatternSyntaxException e) {
                    e.printStackTrace();
                    listener.onError(actual_test);
                    actual_test.applicable = false;
                    for (String key : executions.keySet()) {
                        executions.get(key).interrupt();
                    }
                    break;
                }
            }
            while (alive_count.get() != 0) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException interruptedException) {
                    interruptedException.printStackTrace();
                    // alive_count.getAndDecrement();
                }
            }
            listener.onTestDone(actual_test);
        }
        listener.onExecuteDone();
    }
}
