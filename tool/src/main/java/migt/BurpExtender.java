package migt;

import burp.*;

import javax.swing.*;
import java.awt.*;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Objects;

/**
 * Main class executed by Burp
 *
 * @author Matteo Bitussi
 */
public class BurpExtender implements IBurpExtender, ITab, IProxyListener {

    public static IExtensionHelpers helpers;
    public static PrintStream printStream;
    public static PrintStream errorStream;
    public IBurpExtenderCallbacks callbacks;
    private GUI mainPane; // The GUI

    /**
     * Main function creating the extension
     *
     * @param callbacks The callbacks received by Burp
     */
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        /*
        try {
            System.setOut(new PrintStream("output_log.txt")); // Changes the default outstream with this file
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        try {
            System.setErr(new PrintStream("error_log.txt"));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        */

        System.out.println("Initializing extension");

        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();

        callbacks.setExtensionName("MIG Testing tool");

        //The UI is created
        SwingUtilities.invokeLater(() -> {
            // setup output stream
            OutputStream stdOut = callbacks.getStdout();
            OutputStream stdErr = callbacks.getStderr();
            printStream = new PrintStream(stdOut);
            errorStream = new PrintStream(stdErr);

            mainPane = new GUI();
            mainPane.helpers = callbacks.getHelpers();
            mainPane.callbacks = callbacks;
            mainPane.messageViewer = callbacks.createMessageEditor(mainPane.controller, false);
            mainPane.splitPane.setRightComponent(mainPane.messageViewer.getComponent());

            // add the custom tab to Burp's UI
            callbacks.addSuiteTab(BurpExtender.this);

            // register ourselves as an HTTP listener
            callbacks.registerProxyListener(BurpExtender.this);
            //callbacks.registerHttpListener(BurpExtender.this);
        });
    }

    @Override
    public String getTabCaption() {
        return "MIG-T";
    }

    @Override
    public Component getUiComponent() {
        return mainPane;
    }

    /**
     * Proxy's listener function which is called wheter a new message arrives. Note that if the received message is a
     * request, you cannot access the response
     *
     * @param messageIsRequest Indicates whether the HTTP message is a request
     *                         or a response.
     * @param proxy_message    An
     *                         <code>IInterceptedProxyMessage</code> object that extensions can use to
     *                         query and update details of the message, and control whether the message
     *                         should be intercepted and displayed to the user for manual review or
     */
    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage proxy_message) {
        String port = proxy_message.getListenerInterface().split(":")[1];
        IHttpRequestResponse messageInfo = proxy_message.getMessageInfo();

        if (mainPane.ACTIVE_ENABLED) {
            if (!port.equals(mainPane.act_active_op.session_port)) {
                return;
            }

            log_message(messageIsRequest, proxy_message);

            MessageType msg_type = null;
            try {
                msg_type = MessageType.getFromList(mainPane.messageTypes,
                        mainPane.act_active_op.getMessageType());
            } catch (Exception e) {
                e.printStackTrace();
                mainPane.act_active_op.applicable = false;
            }

            boolean matchMessage = false;

            try {
                /* If the response message name is searched, the getByResponse will be true.
                 * so i have to search for the request, and then evaluate the response*/
                if (msg_type.getByResponse) {
                    if (!messageIsRequest) {
                        matchMessage = Tools.executeChecks(msg_type.checks,
                                new HTTPReqRes(messageInfo, helpers, true),
                                true, mainPane.act_active_op.api.vars);
                    }
                } else if (msg_type.getByRequest) {
                    if (!messageIsRequest) {
                        matchMessage = Tools.executeChecks(msg_type.checks,
                                new HTTPReqRes(messageInfo, helpers, false),
                                false, mainPane.act_active_op.api.vars);
                    }
                } else {
                    if (messageIsRequest == msg_type.isRequest) {
                        matchMessage = Tools.executeChecks(msg_type.checks,
                                new HTTPReqRes(messageInfo, helpers, msg_type.isRequest),
                                msg_type.isRequest, mainPane.act_active_op.api.vars);
                    }
                }
            } catch (ParsingException e) {
                mainPane.act_active_op.applicable = false;
                return;
            }

            if (matchMessage) {
                boolean isRequest = false;
                if (msg_type.getByRequest) {
                    isRequest = false;
                } else if (msg_type.getByResponse) {
                    isRequest = true;
                } else {
                    isRequest = msg_type.isRequest;
                }

                Operation.MatchedMessage m = new Operation.MatchedMessage(
                        new HTTPReqRes(messageInfo, helpers, isRequest),
                        HTTPReqRes.instances,
                        isRequest,
                        !isRequest,
                        false);
                mainPane.act_active_op.matchedMessages.add(m);

                // If the operation's action is an intercept
                if (Objects.requireNonNull(mainPane.act_active_op.getAction()) == Operation.Action.INTERCEPT) {
                    try {
                        /* If the response message name is searched, the getByResponse will be true.
                         * so i have to search for the request, and then evaluate the response*/
                        if (msg_type.getByResponse) {
                            if (!messageIsRequest) {
                                if (matchMessage) {
                                    processMatchedMsg(msg_type, messageInfo);
                                }
                            }
                        } else if (msg_type.getByRequest) {
                            if (!messageIsRequest) {
                                if (matchMessage) {
                                    processMatchedMsg(msg_type, messageInfo);
                                }
                            }
                        } else {
                            if (messageIsRequest == msg_type.isRequest) {
                                if (matchMessage) {
                                    processMatchedMsg(msg_type, messageInfo);
                                    if (mainPane.act_active_op.then != null &
                                            mainPane.act_active_op.then == Operation.Then.DROP) {
                                        proxy_message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        mainPane.act_active_op.applicable = false;
                    }
                }
            }
        }

        if (mainPane.recording) {
            if (!messageIsRequest) { // do not remove
                synchronized (mainPane.interceptedMessages) {
                    IHttpRequestResponsePersisted actual = callbacks.saveBuffersToTempFiles(messageInfo);
                    mainPane.interceptedMessages.add(
                            new HTTPReqRes(actual, helpers)
                    );
                    if (mainPane.defaultSession != null) {
                        mainPane.defaultSession.addMessage(actual, helpers, mainPane.FILTERING);
                    }
                }
            }
        }
    }

    private void processMatchedMsg(MessageType msg_type,
                                   IHttpRequestResponse messageInfo) {
        messageInfo.setHighlight("red");
        HTTPReqRes message = new HTTPReqRes(messageInfo, helpers, msg_type.isRequest);

        mainPane.act_active_op.helpers = helpers;
        mainPane.act_active_op.api.message = message;
        mainPane.act_active_op.api.is_request = msg_type.isRequest; // todo check if with getByResponse is ok
        mainPane.act_active_op.execute();

        // if message has been edited inside operation update the value
        if (mainPane.act_active_op.processed_message != null) {
            //TODO: remove processed_message in future
            if (msg_type.isRequest) {
                messageInfo.setRequest(mainPane.act_active_op.processed_message);
            } else {
                messageInfo.setResponse(mainPane.act_active_op.processed_message);
            }
        } else {
            if (msg_type.isRequest) {
                messageInfo.setRequest(message.getMessage(message.isRequest, helpers));
            } else {
                messageInfo.setResponse(message.getMessage(message.isRequest, helpers));
            }
        }
        resume();
    }

    /**
     * Tells the lock on the Execute Actives process to resume the execution
     */
    private void resume() {
        // Resume the execution thread
        synchronized (mainPane.waiting) {
            mainPane.waiting.notify();
        }
    }

    private void log_message(boolean isRequest, IInterceptedProxyMessage message) {
        mainPane.act_active_op.log_messages.add(message);
    }
}
