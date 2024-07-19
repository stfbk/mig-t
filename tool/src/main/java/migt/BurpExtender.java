package migt;

import burp.*;

import javax.swing.*;
import java.awt.*;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.Objects;

/**
 * Main class executed by Burp
 */
public class BurpExtender implements IBurpExtender, ITab, IProxyListener {

    public static IExtensionHelpers helpers;
    public static PrintStream printStream;
    public static PrintStream errorStream;
    public IBurpExtenderCallbacks callbacks;
    private Main mainPane; // The GUI

    /**
     * Main function creating the extension
     *
     * @param callbacks The callbacks received by Burp
     */
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
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

            mainPane = new Main();
            mainPane.callbacks = callbacks;
            mainPane.messageViewer = callbacks.createMessageEditor(mainPane.controller, false);
            mainPane.splitPane.setRightComponent(mainPane.messageViewer.getComponent());

            // add the custom tab to Burp's UI
            callbacks.addSuiteTab(BurpExtender.this);

            // register ourselves as an HTTP listener
            callbacks.registerProxyListener(BurpExtender.this);
            //callbacks.registerHttpListener(BurpExtender.this);

            ExecuteWebServer ex2 = new ExecuteWebServer(callbacks, mainPane);
            Thread active_ex2 = new Thread(ex2);
            active_ex2.start();
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

        HTTPReqRes message = new HTTPReqRes(
                messageInfo,
                helpers,
                messageIsRequest,
                proxy_message.getMessageReference()
        );

        if (mainPane.INTERCEPT_ENABLED) {
            /* Check at which port of the proxy the message has been received
               if it is different from the one of the session avoid message*/
            if (!port.equals(mainPane.actual_operation.session_port)) {
                return;
            }

            // Log the received message by adding it to the list of received messages
            log_message(messageIsRequest, proxy_message);

            MessageType msg_type = null;
            try {
                msg_type = MessageType.getFromList(mainPane.messageTypes,
                        mainPane.actual_operation.getMessageType());
            } catch (Exception e) {
                e.printStackTrace();
                mainPane.actual_operation.applicable = false;
            }

            // Check that the given message matches the message type specified in the test
            boolean matchMessage = message.matches_msg_type(msg_type, messageIsRequest);

            if (matchMessage) {
                // If the operation's action is an intercept
                if (Objects.requireNonNull(mainPane.actual_operation.getAction()) == Operation.Action.INTERCEPT) {
                    try {
                        processMatchedMsg(msg_type, messageInfo, message);
                        if (mainPane.actual_operation.then != null &
                                mainPane.actual_operation.then == Operation.Then.DROP) {
                            proxy_message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        mainPane.actual_operation.applicable = false;
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

    /**
     * @param msg_type    the message type to be used
     * @param messageInfo the original intercepted messageInfo to being able to edit the message
     * @param message     a custom parsed message to be used in opeations
     */
    private void processMatchedMsg(MessageType msg_type,
                                   IHttpRequestResponse messageInfo,
                                   HTTPReqRes message) {
        messageInfo.setHighlight("red");

        mainPane.actual_operation.setAPI(new Operation_API(message, msg_type.msg_to_process_is_request));
        mainPane.actual_operation.execute();

        // if message has been edited inside operation update the value
        try {
            if (mainPane.actual_operation.processed_message != null) {
                if (msg_type.msg_to_process_is_request) {
                    if (!Arrays.equals(messageInfo.getRequest(), mainPane.actual_operation.processed_message)) {
                        messageInfo.setRequest(mainPane.actual_operation.processed_message);
                    }
                } else {
                    if (!Arrays.equals(messageInfo.getResponse(), mainPane.actual_operation.processed_message)) {
                        messageInfo.setResponse(mainPane.actual_operation.processed_message);
                    }
                }
            }
        } catch (UnsupportedOperationException e) {
            // This is thrown when an already issued request is being substituted
            System.err.println("Warning, edited message that has already been sent");
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
        mainPane.actual_operation.log_messages.add(message);
    }
}
