package org.zaproxy.addon.migt;

//import burp.IBurpExtenderCallbacks;
import com.google.gson.*;
import com.google.gson.reflect.TypeToken;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.server.handler.ResourceHandler;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;

public class ExecuteWebServer implements Runnable {

    static Main mainPane;
    //private IBurpExtenderCallbacks callbacks;

    private boolean enableAuthentication = false;
    private String authenticationKey = null;

    public ExecuteWebServer(/*IBurpExtenderCallbacks callbacks,*/ Main mainPane) {
        //this.callbacks = callbacks;
        this.mainPane = mainPane;

        enableAuthentication = Boolean.parseBoolean(System.getProperty("migt.webserver.enableauth", "false"));
        if(enableAuthentication) {
            authenticationKey = sha256(System.getProperty("migt.webserver.authkey"));
        }

    }

    public String sha256(String original) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(original.getBytes(StandardCharsets.UTF_8));
            return new String(hash, StandardCharsets.UTF_8);
        } catch(NoSuchAlgorithmException ignored) {
            // È sicuro? Probabilmente no
            return original;
        }
    }

    public void run() {
        mainPane.btnselectChrome.setEnabled(true);
        mainPane.btnselectFirefox.setEnabled(false);
        mainPane.btndriverSelector.setEnabled(true);
        try {
            start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void start() throws Exception {
        int port = Integer.parseInt(System.getProperty("migt.webserver.port", "3000"));

        Server server = new Server(port);

        ResourceHandler resourceHandler = new ResourceHandler();

        String jarFilePath = Main.class.getProtectionDomain().getCodeSource().getLocation().getPath();
        resourceHandler.setResourceBase("jar:file:" + jarFilePath + "!/");
        //mainPane.callbacks.printOutput(jarFilePath);

        server.setHandler(new SendMessageHandler());

        server.insertHandler(resourceHandler);
        server.start();

        //Questo solo per un print
        //callbacks.printOutput("Server is running at http://localhost:" + port);
        server.join();
    }

    class SendMessageHandler extends AbstractHandler {

        @Override
        public void handle(String target, org.eclipse.jetty.server.Request baseRequest,
                           HttpServletRequest request, HttpServletResponse response)
                throws IOException {

            if(enableAuthentication) {
                String key = request.getHeader("X-AuthKey");
                if(key == null || !sha256(key).equals(authenticationKey)) {
                    response.sendError(403);
                    return;
                }
            }

            response.setHeader("Access-Control-Allow-Origin", "*");
            response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

            if("/execute".equals(target) && baseRequest.getMethod().equals("POST")) {
                // read param onlyValidate
                String onlyValidateStr = request.getParameter("onlyValidate");
                boolean onlyValidate = Boolean.parseBoolean(onlyValidateStr);

                // read content
                JsonObject body = new Gson().fromJson(request.getReader(), TypeToken.get(JsonObject.class));

                // apply test
                mainPane.txtSearch.setText(body.get("test").getAsString());
                mainPane.btnReadJSON.doClick();

                // verify errors
                JsonObject result = new JsonObject();
                if (mainPane.bot_tabbed.getBackgroundAt(mainPane.bot_tabs_index.get("Input JSON")) == Color.RED) {
                    String error = mainPane.txt_err_debug_tab.getText();
                    result.addProperty("success", false);
                    result.addProperty("error", error);
                } else {
                    // import sessions
                    JsonObject sessions = body.get("sessions").getAsJsonObject();
                    for (Map.Entry<String, JsonElement> s : sessions.asMap().entrySet()) {
                        String content = s.getValue().getAsString();
                        if ("main".equals(s.getKey())) {
                            mainPane.txtScript.setText(content);
                        } else {
                            mainPane.sessions_text.get(s.getKey()).setText(content);
                        }
                    }

                    result.addProperty("success", true);
                }

                if(!onlyValidate) {
                    mainPane.btnExecuteSuite.doClick();
                }

                writeOutputJson(result, response.getWriter());
                baseRequest.setHandled(true);

            } else if("/result".equals(target)) {
                DefaultTableModel res = Main.resultTableModel;
                JsonObject result = new JsonObject();
                if(res.getRowCount() > 0) {
                    String param = request.getParameter("verbose");
                    boolean verbose = Boolean.parseBoolean(param);

                    result.addProperty("finished", true);
                    TestSuite ts = mainPane.testSuite;

                    JsonArray tests = new JsonArray();
                    for(int i = 0; i < ts.tests.size(); i++) {
                        Test t = ts.tests.get(i);
                        JsonObject record = new JsonObject();
                        record.addProperty("references", t.references);
                        record.addProperty("test name", t.getName());
                        record.addProperty("description", t.getDescription());
                        record.addProperty("type", t.isActive ? "active" : "passive");
                        record.addProperty("mitigations", t.mitigations);
                        record.addProperty("result", t.applicable ? (t.success ? "passed" : "failed") : "not applicable");
                        /* record.addProperty("statements", "");
                        System.out.println("Affected entity: " + t.affected_entity);
                        record.add("affected entity", JsonNull.INSTANCE); */

                        JsonArray details = new JsonArray();
                        if(verbose) {
                            for (int ii = 0; ii < t.getRows().size(); ii++) {
                                String[] r = t.getRows().get(ii);
                                int index0 = Integer.parseInt(r[0]);
                                int index = Integer.parseInt(r[4]);

                                JsonObject a = new JsonObject();
                                //a.addProperty("op. num", index0);
                                a.addProperty("message type", r[1]);
                                // a.addProperty("message section", r[2]);
                                // a.addProperty("check/regex", r[3]);
                                // a.addProperty("index", index);
                                // a.addProperty("result", r[4]); // TODO: fix
                                Operation op = t.operations.get(index0);

                                try {
                                    MessageType mt = MessageType.getFromList(mainPane.messageTypes, op.getMessageType());
                                    for (HTTPReqRes msg : op.matchedMessages) {
                                        if (msg.index == index) {
                                            if (mt.msg_to_process_is_request) {
                                                a.addProperty("request", Base64.getEncoder().encodeToString(msg.getRequest()));
                                            } else {
                                                a.addProperty("response", Base64.getEncoder().encodeToString(msg.getResponse()));
                                            }
                                        }
                                    }
                                } catch (ParsingException ignored) {
                                    // nothing
                                }
                                details.add(a);
                            }
                            record.add("details", details);
                        }
                        tests.add(record);
                    }
                    result.add("tests", tests);
                } else {
                    result.addProperty("finished", false);
                }

                writeOutputJson(result, response.getWriter());

                baseRequest.setHandled(true);
            }
        }

    }

    public void writeOutputJson(JsonElement elm, PrintWriter pw) {
        Gson gson = new GsonBuilder()
                .setPrettyPrinting()
                .serializeNulls()
                .create();
        pw.write(gson.toJson(elm));
    }
}