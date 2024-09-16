package migt;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import burp.IBurpExtenderCallbacks;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.jsonwebtoken.security.Keys;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.server.handler.ResourceHandler;

import javax.servlet.ServletException;
import java.io.IOException;

import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.json.JSONObject;
import org.springframework.security.crypto.bcrypt.BCrypt;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.swing.*;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;



public class ExecuteWebServer implements Runnable {

    static Main mainPane;
    static String[] messages = new String[17];
    static String[] outputMessages = new String[4];
    private IBurpExtenderCallbacks callbacks;
    private static final int PORT = 3000;
    private volatile boolean isRunning = true;
    static String outputMessageValidation;
    static String file1;
    static String file2;
    static String userInput;
    static String jsonString;
    private static final List<User> users = new ArrayList<>();
    private static final int BCRYPT_ROUNDS = 10;

    public ExecuteWebServer(IBurpExtenderCallbacks callbacks, Main mainPane) {
        this.callbacks = callbacks;
        this.mainPane = mainPane;
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
        Server server = new Server(PORT);

        ResourceHandler resourceHandler = new ResourceHandler();

        String jarFilePath = Main.class.getProtectionDomain().getCodeSource().getLocation().getPath();
        resourceHandler.setResourceBase("jar:file:" + jarFilePath + "!/");
        //mainPane.callbacks.printOutput(jarFilePath);

        server.setHandler(new SendMessageHandler());

        server.insertHandler(resourceHandler);
        server.start();
        callbacks.printOutput("Server is running at http://localhost:" + PORT);
        server.join();
    }

    static class SendMessageHandler extends AbstractHandler {

        private static final String SECRET_KEY = "eldk8ubHkfPvjNcXVHQX1VRN+T+2pQ/XWRFKH1Ixjuc=";
        private static final BlockingQueue<RequestData> requestQueue = new LinkedBlockingQueue<>();

        @Override
        public void handle(String target, org.eclipse.jetty.server.Request baseRequest,
                           HttpServletRequest request, HttpServletResponse response)
                throws IOException, ServletException {

            response.setHeader("Access-Control-Allow-Origin", "*");
            response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

            if ("/users".equals(target) && baseRequest.getMethod().equals("POST")) {
                //aggiungo nuovo utente solo se non è già presente nel sistema
                try {
                    String requestBody = request.getReader().lines().reduce("", (accumulator, actual) -> accumulator + actual);
                    JsonObject jsonObject = JsonParser.parseString(requestBody).getAsJsonObject();
                    String name = jsonObject.get("name").getAsString();
                    String password = jsonObject.get("password").getAsString();

                    //verifico
                    boolean userExists = users.stream()
                            .anyMatch(u -> u.getName().equals(name));

                    if (userExists) {
                        //utente già presente, 409 Conflict
                        response.setStatus(HttpServletResponse.SC_CONFLICT);
                        PrintWriter out = response.getWriter();
                        out.println("User already exists");
                    } else {
                        //utente non presente, quindi aggiungo
                        //hash
                        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(BCRYPT_ROUNDS));

                        //creo utente
                        User user = new User(name, hashedPassword);
                        users.add(user);

                        response.setStatus(HttpServletResponse.SC_CREATED);
                        baseRequest.setHandled(true);
                    }
                } catch (Exception e) {
                    response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                    baseRequest.setHandled(true);
                }
            }
            if ("/users/login".equals(target) && baseRequest.getMethod().equals("POST")) {
                //Autenticazione utente
                try {
                    String requestBody = request.getReader().lines().reduce("", (accumulator, actual) -> accumulator + actual);
                    JsonObject jsonObject = JsonParser.parseString(requestBody).getAsJsonObject();
                    String name = jsonObject.get("name").getAsString();

                    String password = jsonObject.get("password").getAsString();

                    User user = users.stream()
                            .filter(u -> u.getName().equals(name))
                            .findFirst()
                            .orElse(null);

                    if (user != null && BCrypt.checkpw(password, user.getPassword())) {
                        response.setStatus(HttpServletResponse.SC_OK);
                        PrintWriter out = response.getWriter();
                        //ritorno JWT alla SPA
                        String jwt = generateJWT(user.getName());
                        out.println("{\"token\": \"" + jwt + "\"}");
                    } else {
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        PrintWriter out = response.getWriter();
                        out.println("Not Allowed");
                    }

                    baseRequest.setHandled(true);
                } catch (Exception e) {
                    response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                    baseRequest.setHandled(true);
                }
            }
            //------------------------------------------API only for validation
            if ("/validation".equals(target) && baseRequest.getMethod().equals("POST")) {
                //verifico JWT nell'intestazione Authorization
                String jwt = request.getHeader("Authorization");
                if (jwt != null && jwt.startsWith("Bearer ")) {
                    String token = jwt.substring(7); //rimuove il prefisso "Bearer"

                    //verifica il token
                    try {
                        Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
                        Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
                        String username = claims.getSubject();

                        StringBuilder requestBodyBuilder = new StringBuilder();
                        try (BufferedReader reader = request.getReader()) {
                            String line;
                            while ((line = reader.readLine()) != null) {
                                requestBodyBuilder.append(line).append(System.lineSeparator());
                            }
                        }

                        String requestBody = requestBodyBuilder.toString();

                        response.setStatus(HttpServletResponse.SC_OK);
                        RequestData requestData = new RequestData(System.currentTimeMillis(), requestBody);
                        requestQueue.add(requestData);

                        synchronized (this) {
                            mainPane.readJSONinput(requestBody);
                            outputMessageValidation = mainPane.lblOutput.getText();
                            if (outputMessageValidation == null || outputMessageValidation.trim().isEmpty()) {
                                outputMessageValidation = "Validate Test";
                            }
                        }

                        RequestData oldestRequest = requestQueue.poll();
                        if (oldestRequest != null) {
                            response.setContentType("application/json");
                            response.setCharacterEncoding("UTF-8");

                            JSONObject jsonResponse = new JSONObject();


                            jsonResponse.put("validation:", "" + outputMessageValidation);

                            PrintWriter writer = response.getWriter();
                            writer.println(jsonResponse.toString());
                        }
                        response.setStatus(HttpServletResponse.SC_OK);
                    } catch (Exception e) {
                        //JWT non valido, restituisci un errore
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.getWriter().println("Invalid token");
                    }
                } else {
                    //JWT mancante nell'intestazione Authorization
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().println("JWT missing in Authorization header");
                }
                //richiesta è stata gestita
                baseRequest.setHandled(true);
            }
            //------------------------------------------
            if ("/messages".equals(target) && baseRequest.getMethod().equals("POST")) {
                //verifico JWT nell'intestazione Authorization
                String jwt = request.getHeader("Authorization");
                if (jwt != null && jwt.startsWith("Bearer ")) {
                    String token = jwt.substring(7); //rimuove il prefisso "Bearer"

                    //verifica il token
                    try {
                        Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
                        Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
                        String username = claims.getSubject();

                        StringBuilder requestBodyBuilder = new StringBuilder();
                        try (BufferedReader reader = request.getReader()) {
                            String line;
                            while ((line = reader.readLine()) != null) {
                                requestBodyBuilder.append(line).append(System.lineSeparator());
                            }
                        }

                        String requestBody = requestBodyBuilder.toString();
                        //int index = requestBody.indexOf("&");
                        JSONObject jsonObject = new JSONObject(requestBody);
                        String combinedContent = jsonObject.getString("msg");
                        int index = combinedContent.indexOf("&");

                        //verifica se "&" è presente nella stringa
                        if (index != -1) {
                            //estrai la prima parte (fino a "&" esclusa)
                            //file1 = requestBody.substring(0, index).trim();
                            file1 = combinedContent.substring(0, index).trim();

                            //estrai la seconda parte (da "&" esclusa alla fine)
                            //file2 = requestBody.substring(index + 1).trim();
                            file2 = combinedContent.substring(index + 1).trim();

                        } else {
                            mainPane.callbacks.printOutput("Il carattere '&' non è presente nella stringa.");
                        }

                        response.setStatus(HttpServletResponse.SC_OK);
                        RequestData requestData = new RequestData(System.currentTimeMillis(), requestBody);
                        requestQueue.add(requestData);

                        String[] finalMessages = new String[4];

                        synchronized (this) {
                            mainPane.txtScript.setText(file1);
                            mainPane.txtSearch.setText(file2);
                            mainPane.readJSONinput(file2);
                            mainPane.executeSuite();

                            createMessages();
                            //createJsonString(username);
                            createJsonString();
                            System.out.println("Json returned is\n" + jsonString);
                            finalMessages = outputMessages;
                        }

                        RequestData oldestRequest = requestQueue.poll();
                        if (oldestRequest != null) {
                            response.setContentType("application/json");
                            response.setCharacterEncoding("UTF-8");

                            JSONObject jsonResponse = new JSONObject();
                            jsonResponse.put("Test Name", "Test Name: "+finalMessages[0]);
                            jsonResponse.put("Description", "Description: "+finalMessages[1]);
                            jsonResponse.put("Result", "Result: "+finalMessages[2]);
                            jsonResponse.put("Details", finalMessages[3]);

                            PrintWriter writer = response.getWriter();
                            writer.println(jsonResponse.toString());
                        }
                        response.setStatus(HttpServletResponse.SC_OK);
                    } catch (Exception e) {
                        //JWT non valido, restituisci un errore
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.getWriter().println("Invalid token");
                    }
                } else {
                    //JWT mancante nell'intestazione Authorization
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().println("JWT missing in Authorization header");
                }
                //richiesta è stata gestita
                baseRequest.setHandled(true);
            }
        }

        private static String generateJWT(String user) {
            Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
            String jwt = Jwts.builder()
                    .setHeaderParam("typ", "JWT")
                    .setSubject(user) //==> impostato il soggetto del token
                    .setIssuedAt(new Date()) //==> impostata la data di emissione
                    .setExpiration(new Date(System.currentTimeMillis() + 3600000)) //==> data di scadenza (1 ora)
                    .signWith(key, SignatureAlgorithm.HS256) //==> token firmato
                    .compact();
            return jwt;
        }

    }

    public static void createMessages(){
        messages[0] = mainPane.lblInfo.getText();
        while (mainPane.resultTableModel.getRowCount() == 0) {
            //attendo finché il numero di righe non è diverso da zero ==> finito di eseguire operazioni
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        int rowCount = mainPane.resultTableModel.getRowCount();
        int columnCount = mainPane.resultTableModel.getColumnCount();

        for (int row = 0; row < rowCount; row++) {
            for (int col = 0; col < columnCount; col++) {
                Object value = mainPane.resultTableModel.getValueAt(row, col);
                messages[col+1] = "" + value;
                if(col+1==1){
                    outputMessages[0]=messages[col+1];
                }else if(col+1==2){
                    outputMessages[1]=messages[col+1];
                }else if(col+1==7){
                    outputMessages[2]=messages[col+1];
                }
            }
        }
        messages[8] = mainPane.lblOutput.getText();

        //DEBUG TAB
        String txt_out_debug_tab = mainPane.txt_out_debug_tab.getText();
        messages[9] = mainPane.txt_out_debug_tab.getText();

        String txt_err_debug_tab = mainPane.txt_err_debug_tab.getText();
        messages[10] = mainPane.txt_err_debug_tab.getText();

        //RESULT TABLE
        rowCount = mainPane.testTable.getRowCount();
        int colCount = mainPane.testTable.getColumnCount();

        if(rowCount==0){
            for (int col = 0; col < colCount; col++) {
                messages[col + 11] = "";
            }
        } else {
            for (int row = 0; row < rowCount; row++) {
                for (int col = 0; col < colCount; col++) {
                    messages[col + 11] = mainPane.testTable.getValueAt(row, col) + "";
                }
            }
        }
    }

    static class User {
        private String name;
        private String password;

        public User(String name, String password) {
            this.name = name;
            this.password = password;
        }

        public String getName() {
            return name;
        }

        public String getPassword() {
            return password;
        }
    }

    static class RequestData {
        private static int requestCount = 0;
        private final long timestamp;
        private final String message;
        private final int requestNumber;

        public RequestData(long timestamp, String message) {
            this.timestamp = timestamp;
            this.message = message;
            synchronized (RequestData.class) {
                this.requestNumber = ++requestCount;
            }
        }

        public long getTimestamp() {
            return timestamp;
        }

        public String getMessage() {
            return message;
        }

        public int getRequestNumber() {
            return requestNumber;
        }
    }


    public static void createJsonString() {
        String outputJson;

        MyJsonObject jsonObject = new MyJsonObject(messages);

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        StringWriter stringWriter = new StringWriter();

        gson.toJson(jsonObject, stringWriter);
        outputJson = stringWriter.toString();

        outputMessages[3]= outputJson;
    }

    static class MyJsonObject {
        private String inputJson1;
        private List<TestSuiteResult> testSuiteResult;
        private String inputJson2;
        private List<TestResult> testResult;
        private List<DebugTab> debugTab;

        public MyJsonObject(String[] values) {
            this.inputJson1 = values[0];

            this.testSuiteResult = Arrays.asList(
                    new TestSuiteResult(values[1], values[2], values[3], values[4], values[5], values[6], values[7])
            );

            this.inputJson2 = values[8];

            this.testResult = Arrays.asList(
                    new TestResult(values[11], values[12], values[13], values[14], values[15], values[16])
            );

            this.debugTab = Arrays.asList(
                    new DebugTab(values[9], values[10])
            );

        }
    }

    static class DebugTab {
        private String output_log;
        private String error_log;

        public DebugTab(String output_log, String error_log) {
            this.output_log = output_log;
            this.error_log = error_log;
        }
    }

    static class TestResult {
        private String Op_num;
        private String messageType;
        private String messageSection;
        private String check_regex;
        private String index;
        private String result;

        public TestResult(String Op_num, String messageType, String messageSection, String check_regex, String index, String result) {
            this.Op_num = Op_num;
            this.messageType = messageType;
            this.messageSection = messageSection;
            this.check_regex = check_regex;
            this.index = index;
            this.result = result;
        }
    }

    static class TestSuiteResult {
        private String testName;
        private String description;
        private String references;
        private String statementInRefToTest;
        private String affectedEntity;
        private String mitigations;
        private String result;

        public TestSuiteResult(String testName, String description, String references, String statementInRefToTest, String affectedEntity, String mitigations, String result) {
            this.testName = testName;
            this.description = description;
            this.references = references;
            this.statementInRefToTest = statementInRefToTest;
            this.affectedEntity = affectedEntity;
            this.mitigations = mitigations;
            this.result = result;
        }
    }

}