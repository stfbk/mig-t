package migt;

import migt.HTTPReqRes;
import migt.MessageType;
import migt.Test;
import migt.Tools;
import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class App {

    public static void main(String[] args) throws Exception {
        Path baseDir = Path.of(args.length > 0 ? args[0] : "testdata");

        // legge le definizioni dei messagi
        String msgDefJson = Files.readString(baseDir.resolve("msg_def.json"), StandardCharsets.UTF_8);
        List<MessageType> messageTypes = Tools.readMsgTypesFromJson(msgDefJson);
        System.out.println("Loaded " + messageTypes.size() + " message type definitions");

        // costruisce tutti i messaggi disponibili
        String jwt = Files.readString(baseDir.resolve("openid-federation"), StandardCharsets.UTF_8).trim();
        List<HTTPReqRes> capturedMessages = new ArrayList<>();
        // simulazione delle chiamate
        capturedMessages.add(buildEntityConfigurationMessage(jwt));

        // trova ed esegui ogni file di test dentro testdata/tests/
        Path testsDir = baseDir.resolve("tests");
        List<Path> testFiles = new ArrayList<>();
        try (var stream = Files.list(testsDir)) {
            stream.filter(p -> p.toString().endsWith(".json"))
                .sorted()
                .forEach(testFiles::add);
        }

        System.out.println("Trovati " + testFiles.size() + " file di test in " + testsDir);

        for (Path testFile : testFiles) {
            System.out.println("\n====================================================");
            System.out.println("File: " + testFile.getFileName());

            String testSuiteJson = Files.readString(testFile, StandardCharsets.UTF_8);
            JSONObject root = new JSONObject(testSuiteJson);
            JSONArray testsArr = root.getJSONArray("tests");

            for (int i = 0; i < testsArr.length(); i++) {
                JSONObject testJson = testsArr.getJSONObject(i).getJSONObject("test");
                Test test = new Test(testJson, messageTypes);

                boolean passed = test.execute(capturedMessages, messageTypes);

                int totalMatched = 0;
                for (Operation op : test.operations) {
                    totalMatched += op.matchedMessages.size();
                    System.out.println("  -> operazione su \"" + op.getMessageType() + "\": "
                            + op.matchedMessages.size() + " messaggio/i abbinato/i");
                }

                System.out.println("Test name : " + test.getName());
                System.out.println("Result    : " + (passed ? "PASSED" : "FAILED")
                        + (totalMatched == 0 ? "  <-- ATTENZIONE: nessun messaggio abbinato!" : ""));
            }
        }
    }

    private static HTTPReqRes buildEntityConfigurationMessage(String jwt) {
        List<String> reqHeaders = Arrays.asList(
                "GET /.well-known/openid-federation HTTP/1.1",
                "Host: relying-party.org:8001",
                "Accept: */*"
        );
        List<String> respHeaders = Arrays.asList(
                "HTTP/1.1 200 OK",
                "Content-Type: application/entity-statement+jwt"
        );

        String reqHead = String.join("\r\n", reqHeaders) + "\r\n\r\n";
        String respHead = String.join("\r\n", respHeaders) + "\r\n\r\n";

        byte[] reqBytes = reqHead.getBytes(StandardCharsets.UTF_8);
        byte[] respBytes = (respHead + jwt).getBytes(StandardCharsets.UTF_8);

        HTTPReqRes msg = new HTTPReqRes(reqBytes, respBytes);

        msg.setHeaders(true, new ArrayList<>(reqHeaders));
        msg.setHeaders(false, new ArrayList<>(respHeaders));
        msg.body_offset_resp = respHead.getBytes(StandardCharsets.UTF_8).length;

        return msg;
    }
}