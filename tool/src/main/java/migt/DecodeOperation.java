package migt;

import burp.IExtensionHelpers;
import com.jayway.jsonpath.JsonPath;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import static migt.Tools.executeDecodeOps;
import static migt.Tools.executeEditOps;

/**
 * This class stores a decode operation
 */
public class DecodeOperation extends Module {
    public String decoded_content; // the decoded content
    public String decode_target; // aka decode_param how to decode the raw content
    public DecodeOperationFrom from; // where the raw content is. Depending on the containing module, can be other things
    public List<Encoding> encodings; // the list of encoding to decode and rencode
    public DecodeOpType type; // the type of the decoded param (used only to edit its content)
    public List<Check> checks; // the list of checks to be executed
    public List<DecodeOperation> decodeOperations; // a list of decode operations to execute them recursevly
    public List<EditOperation> editOperations; // a list of edit operations

    JWT jwt;

    String what;

    public DecodeOperation() {
        init();
    }

    /**
     * Instantiate a decode operation object parsing a json object
     *
     * @param decode_op_json the json object
     * @throws ParsingException
     */
    public DecodeOperation(JSONObject decode_op_json) throws ParsingException {
        init();
        java.util.Iterator<String> keys = decode_op_json.keys();
        while (keys.hasNext()) {
            String key = keys.next();

            switch (key) {
                case "type":
                    type = DecodeOpType.fromString(decode_op_json.getString("type"));
                    break;
                case "decode param":
                    decode_target = decode_op_json.getString("decode param");
                    break;
                case "encodings":
                    JSONArray encodings = decode_op_json.getJSONArray("encodings");
                    Iterator<Object> it = encodings.iterator();

                    while (it.hasNext()) {
                        String act_enc = (String) it.next();
                        this.encodings.add(
                                Encoding.fromString(act_enc));
                    }
                    break;
                case "from":
                    String f = decode_op_json.getString("from");
                    from = DecodeOperationFrom.fromString(f);
                    break;
                case "decode operations":
                    // Recursion goes brr
                    JSONArray decode_ops = decode_op_json.getJSONArray("decode operations");
                    for (int k = 0; k < decode_ops.length(); k++) {
                        JSONObject act_decode_op = decode_ops.getJSONObject(k);
                        DecodeOperation decode_op = new DecodeOperation(act_decode_op);
                        decodeOperations.add(decode_op);
                    }
                    break;
                case "checks":
                    checks = Tools.parseChecksFromJSON(decode_op_json.getJSONArray("checks"));
                    break;
                case "edits":
                    editOperations = Tools.parseEditsFromJSON(decode_op_json.getJSONArray("edits"));
                    break;
            }
        }
    }

    /**
     * Decodes a parameter from a message, given the message section and the list of encodings to be applied during
     * decoding
     *
     * @param helpers      IExtensionHelpers helpers object from Burp
     * @param ms           The message section that contains the parameter to be decoded
     * @param encodings    The list of encodings to be applied to decode the parameter
     * @param messageInfo  The message to be decoded
     * @param isRequest    True if the message containing the parameter is a request
     * @param decode_param The name of the parameter to be decoded
     * @return The decoded parameter as a string
     * @throws ParsingException If problems are encountered during decoding
     */
    public static String decodeParam(IExtensionHelpers helpers,
                                     DecodeOperationFrom ms,
                                     List<Encoding> encodings,
                                     HTTPReqRes messageInfo,
                                     Boolean isRequest,
                                     String decode_param) throws ParsingException {
        String decoded_param = "";
        switch (ms) {
            case HEAD:
                decoded_param = decode(
                        encodings, messageInfo.getHeadParam(isRequest, decode_param), helpers);
                break;
            case BODY:
                decoded_param = decode(
                        encodings, messageInfo.getBodyRegex(isRequest, decode_param), helpers);
                break;
            case URL:
                decoded_param = decode(
                        encodings, messageInfo.getUrlParam(decode_param), helpers);
                break;
        }

        decoded_param = Tools.removeNewline(decoded_param);

        return decoded_param;
    }

    /**
     * Decode the given string, with the given ordered encodings
     * Example taken from
     * <a href="https://github.com/CompassSecurity/SAMLRaider/blob/master/src/main/java/application/SamlTabController.java">Saml Raider</a>
     *
     * @param encodings the ordered list of encodings to be applied
     * @param encoded   the string to be decoded
     * @return the decoded string
     * @throws ParsingException if the decoding fails
     */
    public static String decode(List<Encoding> encodings, String encoded, IExtensionHelpers helpers) throws ParsingException {
        // TODO: remove dependency from helpers
        String actual = encoded;
        byte[] actual_b = null;
        boolean isActualString = true;

        if (encoded.length() == 0) {
            return "";
        }

        for (Encoding e : encodings) {
            switch (e) {
                case BASE64:
                    if (isActualString) {
                        actual_b = helpers.base64Decode(actual);
                        isActualString = false;
                    } else {
                        actual_b = helpers.base64Decode(actual_b);
                    }
                    break;
                case URL:

                    if (isActualString) {
                        actual = helpers.urlDecode(actual);
                    } else {
                        actual = helpers.urlDecode(new String(actual_b));
                        isActualString = true;
                    }
                    break;
                case DEFLATE:
                    boolean done = false;
                    if (isActualString) {
                        byte[] data = actual.getBytes();

                        try {
                            actual_b = decompress(data, true);
                            done = true;
                            isActualString = false;
                        } catch (IOException | DataFormatException ioException) {
                            ioException.printStackTrace();
                            //ioException.printStackTrace();
                        }

                        try {
                            if (!done) {
                                actual_b = decompress(data, false);
                                done = true;
                                isActualString = false;
                            }
                        } catch (IOException | DataFormatException ioException) {
                            //ioException.printStackTrace();

                        }
                    } else {
                        try {
                            actual_b = decompress(actual_b, true);
                            done = true;
                        } catch (IOException | DataFormatException ioException) {

                            //ioException.printStackTrace();
                        }

                        try {
                            if (!done) {
                                actual_b = decompress(actual_b, false);
                                done = true;
                            }
                        } catch (IOException | DataFormatException ioException) {

                        }
                    }
                    break;
            }
        }
        if (isActualString) {
            return actual;
        } else {
            return new String(actual_b, StandardCharsets.UTF_8);
        }
    }

    /**
     * Encode the given string, with the given encodings (in the specified order)
     * Example taken from
     * <a href="https://github.com/CompassSecurity/SAMLRaider/blob/master/src/main/java/application/SamlTabController.java">Saml Raider</a>
     *
     * @param encodings the ordered list of encodings to be applied
     * @param decoded   the string to be encoded
     * @return the encoded string
     */
    public static String encode(List<Encoding> encodings, String decoded, IExtensionHelpers helpers) {
        String actual = decoded;
        byte[] actual_b = null;
        boolean isActualString = true;
        for (Encoding e : encodings) {
            switch (e) {
                case BASE64:

                    if (isActualString) {
                        actual = helpers.base64Encode(actual);
                    } else {
                        actual = helpers.base64Encode(actual_b);
                        isActualString = true;
                    }
                    break;

                case URL:

                    if (isActualString) {
                        actual = URLEncoder.encode(actual);
                    } else {
                        actual = new String(actual_b);
                        actual = URLEncoder.encode(actual);
                        isActualString = true;
                    }
                    break;

                case DEFLATE:

                    if (isActualString) {
                        try {
                            actual_b = compress(actual.getBytes(StandardCharsets.UTF_8), true);
                        } catch (IOException ioException) {

                            //ioException.printStackTrace();
                        }
                        isActualString = false;
                    } else {
                        try {
                            actual_b = compress(actual_b, true);
                        } catch (IOException ioException) {

                            //ioException.printStackTrace();
                        }
                        isActualString = false;
                    }
            }
        }

        if (isActualString) {
            return actual;
        } else {
            return new String(actual_b, StandardCharsets.UTF_8);
        }
    }

    /**
     * Also named Inflate, taken from
     * <a href="http://qupera.blogspot.ch/2013/02/howto-compress-and-uncompress-java-byte.html">here</a>
     *
     * @param data the data to be decompressed (inflated)
     * @param gzip true to use gzip
     * @return returns the decompressed data
     * @throws IOException         if something goes wrong
     * @throws DataFormatException if something goes wrong
     */
    public static byte[] decompress(byte[] data, boolean gzip) throws IOException, DataFormatException {
        Inflater inflater = new Inflater(true);
        inflater.setInput(data);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
        byte[] buffer = new byte[1024];
        while (!inflater.finished()) {
            int count = inflater.inflate(buffer);
            outputStream.write(buffer, 0, count);
        }
        outputStream.close();
        byte[] output = outputStream.toByteArray();

        inflater.end();

        return output;
    }

    /**
     * Also named Deflate, taken from
     * <a href="http://qupera.blogspot.ch/2013/02/howto-compress-and-uncompress-java-byte.html">here</a>
     *
     * @param data data to be compressed (deflated)
     * @param gzip true to use gzip
     * @return the compressed data
     * @throws IOException if the compression goes wrong
     */
    public static byte[] compress(byte[] data, boolean gzip) throws IOException {
        Deflater deflater = new Deflater(5, gzip);
        deflater.setInput(data);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);

        deflater.finish();
        byte[] buffer = new byte[1024];
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            outputStream.write(buffer, 0, count);
        }
        outputStream.close();
        byte[] output = outputStream.toByteArray();

        deflater.end();

        return output;
    }

    public void init() {
        decoded_content = "";
        decode_target = "";
        checks = new ArrayList<>();
        encodings = new ArrayList<>();
        decodeOperations = new ArrayList<>();
        what = "";
        type = DecodeOpType.NONE;
        editOperations = new ArrayList<>();
    }

    @Override
    public DecodeOperation_API getAPI() {
        api = new DecodeOperation_API(this);
        return (DecodeOperation_API) api;
    }

    public void setAPI(DecodeOperation_API dop_api) {
        this.api = dop_api;
        // assign values returned from the api
        switch (type) {
            case JWT:
                this.jwt.header = dop_api.jwt_header;
                this.jwt.payload = dop_api.jwt_payload;
                this.jwt.signature = dop_api.jwt_signature;
                break;
            case NONE:
                this.decoded_content = dop_api.txt;
                break;
            case XML:
                this.decoded_content = dop_api.xml;
                break;
        }
    }

    /**
     * Loads an Operation API
     *
     * @param api
     * @param helpers
     * @throws ParsingException
     */
    public void loader(Operation_API api, IExtensionHelpers helpers) {
        // load api, extract needed things
        this.helpers = helpers;
        this.imported_api = api;
    }

    /**
     * Loads a decode operation API
     *
     * @param api
     */
    public void loader(DecodeOperation_API api, IExtensionHelpers helpers) {
        this.imported_api = api;
        this.helpers = helpers;

    }

    /**
     * Exports the API of this decode operation to be used by another operation
     *
     * @return the API
     * @throws ParsingException
     */
    @Override
    public Operation_API exporter() throws ParsingException {
        Collections.reverse(encodings); // Set the right order for encoding
        String encoded = encode(encodings, decoded_content, helpers);

        Tools.editMessageParam(
                helpers,
                decode_target,
                from,
                ((Operation_API) imported_api).message,
                ((Operation_API) imported_api).is_request,
                encoded,
                true);

        // the previous function should already have updated the message inside api
        return ((Operation_API) imported_api);
    }

    /**
     * Executes this decode operation
     *
     * @param mainPane the mainpane is needed to access the variables
     * @throws ParsingException
     */
    public void execute(List<Var> vars) throws ParsingException {
        if (imported_api instanceof Operation_API) {
            decoded_content = decodeParam(
                    helpers,
                    from,
                    encodings,
                    ((Operation_API) imported_api).message,
                    ((Operation_API) imported_api).is_request,
                    decode_target);

            // If type is jwt, parse
            if (Objects.requireNonNull(type) == DecodeOpType.JWT) {
                jwt = new JWT();

                jwt.parse(decoded_content);
            }

        } else if (imported_api instanceof DecodeOperation_API) {
            switch (from) {
                case JWT_HEADER:
                case JWT_PAYLOAD:
                case JWT_SIGNATURE:
                    // recursevly decode from a jwt
                    String j = ((DecodeOperation_API) imported_api).getDecodedContent(from);

                    String found = "";
                    // https://github.com/json-path/JsonPath
                    try {
                        found = JsonPath.read(j, what); // select what to decode
                    } catch (com.jayway.jsonpath.PathNotFoundException e) {
                        applicable = false;
                        result = false;
                        return;
                    }
                    decoded_content = decode(encodings, found, helpers);
                    break;
                default:
                    throw new UnsupportedOperationException(
                            "the from you selected in the recursive decode operation is not yet supported");
                    //TODO implement missing
            }
        }

        // execute edit operations
        if (editOperations.size() > 0) {
            executeEditOps(this, vars);
        }

        // executes recursive decode operations
        if (decodeOperations.size() != 0) {
            executeDecodeOps(this, helpers, vars);
        }

        // execute checks
        if (checks.size() != 0) {
            executeChecks(vars);
        }

        // Rebuild JWT before encoding it
        if (Objects.requireNonNull(type) == DecodeOpType.JWT) {
            decoded_content = jwt.build();
        }
        applicable = true;
    }

    /**
     * Execute a list of checks inside a decode operation. This function uses the APIs Sets also the result to the
     * decode op
     *
     * @return the result, for convenience
     * @throws ParsingException if errors are found
     */
    public boolean executeChecks(List<Var> vars) throws ParsingException {
        for (Check c : checks) {
            c.loader(getAPI());
            c.execute(vars);
            if (!setResult(c)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Used in decode operation to specify where to search for the content to decode
     */
    public enum DecodeOperationFrom {
        // standard message
        HEAD,
        BODY,
        URL,
        // jwt
        JWT_HEADER,
        JWT_PAYLOAD,
        JWT_SIGNATURE;

        public static DecodeOperationFrom fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "head":
                        return HEAD;
                    case "body":
                        return BODY;
                    case "url":
                        return URL;
                    case "jwt header":
                        return JWT_HEADER;
                    case "jwt payload":
                        return JWT_PAYLOAD;
                    case "jwt signature":
                        return JWT_SIGNATURE;
                    default:
                        throw new ParsingException("invalid decode operation from '" + input + "'");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }

    /**
     * The possible encodings to be used
     */
    public enum Encoding {
        BASE64,
        URL,
        DEFLATE;

        /**
         * From a string get the corresponding enum value
         *
         * @param input the string
         * @return the enum value
         * @throws ParsingException if the input is malformed
         */
        public static Encoding fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "base64":
                        return BASE64;
                    case "url":
                        return URL;
                    case "deflate":
                        return DEFLATE;
                    default:
                        throw new ParsingException("invalid encoding");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }

    /**
     * Used to specify the type of decoded content, only when that content has to be edited.
     */
    public enum DecodeOpType {
        JWT,
        NONE,
        XML;

        public static DecodeOpType fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "jwt":
                        return JWT;
                    case "xml":
                        return XML;
                    default:
                        throw new ParsingException("invalid message Op Type");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }
}
