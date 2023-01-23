 package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * Class containing methods used for the encoding of variables in messages
 *
 * @author Matteo Bitussi
 */
public class Encoding {

    /**
     * Decodes a parameter from a message, given the message section and the list of encodings to be applied during
     * decoding
     * @param helpers IExtensionHelpers helpers object from Burp
     * @param ms The message section that contains the parameter to be decoded
     * @param encodings The list of encodings to be applied to decode the parameter
     * @param messageInfo The message to be decoded
     * @param isRequest True if the message containing the parameter is a request
     * @param decode_param The name of the parameter to be decoded
     * @return The decoded parameter as a string
     * @throws ParsingException If problems are encountered during decoding
     */
    public static String decodeParam(IExtensionHelpers helpers,
                                     Utils.MessageSection ms,
                                     List<Utils.Encoding> encodings,
                                     HTTPReqRes messageInfo,
                                     Boolean isRequest,
                                     String decode_param) throws ParsingException {
        String decoded_param = "";
        switch (ms) {
            case HEAD:
                decoded_param = Encoding.decode(
                        encodings, Utils.getHeadParam(helpers, messageInfo, isRequest, decode_param), helpers);
                break;
            case BODY:
                decoded_param = Encoding.decode(
                        encodings, Utils.getBodyParam(helpers, messageInfo, isRequest, decode_param), helpers);
                break;
            case URL:
                decoded_param = Encoding.decode(
                        encodings, Utils.getUrlParam(helpers, messageInfo, isRequest, decode_param), helpers);
                break;
        }

        decoded_param = Utils.removeNewline(decoded_param);

        return decoded_param;
    }

    /**
     * Decodes a parameter from a message, given the message section and the list of encodings to be applied during
     * decoding
     * @param helpers IExtensionHelpers helpers object from Burp
     * @param ms The message section that contains the parameter to be decoded
     * @param encodings The list of encodings to be applied to decode the parameter
     * @param messageInfo The message to be decoded
     * @param isRequest True if the message containing the parameter is a request
     * @param decode_param The name of the parameter to be decoded
     * @return The decoded parameter as a string
     * @throws ParsingException If problems are encountered during decoding
     */
    public static String decodeParam(IExtensionHelpers helpers,
                                     Utils.MessageSection ms,
                                     List<Utils.Encoding> encodings,
                                     IHttpRequestResponse messageInfo,
                                     Boolean isRequest,
                                     String decode_param) throws ParsingException {
        String decoded_param = "";
        switch (ms) {
            case HEAD:
                decoded_param = Encoding.decode(
                        encodings, Utils.getHeadParam(helpers, messageInfo, isRequest, decode_param), helpers);
                break;
            case BODY:
                decoded_param = Encoding.decode(
                        encodings, Utils.getBodyParam(helpers, messageInfo, isRequest, decode_param), helpers);
                break;
            case URL:
                decoded_param = Encoding.decode(
                        encodings, Utils.getUrlParam(helpers, messageInfo, isRequest, decode_param), helpers);
                break;
        }

        decoded_param = Utils.removeNewline(decoded_param);

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
    public static String decode(List<Utils.Encoding> encodings, String encoded, IExtensionHelpers helpers) throws ParsingException {
        String actual = encoded;
        byte[] actual_b = null;
        boolean isActualString = true;

        if (encoded.length() == 0) {
            return "";
        }

        for (Utils.Encoding e : encodings) {
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
                case JWT:
                    if (!isActualString) {
                        actual = new String(actual_b);
                        isActualString = true;
                    }
                    actual = burp.JWT.decode_raw_jwt(actual);

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
    public static String encode(List<Utils.Encoding> encodings, String decoded, IExtensionHelpers helpers) {
        String actual = decoded;
        byte[] actual_b = null;
        boolean isActualString = true;
        for (Utils.Encoding e : encodings) {
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

                case JWT:
                    //TBD
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
}
