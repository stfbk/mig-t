package migt;

import io.jsonwebtoken.*;
import org.json.JSONException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * Class to manage JWT tokens
 *
 * @Author Matteo Bitussi
 */
public class JWT {
    public String header;
    public String payload;
    public String signature;
    public String raw;
    public Jwt<Header, Claims> jwt;
    public String singing_alg;
    public boolean sign;
    private boolean isProcessedAsString;

    /**
     * Constructor that instantiate a JWT object
     */
    public JWT() {
        this.raw = "";
        this.signature = "";
        this.header = "";
        this.payload = "";
        this.sign = false;
    }

    /**
     * Function that decodes a raw jwt with Base64 and splitting it into the three parts
     *
     * @param jwt the raw jwt as string
     * @return an array of length 3 containing the three parts of the decoded JWT in order.
     */
    static public String decode_raw_jwt(String jwt) {
        String[] parts = jwt.split("\\.");
        String res = "";

        if (parts.length != 3) {
            return "";
        }

        res = new String(Base64.getDecoder().decode(parts[0]), StandardCharsets.UTF_8) + ".";
        res += new String(Base64.getDecoder().decode(parts[1]), StandardCharsets.UTF_8) + ".";
        res += parts[2];

        return res;
    }

    /**
     * Parse a jwt token from a string.
     *
     * @param raw_jwt the raw jwt to be parsed
     */
    public void parseJWT(String raw_jwt) throws ParsingException {
        int i = raw_jwt.lastIndexOf('.');
        String withoutSignature = raw_jwt.substring(0, i + 1);
        jwt = Jwts.parserBuilder().build().parse(withoutSignature);

        singing_alg = (String) jwt.getHeader().get("alg");

        signature = raw_jwt.substring(i + 1);
        isProcessedAsString = false;
    }

    /**
     * Builds a jwt token in form of a string, from the Claims and the Header declared in this class
     *
     * @return the jwt token in string format
     */
    public String buildJWT() {
        JwtBuilder builder = Jwts.builder();
        builder.setHeader((Map<String, Object>) jwt.getHeader());
        builder.setClaims(jwt.getBody());

        boolean isNone = jwt.getHeader().get("alg") != null && jwt.getHeader().get("alg").equals("none");

        String tmp = builder.compact();
        tmp += signature;

        String[] splitted = tmp.split("\\.");

        String header = new String(Base64.getDecoder().decode(splitted[0]));
        header = isNone ? header : header.replaceAll("none", singing_alg);
        header = Base64.getEncoder().encodeToString(header.getBytes());
        header = header.replaceAll("=", "");
        splitted[0] = header;

        tmp = splitted[0] + "." + splitted[1];
        if (splitted.length == 3) {
            tmp = tmp + "." + splitted[2];
        }

        return tmp;
    }

    /**
     * Parse a JWT token from a string and stores string values of it
     *
     * @param raw_jwt the raw JWT in string format
     * @throws ParsingException if there are problems in the parsing
     */
    public void parseJWT_string(String raw_jwt) throws ParsingException {
        String[] splitted = raw_jwt.split("\\.");
        if (splitted.length != 3) throw new ParsingException("Invalid jwt");

        try {
            header = new String(Base64.getDecoder().decode(splitted[0]));
            payload = new String(Base64.getDecoder().decode(splitted[1]));
            signature = splitted[2];
        } catch (JSONException e) {
            throw new ParsingException("Error parsing JWT tokens");
        }
        isProcessedAsString = true;
    }

    /**
     * Builds a JWT token from the string values in this class
     *
     * @return A JWT as a string
     * @throws ParsingException
     */
    public String buildJWT_string() throws ParsingException {
        String res = "";

        if (isProcessedAsString)
            throw new ParsingException("error in building jwt, tried to build from string");

        if (this.header.equals("") || this.payload.equals(""))
            throw new ParsingException("error in building jwt, empty values");

        res += Base64.getEncoder().encodeToString(header.getBytes());
        res += "." + Base64.getEncoder().encodeToString(payload.getBytes());

        if (signature != null && !signature.equals("")) {
            res += "." + signature;
        }

        res = res.replaceAll("=", "");
        return res;
    }

    /**
     * Removes a claim from the given jwt section
     *
     * @param section the section containing the claim to remove
     * @param what    the name of the claim to remove
     */
    public void removeClaim(Utils.Jwt_section section, String what) {
        switch (section) {
            case HEADER:
                jwt.getHeader().remove(what);
                break;
            case PAYLOAD:
                jwt.getBody().remove(what);
                break;
            case SIGNATURE:
                signature = "";
                break;
            case RAW_HEADER:
                break;
            case RAW_PAYLOAD:
                break;
            case RAW_SIGNATURE:
                break;
        }
    }

    /**
     * This function add or edit a claim from the given section. If the claim is present, it edits it, otherwise it
     * adds it.
     *
     * @param section the section containing the claim or that should contain the claim
     * @param what    the name of the claim
     * @param value   the value of the claim to set
     */
    public void editAddClaim(Utils.Jwt_section section, String what, String value) {
        switch (section) {
            case HEADER:
                jwt.getHeader().put(what, value);
                break;
            case PAYLOAD:
                jwt.getBody().put(what, value);
                break;
            case SIGNATURE:
                signature = value;
                break;
            case RAW_HEADER:
                break;
            case RAW_PAYLOAD:
                break;
            case RAW_SIGNATURE:
                break;
        }
    }

    /**
     * Function used to get the value of a claim
     *
     * @param section the section containing the claim
     * @param what    the name of the claim
     * @return the value of the claim
     */
    public String getClaim(Utils.Jwt_section section, String what) {
        String res = "";
        if (isProcessedAsString) {
            res = "";
        } else {
            switch (section) {
                case HEADER:
                    res = (String) jwt.getHeader().get(what);
                    break;
                case PAYLOAD:
                    res = (String) jwt.getBody().get(what);
                    break;
                case SIGNATURE:
                    res = signature;
                    break;
                case RAW_HEADER:
                    break;
                case RAW_PAYLOAD:
                    break;
                case RAW_SIGNATURE:
                    break;
            }
        }
        return res;
    }

    //TODO: add sign with private key
}
