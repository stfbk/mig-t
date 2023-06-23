package migt;

import io.jsonwebtoken.Jwts;
import org.json.JSONException;

import java.util.Base64;


/**
 * Class to manage JWT tokens
 * Uses https://github.com/jwtk/jjwt
 *
 * @Author Matteo Bitussi
 */
public class JWT {
    public String header;
    public String payload;
    public String signature;
    public String raw;
    // TODO: specify the following tags in parsing
    public boolean sign; // put to true if you want to sign the jwt after edit (need private key)
    public String private_key; // PEM the private key used to sign the jwtù
    // TODO: the key algorithm used should be specified
    public boolean check_sig; // set to true if you want to check the signature of the jwt (when decoding)
    public String public_key; // PEM public key used to check the signature of the jwt

    /**
     * Constructor that instantiate a JWT object
     */
    public JWT() {
        this.raw = "";
        this.signature = "";
        this.header = "";
        this.payload = "";
        this.sign = false;
        this.private_key = "";
        this.check_sig = false;
    }

    /**
     * Parse a JWT token from a string and stores string values of it
     *
     * @param raw_jwt the raw JWT in string format
     * @throws ParsingException if there are problems in the parsing
     */
    public void parse(String raw_jwt) throws ParsingException {
        this.raw = raw_jwt;

        if (check_sig) {
            // TODO: take the public key and check the signature
            Jwts.parserBuilder().build().parse(raw_jwt);
        }

        String[] splitted = raw_jwt.split("\\.");
        if (splitted.length != 3) throw new ParsingException("Invalid jwt");

        try {
            header = new String(Base64.getDecoder().decode(splitted[0]));
            payload = new String(Base64.getDecoder().decode(splitted[1]));
            signature = splitted[2]; //TODO: does it make sense do decode?
        } catch (JSONException e) {
            throw new ParsingException("Error parsing JWT tokens");
        }
    }

    /**
     * Builds a JWT token from the string values in this class
     *
     * @return A JWT as a string
     * @throws ParsingException
     */
    public String build() throws ParsingException {
        String res = "";

        if (this.header.equals("") || this.payload.equals(""))
            throw new ParsingException("error in building jwt, empty values");

        res += Base64.getEncoder().encodeToString(header.getBytes());
        res += "." + Base64.getEncoder().encodeToString(payload.getBytes());

        if (sign) {
            //TODO sign the jwt with pk
        } else {
            if (signature != null && !signature.equals("")) {
                res += "." + signature; // TODO encode
            }
        }

        res = res.replaceAll("=", "");
        return res;
    }
}
