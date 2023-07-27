import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import migt.JWT;
import migt.ParsingException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.*;

public class JWT_Test {
    JWT j;
    String raw_jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ";

    String raw_header = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9";
    String raw_payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
    String raw_signature = "NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ";

    String header = "{\"alg\": \"HS256\",\"typ\": \"JWT\"\n}";
    String payload = "";
    String signature = "";
    String public_pem_ed = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAPq3ZL01cG1DHZ4iZLiRlRJIlupb5MGfHipSBq1hG2Jo=\n-----END PUBLIC KEY-----\n";
    String private_pem_ed = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFlqmiu8kHunEywNZhbZjdZcT1YGTUCoOlh9aHF+43UE\n-----END PRIVATE KEY-----\n";

    String private_pem_rsa = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIJKQIBAAKCAgEAlD5LtoIK0+dFO2bEaGWRdK3yO4BXOty05yv61WTJO8l8gl1X\n" +
            "LoQZS35bXYmsrh/4a58Wr+d2KrFx71ZzBrx0hJsJ/5+Ia+9q7zUCAmyuv+A73e/k\n" +
            "kf/CIRSyg2tq++etsFoyUtx8AEw7IrGcLzhvy4R4h2vmgtqaln7Nw55FoLKJ8QiE\n" +
            "Tq9UPz9KiV3OhA6ks07y6Brj63fCv6G9sX7uxDoflxVTiH7CaimlLv0h0hrA8s1O\n" +
            "D3VfZjsKIGP+bTtsGzeBzGhxPCkg5DRGTRM/ST1OBMe3Swf9/kZ0ZsbcM2RliEVi\n" +
            "OigVm4gYoVyIHbt+/Sig438qcrc581w1jdOzvmrPjXRlj60iKBjXnhPwT8UGZn4O\n" +
            "WFu9NypVSfMjHgAIdEs+rOVp0YDxPhRU41DbRXci7TefZmCguaoir+7S7em5vPVO\n" +
            "73fnYFrTEKTGdhlsYo43t5I9NkWlRZigg3UsdSREDZCdBlDcPx7UQDiBs9u3Uh4+\n" +
            "2RT7R/Cdp4aPihq2lI4+iWVUk51xdWRJHeI4vbUYj3bwn4OrkXsb0PgzSz2Ss84f\n" +
            "VIsFd6oLprxQn2OOj5Ra6P3ZpoosSvyD4J8zVZGUhi4sHzKDL3B7/wHTjXvHYbRW\n" +
            "kWnvde7YV7aHMY+RlT+4LscDozIYRp5fPoh/DLNWfy8zTwGDWiiZGrB9RrcCAwEA\n" +
            "AQKCAgA0R2PcETBQWpcHw84wIuGRDGcIpNIeaAdEHzZuWwS8mOnX76L3PI7PGNiP\n" +
            "vCWxooSxL4GIt0/s7ncHuK0ICx3sReDYzSIHLn+/rCnxQPK/qAx00E0DT/beQ7ZQ\n" +
            "smkgPSv7rVNh9W+lizyvl4NFA9opI6Z924eHTiCGQmG+Quq7KTuMTTyboylKxL88\n" +
            "gmB6Ic/jjEwNnq4SNEHx4tBK8ECz4uuRFGxJDqrxVY5za8GpntW8yrpkqTfjjZ6c\n" +
            "nab0TqhpUMHtnEeSt85prCW+uLLw2TXSabwyMbdZHO+f7zFozlcgH5fseoZkOzK0\n" +
            "dTVrhtvZ26IhmI8XtZYyRKp+QdJ5IwF3XpXWt7zafUdYCu8Z45HZhEe+aTpNIDvv\n" +
            "z2nkqiJ0zAMH188YqbgawCdWow6D3/vqoyr5IlZcj9qE2wKunT5eqr248rNQsLA5\n" +
            "2nOwz4fPcN4RHyiBygD8G4867di7Q+qRBdMAfRx5DrG0ottL2oNrr5G9Wv94Dsu8\n" +
            "+A0q8EpwAvwYsxCNVnrjd2ypfJhyS30Pktz/LWj/MWbee1BP83C3zveqwBQ+zxTd\n" +
            "03surmBlNS7tZOZvThMbBlWIO66wQWCzkZwi6zbrJwHCf4B30jTepERsiLSv2jyI\n" +
            "oHNGOa84i2IEdWtXGVVyAET9E+pzNVQjFHsembIS6H1W4GTjwQKCAQEAzkB4lLkx\n" +
            "6gm5o5IhRC2ZAL9RaZGSrT9sXJThtq7qVqQiLItvNRa633eqfxzlkgBgmH2dGgc+\n" +
            "OqZMOHE2u0PSWBUinkrzatFTyjn99H6jYtG70rxLMZcS9GD5padP2mFklrM9+WaN\n" +
            "f7fuvZjsiIanVxhykyEqB7y43JSR5vUSab9tltbnG2+V2ZMmh+8GWEDwozhyOZW9\n" +
            "cjhu+eI+7FqyU1JBydArO3Ds8ZpWrjfZvxmS7LzoJEkJ4hdfMmeAWFNv+tLhYGAT\n" +
            "Et7d6atoxPL6bId+F+ncqgCF9SVmYpq9faoXsvOr7yxR3n6MLY5Fvz2fX0tvBeSv\n" +
            "skn/a1mei1yqHQKCAQEAt//yZzEjCgi49QeT01CHPbkogbtkG+tVuB5V2zpLArj1\n" +
            "AXXKSNZn96+UjgScEY/DTWm8ljjDP8UYZXmYgkBm+oEdYnyLa60u/ZSdP4E1ICJT\n" +
            "32XHrbkt1Z9SdMDFwhitKuA9uyUIuLf2OfIvZQQDU6BPmr18OX82ODxZXqCMdGJH\n" +
            "3rml16joa5u9KDPNLfei2NEEKc9L7szvtBwQYf2DKd4jgpZMOg8EFQBd3+szl7UD\n" +
            "gTPRT7sZX035mNYfZkFTjj0z4vqEu1ARCkKz0fp05uEQnQLOTUGEgECDTh7jZnfn\n" +
            "PDDio4/vW8qEPEfUcfpetbNr3i8hhAeA5xHyBij74wKCAQEAvPo1gY9uPJJMlaL+\n" +
            "+AkPd6/UWHYZfsPt9aY0ab462MfqyAW6D1qUPszWW0GO1wehehceKwsX6YUVsWGK\n" +
            "VGr//9Tds0vZXLYPn+si1TJzYcfp4FzGSNmzdFamZzG16NHz6GCzGCDu5WcSSIYl\n" +
            "s7ItAZBU6pooeI5ikzlNteA2zs2nC948Qtcq5f/9/e70UUivM940Sq74tf8fL7Yt\n" +
            "EULIwa9MuC0Ub5I4h+ZyJY7m5EH6bQ9pZFXHyHDBuN08q7FHmPo/pp5g25l4mvGD\n" +
            "PXGkImzDDAYrOVjhZIywEwjVNp7yt/SsRKjHGqW4qsUBAwjjTd1ADJZMpX9HmIS0\n" +
            "z9xHwQKCAQEAp3O0LHuIcupLQRvbSZXg7qhil+ZtjgcXZM+evTwI5fpjZyfGp5EQ\n" +
            "31YYcUL6sfTO/dW7vk78Sj3aHQeTZv6reVEl5+qGi8D5oeetUA0LxynWgNnE5nI/\n" +
            "p0kupniFwUXp2rpnE7j5ffpViJjCz0Desi2UJLRLqJwAQR+TCc485PJIjAcSSfk7\n" +
            "RCtg84RpN2tF9eIK0u4IIdS6VYSw2Cz6QJEcagzUZIYj5eUGifEoa+ldvijlVZVl\n" +
            "2tlAzPoZa1sKasmCPhBV2Y5dY6QeuHsiBrhPAUV7cM2ug3WyydbMhwWaGKo4qDgm\n" +
            "0re0rpOEYRJFPUGDapoj+19EzYYEZ9zGlwKCAQBdOy3ctg82hG8y2GR2S8abgVI1\n" +
            "b9S4s8FOYxxujzM6nkB+m8J1el4Sk8n4HuYDY9kivfI9/sbR7wUX9fV0QJHlr70t\n" +
            "z8aTKNQVxzGzO+OLEGs66ieAI8uCOByCEbyqPUZZAg0YN7BWtfFsqdAwOdEdYCMO\n" +
            "CR0axKnVhkIV7Oj9JQ1+mucB8gL5N8miSxc9lsWuOz2tGEM8rcTAoGSmvwMkgcfK\n" +
            "P34FFHdGk4fZnRYA6pGfgVZD3ZyRYF9cWnNgw823JlsYhzGGX4pQbFFGZ4rGuQ9z\n" +
            "ursu/oNFRzKSZrb1FHOHvv5DfkINWXPVL8EgQG2HN2AF+LSZllSrStef9Urw\n" +
            "-----END RSA PRIVATE KEY-----";

    String public_pem_rsa = "-----BEGIN PUBLIC KEY-----\n" +
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlD5LtoIK0+dFO2bEaGWR\n" +
            "dK3yO4BXOty05yv61WTJO8l8gl1XLoQZS35bXYmsrh/4a58Wr+d2KrFx71ZzBrx0\n" +
            "hJsJ/5+Ia+9q7zUCAmyuv+A73e/kkf/CIRSyg2tq++etsFoyUtx8AEw7IrGcLzhv\n" +
            "y4R4h2vmgtqaln7Nw55FoLKJ8QiETq9UPz9KiV3OhA6ks07y6Brj63fCv6G9sX7u\n" +
            "xDoflxVTiH7CaimlLv0h0hrA8s1OD3VfZjsKIGP+bTtsGzeBzGhxPCkg5DRGTRM/\n" +
            "ST1OBMe3Swf9/kZ0ZsbcM2RliEViOigVm4gYoVyIHbt+/Sig438qcrc581w1jdOz\n" +
            "vmrPjXRlj60iKBjXnhPwT8UGZn4OWFu9NypVSfMjHgAIdEs+rOVp0YDxPhRU41Db\n" +
            "RXci7TefZmCguaoir+7S7em5vPVO73fnYFrTEKTGdhlsYo43t5I9NkWlRZigg3Us\n" +
            "dSREDZCdBlDcPx7UQDiBs9u3Uh4+2RT7R/Cdp4aPihq2lI4+iWVUk51xdWRJHeI4\n" +
            "vbUYj3bwn4OrkXsb0PgzSz2Ss84fVIsFd6oLprxQn2OOj5Ra6P3ZpoosSvyD4J8z\n" +
            "VZGUhi4sHzKDL3B7/wHTjXvHYbRWkWnvde7YV7aHMY+RlT+4LscDozIYRp5fPoh/\n" +
            "DLNWfy8zTwGDWiiZGrB9RrcCAwEAAQ==\n" +
            "-----END PUBLIC KEY-----";

    @BeforeEach
    void setUp() {
        j = new JWT();
    }

    @Test
    @DisplayName("Testing default values")
    void testDefaultValues() {
        JWT j = new JWT();
        assertEquals("", j.raw);
        assertEquals("", j.signature);
        assertEquals("", j.header);
        assertEquals("", j.payload);
    }

    @Test
    @DisplayName("Testing jwt decode and encode")
    void testJWTParse_build() {
        JWT j = new JWT();
        boolean errors = false;
        try {
            j.parse(raw_jwt);

            String out = j.build();
            assertEquals(raw_jwt, out);
            String[] splitted = out.split("\\.");

            assertEquals(3, splitted.length);

            assertEquals(raw_header, splitted[0]);
            assertEquals(raw_payload, splitted[1]);
            assertEquals(raw_signature, splitted[2]);

            //assertEquals(raw_header, j.header);
            //assertEquals(raw_payload, j.payload);
            //assertEquals(raw_signature, j.signature);
        } catch (ParsingException e) {
            errors = true;
        }
        assertFalse(errors);
    }

    @Test
    @DisplayName("Testing jwt signing and verify")
    void testJWTSign_and_verify() {
        JWT j = new JWT();
        boolean errors = false;
        try {
            j.parse(raw_jwt);
            j.sign = true;
            j.private_key_pem = private_pem_rsa;

            String out = j.build();
            assertNotEquals(raw_jwt, out);
            String[] splitted = out.split("\\.");

            assertEquals(3, splitted.length);

            assertEquals(raw_header, splitted[0]);
            assertEquals(raw_payload, splitted[1]);
            assertNotEquals(raw_signature, splitted[2]);

            JWT j2 = new JWT();
            j2.parse(out);
            j2.public_key_pem = public_pem_rsa;
            assertTrue(j2.check_sig());
        } catch (ParsingException e) {
            errors = true;
        }
        assertFalse(errors);
    }

    @Test
    @DisplayName("Testing jwt decode and encode")
    void test_jwt_wrong_signature() {
        JWT j = new JWT();
        boolean errors = false;
        try {
            j.parse(raw_jwt);
            j.public_key_pem = public_pem_rsa;
            assertFalse(j.check_sig());
        } catch (ParsingException e) {
            errors = true;
        }
        assertFalse(errors);
    }

    @Test
    void test_check_key() throws JOSEException, ParseException, ParsingException {


        JWK jwk = JWK.parseFromPEMEncodedObjects(public_pem_rsa); // NON VA PER EDDSA

        System.out.println(jwk.getKeyType());
        System.out.println(jwk.getAlgorithm());

        SignedJWT decoded = SignedJWT.parse(raw_jwt);
        JWSHeader header = decoded.getHeader();
        switch (header.getAlgorithm().getName()) {

        }

        JWSVerifier verifier = new RSASSAVerifier(jwk.toRSAKey());
        decoded.verify(verifier);

        // get the algorithm from the jwt

        JWT j = new JWT();
        j.parse(raw_jwt);

        /*
        ByteArrayInputStream tube = new ByteArrayInputStream(public_pem.getBytes());
        Reader fRd = new BufferedReader(new InputStreamReader(tube));
        PemReader pr = new PemReader(fRd);
        System.out.println(pr);

        KeyPair kp;
        //PemObject o = pr.readPemObject();
        PEMParser pemParser = new PEMParser(fRd);
        Object o = pemParser.readObject();
        if (o instanceof SubjectPublicKeyInfo) {
            System.out.println("asd");
            AlgorithmIdentifier ai = ((SubjectPublicKeyInfo) o).getAlgorithm();
            System.out.print(ai);
        }
        */
    }

    /**
     @Test void test_complete() throws NoSuchAlgorithmException, ParsingException {
     String public_pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAPq3ZL01cG1DHZ4iZLiRlRJIlupb5MGfHipSBq1hG2Jo=\n-----END PUBLIC KEY-----\n";
     String private_pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIFlqmiu8kHunEywNZhbZjdZcT1YGTUCoOlh9aHF+43UE\n-----END PRIVATE KEY-----\n";

     //KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
     //keyGen.initialize(2048);
     //KeyPair pair = keyGen.generateKeyPair();
     //PrivateKey sk = pair.getPrivate();
     //PublicKey pk = pair.getPublic();

     String jws = Jwts.builder()
     .setSubject("Bob")
     .signWith(sk)
     .compact();

     assertFalse(jws.equals(""));

     JWT j = new JWT();
     j.check_sig = true;
     j.public_key = "pk_string";
     j.parse(raw_jwt);
     }


     @Test
     @DisplayName("Testing jwt remove claim")
     void testJWTRemoveClaim() {
     boolean errors = false;
     try {
     JWT j = new JWT();
     j.parse(raw_jwt);
     j.removeClaim(Utils.Jwt_section.HEADER, "typ");
     String out = j.build();
     assertEquals("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ", out);

     j = new JWT();
     j.parse(raw_jwt);
     j.removeClaim(Utils.Jwt_section.PAYLOAD, "name");
     out = j.build();
     assertEquals("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ", out);

     String[] splitted = out.split("\\.");

     } catch (ParsingException e) {
     errors = true;
     }
     assertFalse(errors);
     }

     @Test
     @DisplayName("Testing jwt edit claim")
     void testJWTEditClaim() {
     boolean errors = false;
     try {
     JWT j = new JWT();
     j.parse(raw_jwt);
     j.editAddClaim(Utils.Jwt_section.HEADER, "typ", "asdasd");
     String out = j.build();
     assertEquals("eyJhbGciOiJSUzI1NiIsInR5cCI6ImFzZGFzZCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ", out);

     j = new JWT();
     j.parse(raw_jwt);
     j.editAddClaim(Utils.Jwt_section.PAYLOAD, "name", "peppe");
     out = j.build();
     assertEquals("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InBlcHBlIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ", out);

     j = new JWT();
     j.parse(raw_jwt);
     j.editAddClaim(Utils.Jwt_section.SIGNATURE, "", "peppe");
     out = j.build();
     assertEquals("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.peppe", out);

     j = new JWT();
     j.parse(raw_jwt);
     j.editAddClaim(Utils.Jwt_section.HEADER, "prova", "provona");
     out = j.build();
     assertEquals("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsInByb3ZhIjoicHJvdm9uYSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ", out);

     j = new JWT();
     j.parse(raw_jwt);
     j.editAddClaim(Utils.Jwt_section.PAYLOAD, "prova", "provona");
     out = j.build();
     assertEquals("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwicHJvdmEiOiJwcm92b25hIn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ", out);
     } catch (ParsingException e) {
     errors = true;
     }
     assertFalse(errors);
     }

     @Test
     @DisplayName("Claims edit")
     void test_claimEdit() {
     String in = "eyJhbGciOiJSUzI1NiIsImtpZCI6IllodUlKVTZvMTVFVUN5cUEwTEhFcUpkLXhWUEpnb3lXNXdaMW80cGFkV3MifQ.eyJzY29wZSI6Im9wZW5pZCIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly9yZWx5aW5nLXBhcnR5Lm9yZzo4MDAxL29pZGMvcnAvY2FsbGJhY2siLCJyZXNwb25zZV90eXBlIjoiY29kZSIsIm5vbmNlIjoidUNhQkJ6RDNPa3VPbEVVenZUSGJOcWFoOHVZdTRVa3UiLCJzdGF0ZSI6IjZFY3JwdzlYNThZaFVXMVlYSHF4bEVEVUhvbXczNUlxIiwiY2xpZW50X2lkIjoiaHR0cDovL3JlbHlpbmctcGFydHkub3JnOjgwMDEvIiwiZW5kcG9pbnQiOiJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AvYXV0aG9yaXphdGlvbiIsImFjcl92YWx1ZXMiOiJodHRwczovL3d3dy5zcGlkLmdvdi5pdC9TcGlkTDIiLCJpYXQiOjE2NTM5ODM4NTksImF1ZCI6WyJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AvIiwiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9vaWRjL29wL2F1dGhvcml6YXRpb24iXSwiY2xhaW1zIjp7ImlkX3Rva2VuIjp7ImZhbWlseV9uYW1lIjp7ImVzc2VudGlhbCI6dHJ1ZX0sImVtYWlsIjp7ImVzc2VudGlhbCI6dHJ1ZX19LCJ1c2VyaW5mbyI6eyJnaXZlbl9uYW1lIjpudWxsLCJmYW1pbHlfbmFtZSI6bnVsbCwiZW1haWwiOm51bGwsImZpc2NhbF9udW1iZXIiOm51bGx9fSwicHJvbXB0IjoiY29uc2VudCBsb2dpbiIsImNvZGVfY2hhbGxlbmdlIjoiU2hOX0t0U3ZhMEtwS1pZUFZ2MEhVd0lFM1lHclhZeHBuVS1Vb1BGTEluZyIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJpc3MiOiJodHRwOi8vcmVseWluZy1wYXJ0eS5vcmc6ODAwMS8iLCJzdWIiOiJodHRwOi8vcmVseWluZy1wYXJ0eS5vcmc6ODAwMS8ifQ.mETftfWL9MYrf3BVnahWOilFYItkBSaTw3nhKu0UzfiAI5lFy1orNGatNIR-Dg4hgsFCXgaY9rJSi2TVRSqIsHAJPe0HC5sKfXJ-mka0_w4koGDjbmYRZVN3yI05QWsLpENlsuCk2JEgZfz5BvAuX_MgxytIQHhUgy7DsdoJW-6Bk2DPDUiG_bDrBBjdFYgVocaQrxW49NmVIwtVz3dbhdslGA6g0uX7Dp9lQ9HqyWr1YnHtxUdyfuM2wdwPf11fhZNI8Nu_tpgVUxUMQgyEFA1nAscos2FuvLhpNovuciyh0BAlrYTpbXpZ-hjBv5rbfIrv5wytRNhlK2VxP7DA2g";
     boolean errors = false;
     try {
     j = new JWT();
     j.parse(in);

     boolean a = j.jwt.getBody().containsKey("family_name");
     String s = (String) j.jwt.getBody().get("family_name");
     if (!a) {
     Object c = j.jwt.getBody().get("claims");
     }
     } catch (ParsingException e) {
     errors = true;
     }
     assertFalse(errors);
     }

     @Test
     @DisplayName("Decode raw jwt")
     void test_decodeRawJwt() {
     String in = "eyJhbGciOiJSUzI1NiIsImtpZCI6IllodUlKVTZvMTVFVUN5cUEwTEhFcUpkLXhWUEpnb3lXNXdaMW80cGFkV3MifQ.eyJzY29wZSI6Im9wZW5pZCIsInJlZGlyZWN0X3VyaSI6Imh0dHA6Ly9yZWx5aW5nLXBhcnR5Lm9yZzo4MDAxL29pZGMvcnAvY2FsbGJhY2siLCJyZXNwb25zZV90eXBlIjoiY29kZSIsIm5vbmNlIjoiOUZKcWczZDBBS0FYTWpEcDRVRnpkbGJUdG5kazgxanUiLCJzdGF0ZSI6ImhURHVRS0t1YUY4dnVxRk1XSVN4NWlxaTBlOXlmRGJiIiwiY2xpZW50X2lkIjoiaHR0cDovL3JlbHlpbmctcGFydHkub3JnOjgwMDEvIiwiZW5kcG9pbnQiOiJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AvYXV0aG9yaXphdGlvbiIsImFjcl92YWx1ZXMiOiJodHRwczovL3d3dy5zcGlkLmdvdi5pdC9TcGlkTDIiLCJpYXQiOjE2NTY0MDMxNzEsImF1ZCI6WyJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AvIiwiaHR0cDovL2NpZS1wcm92aWRlci5vcmc6ODAwMi9vaWRjL29wL2F1dGhvcml6YXRpb24iXSwiY2xhaW1zIjp7ImlkX3Rva2VuIjp7ImZhbWlseV9uYW1lIjp7ImVzc2VudGlhbCI6dHJ1ZX0sImVtYWlsIjp7ImVzc2VudGlhbCI6dHJ1ZX19LCJ1c2VyaW5mbyI6eyJnaXZlbl9uYW1lIjpudWxsLCJmYW1pbHlfbmFtZSI6bnVsbCwiZW1haWwiOm51bGwsImZpc2NhbF9udW1iZXIiOm51bGx9fSwicHJvbXB0IjoiY29uc2VudCBsb2dpbiIsImNvZGVfY2hhbGxlbmdlIjoiLXJQSkJfNDFPaUVzUmtXSTNQeDJmNkdaVjdpdWNOQkVReTZXVzRaenVTOCIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJpc3MiOiJodHRwOi8vcmVseWluZy1wYXJ0eS5vcmc6ODAwMS8ifQ.hZQdNZoZeLNJrIezuXQIV0C5a9ZOubiYTOUYdtmbsR4F_NFZFKDZccbjYk-ntYa2O7_DgcwQ083kAv5dutwU6nhiHBh3K__W4zct2yxcsLspE2pvBbmMjvq7IqmEYgIR2NEBwtCz9RrV6srnjzygm3XHb7kpfu-Z2eVPzxRTqi1C5l-ZX-xPDr2YFFdpHVB17G3lXTEj_Mm6zr6uNeJkS8Ytscq6SXyni3OTj_bRLTLONjoypLRO-qw8z2d8lY7bYgx9mZCAuUtgS75yRlrHuGu4zsE3Bg3UigfnCO_Pqouq-HZOGEZ_7_Hra0S5V8BPek_fRhRH6K534rFWlApRMQ";

     String out = JWT.decode_raw_jwt(in);

     assertEquals("{" +
     "\"alg\":\"RS256\"," +
     "\"kid\":\"YhuIJU6o15EUCyqA0LHEqJd-xVPJgoyW5wZ1o4padWs\"" +
     "}.{\"scope\":\"openid\",\"redirect_uri\":\"http://relying-party.org:8001/oidc/rp/callback\",\"response_type\":\"code\",\"nonce\":\"9FJqg3d0AKAXMjDp4UFzdlbTtndk81ju\",\"state\":\"hTDuQKKuaF8vuqFMWISx5iqi0e9yfDbb\",\"client_id\":\"http://relying-party.org:8001/\",\"endpoint\":\"http://cie-provider.org:8002/oidc/op/authorization\",\"acr_values\":\"https://www.spid.gov.it/SpidL2\",\"iat\":1656403171,\"aud\":[\"http://cie-provider.org:8002/oidc/op/\",\"http://cie-provider.org:8002/oidc/op/authorization\"],\"claims\":{\"id_token\":{\"family_name\":{\"essential\":true},\"email\":{\"essential\":true}},\"userinfo\":{\"given_name\":null,\"family_name\":null,\"email\":null,\"fiscal_number\":null}},\"prompt\":\"consent login\",\"code_challenge\":\"-rPJB_41OiEsRkWI3Px2f6GZV7iucNBEQy6WW4ZzuS8\",\"code_challenge_method\":\"S256\",\"iss\":\"http://relying-party.org:8001/\"}" +
     ".hZQdNZoZeLNJrIezuXQIV0C5a9ZOubiYTOUYdtmbsR4F_NFZFKDZccbjYk-ntYa2O7_DgcwQ083kAv5dutwU6nhiHBh3K__W4zct2yxcsLspE2pvBbmMjvq7IqmEYgIR2NEBwtCz9RrV6srnjzygm3XHb7kpfu-Z2eVPzxRTqi1C5l-ZX-xPDr2YFFdpHVB17G3lXTEj_Mm6zr6uNeJkS8Ytscq6SXyni3OTj_bRLTLONjoypLRO-qw8z2d8lY7bYgx9mZCAuUtgS75yRlrHuGu4zsE3Bg3UigfnCO_Pqouq-HZOGEZ_7_Hra0S5V8BPek_fRhRH6K534rFWlApRMQ",
     out);
     }
     */
}
