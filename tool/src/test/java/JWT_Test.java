import migt.JWT;
import migt.ParsingException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class JWT_Test {
    JWT j;
    String raw_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ";

    String raw_header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
    String raw_payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
    String raw_signature = "NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ";

    String header = "{\"alg\": \"HS256\",\"typ\": \"JWT\"\n}";
    String payload = "";
    String signature = "";

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

    /**
    @Test
    void test_complete() throws NoSuchAlgorithmException, ParsingException {
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
