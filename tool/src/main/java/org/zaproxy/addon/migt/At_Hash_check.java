/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.migt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.apache.commons.codec.binary.Base64;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Module used to check the correctness of the at_hash parameter inside of the id_token wrt to the
 * released access_token https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
 */
public class At_Hash_check extends Module {

    public At_Hash_check() {}

    @Override
    public void loader(API api) {
        if (!(api instanceof Operation_API)) {
            throw new RuntimeException("Tried to load an api not supported in At_Hash module");
        }
        imported_api = api;
    }

    @Override
    public void execute() {
        if (imported_api == null) {
            throw new RuntimeException("imported API is null in module At_Hash");
        }

        if (((Operation_API) imported_api).is_request) {
            throw new RuntimeException("Expecting a response got request in At_Hash module");
        }

        // parse message body and take id_token and access_token values
        String body = new String(((Operation_API) imported_api).message.getBody(false));

        String id_token = "";
        String access_token = "";

        try {
            JSONObject o = new JSONObject(body);
            id_token = o.getString("id_token");
            access_token = o.getString("access_token");
        } catch (JSONException e) {
            throw new RuntimeException("Invalid JSON in body");
        }

        // parse id_token jwt taking alg and at_hash parameters
        String alg = "";
        String at_hash = "";
        try {
            JWT j = new JWT();
            j.parse(id_token);
            JSONObject o = new JSONObject(j.header);
            alg = o.getString("alg");
            o = new JSONObject(j.payload);
            at_hash = o.getString("at_hash");

        } catch (ParsingException | JSONException e) {
            System.out.println(e);
            result = false;
            return;
        }

        // select the hashing algorithm based on the ID_TOKEN alg header parameter
        String hash_alg = alg.substring(1);
        byte[] hashed;
        try {
            switch (hash_alg) {
                case "S256":
                    hashed = MessageDigest.getInstance("SHA-256").digest(access_token.getBytes());
                    break;
                case "S384":
                    hashed = MessageDigest.getInstance("SHA-384").digest(access_token.getBytes());
                    break;
                case "S512":
                    hashed = MessageDigest.getInstance("SHA-512").digest(access_token.getBytes());
                    break;
                default:
                    System.out.println("At_Hash module: unsupported hashing alg: " + alg);
                    result = false;
                    return;
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("At_Hash: Invalid algorithm selected to hash content");
        }

        // select the first 128 bits of the hash of the access token
        byte[] left = Arrays.copyOfRange(hashed, 0, 16);

        // base64url encode the previous value
        String at_hash_generated = Base64.encodeBase64URLSafeString(left);

        // remove "=" characters
        at_hash_generated = at_hash_generated.replaceAll("=", "");

        applicable =
                true; // this means that all the steps that precedes the check were accomplished
        // correctly

        // check previous value is equal to at_hash
        result = at_hash_generated.equals(at_hash);
    }
}
