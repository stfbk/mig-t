/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.addon.migt.samlraider.helpers;

// import com.sun.org.apache.xml.internal.security.signature.XMLSignature;

// Source:
/*http://www.oracle.com/technetwork/articles/javase/dig-signature-api-140772.html*/
// for Validation purposes only
// public class X509KeySelector extends KeySelector {
//    static boolean algEquals(String algURI, String algName) {
//        return (algName.equalsIgnoreCase("DSA") &&
//                algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) ||
//                (algName.equalsIgnoreCase("RSA") &&
//                        algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1)) ||
//                (algName.equalsIgnoreCase("RSA") &&
//                        algURI.equalsIgnoreCase(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256));
//    }
//
//    public KeySelectorResult select(KeyInfo keyInfo,
//                                    KeySelector.Purpose purpose,
//                                    AlgorithmMethod method,
//                                    XMLCryptoContext context)
//            throws KeySelectorException {
//        @SuppressWarnings("rawtypes")
//        Iterator ki = keyInfo.getContent().iterator();
//        while (ki.hasNext()) {
//            XMLStructure info = (XMLStructure) ki.next();
//            if (!(info instanceof X509Data))
//                continue;
//            X509Data x509Data = (X509Data) info;
//            @SuppressWarnings("rawtypes")
//            Iterator xi = x509Data.getContent().iterator();
//            while (xi.hasNext()) {
//                Object o = xi.next();
//                if (!(o instanceof X509Certificate))
//                    continue;
//                final PublicKey key = ((X509Certificate) o).getPublicKey();
//                // Make sure the algorithm is compatible
//                // with the method.
//                if (algEquals(method.getAlgorithm(), key.getAlgorithm())) {
//                    return new KeySelectorResult() {
//                        public Key getKey() {
//                            return key;
//                        }
//                    };
//                }
//            }
//        }
//        throw new KeySelectorException("No key found!");
//    }
// }
