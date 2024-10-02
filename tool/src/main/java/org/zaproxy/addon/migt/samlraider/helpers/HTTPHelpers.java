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

public class HTTPHelpers {
    //
    //    // Source:
    //    // http://qupera.blogspot.ch/2013/02/howto-compress-and-uncompress-java-byte.html
    //    public byte[] decompress(byte[] data, boolean gzip) throws IOException,
    // DataFormatException {
    //        Inflater inflater = new Inflater(true);
    //        inflater.setInput(data);
    //
    //        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
    //        byte[] buffer = new byte[1024];
    //        while (!inflater.finished()) {
    //            int count = inflater.inflate(buffer);
    //            outputStream.write(buffer, 0, count);
    //        }
    //        outputStream.close();
    //        byte[] output = outputStream.toByteArray();
    //
    //        inflater.end();
    //
    //        return output;
    //    }
    //
    //    // Source:
    //    // http://qupera.blogspot.ch/2013/02/howto-compress-and-uncompress-java-byte.html
    //    public byte[] compress(byte[] data, boolean gzip) throws IOException {
    //        Deflater deflater = new Deflater(5, gzip);
    //        deflater.setInput(data);
    //
    //        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
    //
    //        deflater.finish();
    //        byte[] buffer = new byte[1024];
    //        while (!deflater.finished()) {
    //            int count = deflater.deflate(buffer);
    //            outputStream.write(buffer, 0, count);
    //        }
    //        outputStream.close();
    //        byte[] output = outputStream.toByteArray();
    //
    //        deflater.end();
    //
    //        return output;
    //    }
    //

}
