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

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.nio.file.Files;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

public class FileHelper {

    /**
     * Read file from JAR and export it to temporary file
     *
     * @param filename
     * @return temporary file name
     */
    public String exportRessourceFromJar(String filename) throws IOException {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream(filename);
        File outputFile = File.createTempFile(filename, "");
        outputFile.deleteOnExit();
        Files.copy(
                inputStream,
                outputFile.toPath(),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        return outputFile.getAbsolutePath();
    }

    /**
     * Helper method for exporting PEM object.
     *
     * @param pemObject to export in PEM format.
     * @param filename for the file to export.
     */
    public void exportPEMObject(Object pemObject, String filename) throws IOException {
        Writer writer;
        writer = new FileWriter(filename);
        JcaPEMWriter jcaPemWriter = new JcaPEMWriter(writer);
        jcaPemWriter.writeObject(pemObject);
        jcaPemWriter.flush();
        jcaPemWriter.close();
    }

    /**
     * Checks if the program is started from jar.
     *
     * @return true if started from jar.
     */
    public boolean startedFromJar() {
        // Check if running from a jar or not and add certificates
        // https://stackoverflow.com/questions/482560/can-you-tell-on-runtime-if-youre-running-java-from-within-a-jar
        String className = getClass().getName().replace('.', '/');
        String classJar = getClass().getResource("/" + className + ".class").toString();
        return classJar.startsWith("jar:");
    }
}
