/*
 * https://github.com/CompassSecurity/SAMLRaider
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Roland Bischofberger and Emanuel Duss
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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
