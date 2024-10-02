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
package org.zaproxy.addon.migt.samlraider.gui;

import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import javax.imageio.ImageIO;
import javax.swing.JPanel;

public class ImagePanel extends JPanel {

    private static final long serialVersionUID = 1L;
    private final int preferredHeight = 1200;
    private final int preferredWidth = 800;
    private transient BufferedImage image;

    public ImagePanel(String path) {
        try {
            image = ImageIO.read(new File(path));
        } catch (IOException ex) {
            try {
                image = ImageIO.read(getClass().getResourceAsStream("/" + path));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        BufferedImage resized = new BufferedImage(preferredWidth, preferredHeight, image.getType());
        Graphics2D g = resized.createGraphics();
        g.setRenderingHint(
                RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);
        g.drawImage(
                image,
                0,
                0,
                preferredWidth,
                preferredHeight,
                0,
                0,
                image.getWidth(),
                image.getHeight(),
                null);
        g.dispose();
        image = resized;
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        g.drawImage(image, 0, 0, null);
    }

    @Override
    public Dimension getPreferredSize() {
        return new Dimension(preferredWidth, preferredHeight);
    }
}
