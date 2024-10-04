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
package org.zaproxy.addon.migt.samlraider.model;

import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;

public class BurpCertificateStore {

    private final DefaultMutableTreeNode rootNode;

    public BurpCertificateStore() {
        rootNode = new DefaultMutableTreeNode("Certificates");
    }

    /**
     * Adds a new certificate to the store directly under the root node.
     *
     * @param burpCertificate to add
     */
    public void addCertificate(BurpCertificate burpCertificate) {
        rootNode.add(new DefaultMutableTreeNode(burpCertificate));
    }

    /**
     * Adds a complete certificate chain to the store. The top certificate of the chain is directly
     * under the root node.
     *
     * @param burpCertificateChain to add
     */
    public void addCertificateChain(List<BurpCertificate> burpCertificateChain) {
        Collections.reverse(burpCertificateChain); // CA first

        DefaultMutableTreeNode currentNode = null;
        DefaultMutableTreeNode previousNode = null;
        for (BurpCertificate c : burpCertificateChain) {
            currentNode = new DefaultMutableTreeNode(c);
            if (previousNode == null) { // Self-Signed
                rootNode.add(currentNode);
            } else {
                previousNode.add(currentNode);
            }
            previousNode = currentNode;
        }
    }

    /**
     * Deletes a certificate from the store. It can be placed anywhere in the tree.
     *
     * @param burpCertificate to remove
     */
    public void removeCertificate(BurpCertificate burpCertificate) {
        @SuppressWarnings("unchecked")
        Enumeration<TreeNode> en = rootNode.depthFirstEnumeration();
        while (en.hasMoreElements()) {
            DefaultMutableTreeNode foundNode = (DefaultMutableTreeNode) en.nextElement();
            if (foundNode.getUserObject() instanceof BurpCertificate) {
                if (foundNode.getUserObject() == burpCertificate) {
                    foundNode.removeFromParent();
                }
            }
        }
    }

    /**
     * Get all certificates of the store.
     *
     * @return a List of all certificates
     */
    public List<BurpCertificate> getBurpCertificates() {
        List<BurpCertificate> certificates = new LinkedList<>();
        return certificates;
    }

    /**
     * Returns the root node of the store tree.
     *
     * @return root node
     */
    public DefaultMutableTreeNode getRootNode() {
        return rootNode;
    }

    /**
     * Get a list of all certificates which have a private key.
     *
     * @return List of certificates with a private key
     */
    public List<BurpCertificate> getBurpCertificatesWithPrivateKey() {
        List<BurpCertificate> certificatesWithPrivateKey = new LinkedList<>();
        @SuppressWarnings("unchecked")
        Enumeration<TreeNode> en = rootNode.depthFirstEnumeration();
        while (en.hasMoreElements()) {
            DefaultMutableTreeNode foundNode = (DefaultMutableTreeNode) en.nextElement();
            if (foundNode.getUserObject() instanceof BurpCertificate) {
                BurpCertificate b = (BurpCertificate) foundNode.getUserObject();
                if (b.hasPrivateKey()) {
                    certificatesWithPrivateKey.add((BurpCertificate) foundNode.getUserObject());
                }
            }
        }
        return certificatesWithPrivateKey;
    }
}
