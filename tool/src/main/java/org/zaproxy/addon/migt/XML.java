package org.zaproxy.addon.migt;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/** Class used to parse and edit xml strings */
public class XML {

    /**
     * Given an xml string, returns the corresponding Document object
     *
     * @param input the xml string
     * @return the Document object
     * @throws ParserConfigurationException if something goes wrong
     * @throws IOException if something goes wrong
     * @throws SAXException if something goes wrong
     */
    public static Document documentFromString(String input)
            throws ParserConfigurationException, IOException, SAXException {
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
        Document doc = docBuilder.parse(new InputSource(new StringReader(input)));
        return doc;
    }

    /**
     * Given a Document object, get the string
     *
     * @param doc the Document object
     * @return the xml string
     */
    public static String stringFromDocument(Document doc) {
        // https://stackoverflow.com/questions/2567416/xml-document-to-string
        try {
            StringWriter sw = new StringWriter();
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

            transformer.transform(new DOMSource(doc), new StreamResult(sw));
            return sw.toString();
        } catch (Exception ex) {
            throw new RuntimeException("Error converting to String", ex);
        }
    }

    /**
     * This function edits the given tag attribute from an xml string into a new value, and returns
     * the xml string
     *
     * @param input the xml string
     * @param tag the tag of the attribute
     * @param attribute the attribute to be edited
     * @param newValue the new value of the attribute
     * @param occurency tells the index of the matched occurency to do the thing on, set it to -1 to
     *     do for all occurencies
     * @return the edited xml
     */
    public static String editTagAttributes(
            String input, String tag, String attribute, String newValue, Integer occurency)
            throws ParsingException {
        try {
            Document doc = documentFromString(input);

            NodeList matched = doc.getElementsByTagName(tag);

            if (occurency != -1) {
                matched.item(occurency)
                        .getAttributes()
                        .getNamedItem(attribute)
                        .setTextContent(newValue);
            } else {
                for (int i = 0; i < matched.getLength(); i++) {
                    Node act_node = matched.item(i);
                    act_node.getAttributes().getNamedItem(attribute).setTextContent(newValue);
                }
            }

            return stringFromDocument(doc);

        } catch (ParserConfigurationException | IOException | SAXException pce) {
            pce.printStackTrace();
            return "";
        } catch (NullPointerException ne) {
            throw new ParsingException("invalid occurency");
        }
    }

    /**
     * This function edits the given tag value from an xml string into a new value and returns the
     * edited xml string
     *
     * @param input the xml string
     * @param tag the tag to be edited
     * @param newValue the new value of the tag
     * @param occurency tells the index of the matched occurency to do the thing on, set it to -1 to
     *     do for all occurencies
     * @return the edited xml
     */
    public static String editTagValue(String input, String tag, String newValue, Integer occurency)
            throws ParsingException {
        try {
            Document doc = documentFromString(input);

            NodeList matched = doc.getElementsByTagName(tag);

            if (occurency != -1) {
                matched.item(occurency).setTextContent(newValue);
            } else {
                for (int i = 0; i < matched.getLength(); i++) {
                    Node act_node = matched.item(i);
                    act_node.setTextContent(newValue);
                }
            }

            return stringFromDocument(doc);

        } catch (ParserConfigurationException | IOException | SAXException pce) {
            pce.printStackTrace();
            return "";
        } catch (NullPointerException ne) {
            throw new ParsingException("invalid occurency");
        }
    }

    /**
     * This function removes a tag from an xml string
     *
     * @param input the input xml string
     * @param tag the tag to be removed
     * @param occurency tells the index of the matched occurency to do the thing on, set it to -1 to
     *     do for all occurencies
     * @return the xml result
     */
    public static String removeTag(String input, String tag, Integer occurency)
            throws ParsingException {
        try {
            Document doc = documentFromString(input);

            NodeList matched = doc.getElementsByTagName(tag);

            if (occurency != -1) {
                matched.item(occurency).getParentNode().removeChild(matched.item(occurency));
            } else {
                for (int i = 0; i < matched.getLength(); i++) {
                    Node act_node = matched.item(i);
                    act_node.getParentNode().removeChild(act_node);
                }
            }

            return stringFromDocument(doc);

        } catch (ParserConfigurationException | IOException | SAXException pce) {
            pce.printStackTrace();
            return "";
        } catch (NullPointerException ne) {
            throw new ParsingException("invalid occurency");
        }
    }

    /**
     * This function removes a tag's attribute from an xml string
     *
     * @param input the xml string
     * @param tag the tag in which contains the attribute
     * @param attribute the attribute to be removed
     * @param occurency tells the index of the matched occurency to do the thing on, set it to -1 to
     *     do for all occurencies
     * @return the edited xml string
     */
    public static String removeTagAttribute(
            String input, String tag, String attribute, Integer occurency) throws ParsingException {
        try {
            Document doc = documentFromString(input);

            NodeList matched = doc.getElementsByTagName(tag);

            if (occurency != -1) {
                matched.item(occurency).getAttributes().removeNamedItem(attribute);
            } else {
                for (int i = 0; i < matched.getLength(); i++) {
                    Node act_node = matched.item(i);
                    act_node.getAttributes().removeNamedItem(attribute);
                }
            }

            return stringFromDocument(doc);

        } catch (ParserConfigurationException | IOException | SAXException pce) {
            pce.printStackTrace();
            return "";
        } catch (NullPointerException ne) {
            throw new ParsingException("invalid occurency");
        }
    }

    /**
     * This function adds an attribute in a tag from an xml string
     *
     * @param input the xml string
     * @param tag the tag to add the attribute
     * @param attribute the attribute name to be added
     * @param value the attribute value to be added
     * @param occurrency tells the index of the matched occurency to do the thing on, set it to -1
     *     to do for all occurencies
     * @return the edited xml string
     */
    public static String addTagAttribute(
            String input, String tag, String attribute, String value, Integer occurrency)
            throws ParsingException {
        try {
            Document doc = documentFromString(input);

            NodeList matched = doc.getElementsByTagName(tag);

            if (occurrency != -1) {
                Node new_param = doc.createAttribute(attribute);
                new_param.setTextContent(value);
                matched.item(occurrency).getAttributes().setNamedItem(new_param);
            } else {
                for (int i = 0; i < matched.getLength(); i++) {
                    Node act_node = matched.item(i);
                    Node new_param = doc.createAttribute(attribute);
                    new_param.setTextContent(value);
                    act_node.getAttributes().setNamedItem(new_param);
                }
            }

            return stringFromDocument(doc);

        } catch (ParserConfigurationException | IOException | SAXException pce) {
            pce.printStackTrace();
            return "";
        } catch (NullPointerException ne) {
            throw new ParsingException("invalid occurency");
        }
    }

    /**
     * This function adds a tag specifing it's parent
     *
     * @param input the xml string
     * @param parent the parent tag to add the new tag as a child
     * @param tag the new tag name
     * @param value the new tag value
     * @param occurency tells the index of the matched occurency to do the thing on, set it to -1 to
     *     do for all occurencies
     * @return the edited xml string
     */
    public static String addTag(
            String input, String parent, String tag, String value, Integer occurency)
            throws ParsingException {
        try {
            Document doc = documentFromString(input);

            NodeList matched = doc.getElementsByTagName(parent);

            Node new_tag = doc.createElement(tag);
            new_tag.setTextContent(value);

            if (occurency != -1) {

                matched.item(occurency).appendChild(new_tag);
            } else {
                for (int i = 0; i < matched.getLength(); i++) {
                    Node act_node = matched.item(i);
                    act_node.appendChild(new_tag);
                }
            }

            return stringFromDocument(doc);

        } catch (ParserConfigurationException | IOException | SAXException pce) {
            pce.printStackTrace();
            return "";
        } catch (NullPointerException ne) {
            throw new ParsingException("invalid occurency");
        }
    }

    /**
     * This function returns a value of a given tag's attribute
     *
     * @param input the input xml string
     * @param tag the tag containing the attribute
     * @param attribute the attribute
     * @param occurency tells the index of the matched occurency to do the thing on, set it to -1 to
     *     do for all occurencies
     * @return the attribute value
     */
    public static String getTagAttributeValue(
            String input, String tag, String attribute, Integer occurency) throws ParsingException {
        try {
            Document doc = documentFromString(input);
            Node matched = null;
            if (occurency != -1) {
                matched = doc.getElementsByTagName(tag).item(occurency);
            } else {
                matched = doc.getElementsByTagName(tag).item(0);
            }

            return matched.getAttributes().getNamedItem(attribute).getTextContent();

        } catch (ParserConfigurationException | IOException | SAXException pce) {
            pce.printStackTrace();
            return "";
        } catch (NullPointerException ne) {
            throw new ParsingException("invalid occurency");
        }
    }

    /**
     * This fucntion returns the value of a given tag
     *
     * @param input the input xml string
     * @param tag the tag name
     * @param occurency tells the index of the matched occurency to do the thing on, set it to -1 to
     *     do for all occurencies
     * @return the tag value
     */
    public static String getTagValaue(String input, String tag, Integer occurency)
            throws ParsingException {
        try {
            Document doc = documentFromString(input);
            Node matched = null;

            if (occurency != -1) {
                matched = doc.getElementsByTagName(tag).item(occurency);
            } else {
                matched = doc.getElementsByTagName(tag).item(0);
            }

            return matched.getTextContent();

        } catch (ParserConfigurationException | IOException | SAXException pce) {
            pce.printStackTrace();
            return "";
        } catch (NullPointerException ne) {
            throw new ParsingException("invalid occurency");
        }
    }
}
