package org.owasp.psafix.top10.vulnerable;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.*;
import java.io.IOException;

/**
 *
 */
public class A1XPath {
    private boolean doLogin(String userName, char[] password)
            throws ParserConfigurationException, SAXException, IOException, XPathExpressionException {

        DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
        domFactory.setNamespaceAware(true);
        DocumentBuilder builder = domFactory.newDocumentBuilder();
        Document doc = builder.parse("users.xml");
        String pwd = hashPassword( password);

        XPathFactory factory = XPathFactory.newInstance();
        XPath xpath = factory.newXPath();
        XPathExpression expr = xpath.compile("//users/user[username/text()='" +
                userName + "' and password/text()='" + pwd + "' ]");
        Object result = expr.evaluate(doc, XPathConstants.NODESET);
        NodeList nodes = (NodeList) result;

        // Print first names to the console
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i).getChildNodes().item(1).getChildNodes().item(0);
            System.out.println( "Authenticated: " + node.getNodeValue());
        }

        return (nodes.getLength() >= 1);
    }

    private String hashPassword(char[] password) {
        return "";
    }
}
