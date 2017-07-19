package main.com.sri.core;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class ParseXmlToJSON {
    private static final String INPUT_XML = "https://outscan.outpost24.com/pub/report_test.xml";
    private static final String OUTPUT_JSON = "C:/Test/" + "test" + RandomStringUtils.randomNumeric(4) + ".json";
    private static final Logger LOGGER = Logger.getLogger("InfoLogging");

    private void convertXmlToJson() {
        try {
            URL uri = new URL(INPUT_XML);
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
            Document document = documentBuilder.parse(uri.openStream());
            parseDocument(document);
        } catch (Exception e) {
            LOGGER.error("Exception is thrown" + e.toString());
        }
    }

    @SuppressWarnings("unchecked")
    private void parseDocument(Document document) throws IOException {
        NodeList nodeList = document.getElementsByTagName("detail");

        int highRisk = 0;
        int mediumRisk = 0;
        int lowRisk = 0;
        int port = 0;
        int host = 0;

        JSONArray arrayLow = new JSONArray();
        JSONArray arrayMedium = new JSONArray();
        JSONArray arrayHigh = new JSONArray();
        JSONArray arrayPort = new JSONArray();
        JSONArray arrayHost = new JSONArray();

        for (int i = 0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);

            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element eElement = (Element) node;
                switch (eElement.getElementsByTagName("risk").item(0).getTextContent()) {
                    case "0":
                    case "1":
                        List<String> cveLow = new ArrayList<>();
                        cveLow.add(eElement.getElementsByTagName("cve").item(0).getTextContent());
                        lowRisk++;
                        arrayLow.add(cveLow);
                        break;
                    case "2":
                    case "3":
                        List<String> cveMedium = new ArrayList<>();
                        cveMedium.add(eElement.getElementsByTagName("cve").item(0).getTextContent());
                        mediumRisk++;
                        arrayMedium.add(cveMedium);
                        break;
                    case "4":
                    case "5":
                        List<String> cveHigh = new ArrayList<>();
                        cveHigh.add(eElement.getElementsByTagName("cve").item(0).getTextContent());
                        highRisk++;
                        arrayHigh.add(cveHigh);
                        break;
                    default:
                        LOGGER.info("Out of Risk Evaluation CVE : ");
                }
                List<String> hostList = new ArrayList<>();
                hostList.add(eElement.getElementsByTagName("hostname").item(0).getTextContent());
                host += getPortOrHostCount("hostname", eElement);
                arrayHost.add(hostList);

                List<String> portList = new ArrayList<>();
                portList.add(eElement.getElementsByTagName("portnumber").item(0).getTextContent());
                port += getPortOrHostCount("portnumber", eElement);
                arrayPort.add(portList);
            }

            JSONObject jsonObject = new JSONObject();
            putRiskAndCveToJSONObject(highRisk, mediumRisk, lowRisk, jsonObject, arrayLow, arrayMedium, arrayHigh);
            putPortAndHostToJSONObject(jsonObject, port, host, arrayPort, arrayHost);

            writeToJsonFile(jsonObject);
            System.out.println(jsonObject);
        }

    }

    private int getPortOrHostCount(String type, Element element) {
        if (!(element.getElementsByTagName(type).item(0).getTextContent()).isEmpty()) {
            return 1;
        }
        return 0;
    }

    private void writeToJsonFile(JSONObject jsonObject) throws IOException {
        File file = new File(OUTPUT_JSON);
        boolean wasSuccessful = file.getParentFile().mkdirs();
        if (!wasSuccessful) {
            LOGGER.info("Folder Creation Error");
        }
        if (!file.createNewFile()) {
            LOGGER.info("File Creation failed. May be the file is already present");
        }
        try (FileOutputStream s = new FileOutputStream(file, false)) {
            byte[] xyc = jsonObject.toString().getBytes();
            s.write(xyc);
            s.close();
        } catch (IOException e) {
            LOGGER.error("IO Exception" + e.toString());
        } catch (NumberFormatException en) {
            LOGGER.error(" NumberFormat Exception" + en.toString());
        }
    }

    @SuppressWarnings("unchecked")
    private void putRiskAndCveToJSONObject(int highRisk, int mediumRisk, int lowRisk, JSONObject jsonObject, JSONArray arrayLow, JSONArray arrayMedium, JSONArray arrayHigh) {
        jsonObject.put("Number of high risks", highRisk);
        jsonObject.put("List of high risk CVE", arrayHigh);

        jsonObject.put("Number of medium risks", mediumRisk);
        jsonObject.put("List of medium Risk CVE", arrayMedium);


        jsonObject.put("Number of low risks", lowRisk);
        jsonObject.put("List of low Risk CVE", arrayLow);
    }

    @SuppressWarnings("unchecked")
    private void putPortAndHostToJSONObject(JSONObject jsonObject, int port, int host, JSONArray arrayPort, JSONArray arrayHost) {
        jsonObject.put("Number of Ports open", port);
        jsonObject.put("List of Ports Open", arrayPort);

        jsonObject.put("Number of hosts", host);
        jsonObject.put("List of hosts", arrayHost);
    }

    public static void main(String[] args) {
        ParseXmlToJSON parse = new ParseXmlToJSON();
        parse.convertXmlToJson();
    }
}
