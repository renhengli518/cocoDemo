package com.codyy.coco.utils;

import java.io.IOException;
import java.io.StringReader;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.codyy.coco.dto.Message;

public class XMLAndStringUtil {

	/**
	 * XML字符串转XML对象
	 * @param xmlString
	 * @return
	 */
	public static Document stringToXML(String xmlString){
		System.out.println("xml string to xml object ===" + xmlString);
		if (xmlString == null) {
			return (null);
		}
		try {
			StringReader sr = new StringReader(xmlString.trim());
			InputSource is = new InputSource(sr);
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder=factory.newDocumentBuilder();
			Document doc = builder.parse(is);
			return doc;
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null; 
	}
	
	/**
	 * xml字符串转javabean对象
	 * @param xmlString
	 * @return
	 */
	public static Message stringXMLToJavaBean(String xmlString){
		System.out.println("receive message ==="+xmlString);
		Document doc = stringToXML(xmlString);
		Element root = doc.getDocumentElement();
		Message msg = new Message();
		msg.setType(root.getAttribute("type"));
		msg.setFrom(root.getAttribute("from"));
		msg.setTo(root.getAttribute("to"));
		msg.setGid(root.getAttribute("gid"));
		msg.setEnterpriseId(root.getAttribute("enterpriseId"));
		msg.setServerType(root.getAttribute("serverType"));
		msg.setLicense(root.getAttribute("license"));
		msg.setCipher(root.getAttribute("cipher"));
		msg.setRemainSeconds(root.getAttribute("remainSeconds"));
		msg.setSay(root.getAttribute("say"));
		msg.setResult(root.getAttribute("result"));
		msg.setLife(root.getAttribute("life"));
		
		msg.setSendNick(root.getAttribute("send_nick"));
		msg.setGroup(root.getAttribute("group"));
		return msg;
	}
}
