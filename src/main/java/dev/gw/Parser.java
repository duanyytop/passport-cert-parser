package dev.gw;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Certificate;

import java.io.*;
import java.util.*;

import static dev.gw.Config.CRL_FILE_NAME;
import static dev.gw.Config.MASTER_LIST_FILE_NAME;

public class Parser {

	public static void analysisMasterList() throws Exception {
		String startFlag = "CscaMasterListData::";
		String projectPath = System.getProperty("user.dir");
		String readPath = projectPath + "/docs/ldif/" + MASTER_LIST_FILE_NAME;
		String writePath = projectPath + "/docs/cert/master-list/";
		String cerString = "";
		StringBuilder sb = new StringBuilder();

		BufferedReader br = new BufferedReader(new FileReader(new File(readPath)));
		String line;
		while((line=br.readLine()) != null) {

			if(line.contains(startFlag)) {
				sb.append(line.substring(startFlag.length())); 
				while(true) {
					line = br.readLine();
					if (null == line || line.startsWith("dn:")) {
						break;
					} else {
						sb.append(line); 
					}
				}
				cerString = sb.toString();
				sb.delete(0, sb.length());
				
				byte[] certBytes = Base64.getDecoder().decode(cerString.replaceAll("\\s*", ""));
				ByteArrayInputStream bIn = new ByteArrayInputStream(certBytes);
				ASN1InputStream aIn = new ASN1InputStream(bIn);
				ASN1Primitive aP = aIn.readObject();
				ASN1Sequence aS = ASN1Sequence.getInstance(aP);
                ASN1TaggedObject aT = ASN1TaggedObject.getInstance(aS.getObjectAt(1));
                aP = ASN1Sequence.getInstance(aT.getObject().toASN1Primitive()).getObjectAt(2).toASN1Primitive();
                aS = ASN1Sequence.getInstance(aP);
                aT = ASN1TaggedObject.getInstance(aS.getObjectAt(1));
                DEROctetString derOS = (DEROctetString)(aT.getObject());

                bIn = new ByteArrayInputStream(Util.hexStringToByteArray(derOS.toString().substring(1)));
                aIn = new ASN1InputStream(bIn);
                while((aP = aIn.readObject()) != null) {
                	 ASN1Sequence asn1 = ASN1Sequence.getInstance(aP);
                     if (asn1 == null || asn1.size() == 0) {
                         throw new IllegalArgumentException("null or empty sequence passed.");
                     }
                     if (asn1.size() != 2) {
                         throw new IllegalArgumentException("Incorrect sequence size: " + asn1.size());
                     }
                     ASN1Set certSet = ASN1Set.getInstance(asn1.getObjectAt(1));
                     
                     for (int i = 0; i < certSet.size(); i++) {
						 Certificate certificate = Certificate.getInstance(certSet.getObjectAt(i));
						 System.out.println("Algorithm: " + certificate.getIssuer().toString());
						 String serialNumber = Util.bytesToHexString(certificate.getSerialNumber().getEncoded());
						 FileOutputStream fos = new FileOutputStream(new File(writePath + serialNumber + ".cer"));
						 fos.write(certificate.getEncoded());
						 fos.flush();
						 fos.close();
                     }
                }
                aIn.close();
			}
		}
		br.close();
	}


	public static void analysisCrl() throws Exception {
		String startFlag = "userCertificate;binary::";
		String projectPath = System.getProperty("user.dir");
		String crlReadPath = projectPath + "/docs/ldif/" + CRL_FILE_NAME;
		String crlWritePath = projectPath + "/docs/cert/crl/";
		String cerString = "";
		StringBuilder sb = new StringBuilder();

		BufferedReader br = new BufferedReader(new FileReader(new File(crlReadPath)));
		String line;
		while((line=br.readLine()) != null) {
			if(line.contains(startFlag)) {
				sb.append(line.substring(startFlag.length()));
				while(true) {
					line = br.readLine();
					if (line.startsWith("sn:")) {
						break;
					} else {
						sb.append(line);
					}
				}
				cerString = sb.toString();
				sb.delete(0, sb.length());

				byte[] certBytes = Base64.getDecoder().decode(cerString.replaceAll("\\s*", ""));
				ByteArrayInputStream bIn = new ByteArrayInputStream(certBytes);
				ASN1InputStream aIn = new ASN1InputStream(bIn);
				ASN1Sequence seq = (ASN1Sequence)aIn.readObject();
				Certificate certificate = Certificate.getInstance(seq);

				String sn = Util.bytesToHexString(certificate.getSerialNumber().getEncoded());
				FileOutputStream fos = new FileOutputStream(new File(crlWritePath + sn + ".cer"));
				fos.write(certBytes);
				fos.flush();
				fos.close();
			}
		}
		br.close();
	}
	
}

