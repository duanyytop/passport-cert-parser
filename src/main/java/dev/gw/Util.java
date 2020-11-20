package dev.gw;

public class Util {

	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] b = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        b[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character
	                .digit(s.charAt(i + 1), 16));
	    }
	    return b;
	}
	
	 public static String bytesToHexString(byte[] bArray) {
		  StringBuilder sb = new StringBuilder(bArray.length);
		  String sTemp;
		 for (byte b : bArray) {
			 sTemp = Integer.toHexString(0xFF & b);
			 if (sTemp.length() < 2)
				 sb.append(0);
			 sb.append(sTemp.toUpperCase());
		 }
		  return sb.toString();
	 }
}
