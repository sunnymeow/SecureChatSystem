import java.io.*;
import java.security.*;
import java.security.cert.*;

public class Help {

	/**
     * check for matching strings
     * 
     * @param two strings to be check
     */
	public static void commandEqual(String toBeCheck, String template) throws ErrorException{
		if	(!toBeCheck.equals(template)) 
			throw new ErrorException(":fail COMMAND " + template + " NOT FOUND!\n");
	}
	
	/**
     * check for matching byte[] and string
     * conver the toBeCheck into string first then check with  template 
     * 
     * @param byte[] and strings to be check
     */
	public static void commandEqual(byte[] toBeCheck, String template) throws ErrorException{
		String toBeCheck_string = new String(toBeCheck);
		if	(!toBeCheck_string.equals(template)) 
			throw new ErrorException(":fail COMMAND " + template + " NOT FOUND!\n");
	}
	
	/**
     * get the command string before the " "
     * 
     * @param wholeString including command and message
     * @return the string before " "
     */
	public static String getCommand(String wholeString) {
		String[] split = wholeString.split(" ");
		return split[0];
	}
	
	/**
     * look for serverCipher within receivedCipher
     * if serverCipher not found, throw ErrorException
     * 
     * @param serverCipher and receivedCipher
	 * @throws ErrorException 
     */
	public static void findCipherSuite(String serverCipher, String receivedCipher) throws ErrorException {
		String[] clientCipher = receivedCipher.split("//");
		boolean found = false;
		
		for (int i = 0; i < clientCipher.length; i++) {
			if (clientCipher[i].equals(serverCipher)) {
				found = true;
			}
		}
		
		if (found == false) {
			throw new ErrorException(":fail " + serverCipher + "IS NOT FOUND IN CLIENT'S CIPHERSUITE!\n");
		}
	}
	
	/**
     * get the cipher suite after the " "
     * 
     * @param wholeString including command and message
     * @return the string after " "
     */
	public static String getCipherSuite(String wholeString) {
		String[] split = wholeString.split(" ");
		return split[1];
	}
	
	/**
     * attach command to the base64 encode public key 
     * 
     * @param command need to be attached
     * @param the base64 encoded string of public key
     * @return the combination of command and base64 encoded string of public key 
     */
	public static byte[] addCommand(String command, byte[] encoded) {
		byte[] command_byte = command.getBytes();
		int command_length = command.length();
		byte[] combined = new byte[command_length + encoded.length];

		for (int i = 0; i < combined.length; i++) {
		    combined[i] = i < command_length ? command_byte[i] : encoded[i - command_length];
		}
		return combined;
	}
	
	/**
     * get the byte[] of command
     * 
     * @param command need to be returned
     * @param the combination of command and base64 encoded string of public key 
     * @return the byte[] of command 
     */
	public static byte[] getCommand(String command, byte[] combined) {
		int command_length = command.length();
		byte[] command_byte = new byte[command_length];
		
		for (int i = 0; i < command_length; i++) {
			command_byte[i] = combined[i];
		}
		return command_byte;
	}
	
	/**
     * get byte[] of base64 encoded string that's preceded by command
     * 
     * @param combined is the byte[] of combination of command and base64 encoded string
     * @param command is the command need to be split out
     * @return byte[] of base64 encoded string that attached to the command
     */
	public static byte[] splitCommand(String command, byte[] combined ) {
		int command_length = command.length();
		byte[] split = new byte[combined.length-command_length];
		
		for (int i = 0; i < split.length; i++) {
			split[i] = combined[i+command_length];
		}
		return split;
	}
	
	/**
     * display greeting message
     */
	public static void greeting(String alias) {
		System.out.println("*******************************************************************************");
		System.out.println("\t\tHi " + alias + "! Welcome to the Chat Hub! ");
		System.out.println("\t1. Type \"To alias: message\" to send message (LETTERCASE OF ALIAS MATTERS!)");
		System.out.println("\t   - Exp: To bob: Hi How are you? (message will be sent to alice)  ");
		System.out.println("\t2. Type \"To all: message\" to talk to all (LETTERCASE OF ALL DOES NOT MATTER)");
		System.out.println("\t   - Exp: To all: Hi How are you? (message will be sent to everyone in the chat hub) ");
		System.out.println("\t3. When finish chatting, enter \"exit\" to exit the chat hub    ");
		System.out.println("*******************************************************************************");
	}
	
	/**
     * display ending message
     */
	public static void ending(String alias) {
		System.out.println("\n************ Bye " + alias + "! Thanks for chatting! ************\n");
	}
	
	
	/**
     * linked keystore with corresponding keystoreFileName and password
     * @param the name of keystore file and password for the keystore
     */
	public static KeyStore linkKeyStore(String keystoreFileName, String password) {
	    char[] pw = password.toCharArray();
	    KeyStore keystore = null;
	    
	    try {
		    FileInputStream fIn = new FileInputStream(keystoreFileName);
		    keystore = KeyStore.getInstance("JKS");
		    keystore.load(fIn, pw);
	    } catch (Exception e) {
	    		System.err.println(":fail KEYSTORE " + keystoreFileName + " FAILED TO LINK TO CHAT HUB SOCKET!\n");
	    }
	    return keystore;
	}
	
	/**
     * get the based64 encoded byte[] certificate
     * @param the keystore and alias for the certificate
     */
	public static byte[] getCert(KeyStore ks, String alias) {
		byte[] cert = null;
		try {
			cert = ks.getCertificate(alias).getEncoded();
		} catch (Exception fail) {
			System.err.println(":fail GET CERTIFICATE FOR ALIAS " + alias + " FAILED!\n");
		}
		return cert;
	}
	
	/**
     * verify certificate with public key
     * 
     * @param two certificates to be verified
     * @return if matches, return TRUE; otherwise return FALSE
     */
	public static void certVerify(KeyStore ks, String alias, byte[] received, String integrity) {
		try {
			// recover received certificate from byte[]
			CertificateFactory certFactory = CertificateFactory.getInstance(integrity);
			ByteArrayInputStream in = new ByteArrayInputStream(received);			
			X509Certificate receivedCert = (X509Certificate)certFactory.generateCertificate(in);
			
			// verify received certificate with keystore certificate
			ks.getCertificate(alias).verify(receivedCert.getPublicKey());

		} catch (KeyStoreException fail) {
			System.err.println(":fail GET CERTIFICATE FOR ALIAS " + alias + " FAILED!\n");
		} catch (Exception fail)	{
			System.err.println(":fail CERTIFICATES VERIFICATION FOR ALIAS " + alias + " FAILED!\n");
		}
	}
	
	
	/**
     * find the alias name for certByte in ks
     * 
     * @param ks is keystore that stores all certificate
     * @param certByte is the based64 encoded byte[] of certificate
     * @return alias of the certByte
     */
	public static String getAlias(KeyStore ks, byte[] certByte, String integrity) {
		String alias = null;
		try {	
			// recover received certificate from byte[]
			CertificateFactory certFactory = CertificateFactory.getInstance(integrity);
			ByteArrayInputStream in = new ByteArrayInputStream(certByte);			
			X509Certificate receivedCert = (X509Certificate)certFactory.generateCertificate(in);
			
			// get alias from the certificate within keystore
			alias = ks.getCertificateAlias(receivedCert);
		} catch (Exception fail) {
			System.err.println(":fail CERTIFICATES IS NOT FOUND IN CHATHUB'S KEYSTORE!\n");
		}
		return alias;
	}
	
	
}
