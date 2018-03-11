import java.nio.*;

public class Help {
	private static int ka1Length = ":ka1 ".length();

	/**
     * check for matching strings
     * 
     * @param two strings to be check
     * @return if matches, return TRUE; otherwise return FALSE
     */
	public static void commandEqual(String toBeCheck, String template) throws ErrorException{
		if	(toBeCheck.equals(template)) {}
		else {
			throw new ErrorException(":fail COMMAND " + template + " NOT FOUND!\n");
		}
	}
	
	/**
     * check for matching byte[] and string
     * conver the toBeCheck into string first then check with  template 
     * 
     * @param byte[] and strings to be check
     * @return if matches, return TRUE; otherwise return FALSE
     */
	public static void commandEqual(byte[] toBeCheck, String template) throws ErrorException{
		String toBeCheck_string = new String(toBeCheck);
		if	(toBeCheck_string.equals(template)) {}
		else {
			throw new ErrorException(":fail COMMAND " + template + " NOT FOUND!\n");
		}
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
			throw new ErrorException(":fail " + serverCipher + "is NOT FOUND in client's ciphersuite!\n");
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
     * add byte[] of :ka1 to the base64 encode public key 
     * 
     * @param the base64 encoded string of public key
     * @return the combination of :ka1 and base64 encoded string of public key 
     */
	public static byte[] addKa1(byte[] encodedPublic) {
		byte[] ka1 = ":ka1 ".getBytes();
		byte[] combined = new byte[ka1Length + encodedPublic.length];

		for (int i = 0; i < combined.length; i++) {
		    combined[i] = i < ka1Length ? ka1[i] : encodedPublic[i - ka1Length];
		}
		return combined;
	}
	
	/**
     * get the byte[] of :ka1 
     * 
     * @param the combination of :ka1 and base64 encoded string of public key 
     * @return the byte[] of :ka1  
     */
	public static byte[] getKa1(byte[] combined) {
		byte[] ka1new = new byte[ka1Length];
		
		for (int i = 0; i < ka1Length; i++) {
			ka1new[i] = combined[i];
		}
		return ka1new;
	}
	
	/**
     * get byte[] of base64 encoded string of public key
     * 
     * @param the combination of :ka1 and base64 encoded string of public key 
     * @return byte[] of base64 encoded string of public key 
     */
	public static byte[] splitEncodedPublic(byte[] combined) {
		byte[] split = new byte[combined.length-ka1Length];
		
		for (int i = 0; i < split.length; i++) {
			split[i] = combined[i+ka1Length];
		}
		return split;
	}
	
	/**
     * display greeting message
     */
	public static void greeting() {
		System.out.println("************** Welcome to the Chat Hub! **************");
		System.out.println("*  - Type receiver's alias: message you want to send *");
		System.out.println("*  - Example: Type the following to talk to Alice    *");
		System.out.println("*  - Example: Alice: Hi How are you? (press enter)   *");
		System.out.println("*  - When finish, enter \"exit\" to exit the chat      *");
		System.out.println("******************************************************");
	}
	
	/**
     * display ending message
     */
	public static void ending() {
		System.out.println("\n************ Thanks for chatting! ************\n");
	}
	
}
