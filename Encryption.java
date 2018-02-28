import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

public class Encryption {
	private static SecretKeySpec secretKey;
	private static String algorithm = "AES";
	private static byte[] keyBytes = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	private static byte[] iv = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	
	/**
     * Initialize the secretKey with keyBytes
     *
     */
	public Encryption () {
		// secret key initialization with key bytes of 16 zeros
	    secretKey = new SecretKeySpec(keyBytes, algorithm);
	}
	
	/**
     * Encrypt a string with AES algorithm.
     *
     * @param message is a string
     * @return the encrypted string
     */
	public String encrypt(String message) throws Exception {
		// initialize cipher with secret key
		Cipher cipher = Cipher.getInstance(algorithm+"/CBC/PKCS5Padding");
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
		
		// encrypt plain text
		byte[] cipherText = cipher.doFinal(message.getBytes());
		
		return Base64.getEncoder().encodeToString(cipherText);
	}
	
	/**
     * Decrypt a string with AES algorithm.
     *
     * @param message is a string
     * @return the decrypted string
     */
	public String decrypt(String message) throws Exception {
		// initialize cipher with secret key
		Cipher cipher = Cipher.getInstance(algorithm+"/CBC/PKCS5Padding");
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
		
		// decrypt cipher text
		byte[] decoder  = Base64.getDecoder().decode(message);
		byte[] plainText = cipher.doFinal(decoder);
		String str = new String(plainText, "UTF-8");
		
		return str;
	}
	

	

}
