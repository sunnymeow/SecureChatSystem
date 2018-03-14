import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class GCMtest {
	private static SecretKeySpec secretKeySpec;
	private static GCMParameterSpec gcmspec;
	private static String algorithm;
	private static byte[] secretBytes;
	private static final int TAG = 128;

	
	public static void main (String[] args) throws NoSuchAlgorithmException {
		algorithm = "AES_128/GCM/NoPadding";
		secretBytes = new byte[16];
		secretKeySpec = new SecretKeySpec(secretBytes, "AES");	
		gcmspec = new GCMParameterSpec(TAG,secretBytes);	// used for AES/GCM

        
		String message = "I need to be encrypted";
		System.out.println("Original text: " + message);
		
		String cipherText = GCMencrypt(message);
		System.out.println("After encryption: " + cipherText);	
		System.out.println("After decryption: " + GCMdecrypt(cipherText));
		
	}
	

	/**
     * Encrypt a string with AES_128/GCM/NoPadding algorithm.
     *
     * @param message is the plain text
     * @return the encrypted cipher text
     */
	public static String GCMencrypt(String plainText) {		
		try {
			// initialize cipher with secret key
			Cipher cipher = Cipher.getInstance(algorithm);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmspec);
			
			// encrypt plain text
			byte[] cipherText = cipher.doFinal(plainText.getBytes());
			return Base64.getEncoder().encodeToString(cipherText);
		} catch (Exception e) {
			System.err.println(":err ENCRYPTION FAILED!\n");
			return null;
		}
	}
	
	/**
     * Decrypt a string with AES_128/GCM/NoPadding algorithm.
     *
     * @param message is the cipher text
     * @return the decrypted plain text
     */
	public static String GCMdecrypt(String cipherText) {
		try {
			// initialize cipher with secret key
			Cipher cipher = Cipher.getInstance(algorithm);
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmspec);
		
			// decrypt cipher text
			byte[] decoder  = Base64.getDecoder().decode(cipherText);
			byte[] plainText = cipher.doFinal(decoder);
			String str = new String(plainText, "UTF-8");
			
			return str;
		} catch (Exception err) {
			System.err.println(":err DECRYPTION FAILED!\n");
			return null;
		} 
	}
}
