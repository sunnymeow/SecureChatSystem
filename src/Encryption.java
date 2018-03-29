import javax.crypto.*;
import javax.crypto.spec.*;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Encryption {
	private IvParameterSpec ivspec;			// used for AES/CBC
	private byte[] iv = new byte[16];		// used for AES/CBC
	
	private GCMParameterSpec gcmspec;		// used for AES/GCM
	private final int TAG = 128;				// used for AES/GCM
	
	private SecretKeySpec secretKeySpec;		// used for AES/CBC and AES/GCM
	private String algorithm;				// used for AES/CBC and AES/GCM
	private byte[] secretBytes;				// used for AES/CBC and AES/GCM
	
	/**
     * Initialize the secretKey with keyBytes
     *
     */
	public Encryption(byte[] secretBytes, String algorithm) throws ErrorException {
		try {
			// different key specs initialization with secretBytes 
			this.algorithm = algorithm;
			this.secretBytes = secretBytes;
		    secretKeySpec = new SecretKeySpec(secretBytes, "AES");	
			ivspec = new IvParameterSpec(iv);				// used for AES/CBC
			gcmspec = new GCMParameterSpec(TAG,secretBytes);	// used for AES/GCM
			
			System.out.println("PHASE 4   shared secret key: " + secretKeySpec);
		} catch (Exception e) {
			throw new ErrorException(":err FAILED TO CREATE AN ENCRYPTION OBJECT!");
		}
	}
	
	/**
     * Encrypt a string with AES/GCM mode
     *
     * @param message is the plain text
     * @return the encrypted cipher text
     */
	public String encrypt(String plainText) throws ErrorException {		
		try {
			// initialize cipher with secret key
			Cipher cipher = Cipher.getInstance(algorithm);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmspec);
			
			// encrypt plain text
			byte[] cipherText = cipher.doFinal(plainText.getBytes());
			return Base64.getEncoder().encodeToString(cipherText);
			
		} catch (AEADBadTagException e) {
			throw new ErrorException(":err MESSAGE INTEGRITY CHECK IN ENCRYPTION FAILED!\n");
		} catch (Exception e) {
			throw new ErrorException(":err ENCRYPTION USING " + algorithm + " FAILED!\n");
		}
	}
	
	/**
     * Decrypt a string with AES/GCM mode
     *
     * @param message is the cipher text
     * @return the decrypted plain text
     */
	public String decrypt(String cipherText) throws ErrorException{
		try {
			// initialize cipher with secret key
			Cipher cipher = Cipher.getInstance(algorithm);
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmspec);
		
			// decrypt cipher text
			byte[] decoder  = Base64.getDecoder().decode(cipherText);
			byte[] plainText = cipher.doFinal(decoder);
			return new String(plainText, "UTF-8");	
			
		} catch (AEADBadTagException e) {
			throw new ErrorException(":err MESSAGE INTEGRITY CHECK IN DECRYPTION FAILED!\n");
		} catch (Exception e) {
			throw new ErrorException(":err DECRYPTION USING " + algorithm + " FAILED!\n");
		}
	}
	
	/**
     * Encrypt a string with AES/CBC mode
     *
     * @param message is the plain text
     * @return the encrypted cipher text
     */
	public String CBCencrypt(String plainText) throws ErrorException {
		try {
			// initialize cipher with secret key
			Cipher cipher = Cipher.getInstance(algorithm);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivspec);
			
			// encrypt plain text
			byte[] cipherText = cipher.doFinal(plainText.getBytes());
			return Base64.getEncoder().encodeToString(cipherText);
			
		} catch (AEADBadTagException e) {
			throw new ErrorException(":err MESSAGE INTEGRITY CHECK IN ENCRYPTION FAILED!\n");
		} catch (Exception e) {
			throw new ErrorException(":err ENCRYPTION USING " + algorithm + " FAILED!\n");
		}
	}
		
	
	/**
     * Decrypt a string with AES/CBC mode
     *
     * @param message is the cipher text
     * @return the decrypted plain text
     */
	public String CBCdecrypt(String cipherText) throws ErrorException{
		try {
			// initialize cipher with secret key
			Cipher cipher = Cipher.getInstance(algorithm);
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec);
		
			// decrypt cipher text
			byte[] decoder  = Base64.getDecoder().decode(cipherText);
			byte[] plainText = cipher.doFinal(decoder);
			return new String(plainText, "UTF-8");	
			
		} catch (AEADBadTagException e) {
			throw new ErrorException(":err MESSAGE INTEGRITY CHECK IN DECRYPTION FAILED!\n");
		} catch (Exception e) {
			throw new ErrorException(":err DECRYPTION USING " + algorithm + " FAILED!\n");
		}
	}
}
