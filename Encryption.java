import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;

public class Encryption {
	private static SecretKey secretKey;
	private String algorithm;
	private static byte[] iv = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	
	/**
     * Initialize the secretKey with keyBytes
     *
     */
	public Encryption(byte[] secretBytes, String algorithm) {
		// secret key initialization with key bytes of 16 zeros
	    secretKey = new SecretKeySpec(secretBytes, "AES");
		this.algorithm = algorithm;
	}
	
	/**
     * Encrypt a string with AES algorithm.
     *
     * @param message is the plain text
     * @return the encrypted cipher text
     */
	public String encrypt(String plainText) throws Exception {
		// initialize cipher with secret key
		Cipher cipher = Cipher.getInstance(algorithm);
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
		
		// encrypt plain text
		byte[] cipherText = cipher.doFinal(plainText.getBytes());
		return Base64.getEncoder().encodeToString(cipherText);
	}
	
	/**
     * Decrypt a string with AES algorithm.
     *
     * @param message is the cipher text
     * @return the decrypted plain text
     */
	public String decrypt(String cipherText) throws Exception {
		// initialize cipher with secret key
		Cipher cipher = Cipher.getInstance(algorithm);
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);

		// decrypt cipher text
		byte[] decoder  = Base64.getDecoder().decode(cipherText);
		byte[] plainText = cipher.doFinal(decoder);
		String str = new String(plainText, "UTF-8");
		
		return str;
	}
}
