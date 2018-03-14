import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;


public class newEncryption {

    private static String transformation = "aes/gcm/nopadding";
    private static String algorithm = "AES";
    private static byte[] keyBytes = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    private static SecretKeySpec secretKeySpec;
    private static GCMParameterSpec gcmParameterSpec;

    public static void main (String[] args) throws NoSuchAlgorithmException {
    	try {

            secretKeySpec = new SecretKeySpec(keyBytes, algorithm);
            gcmParameterSpec = new GCMParameterSpec(128, keyBytes);

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("ERROR : initializing encryption box");
        }
    		
    		String message = "I need to be encrypted";
		System.out.println("Original text: " + message);
		
		String cipherText = encrypt(message);
		System.out.println("After encryption: " + cipherText);	
		System.out.println("After decryption: " + decrypt(cipherText));
		
	}

    public newEncryption(byte[] keyBytes) {
        try {

            this.keyBytes = keyBytes;
            this.secretKeySpec = new SecretKeySpec(keyBytes, algorithm);
            this.gcmParameterSpec = new GCMParameterSpec(128, keyBytes);

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("ERROR : initializing encryption box");
        }

    }

    public static String encrypt(String message) {

        try {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
            byte[] ciphertext = cipher.doFinal(message.getBytes());

            return Base64.getEncoder().encodeToString(ciphertext);

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("ERROR : encrypting message");
            return "";
        }
    }

    public static String decrypt(String message) {

        try {

            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
            byte[] decoded  = Base64.getDecoder().decode(message);
            byte[] plaintext = cipher.doFinal(decoded);

            return new String(plaintext, "UTF-8");

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("ERROR : decrypting message");
            return "";
        }
    }
}