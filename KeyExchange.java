import java.security.*;
import java.security.spec.*;
import javax.crypto.KeyAgreement;

public class KeyExchange {
	private static PrivateKey key_private;
	private static PublicKey key_public;
	private static byte[] key_secret;
	private String keyEstAlgor;		// key establish algorithm
	private String keyEstSpec;		// specific parameter for key establish algorithm
	private String integrity;		// a means for ensuring integrity of public key
	private static int ka1Length = ":ka1 ".length();
	
	/**
     * Initialize the private key and public key  
     * 
     * @param key pair generator specified parameter
     */
	public KeyExchange(String keyEstAlgor, String keyEstSpec, String integrity) throws Exception {
		this.keyEstAlgor = keyEstAlgor;
		this.keyEstSpec = keyEstSpec;
		this.integrity = integrity;
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		ECGenParameterSpec ecsp = new ECGenParameterSpec(keyEstSpec);
		
		// Initializes the key pair generator using the specified parameter set 
	    kpg.initialize(ecsp);
	    
	    // save public key and private key
	    KeyPair key_pair = kpg.generateKeyPair();
	    key_private = key_pair.getPrivate();
	    key_public = key_pair.getPublic();
	    
	    // display key pair
	    System.out.println("\n******************* KeyExchange constructor *******************");
	    System.out.println("Private key: " + key_private.toString());
	    System.out.println("Public key: " + key_public.toString());
	    System.out.println("***************************************************************\n");
	}

	/**
     * do the EDCH and construct shared secret
     * 
     * @param algorithm is the key agreement algorithm
     * @param othersPublicKey is the public key from the other side
     */
	public void doECDH(byte[] receivedPublicKey) throws Exception{
		// decoded public key
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receivedPublicKey);
		PublicKey pubKey = keyFactory.generatePublic(keySpec);
		System.out.println("Public key: " + pubKey.toString());
		
		// create a KeyAgreement object that implements the specified key agreement algorithm
		KeyAgreement ecdh = KeyAgreement.getInstance(keyEstAlgor);
		ecdh.init(key_private);
		ecdh.doPhase(pubKey, true);
		 
		// generate secret key
		byte[] oriSecret = ecdh.generateSecret();
		System.out.println("Original secret key: " + oriSecret.toString());
		System.out.println("Original secret key: " + oriSecret.length);
		
		// only keep the last 16 byte of the secret key as final result
		
		key_secret = new byte[16];
	    for(int i = 0; i < 16; i++)
	        key_secret[i]=oriSecret[oriSecret.length-16+i];
		
		System.out.println("Final secret key: " + key_secret.toString());
		System.out.println("Final secret key: " + key_secret.length);
	}
	
	/**
     * get the byte[] secret key 
     * 
     * @return the shared secret key 
     */
	public byte[] getSecret() {
		return key_secret;
	}
	
	/**
     * get byte[] base64 encode public key 
     * 
     * @return the base64 encoded string of public key 
     */
	public byte[] getEncodedPublic() {
		return key_public.getEncoded();
	}	
	
	/**
     * add byte[] of :ka1 to the base64 encode public key 
     * 
     * @param the base64 encoded string of public key
     * @return the combination of :ka1 and base64 encoded string of public key 
     */
	public byte[] addKa1(byte[] encodedPublic) {
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
	public byte[] getKa1(byte[] combined) {
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
	public byte[] splitEncodedPublic(byte[] combined) {
		byte[] split = new byte[combined.length-ka1Length];
		
		for (int i = 0; i < split.length; i++) {
			split[i] = combined[i+ka1Length];
		}
		return split;
	}
	
	/**
     * check for matching strings
     * 
     * @param two strings to be check
     * @return if matches, return TRUE; otherwise return FALSE
     */
	public boolean commandCheck(String toBeCheck, String template) {
		boolean flag = false;
		if	(toBeCheck.equals(template)) {
			flag = true;
		}
		
		return flag;
	}
	
	/**
     * check for matching byte[] and string
     * conver the toBeCheck into string first then check with  template 
     * 
     * @param byte[] and strings to be check
     * @return if matches, return TRUE; otherwise return FALSE
     */
	public boolean commandCheck(byte[] toBeCheck, String template) {
		boolean flag = false;
		
		String toBeCheck_string = new String(toBeCheck);
		if	(toBeCheck_string.equals(template)) {
			flag = true;
		}
		
		return flag;
	}
	
}
