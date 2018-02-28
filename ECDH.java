//import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.KeyAgreement;


// http://www.java2s.com/Tutorial/Java/0490__Security/SecuritygetProviders.htm
public class ECDH {

	public static void main(String[] argv) throws Exception {

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		//kpg.initialize(256);

		ECGenParameterSpec ecsp = new ECGenParameterSpec("secp256r1");  // secp224r1
		kpg.initialize(ecsp);

		KeyPair kp = kpg.genKeyPair();
		byte[] ourPbk = kp.getPublic().getEncoded();
		byte[] ourPvk = kp.getPrivate().getEncoded();

		System.out.println("Public Key: "+ourPbk);
		System.out.println("Private Key: "+ourPvk);
	}

}
