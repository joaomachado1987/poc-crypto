package teste.crypto;

import java.security.Key;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

//import lombok.experimental.UtilityClass;
//import org.owasp.esapi.ESAPI;
//import org.owasp.esapi.Logger;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


//@UtilityClass
public class CypherUtil {

	// private static final Logger log = ESAPI.getLogger(CypherUtil.class);
	private static final String AES_CBC = "AES/CBC/PKCS5Padding";
	private static final String UTF_8 = "UTF-8";
	private static final String AES = "AES";
	private static final String SHA_256 = "SHA-256";
	private static final String IV_PARAMETER_SPEC = "SECRET_ACCOUNTS_";
	
	public static String crypt(String value) {
		String passSalt = SaltUtil.salt(value);
		try {
			MessageDigest md = MessageDigest.getInstance(SHA_256);
			md.update(passSalt.getBytes(UTF_8));
			return bytesToHex(md.digest());
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	private static String bytesToHex(byte[] bytes) {
		StringBuilder result = new StringBuilder();
		for (byte b : bytes)
			result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
		return result.toString();
	}


	public static String encryptAES(String text, String key) {
		try {
			Key keySpec = new SecretKeySpec(key.getBytes(), AES);
			AlgorithmParameterSpec param = new IvParameterSpec(IV_PARAMETER_SPEC.getBytes());
			Cipher cipher = Cipher.getInstance(AES_CBC);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, param);
			byte[] bytes = cipher.doFinal(text.getBytes(UTF_8));
			return new String(Base64.getEncoder().encode(bytes));

		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static String decryptAES(String text, String key) {
		try {
			Key keySpec = new SecretKeySpec(key.getBytes(), AES);
			AlgorithmParameterSpec param = new IvParameterSpec(IV_PARAMETER_SPEC.getBytes());
			Cipher cipher = Cipher.getInstance(AES_CBC);
			cipher.init(Cipher.DECRYPT_MODE, keySpec, param);
			byte[] bytes = Base64.getDecoder().decode(text.getBytes(UTF_8));
			byte[] decValue = cipher.doFinal(bytes);
			return new String(decValue);

		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static void main(String[] str) throws InterruptedException {
		final String key = "AAAAAAAAAAAAAAAAAAAAAAAA";
		final String documento = "23.237.808/0001-92";
		final String documentoCryptAES = encryptAES(documento, key);
		final String documentoCryptHASH = crypt(documento);
		
		System.out.println("Documento: " + documento);
		System.out.println("Documento criptografado AES: " +documentoCryptAES);
		System.out.println("Documento criptografado HASH: " +documentoCryptHASH);
		System.out.println("Documento descriptografado: " + decryptAES(documentoCryptAES, key));
	}

}