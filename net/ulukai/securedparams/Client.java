package net.ulukai.securedparams;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

public class Client {
	
	// this is the idString sent, it is a public data, and used to match the common private key for AES-256 ciphering.
	final static String clientIdFilePath = "clientId.txt";
	// Password file contains the password to hash into 256bits (it will be done by SHA256), it is known on both side, but never exchanged
	final static String passwordFilePath = "password.txt";
	// IV file contains the dynamic IV value generated for this turn (size and value change on each request)
	final static String ivFilePath = "iv.txt";
	// Message to send
	final static String messageToSendFilePath = "message.txt";
	// Message Request file contains the request ciphered into AES-256 base64 encoded, containing at least the IV value to use for the Answer, prefix by the idString + "."
	final static String messageRequestFilePath = "message.request.txt";
	// Message Ansewer file contains the answer to the request ciphered into AES-256-CBC, using IV data sent into the request
	final static String messageAnswerFilePath = "message.answer.txt";
	// Ciphering method is necessary to cipher renderer and to know the IV/key size needed
	final static String cipherRequestMethod = "AES/ECB/PKCS5Padding";
	// Ciphering method is necessary to cipher renderer and to know the IV/key size needed
	final static String cipherAnswerMethod = "AES/CBC/PKCS5Padding";

	private static String readFileToString(String filePath) {
		try {
		    Path path = Paths.get(filePath);
		    return new String(Files.readAllBytes(path));
		} catch (IOException e) {
			e.printStackTrace();
		}
		return "";
	}

	private static boolean writeBytesIntoBase64File(String filePath, byte[] data) {
		try {
			Files.write(Paths.get(filePath), Base64.getEncoder().encodeToString(data).getBytes(StandardCharsets.UTF_8));
			return true;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return false;
	}

	private static boolean writeStringIntoFile(String filePath, String data) {
		try {
			Files.write(Paths.get(filePath), data.getBytes(StandardCharsets.UTF_8));
			return true;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return false;
	}

    public static void main(String[] args) throws Exception {
    	System.out.println(System.getProperty("user.dir"));

    	String clientId = Client.readFileToString(Client.clientIdFilePath);
        String originalText = Client.readFileToString(Client.messageToSendFilePath);

        byte[] ivBlock = new byte[Cipher.getInstance(Client.cipherAnswerMethod).getBlockSize()];
        new SecureRandom().nextBytes(ivBlock);
        Client.writeBytesIntoBase64File(Client.ivFilePath, ivBlock);
        
    	String password = Client.readFileToString(Client.passwordFilePath).toUpperCase();
        byte[] privateKey = MessageDigest.getInstance("SHA-256").digest(password.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec secretKey = new SecretKeySpec(privateKey, "AES");

        Client.writeStringIntoFile(Client.messageRequestFilePath, clientId + "." + Client.encrypt(originalText, secretKey));
        
        //testing result
        String output = Client.readFileToString(Client.messageRequestFilePath);
        int lastIndexOfPoint = output.lastIndexOf('.');
        String oClientid = output.substring(0, lastIndexOfPoint);
        String oCipheredMsg = output.substring(lastIndexOfPoint+1);
        System.out.println("Encrypt/Decrypt by "
        		+ oClientid
        		+ "msg = ["
        		+ Client.decrypt( oCipheredMsg, secretKey)
        		+ "]");
    }

    public static String encrypt(String input, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }
    public static String encryptCBC(String input, SecretKey key, byte[] ivBlock) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBlock));
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decryptCBC(String cipherText, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }
}
