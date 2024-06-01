package net.ulukai.securedparams;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONArray;
import org.json.JSONObject;

import java.security.MessageDigest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

public class PocClient {
	
	// this is the idString sent, it is a public data, and used to match the common private key for AES-256 ciphering.
	final static String clientIdFilePath = "params/clientId.txt";
	// Password file contains the password to hash into 256bits (it will be done by SHA256), it is known on both side, but never exchanged
	final static String passwordFilePath = "params/password.hex";
	// IV file contains the dynamic IV value generated for this turn (size and value change on each request)
	final static String ivFilePath = "exchange/iv.b64";
	// Message to send
	final static String messageToSendFilePath = "exchange/message.txt";
	// Message Request file contains the request ciphered into AES-256 base64 encoded, containing at least the IV value to use for the Answer, prefix by the idString + "."
	final static String messageRequestFilePath = "exchange/message.request.txt";
	// Message Ansewer file contains the answer to the request ciphered into AES-256-CBC, using IV data sent into the request
	final static String messageAnswerFilePath = "exchange/message.answer.b64";
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

	private static String toBase64(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}
	
	private static boolean writeBytesIntoBase64File(String filePath, byte[] data) {
		try {
			Files.write(Paths.get(filePath), PocClient.toBase64(data).getBytes(StandardCharsets.UTF_8));
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

    	String clientId = PocClient.readFileToString(PocClient.clientIdFilePath);

    	byte[] ivBlock = new byte[Cipher.getInstance(PocClient.cipherAnswerMethod).getBlockSize()];
        new SecureRandom().nextBytes(ivBlock);
        String ivBlockBase64 = PocClient.toBase64(ivBlock);
        PocClient.writeStringIntoFile(PocClient.ivFilePath, ivBlockBase64);

    	ZonedDateTime now = ZonedDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ISO_ZONED_DATE_TIME;
        String timestamp = now.format(formatter);

    	JSONObject jsonObject = new JSONObject();
        jsonObject.put("timestamp", timestamp);
        jsonObject.put("idClientRappel", clientId);
    	JSONObject jsonRequest = new JSONObject();
    	jsonRequest.put("ivBlock", ivBlockBase64);
    	jsonRequest.put("package", "conf1");
    	jsonObject.put("request", jsonRequest);
        JSONArray jsonArray = new JSONArray();
        jsonArray.put("token1");
        jsonArray.put("token2");
        jsonObject.put("tokens", jsonArray);

    	String originalText = jsonObject.toString(2);
    	PocClient.writeStringIntoFile(PocClient.messageToSendFilePath, originalText);
        
    	String password = PocClient.readFileToString(PocClient.passwordFilePath).toUpperCase();
        byte[] privateKey = MessageDigest.getInstance("SHA-256").digest(password.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec secretKey = new SecretKeySpec(privateKey, "AES");

        PocClient.writeStringIntoFile(PocClient.messageRequestFilePath, clientId + "." + PocClient.encrypt(originalText, secretKey));
        
        //testing result
        String output = PocClient.readFileToString(PocClient.messageRequestFilePath);
        int lastIndexOfPoint = output.lastIndexOf('.');
        String oClientid = output.substring(0, lastIndexOfPoint);
        String oCipheredMsg = output.substring(lastIndexOfPoint+1);
        System.out.println("Encrypt/Decrypt by "
        		+ oClientid
        		+ "msg = ["
        		+ PocClient.decrypt( oCipheredMsg, secretKey)
        		+ "]");
        
        int serverReturnedCode = PocClient.generateServerAnswer();
        System.out.println("Return code from server = " + serverReturnedCode );

        if ( 200 != serverReturnedCode ) {
        	System.out.println("Server call failed");
        } else {
        	String answerCipheredBase64 = PocClient.readFileToString(PocClient.messageAnswerFilePath);
        	System.out.println("Data received from server ciphered-base64: " + answerCipheredBase64);
        	String answer = PocClient.decryptCBC(answerCipheredBase64, secretKey, ivBlock);
        	System.out.println("Data received from server: " + answer);
        }
    }

    public static String encrypt(String input, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return PocClient.toBase64(cipherText);
    }

    public static String decrypt(String cipherTextBase64, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherTextBase64));
        return new String(plainText);
    }
    public static String encryptCBC(String input, SecretKey key, byte[] ivBlock) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBlock));
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return PocClient.toBase64(cipherText);
    }

    public static String decryptCBC(String cipherTextBase64, SecretKey key, byte[] ivBlock) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBlock));
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherTextBase64));
        return new String(plainText);
    }

    private static int generateServerAnswer() {
    	int exitCode = 500;
	    try {
	        String command = "php server.php";
	        ProcessBuilder processBuilder = new ProcessBuilder();
	        processBuilder.command("bash", "-c", command);
	        Process process = processBuilder.start();
	        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
	        String line;
	        while ((line = reader.readLine()) != null) {
	            System.out.println(line);
	        }
	        exitCode = process.waitFor();
	        System.out.println("\n(process exit code = " + exitCode + ")");
	    } catch (IOException | InterruptedException e) {
	        e.printStackTrace();
	    }
	    return exitCode;
    }

}
