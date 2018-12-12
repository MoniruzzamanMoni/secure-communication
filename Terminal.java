
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;


import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;

public class Terminal {
	
	public boolean exitFlug;
	public boolean chatFlug;
	
	private int terminalId;
	private int terminalIdDestination;
	String dirPath = "C:\\Users\\USER\\Desktop\\Workshop\\SecureCommunication";
	PrivateKey privateKey;
	PublicKey publicKey;
	SecretKey DESedeKey;
	

	Terminal(int _terminalId, int _destTerminalId){
		this.terminalId = _terminalId;
		this.terminalIdDestination = _destTerminalId;
		this.exitFlug = false;
		this.chatFlug = false;
		
		//Create private folder per terminal if not exist
		File file = new File(dirPath+"\\PRIVATE_DIR_"+terminalId);
		if (!file.exists()) {
			if (file.mkdir()) {
				System.out.println("Directory is created!");
			} else {
				System.out.println("Failed to create directory!");
			}
		}
		
		//try to grab private key from file
		//Get private key form file and convert it PrivateKey type
			
		File filePrivateKey = new File(dirPath+"\\PRIVATE_DIR_"+this.terminalId+"\\PRIVATE_KEY.TXT");
		if (filePrivateKey.exists()) {
			byte bufferFile[] = new byte[(int) filePrivateKey.length()];
			try{
		        BufferedInputStream bi = new BufferedInputStream(new FileInputStream(filePrivateKey));
		        bi.read(bufferFile, 0, bufferFile.length);
		        bi.close();
		        System.out.println("Stored Private Key is Loaded."/*+bytesToHex(bufferFile)*/);
	        }
	        catch(Exception e){
	            e.printStackTrace();
	        }  
			
			RSAPrivateKey privKey = null;
			try {
			    KeyFactory kf;
				kf = KeyFactory.getInstance("RSA");
				KeySpec ks = new PKCS8EncodedKeySpec(bufferFile);
				privKey = (RSAPrivateKey) kf.generatePrivate(ks);
			    //System.out.println("Stored Public Key is Loaded. "/*+bytesToHex(privKey.getEncoded())*/);
				this.privateKey = privKey;
			    
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			System.out.println("Private Key is loaded.");
		} else {
			System.out.println("Private Key file is not found, Please Generate Key pair.\n"+dirPath+"\\PRIVATE_DIR_"+this.terminalId+"\\PRIVATE_KEY.TXT");
		}
			    
		//Load previous 3DESKey from private file	
		String pathFile3DESKey = dirPath+"\\PRIVATE_DIR_"+this.terminalId+"\\DES_KEY.TXT";
		File filePrivate3DESKey = new File(pathFile3DESKey);
		
		if (filePrivate3DESKey.exists()) {
			byte[] fileDataSecretKey = fileReadBytes(pathFile3DESKey);
			this.DESedeKey = new SecretKeySpec(fileDataSecretKey, 0, fileDataSecretKey.length, "DESede");
			System.out.println("Previous 3DES key is loaded: "+bytesToHex(DESedeKey.getEncoded()));
		} else {
			System.out.println("Previous 3DES key is not loaded. 3DESKey is not exist.");
		}
		
	}
	
	public void generateKeyPair() {
		
		try {
			// Generate a 1024-bit RSA key pair
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			KeyPair keypair = keyGen.genKeyPair();
			this.privateKey = keypair.getPrivate();
			this.publicKey = keypair.getPublic();

			System.out.println("Key pair: "+bytesToHex(this.privateKey.getEncoded()));
			//System.out.println("Public key: "+bytesToHex(this.publicKey.getEncoded()));
			
		} catch (java.security.NoSuchAlgorithmException e) {
		     
		}

		//Write privateKey at private folder and write publicKey at public folder 
		try {
			String pathFilePrivateKey = dirPath+"\\PRIVATE_DIR_"+this.terminalId+"\\PRIVATE_KEY.TXT";
			String pathFilePublicKey = dirPath+"\\PUBLIC_DIR\\PUBLIC_KEY_"+this.terminalId+".TXT";
			
			//File filePrivateKey = new File(dirPath+"\\PRIVATE_DIR_"+this.terminalId+"\\PRIVATE_KEY.TXT");
			//File filePublicKey = new File(dirPath+"\\PUBLIC_DIR\\PUBLIC_KEY_"+this.terminalId+".TXT");
			
			// if file doesnt exists, then create it

			this.fileWrite(pathFilePrivateKey, this.privateKey.getEncoded());
			System.out.println(pathFilePrivateKey+" file is created.");
 

			this.fileWrite(pathFilePublicKey, this.publicKey.getEncoded());
			System.out.println(pathFilePublicKey+" file is created.");	

			System.out.println("\nDone");
			
		} catch (IOException e) {
			e.printStackTrace();
			System.out.println(dirPath+"\\PRIVATE_DIR_"+this.terminalId+"\\PRIVATE.TXT");
		}
		
	}
	
	public void generateRSAEncrypted3DES() {
		try{
			//get destination terminal public key
			File file = new File(dirPath+"\\PUBLIC_DIR\\PUBLIC_KEY_"+this.terminalIdDestination+".TXT");
			PublicKey destPublicKey = null;
			if(file.exists()){
		        byte bufferFile[] = new byte[1024];
				try{
			        BufferedInputStream bi = new BufferedInputStream(new FileInputStream(file));
			        bi.read(bufferFile, 0, bufferFile.length);
			        bi.close();
		        }
		        catch(Exception e){
		            e.printStackTrace();
		        }        
				destPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bufferFile));
			} else {
				System.out.println("Destination Terminal's Public key is not found.");
			}
			
			//generate DES and store in private directory
		    this.DESedeKey = this.generate3DESkey();
		    System.out.println("3DES Key is generated: "+ bytesToHex(this.DESedeKey.getEncoded()) );
		    
		    String pathFileDESKey = dirPath+"\\PRIVATE_DIR_"+this.terminalId+"\\DES_KEY.TXT";
		    this.fileWrite(pathFileDESKey, this.DESedeKey.getEncoded());
			System.out.println("3DES Key file location: "+pathFileDESKey);
			
		    // Encrypt DES by destPublicKey and store in public directory
			Cipher desCipher = Cipher.getInstance("RSA", "SunJCE");
		    desCipher.init(Cipher.ENCRYPT_MODE, destPublicKey);
		    byte[] encrypted3DESKey = desCipher.doFinal(this.DESedeKey.getEncoded());
		    System.out.println("RSA Encrypted 3DESKey: "+ bytesToHex(encrypted3DESKey) );

		    String pathFileEncripted3DESKey = dirPath+"\\PUBLIC_DIR\\DESC_KEY_"+this.terminalId+"_"+this.terminalIdDestination+".TXT";
		    this.fileWrite(pathFileEncripted3DESKey, encrypted3DESKey);
			System.out.println("RSA Encrypted 3DESKey file location: "+pathFileEncripted3DESKey);
		    
		    
		} catch(NoSuchAlgorithmException e){
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 

	}
	

	public void decryptRSAEncrypted3DES(){
	
		//Get RSA encrypted 3DES Key form file
		String pathFileEncripted3DESKey = dirPath+"\\PUBLIC_DIR\\DESC_KEY_"+this.terminalIdDestination+"_"+this.terminalId+".TXT";
		byte[] fileDataEncryptedSecretKey = fileReadBytes(pathFileEncripted3DESKey);
		//Decrypt rsa secret key by private key 
		try {
			Cipher desCipher;
			desCipher = Cipher.getInstance("RSA", "SunJCE");
		    desCipher.init(Cipher.DECRYPT_MODE, this.privateKey);
		    byte[] decrypted3DESKey = desCipher.doFinal(fileDataEncryptedSecretKey);

			this.DESedeKey = new SecretKeySpec(decrypted3DESKey, 0, decrypted3DESKey.length, "DESede");
			System.out.println("3DES key IS loaded: "+bytesToHex(DESedeKey.getEncoded()));
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}    
		
		//Replace private 3DES Key file with new decrypted 3DES Key
		try {
			String myPathFile3DESKey = dirPath+"\\PRIVATE_DIR_"+this.terminalId+"\\DES_KEY.TXT";
			this.fileWrite(myPathFile3DESKey, this.DESedeKey.getEncoded());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
				
	}
	
	public void encryptTextBy3DESKey(){
		//Take message from user
		Scanner sc = new Scanner(System.in);
		System.out.println("\nEnter message: ");
		String message = sc.nextLine();
		byte[] text = message.getBytes();
		
		//exit key from chatting
		int exitRule = 1;
		try{
			exitRule = Integer.parseInt(message);
			if(exitRule==0) this.chatFlug = false;
		} catch(NumberFormatException ex){
		
		}
		
		
		
		//Digest the message
		//byte[] digestMessage = getDigest(message);
		byte[] digestMessage = null;
		try {
			MessageDigest sha1;
			sha1 = MessageDigest.getInstance("SHA1");
			digestMessage = sha1.digest(message.getBytes());
			System.out.println("\nHash value:  " + bytesToHex(digestMessage));
			
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		//Combine Text and its digest
		byte[] bytesTextWithDigest = new byte[text.length + digestMessage.length];
		System.arraycopy(text,0,bytesTextWithDigest,0         ,text.length);
		System.arraycopy(digestMessage,0,bytesTextWithDigest,text.length,digestMessage.length);
		//System.out.println("Message with its Digest:  " + bytesToHex(bytesTextWithDigest));
	    
		//encrypt message+digest with 3des key
	    Cipher desCipher = null;
	    try {
			desCipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
		    desCipher.init(Cipher.ENCRYPT_MODE, this.DESedeKey);
		    byte[] textEncrypted = desCipher.doFinal(bytesTextWithDigest);//text
		    
			File filePlainText = new File(dirPath+"\\PRIVATE_DIR_"+this.terminalId+"\\PLAINTEXT.TXT");
			FileWriter fw;
			fw = new FileWriter(filePlainText.getAbsoluteFile());
	
			BufferedWriter bw = new BufferedWriter(fw);
			bw.write(message);
			bw.close();
	
			String pathFileCipher = dirPath+"\\PUBLIC_DIR\\CIPHER_"+this.terminalId+"_"+this.terminalIdDestination+".TXT";
			this.fileWrite(pathFileCipher, textEncrypted);
	
			String pathFileReadStatus = dirPath+"\\PUBLIC_DIR\\READSTATUS_"+this.terminalId+"_"+this.terminalIdDestination+".TXT";
			this.fileWrite(pathFileReadStatus, "UNREAD".getBytes());
	
			//System.out.println("\nCipher Text: "+bytesToHex(textEncrypted));
		    
	    } catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	
		
	}

	public void decryptTextBy3DESKey(){
		//load cipher text from file
		String pathFileCipherText = dirPath+"\\PUBLIC_DIR\\CIPHER_"+this.terminalIdDestination+"_"+this.terminalId+".TXT";
		byte[] cipherTextWithDigest = fileReadBytes(pathFileCipherText);
		//System.out.println("Cipher text with digest: "+bytesToHex(cipherTextWithDigest));
		
		//decrypt cipher text to read
		Cipher desCipher = null;
	    try {
			desCipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
		    desCipher.init(Cipher.DECRYPT_MODE, this.DESedeKey);
		    byte[] textDecrypted = desCipher.doFinal(cipherTextWithDigest);
		    //System.out.println("Text Decryted : " + new String(textDecrypted));
		    
			File filePlainText = new File(dirPath+"\\PRIVATE_DIR_"+this.terminalId+"\\PLAINTEXT.TXT");
			FileWriter fw;
			fw = new FileWriter(filePlainText.getAbsoluteFile());
	
			BufferedWriter bw = new BufferedWriter(fw);
			bw.write(new String(textDecrypted));
			bw.close();
	
			//separate digest from Cipher text
			byte[] originalText = Arrays.copyOfRange(textDecrypted,0, textDecrypted.length-20);
			System.out.println("Terminal "+this.terminalId+": "+ new String(originalText));
	
			byte[] digestValue = Arrays.copyOfRange(textDecrypted,originalText.length, textDecrypted.length);
			System.out.println("\nHash Value: "+ bytesToHex(digestValue));
			
			//Verify message integrity
			//1. Digest the message
			byte[] digestMessage = null;
			try {
				MessageDigest sha1;
				sha1 = MessageDigest.getInstance("SHA1");
				digestMessage = sha1.digest(originalText);
			} catch (NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			
			if(Arrays.equals(digestMessage, digestValue)){
				System.out.println("Integrity verifying status: VALID ");
			} else {
				System.out.println("Integrity verifying status: INVALID ");
			}
	
	
	    } catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	
	}

	public void startListen(){
		String pathFileReadStatus = dirPath+"\\PUBLIC_DIR\\READSTATUS_"+this.terminalIdDestination+"_"+this.terminalId+".TXT";
		File file = new File(pathFileReadStatus);
		if (file.exists()) {
			byte[] bytesReadStatus = fileReadBytes(pathFileReadStatus);
			if(Arrays.equals(bytesReadStatus, "UNREAD".getBytes())){
				try {
					this.decryptTextBy3DESKey();
					this.fileWrite( pathFileReadStatus, "READ".getBytes());
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
	}
	public void writeText(){
		while(this.chatFlug){
			this.encryptTextBy3DESKey();
		}
	}
	
	public void exitTerminal(){
		this.exitFlug = true;
	}

	private static String bytesToHex(byte[] bytes) {
		char[] hexArray = "0123456789ABCDEF".toCharArray();
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	private SecretKey generate3DESkey() {
	    KeyGenerator keyGen = null;
        try {
			keyGen = KeyGenerator.getInstance("DESede");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	    keyGen.init(168); // key length 112 for two keys, 168 for three keys
	    SecretKey secretKey = keyGen.generateKey();
	    return secretKey;
	}
	
	private byte[] fileReadBytes(String filePath) {
		FileInputStream fileInputStream=null;
		 
        File file = new File(filePath);
 
        byte[] bFile = new byte[(int) file.length()];
 
        try {
            //convert file into array of bytes
	    fileInputStream = new FileInputStream(file);
	    fileInputStream.read(bFile);
	    fileInputStream.close();

        }catch(Exception e){
        	e.printStackTrace();
        }
        return bFile;
	}
	
	private void fileWrite(String filePath, byte[] byteData) throws IOException{
		File file = new File(filePath);
		file.createNewFile();
		BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(file));
		bos.write(byteData);
		bos.flush();
		bos.close();
	}
	
	/*
	private byte[] getDigest(String message) {
		String MAC_ALG = "HmacSHA1";
		String fKey = "abc123";
	    try {
	    	byte[] bkey = fKey.getBytes();
	        byte[] data = message.getBytes();
	        Mac mac = null;
	        try {
	        	mac = Mac.getInstance(MAC_ALG);
	            mac.init(new SecretKeySpec(bkey, MAC_ALG));
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	        byte[] digestMessage = mac.doFinal(data);
	        return digestMessage;
	    } catch (IllegalStateException e) {
	       	e.printStackTrace();
	    }        
	    return null;
	}
	*/
}
