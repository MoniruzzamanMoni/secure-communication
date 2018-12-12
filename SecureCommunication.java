/**
 * @author Md. Moniruzzaman
 *
 */
import java.util.Scanner;

public class SecureCommunication
{   
	public static void main(String[] argv) {
		int chooseFlug = -1;
		
		Scanner sc = new Scanner(System.in);
		System.out.println("\nLogin as (Terminal ID):");
		int sourceTerminalId = sc.nextInt();
		System.out.println("\nDestination Terminal ID:");
		int destinationTerminalId = sc.nextInt();
		Terminal t1 = new Terminal(sourceTerminalId, destinationTerminalId);
		ListenerThread listenerThread = new ListenerThread(t1);
		while(!t1.exitFlug){
			System.out.println("\nTerminal " +
					sourceTerminalId +
					"\n=================================== " +
					"\n1. Generate Key-pair (Generate Private-key + Public-key)" +
					"\n2. Generate Encrypted(RSA) 3DES KEY (Generate 3DES Key and RSA encryption) " +
					"\n3. Decrypt Encrypted(RSA) 3DES KEY (Decrypt 3DES key to Connection) " +
					"\n4. Write Message and encrypt with 3DES Key (Write message and encrypt) " +
					"\n5. Decrypt message by 3DES Key and Read Message (Decrypt message and read) " +
					"\n6. Start secure chatting" +
					"\n7. Exit\n");				
			chooseFlug = sc.nextInt();
			/*String s = sc.nextLine();
			try{
				chooseFlug = Integer.parseInt(s);
			} catch(NumberFormatException ex){
				System.out.println("Its not a valid Integer");
				chooseFlug = -1;
			}*/
				
		switch(chooseFlug){
			case 1:
				t1.generateKeyPair();
				break;
			case 2:
				t1.generateRSAEncrypted3DES();
				break;
			case 3:
				t1.decryptRSAEncrypted3DES();
				break;
			case 4:
				t1.encryptTextBy3DESKey();
				break;
			case 5:
				t1.decryptTextBy3DESKey();
				break;
			case 6:
				listenerThread.start();
				t1.chatFlug = true;
				t1.writeText();
				break;
			case 7:
				t1.exitTerminal();; 
				break;
			default:
				System.out.println("\nInvalid Input! Please try again\n");
				break;
			}
			
		} // end while
	
	} // end main
}
