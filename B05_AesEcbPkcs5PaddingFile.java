package B_SymmetricEncryption;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 181 x64
* Datum/Date (dd.mm.jjjj): 30.09.2018 
* Funktion: liest eine datei und verschlüsselt sie im aes ecb modus pkcs5 padding
* Function: encrypts a file using aes ecb modus with pkcs5 padding
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine 
* korrekte Funktion, insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class B05_AesEcbPkcs5PaddingFile {

	public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		System.out.println("B05 AES im Betriebsmodus ECB PKCS5Padding mit einer Datei");
		
		// es werden ein paar variablen benötigt:
		String dateinameReadString = "b05_test.txt"; // aus der datei wird das plaintextByte eingelesen
		String dateinameWriteString = "test.enc"; // in diese datei wird das ciphertextByte geschrieben

		String plaintextString = ""; // die daten werden aus der datei gelesen
		byte[] plaintextByte = null; // die daten werden aus der datei gelesen

		// zuerst testen wir ob die datei existiert
		if (FileExistsCheck(dateinameReadString) == false) {
			System.out.println("Die Datei " + dateinameReadString + " existiert nicht. Das Programm wird beendet.");
			System.exit(0);
		};
		
		// datei in byte array einlesen
		plaintextByte = readBytesFromFileNio(dateinameReadString);
		plaintextString = new String(plaintextByte, "UTF-8"); // die umwandlung erfolgt nur zur späteren anzeige

		// diese konstanten und variablen benötigen wir zur ver- und entschlüsselung
		// der genutzte algorithmus
		final String AESMODE_ECB_PKCS5PADDING = "AES/ECB/PKCS5PADDING";
		// der schlüssel ist exakt 16 zeichen lang und bestimmt die stärke der
		// verschlüsselung
		// hier ist der schlüssel 16 byte = 128 bit lang
		// mögliche schlüssellängen sind 16 byte (128 bit), 24 byte (192 bit) oder 32
		// byte (256 bit)
		final byte[] keyByte = "1234567890123456".getBytes("UTF-8");

		// der verschluesselte (encrypted) text kommt in diese variable in form eines byte arrays
		byte[] ciphertextByte = null; // die länge steht noch nicht fest, da sie von der größe des plaintextes abhängt

		// der entschlüsselte (decrypted) text kommt in dieses byte array, welches
		// später in einen string umkodiert wird
		byte[] decryptedtextByte = null; // die länge steht noch nicht fest, da sie von der größe des plaintextes
											// abhängt
		String decryptedtextString = ""; // enthält später den entschlüsselten text
		
		// ab hier arbeiten wir nun im verschlüsselungsmodus

		// der schlüssel wird in die richtige form gebracht
		SecretKeySpec keySpec = new SecretKeySpec(keyByte, "AES");
		// die verschlüsselungsroutine wird mit dem gewünschten parameter erstellt
		Cipher aesCipherEnc = Cipher.getInstance(AESMODE_ECB_PKCS5PADDING);
		// nun wird die routine mit dem schlüssel initialisiert
		aesCipherEnc.init(Cipher.ENCRYPT_MODE, keySpec);
		// hier erfolgt nun die verschlüsselung des plaintextes
		ciphertextByte = aesCipherEnc.doFinal(plaintextByte);

		// byte array in eine datei schreiben
		writeBytesToFileNio(ciphertextByte, dateinameWriteString);

		System.out.println("");
		System.out.println("Klartextdaten einlesen und als verschlüsselte Datei speichern");
		System.out.println("keyByte (hex)          :" + DatatypeConverter.printHexBinary(keyByte));
		System.out.println("Dateiname Lesen        :" + dateinameReadString);
		System.out.println("Dateiname Schreiben    :" + dateinameWriteString);
		System.out.println("plaintextByte (hex)    :" + DatatypeConverter.printHexBinary(plaintextByte));
		System.out.println("plaintextString        :" + plaintextString);
		System.out.println("= = = Verschlüsselung = = =");
		System.out.println("ciphertextByte (hex)   :" + DatatypeConverter.printHexBinary(ciphertextByte));

		// ab hier arbeiten wir nun im entschlüsselungsmodus

		// wir starten die entschlüsselung mit einem leeren ciphertext
		ciphertextByte = null;

		// byte array einlesen
		dateinameReadString = "test.enc"; // ciphertextByte lesen
		dateinameWriteString = "test.dec"; // decryptedtextByte schreiben
		
		// zuerst testen wir ob die datei existiert
				if (FileExistsCheck(dateinameReadString) == false) {
					System.out.println("Die Datei " + dateinameReadString + " existiert nicht. Das Programm wird beendet.");
					System.exit(0);
				};
		// das ciphertextByte wird aus der datei gelesen 
		ciphertextByte = readBytesFromFileNio(dateinameReadString);

		// die verschlüsselungsroutine wird mit dem gewünschten parameter erstellt
		Cipher aesCipherDec = Cipher.getInstance(AESMODE_ECB_PKCS5PADDING);
		// zum einsatz kommt derselbe schlüssel, daher symmetrische verschlüsselung
		// achtung: hier wird der DECRYPT_MODE = entschlüsselung genutzt
		aesCipherDec.init(Cipher.DECRYPT_MODE, keySpec);
		// nun wird der ciphertext wieder entschlüsselt
		decryptedtextByte = aesCipherDec.doFinal(ciphertextByte);

		// wir schreiben die entschlüsselten daten in eine datei
		writeBytesToFileNio(decryptedtextByte, dateinameWriteString);

		// zurück-kodierung des byte array in text nur zur anzeige
		decryptedtextString = new String(decryptedtextByte, "UTF-8");

		// ausgabe der variablen
		System.out.println("");
		System.out.println("Verschlüsselte Daten einlesen und als entschlüsselte Datei speichern");
		System.out.println("keyByte (hex)          :" + DatatypeConverter.printHexBinary(keyByte));
		System.out.println("Dateiname Lesen        :" + dateinameReadString);
		System.out.println("Dateiname Schreiben    :" + dateinameWriteString);
		System.out.println("ciphertextByte (hex)   :" + DatatypeConverter.printHexBinary(ciphertextByte));
		System.out.println("= = = Entschlüsselung = = =");
		System.out.println("decryptedtextByte (hex):" + DatatypeConverter.printHexBinary(decryptedtextByte));
		System.out.println("decryptedtextString    :" + decryptedtextString);
	}

	private static boolean FileExistsCheck(String dateinameString) {
		return Files.exists(Paths.get(dateinameString), new LinkOption[] { LinkOption.NOFOLLOW_LINKS });
	}
	
	private static void writeBytesToFileNio(byte[] byteToFileByte, String filenameString) {
		try {
			Path path = Paths.get(filenameString);
			Files.write(path, byteToFileByte);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static byte[] readBytesFromFileNio(String filenameString) {
		byte[] byteFromFileByte = null;
		try {
			// bFile = Files.readAllBytes(new File(filenameString).toPath());
			byteFromFileByte = Files.readAllBytes(Paths.get(filenameString));
		} catch (IOException e) {
			e.printStackTrace();
		}
		return byteFromFileByte;
	}
}
