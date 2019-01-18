package net.bplaced.javacrypto.symmetricencryption;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 13.01.2019
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

public class B05_AesEcbPkcs5PaddingFileJava11 {

	public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		System.out.println("B05 AES im Betriebsmodus ECB PKCS5Padding mit einer Datei");

		// es werden ein paar variablen benötigt:
		String dateinameReadString = "b05_test.txt"; // aus der datei wird das plaintextByte eingelesen
		String dateinameWriteString = "b05_test.enc"; // in diese datei wird das ciphertextByte geschrieben

		String plaintextString = ""; // die daten werden aus der datei gelesen
		byte[] plaintextByte = null; // die daten werden aus der datei gelesen

		// zuerst testen wir ob die einzulesende datei existiert
		if (FileExistsCheck(dateinameReadString) == false) {
			System.out.println("Die Datei " + dateinameReadString + " existiert nicht. Das Programm wird beendet.");
			System.exit(0);
		};

		// datei in byte array einlesen
		plaintextByte = readBytesFromFileNio(dateinameReadString);
		plaintextString = new String(plaintextByte, "UTF-8"); // die umwandlung erfolgt nur zur späteren anzeige

		// diese konstanten und variablen benötigen wir zur ver- und entschlüsselung
		// der schlüssel ist exakt 32 zeichen lang und bestimmt die stärke der
		// verschlüsselung
		// hier ist der schlüssel 32 byte = 256 bit lang
		// mögliche schlüssellängen sind 16 byte (128 bit), 24 byte (192 bit) und 32
		// byte (256 bit)
		// final byte[] keyByte = "1234567890123456".getBytes("UTF-8"); // 16 byte
		final byte[] keyByte = "12345678901234567890123456789012".getBytes("UTF-8"); // 32 byte

		// der verschluesselte (encrypted) text kommt in diese variable in form eines
		// byte arrays
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
		Cipher aesCipherEnc = Cipher.getInstance("AES/ECB/PKCS5PADDING");
		// nun wird die routine mit dem schlüssel initialisiert
		aesCipherEnc.init(Cipher.ENCRYPT_MODE, keySpec);
		// hier erfolgt nun die verschlüsselung des plaintextes
		ciphertextByte = aesCipherEnc.doFinal(plaintextByte);

		// byte array in eine datei schreiben
		writeBytesToFileNio(ciphertextByte, dateinameWriteString);

		System.out.println("");
		System.out.println("Klartextdaten einlesen und als verschlüsselte Datei speichern");
		System.out.println("keyByte (hex)          :" + printHexBinary(keyByte));
		System.out.println("Dateiname Lesen        :" + dateinameReadString);
		System.out.println("Dateiname Schreiben    :" + dateinameWriteString);
		System.out.println("plaintextByte (hex)    :" + printHexBinary(plaintextByte));
		System.out.println("plaintextString        :" + plaintextString);
		System.out.println("= = = Verschlüsselung = = =");
		System.out.println("ciphertextByte (hex)   :" + printHexBinary(ciphertextByte));

		// ab hier arbeiten wir nun im entschlüsselungsmodus

		// wir starten die entschlüsselung mit einem leeren ciphertext
		ciphertextByte = null;

		// byte array einlesen
		dateinameReadString = "b05_test.enc"; // ciphertextByte lesen
		dateinameWriteString = "b05_test.dec"; // decryptedtextByte schreiben

		// zuerst testen wir ob die einzulesende datei existiert
		if (FileExistsCheck(dateinameReadString) == false) {
			System.out.println("Die Datei " + dateinameReadString + " existiert nicht. Das Programm wird beendet.");
			System.exit(0);
		};
		// das ciphertextByte wird aus der datei gelesen
		ciphertextByte = readBytesFromFileNio(dateinameReadString);

		// die verschlüsselungsroutine wird mit dem gewünschten parameter erstellt
		Cipher aesCipherDec = Cipher.getInstance("AES/ECB/PKCS5PADDING");
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
		System.out.println("keyByte (hex)          :" + printHexBinary(keyByte));
		System.out.println("Dateiname Lesen        :" + dateinameReadString);
		System.out.println("Dateiname Schreiben    :" + dateinameWriteString);
		System.out.println("ciphertextByte (hex)   :" + printHexBinary(ciphertextByte));
		System.out.println("= = = Entschlüsselung = = =");
		System.out.println("decryptedtextByte (hex):" + printHexBinary(decryptedtextByte));
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
	public static String printHexBinary(byte[] bytes) {
		final char[] hexArray = "0123456789ABCDEF".toCharArray();
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}
}