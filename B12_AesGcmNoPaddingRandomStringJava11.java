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
* Funktion: verschlüsselt einen Text im AESs GCM Modus kein Padding
* Function: encrypts a text string using AES GCM modus with no padding
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine 
* korrekte Funktion, insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class B12_AesGcmNoPaddingRandomStringJava11 {

	public static void main(String[] args)
			throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		System.out.println("B12 AES im Betriebsmodus GCM Kein Padding mit Zufalls-GCM Nonce mit einem String");
		// es werden ein paar variablen benötigt:
		String plaintextString = "Dieses ist der zu verschlüsselnde Text";
		byte[] plaintextByte = plaintextString.getBytes("UTF-8");

		final int GCMNONCELENGTH = 12; // = 96 bit

		String decryptedtextString = ""; // enthält später den entschlüsselten text

		// diese konstanten und variablen benötigen wir zur ver- und entschlüsselung
		// der schlüssel ist exakt 32 zeichen lang und bestimmt die stärke der
		// verschlüsselung. mögliche schlüssellängen sind 16 byte (128 bit),
		// 24 byte (192 bit) und 32 byte (256 bit)
		final byte[] keyByte = "12345678901234567890123456789012".getBytes("UTF-8"); // 32 byte

		// GENERATE random nonce (number used once)
		final byte[] gcmNonceByte = new byte[GCMNONCELENGTH];
		SecureRandom secureRandomGcm = new SecureRandom();
		secureRandomGcm.nextBytes(gcmNonceByte);

		// der verschluesselte (encrypted) text kommt in diese variable in form eines
		// byte arrays
		byte[] ciphertextByte = null; // die länge steht noch nicht fest, da sie von der größe des plaintextes abhängt
		// der entschlüsselte (decrypted) text kommt in dieses byte array, welches
		// später in einen string umkodiert wird
		byte[] decryptedtextByte = null; // die länge steht noch nicht fest, da sie von der größe des plaintextes
											// abhängt

		// ab hier arbeiten wir nun im verschlüsselungsmodus
		// umwandlung des klartextes in ein byte array
		plaintextByte = plaintextString.getBytes("UTF-8");
		// hier erfolgt nun die verschlüsselung des plaintextes
		ciphertextByte = AesGcmNoPaddingEncrypt(plaintextByte, keyByte, gcmNonceByte);

		System.out.println("");
		System.out.println("Klartextdaten einlesen und als verschlüsselte Daten ausgeben");
		System.out.println("keyByte (hex)          :" + printHexBinary(keyByte));
		System.out.println("gcmNonceByte (hex)     :" + printHexBinary(gcmNonceByte));
		System.out.println("plaintextByte (hex)    :" + printHexBinary(plaintextByte));
		System.out.println("plaintextString        :" + plaintextString);
		System.out.println("= = = Verschlüsselung = = =");
		System.out.println("ciphertextByte (hex)   :" + printHexBinary(ciphertextByte));

		// ab hier arbeiten wir nun im entschlüsselungsmodus

		// nun wird der ciphertext wieder entschlüsselt
		decryptedtextByte = AesGcmNoPaddingDecrypt(ciphertextByte, keyByte, gcmNonceByte);

		// zurück-kodierung des byte array in text
		decryptedtextString = new String(decryptedtextByte, "UTF-8");

		// ausgabe der variablen
		System.out.println("");
		System.out.println("Verschlüsselte Daten einlesen und als Klartext-Daten ausgeben");
		System.out.println("keyByte (hex)          :" + printHexBinary(keyByte));
		System.out.println("gcmNonceByte (hex)     :" + printHexBinary(gcmNonceByte));
		System.out.println("ciphertextByte (hex)   :" + printHexBinary(ciphertextByte));
		System.out.println("= = = Entschlüsselung = = =");
		System.out.println("decryptedtextByte (hex):" + printHexBinary(decryptedtextByte));
		System.out.println("decryptedtextString    :" + decryptedtextString);
	}

	public static byte[] AesGcmNoPaddingEncrypt(byte[] plaintextByte, byte[] keyByte, byte[] gcmNonceByte)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		final int GCM_TAG_LENGTH = 128;
		byte[] ciphertextByte = null;
		// der schlüssel wird in die richtige form gebracht
		SecretKeySpec keySpec = new SecretKeySpec(keyByte, "AES");
		// statt eines initvectors wird ein gcm parameter benoetigt
		GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, gcmNonceByte);
		// die verschlüsselungsroutine wird mit dem gewünschten parameter erstellt
		Cipher aesCipherEnc = Cipher.getInstance("AES/GCM/NoPadding");
		// nun wird die routine mit dem schlüssel initialisiert
		aesCipherEnc.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
		// hier erfolgt nun die verschlüsselung des plaintextes
		ciphertextByte = aesCipherEnc.doFinal(plaintextByte);
		return ciphertextByte;
	}

	public static byte[] AesGcmNoPaddingDecrypt(byte[] ciphertextByte, byte[] keyByte, byte[] gcmNonceByte)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		final int GCM_TAG_LENGTH = 128;
		byte[] decryptedtextByte = null;
		// der schlüssel wird in die richtige form gebracht
		SecretKeySpec keySpec = new SecretKeySpec(keyByte, "AES");
		// statt eines initvectors wird ein gcm parameter benoetigt
		GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, gcmNonceByte);
		// die verschlüsselungsroutine wird mit dem gewünschten parameter erstellt
		Cipher aesCipherDec = Cipher.getInstance("AES/GCM/NoPadding");
		// nun wird die routine mit dem schlüssel initialisiert
		aesCipherDec.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
		// hier erfolgt nun die verschlüsselung des plaintextes
		decryptedtextByte = aesCipherDec.doFinal(ciphertextByte);
		return decryptedtextByte;
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
