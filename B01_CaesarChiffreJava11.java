package net.bplaced.javacrypto.symmetricencryption;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 181 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 13.01.2019
* Funktion: einfache Demonstration der Caesar Chiffre
* Function: simple demonstration of the Caesar Chiffre
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine 
* korrekte Funktion, insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

import java.io.UnsupportedEncodingException;

public class B01_CaesarChiffreJava11 {

	public static void main(String[] args) throws UnsupportedEncodingException {
		System.out.println("B01 Caesar Chiffre");

		// es werden ein paar variablen benötigt:
		String plaintextString = "HalloWelt0123456";
		int caesarKeyInt = 3; // drei zeichen verschieben

		// verschlüsselung
		int cipherInt = 0;
		String ciphertextString = "";
		int plaintextLengthInt = plaintextString.length();
		byte[] plaintextByte = new byte[plaintextLengthInt];
		plaintextByte = plaintextString.getBytes("UTF-8");
		byte[] ciphertextByte = new byte[plaintextLengthInt];
		for (int i = 0; i < plaintextLengthInt; i++) {
			cipherInt = plaintextByte[i];
			cipherInt = cipherInt + caesarKeyInt;
			ciphertextByte[i] = (byte) cipherInt;
		}
		ciphertextString = new String(ciphertextByte, "UTF-8");
		// der ciphertextString wird übermittelt
		
		// entschlüsselung
		int ciphertextLengthInt = ciphertextString.length();
		byte[] ciphertextDecByte = new byte[ciphertextLengthInt];
		ciphertextDecByte = ciphertextString.getBytes("UTF-8");
		byte[] decryptedtextByte = new byte[ciphertextLengthInt];
		for (int i = 0; i < ciphertextLengthInt; i++) {
			cipherInt = ciphertextDecByte[i];
			cipherInt = cipherInt - caesarKeyInt;
			decryptedtextByte[i] = (byte) cipherInt;
		}
		String decryptedtextString = ""; // enthält den entschlüsselten text
		decryptedtextString = new String(decryptedtextByte, "UTF-8");

		// ausgabe der variablen
		System.out.println("caesarKeyInt           :" + caesarKeyInt);
		System.out.println("plaintextString        :" + plaintextString);
		System.out.println("plaintextByte (hex)    :" + printHexBinary(plaintextByte));
		System.out.println("= = = Verschlüsselung = = =");
		System.out.println("ciphertextByte (hex)   :" + printHexBinary(ciphertextByte));
		System.out.println("ciphertextString       :" + ciphertextString);
		System.out.println("= = = Entschlüsselung = = =");
		System.out.println("decryptedtextByte (hex):" + printHexBinary(decryptedtextByte));
		System.out.println("decryptedtextString    :" + decryptedtextString);
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

