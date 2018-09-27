package net.bplaced.javacrypto.symmetricencryption;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 181 x64
* Datum/Date (dd.mm.jjjj): 27.09.2018
* Funktion: einfache Demonstration der XOR-Kodierung
* Function: simple demonstration of the XOR-codec
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine 
* korrekte Funktion, insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

import java.io.UnsupportedEncodingException;
import javax.xml.bind.DatatypeConverter;

public class B02_XorCodec {

	public static void main(String[] args) throws UnsupportedEncodingException {
		System.out.println("B02 XOR Kodierung");

		// es werden ein paar variablen benötigt:
		char xorCodecChar = 'h'; // mit diesem Wert wird xor-kodiert
		String plaintextString = "HalloWelt0123456";
		int plaintextLengthInt = plaintextString.length(); // länge des plaintextString
		byte[] plaintextByte = new byte[plaintextLengthInt]; // das plaintextByte array erzeugen
		plaintextByte = plaintextString.getBytes("UTF-8"); // plaintextString in das byte array bringen

		// beispiel der xor-kodierung anhand des ersten buchstabens von plaintextString
		System.out.println("");
		System.out.println("= = = XOR-Kodierung anhand des ersten Buchstabens = = =");
		System.out.println("xorCodecChar           :" + xorCodecChar);
		System.out.println("plaintextString        :" + plaintextString);
		// hier die bit-darstellung der xor-kodierung des ersten
		// plaintextString-Buchstabens
		int xorCodecInt = xorCodecChar; // "h"
		System.out.println("xorCodecChar    Zeichen: " + (char) xorCodecInt + " Int: " + xorCodecInt 
				+ "  Hex: " + Integer.toHexString(xorCodecInt) + " Bit:" + intToString(xorCodecInt, 4));
		int plaintextInt = plaintextByte[0]; // "H"
		System.out.println("plaintextString Zeichen: " + (char) plaintextInt + " Int:  " + plaintextInt 
				+ "  Hex: " + Integer.toHexString(plaintextInt) + " Bit:" + intToString(plaintextInt, 4));
		// hier folgt die xor-kodierung des einzelnen zeichens
		int ciphertextInt = plaintextInt ^ xorCodecInt; 
		System.out.println("xor-Kodierung   Zeichen: " + (char) ciphertextInt + " Int:  " + ciphertextInt 
				+ "  Hex: " + Integer.toHexString(ciphertextInt) + " Bit:" + intToString(ciphertextInt, 4));

		// verschlüsselung des gesamten plaintextString
		System.out.println("");
		System.out.println("= = = XOR-Kodierung des gesamten plaintextString = = =");
		int cipherInt = 0; // ein einzelnes zeichen
		byte[] ciphertextByte = new byte[plaintextLengthInt]; // das ciphertextByte array erzeugen
		for (int i = 0; i < plaintextLengthInt; i++) {
			cipherInt = plaintextByte[i];
			cipherInt = cipherInt ^ xorCodecChar; // hier erfolgt die xor-kodierung
			ciphertextByte[i] = (byte) cipherInt;
		}

		// das ciphertextByte wird an den empfänger gesendet und dort entschlüsselt
		// entschlüsselung
		int ciphertextLengthInt = ciphertextByte.length; // länge des ciphertextByte arrays
		int decryptedInt = 0; // ein einzelnes zeichen
		byte[] decryptedtextByte = new byte[ciphertextLengthInt];
		for (int i = 0; i < ciphertextLengthInt; i++) {
			decryptedInt = ciphertextByte[i];
			decryptedInt = decryptedInt ^ xorCodecChar; // hier erfolgt die xor-(de-)kodierung
			decryptedtextByte[i] = (byte) decryptedInt;
		}
		String decryptedtextString = new String(decryptedtextByte, "UTF-8");

		// ausgabe der variablen
		System.out.println("xorCodecChar           :" + xorCodecChar);
		System.out.println("plaintextString        :" + plaintextString);
		System.out.println("plaintextByte (hex)    :" + DatatypeConverter.printHexBinary(plaintextByte));
		System.out.println("= = = Verschlüsselung = = =");
		System.out.println("ciphertextByte (hex)   :" + DatatypeConverter.printHexBinary(ciphertextByte));
		System.out.println("= = = Entschlüsselung = = =");
		System.out.println("decryptedtextByte (hex):" + DatatypeConverter.printHexBinary(decryptedtextByte));
		System.out.println("decryptedtextString    :" + decryptedtextString);
	}

	/**
	 * Converts an integer to a 32-bit binary string
	 * 
	 * @param number    The number to convert
	 * @param groupSize The number of bits in a group
	 * @return The 32-bit long bit string
	 *         https://stackoverflow.com/questions/5263187/print-an-integer-in-binary-format-in-java
	 */
	public static String intToString(int number, int groupSize) {
		StringBuilder result = new StringBuilder();
		for (int i = 31; i >= 0; i--) {
			int mask = 1 << i;
			result.append((number & mask) != 0 ? "1" : "0");

			if (i % groupSize == 0)
				result.append(" ");
		}
		result.replace(result.length() - 1, result.length(), "");
		return result.toString();
	}
}
