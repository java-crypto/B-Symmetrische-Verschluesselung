package javaCrypto;

import javax.xml.bind.DatatypeConverter;

/*
* Programm/Program B01_XorVerschluesselung.java
* Kurzbeschreibung/Short description:
* XOR-Verschlüsselung eines Strings / XOR encryption of a string 
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Sourcecode: https://github.com/java-crypto/B-Symmetrische-Verschluesselung/
* Programmierer/Programmer: Michael Fehr
*
* getestet mit/checked with Java Runtime Environment 8 Update 131
* letzter Test/last check: 06.07.2017/July 6th. 2017 
*
* Copyright/Copyright: frei verwendbares Programm/Public Domain
* Lizenzmodell/Licence model: CC0 (Public Domain wo verfügbar/where available)
* Lizenzhinweise/Licence links:
* https://de.wikipedia.org/wiki/Creative_Commons#CC_Zero
* https://en.wikipedia.org/wiki/Creative_Commons_license
* 
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion, 
* insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor die Programm in der echten Welt eingesetzt werden.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

// ### SICHERHEITSWARNUNG: Diese Verschlüsselung ist nicht sicher, bitte nicht benutzen ! ###
// ### SECURITY NOTICE: This encryption ist not safe, do use it ! ###

public class B01_XorVerschluesselung {

	public static void main(String[] args) {
		System.out.println("B01 XOR Verschlüsselung");
		String KlartextString = "Dies ist ein geheimer Geheimsatz";
		// String KlartextString = "This a very secret text of secret words";
		String SchluesselString = "abcDEF123";
		int[] VerschluesseltInt;
		String EntschluesseltString = "";

		VerschluesseltInt = encrypt(KlartextString, SchluesselString);
		System.out.println("");
		System.out.println("Programmteil Verschlüsselung");
		System.out.println("KlartextString      :" + KlartextString);
		System.out.println("Schluessel          :" + SchluesselString);
		System.out.println("VerschluesseltInt   :" + VerschluesseltInt);
		System.out.print("VerschluesseltIntHex:");
		intArrayPrint(VerschluesseltInt);
		// ausgabe im dezimalcode
		System.out.print("VerschluesseltDez   :");
		for (int i = 0; i < VerschluesseltInt.length; i++)
			System.out.printf("%d ", VerschluesseltInt[i]);
		System.out.println("");

		System.out.println("");
		EntschluesseltString = decrypt(VerschluesseltInt, SchluesselString);
		System.out.println("Programmteil Entschlüsselung");
		System.out.println("VerschluesseltInt   :" + VerschluesseltInt);
		System.out.print("VerschluesseltIntHex:");
		intArrayPrint(VerschluesseltInt);
		// ausgabe im dezimalcode
		System.out.print("VerschluesseltDez   :");
		for (int i = 0; i < VerschluesseltInt.length; i++)
			// System.out.printf("%d,", VerschluesseltInt[i]);
			System.out.printf("%d ", VerschluesseltInt[i]);
		System.out.println("");
		System.out.println("Schluessel          :" + SchluesselString);
		System.out.println("EntschluesseltString:" + EntschluesseltString);
		System.out.println("");
	}

	private static int[] encrypt(String str, String key) {
		int[] output = new int[str.length()];
		for (int i = 0; i < str.length(); i++) {
			int o = (Integer.valueOf(str.charAt(i)) ^ Integer.valueOf(key.charAt(i % (key.length() - 1)))) + '0';
			output[i] = o;
		}
		return output;
	}

	private static String decrypt(int[] input, String key) {
		String output = "";
		for (int i = 0; i < input.length; i++) {
			output += (char) ((input[i] - 48) ^ (int) key.charAt(i % (key.length() - 1)));
		}
		return output;
	}
	
	public static void intArrayPrint(int[] intData) {
		// gibt ein int Array im hexformat aus		
		int rawLength = intData.length;
		// System.out.println("Daten im Hex-Format");
		int i = 0;
		int j = 1;
		int z = 0;
		for (i = 0; i < rawLength; i++) {
			z++;
			System.out.print(Integer.toHexString(intData[i]));
			//System.out.print(intData[i]);
			if (j == 1) {
				System.out.print(" ");
				j = 0;
			}
			j++;
			if (z == 32) {
				System.out.println("");
				z = 0;
			}
		}
		// System.out.println("");
	}
}