package net.bplaced.javacrypto.symmetricencryption;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 181 x64
* Datum/Date (dd.mm.jjjj): 27.09.2018 
* Funktion: verschlüsselt einen string im aes ecb modus ohne padding
* Function: encrypts a string using aes ecb modus without a padding
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine 
* korrekte Funktion, insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class B03_AesEcbNopaddingString {

	public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException, 
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		System.out.println("B03 AES im Betriebsmodus ECB NoPadding mit einem String");
		// es werden ein paar variablen benötigt:
		String plaintextString = "HalloWelt0123456"; // exakt 16 zeichen
		String decryptedtextString = ""; // enthält später den entschlüsselten text
		
		// diese konstanten und variablen benötigen wir zur ver- und entschlüsselung
		// der genutzte algorithmus
		final String AESMODE_ECB_NOPADDING = "AES/ECB/NOPADDING"; 
		// der schlüssel ist exakt 16 zeichen lang und bestimmt die stärke der verschlüsselung
		// hier ist der schlüssel 16 byte = 128 bit lang
		// mögliche schlüssellängen sind 16 byte (128 bit), 24 byte (192 bit) und 32 byte (256 bit)
		final byte[] keyByte = "1234567890123456".getBytes("UTF-8"); 
		
		byte[] plaintextByte = null; 
		// der verschluesselte (encrypted) text kommt in diese variable in form eines byte arrays
		byte[] ciphertextByte = null; // die länge steht noch nicht fest, da sie von der größe des plaintextes abhängt
		// der entschlüsselte (decrypted) text kommt in dieses byte array, welches später in einen string umkodiert wird
		byte[] decryptedtextByte = null; // die länge steht noch nicht fest, da sie von der größe des plaintextes abhängt
		
		// ab hier arbeiten wir nun im verschlüsselungsmodus
		// umwandlung des klartextes in ein byte array
		plaintextByte = plaintextString.getBytes("UTF-8");
		// der schlüssel wird in die richtige form gebracht
		SecretKeySpec keySpec = new SecretKeySpec(keyByte, "AES");
		// die verschlüsselungsroutine wird mit dem gewünschten parameter erstellt
		Cipher aesCipherEnc = Cipher.getInstance(AESMODE_ECB_NOPADDING);
		// nun wird die routine mit dem schlüssel initialisiert
		aesCipherEnc.init(Cipher.ENCRYPT_MODE, keySpec);
		// hier erfolgt nun die verschlüsselung des plaintextes
		ciphertextByte = aesCipherEnc.doFinal(plaintextByte);
		
		// ab hier arbeiten wir nun im entschlüsselungsmodus
		// die verschlüsselungsroutine wird mit dem gewünschten parameter erstellt
		Cipher aesCipherDec = Cipher.getInstance(AESMODE_ECB_NOPADDING); 
		// zum einsatz kommt derselbe schlüssel, daher symmetrische verschlüsselung
		// achtung: hier wird der DECRYPT_MODE = entschlüsselung genutzt
		aesCipherDec.init(Cipher.DECRYPT_MODE, keySpec);
		// nun wird der ciphertext wieder entschlüsselt
		decryptedtextByte = aesCipherDec.doFinal(ciphertextByte);
		
		// zurück-kodierung des byte array in text
		decryptedtextString = new String(decryptedtextByte,"UTF-8");
		
		// ausgabe der variablen
		System.out.println("");
		System.out.println("keyByte (hex)          :" + DatatypeConverter.printHexBinary(keyByte));
		System.out.println("plaintextString        :" + plaintextString);
		System.out.println("plaintextByte (hex)    :" + DatatypeConverter.printHexBinary(plaintextByte));
		System.out.println("= = = Verschlüsselung = = =");
		System.out.println("ciphertextByte (hex)   :" + DatatypeConverter.printHexBinary(ciphertextByte));
		System.out.println("= = = Entschlüsselung = = =");
		System.out.println("decryptedtextByte (hex):" + DatatypeConverter.printHexBinary(decryptedtextByte));
		System.out.println("decryptedtextString    :" + decryptedtextString);
	}

}
