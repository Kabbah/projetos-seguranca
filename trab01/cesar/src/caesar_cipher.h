/*============================================================================*/
/* caesar_cipher.h                                                            */
/*                                                                            */
/* CLASSE QUE IMPLEMENTA A CIFRA DE CÉSAR                                     */
/*============================================================================*/
/* Autor: Victor Barpp Gomes                                                  */
/*                                                                            */
/* 2018-08-15                                                                 */
/*============================================================================*/
/** Esta classe apenas implementa a cifra de César. */
/*============================================================================*/

#ifndef __CAESAR_CIPHER_H
#define __CAESAR_CIPHER_H

/*============================================================================*/

#define LETTER_COUNT 26
#define NUMBER_COUNT 10

/*============================================================================*/

class CaesarCipher {
public:
	CaesarCipher(short key);

	char cipherChar(char c);
	char decipherChar(char c);
	
	static short charToIndex(char c);
	static char indexToChar(short index);
	
private:
	short key;
};

/*============================================================================*/

#endif // __CAESAR_CIPHER_H
