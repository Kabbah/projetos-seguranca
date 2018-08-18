/*============================================================================*/
/* caesar_cipher.cpp                                                          */
/*                                                                            */
/* CLASSE QUE IMPLEMENTA A CIFRA DE CÉSAR                                     */
/*============================================================================*/
/* Autor: Victor Barpp Gomes                                                  */
/*                                                                            */
/* 2018-08-15                                                                 */
/*============================================================================*/
/** Esta classe apenas implementa a cifra de César. */
/*============================================================================*/

#include "caesar_cipher.h"

using namespace std;

/*============================================================================*/

CaesarCipher::CaesarCipher(short key) {
	this->key = key;
	
	// Apenas corrige chaves negativas
	while (this->key < 0) {
		this->key += 2*LETTER_COUNT + NUMBER_COUNT;
	}
}

/*----------------------------------------------------------------------------*/

char CaesarCipher::cipherChar(char c) {
	// Calcula o índice dentro do intervalo [A-Z] U [a-z] U [0-9]
	short index = charToIndex(c);
	
	if (index >= 0) {
		// Soma a chave ao índice
		index += key;
		index %= (2*LETTER_COUNT + NUMBER_COUNT);
		
		return indexToChar(index);
	}
	
	// Retorna o mesmo caractere se não estiver no intervalo (ex: CR, LF)
	return c;
}

/*----------------------------------------------------------------------------*/

char CaesarCipher::decipherChar(char c) {
	// Calcula o índice dentro do intervalo [A-Z] U [a-z] U [0-9]
	short index = charToIndex(c);
	
	if (index >= 0) {
		// Subtrai a chave do índice
		index -= key;
		if (index < 0) {
			index += 2*LETTER_COUNT + NUMBER_COUNT;
		}
		index %= (2*LETTER_COUNT + NUMBER_COUNT);
		
		return indexToChar(index);
	}
	
	// Retorna o mesmo caractere se não estiver no intervalo (ex: CR, LF)
	return c;
}

/*----------------------------------------------------------------------------*/

short CaesarCipher::charToIndex(char c) {
	// Converte o caractere em um número (índice) resultante da enumeração dos
	// caracteres no intervalo [A-Z] U [a-z] U [0-9].
	if (c >= 'A' && c <= 'Z') {
		return (short) c - 'A';
	}
	if (c >= 'a' && c <= 'z') {
		return (short) c + LETTER_COUNT - 'a';
	}
	if (c >= '0' && c <= '9') {
		return (short) c + 2*LETTER_COUNT - '0';
	}
	
	// Retorna -1 se não estiver no intervalo (ex: CR, LF)
	return -1;
}

/*----------------------------------------------------------------------------*/

char CaesarCipher::indexToChar(short index) {
	// Volta de índice para caractere
	if (index < LETTER_COUNT) {
		return (char) index + 'A';
	}
	if (index < 2*LETTER_COUNT) {
		return (char) (index-LETTER_COUNT) + 'a';
	}
	if (index < 2*LETTER_COUNT + NUMBER_COUNT) {
		return (char) (index-2*LETTER_COUNT) + '0';
	}
	
	// Retorna o caractere 0 se não está no intervalo (ex: CR, LF)
	return (char) 0;
}

/*============================================================================*/
