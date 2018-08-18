/*============================================================================*/
/* vernam_cipher.h                                                            */
/*                                                                            */
/* CLASSE QUE IMPLEMENTA A CIFRA DE VERNAM                                    */
/*============================================================================*/
/* Autor: Victor Barpp Gomes                                                  */
/*                                                                            */
/* 2018-08-16                                                                 */
/*============================================================================*/
/** Esta classe apenas implementa a cifra de Vernam. */
/*============================================================================*/

#ifndef __VERNAM_CIPHER_H
#define __VERNAM_CIPHER_H

/*============================================================================*/

#include <string>
#include <vector>

/*============================================================================*/

#define LETTER_COUNT 26
#define NUMBER_COUNT 10

/*============================================================================*/

class VernamCipher {
public:
	VernamCipher(int keySize);
	VernamCipher(std::string filename);

	void saveKeyToFile(std::string filename);
	
	void cipherBytes(std::vector<char> input, std::vector<char>& output);
	void decipherBytes(std::vector<char> input, std::vector<char>& output);
	
	unsigned int getKeySize();

private:
	std::vector<char> key;
};

/*============================================================================*/

#endif // __VERNAM_CIPHER_H
