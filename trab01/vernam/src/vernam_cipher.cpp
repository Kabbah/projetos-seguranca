/*============================================================================*/
/* vernam_cipher.cpp                                                          */
/*                                                                            */
/* CLASSE QUE IMPLEMENTA A CIFRA DE VERNAM                                    */
/*============================================================================*/
/* Autor: Victor Barpp Gomes                                                  */
/*                                                                            */
/* 2018-08-15                                                                 */
/*============================================================================*/
/** Esta classe apenas implementa a cifra de Vernam. */
/*============================================================================*/

#include "vernam_cipher.h"

#include <cstdlib>
#include <ctime>
#include <iostream>
#include <fstream>

using namespace std;

/*============================================================================*/

VernamCipher::VernamCipher(int keySize) : key(keySize) {
	// Gera uma chave randômica
	srand(time(NULL));
	for (int i = 0; i < key.size(); ++i) {
		key[i] = rand() & 0xFF;
	}
}

/*----------------------------------------------------------------------------*/

VernamCipher::VernamCipher(std::string filename) {
	// Abre o arquivo (leitura)
	ifstream keyFile;
	keyFile.open(filename, ios::in | ios::binary);
	
	// Preenche o vetor interno com os bytes do arquivo
	if (!keyFile.eof() && !keyFile.fail()) {
		// Redimensiona o vetor
		keyFile.seekg(0, ios_base::end);
		streampos fileSize = keyFile.tellg();
		key.resize(fileSize);
		
		// Agora lê
		keyFile.seekg(0, ios_base::beg);
		keyFile.read(&key[0], fileSize);
	}
}

/*----------------------------------------------------------------------------*/

void VernamCipher::saveKeyToFile(std::string filename) {
	// Abre o arquivo (escrita)
	ofstream keyFile;
	keyFile.open(filename, ios::out | ios::binary);
	keyFile.write(&key[0], key.size() * sizeof(char));
	keyFile.close();
}

/*----------------------------------------------------------------------------*/

void VernamCipher::cipherBytes(vector<char> input, vector<char>& output) {
	for (int i = 0; i < input.size(); ++i) {
		output[i] = input[i] ^ key[i];
	}
}

/*----------------------------------------------------------------------------*/

void VernamCipher::decipherBytes(vector<char> input, vector<char>& output) {
	for (int i = 0; i < input.size(); ++i) {
		output[i] = input[i] ^ key[i];
	}
}

/*----------------------------------------------------------------------------*/

unsigned int VernamCipher::getKeySize() {
	return key.size();
}

/*============================================================================*/
