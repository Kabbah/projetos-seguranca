/*============================================================================*/
/* main_analisador_freq.cpp                                                   */
/*                                                                            */
/* PROGRAMA QUE IMPLEMENTA UM "QUEBRADOR" DE CHAVE DO CIFRADOR DE CÉSAR,      */
/* UTILIZANDO UM ANALISADOR DE FREQUÊNCIA DE CARACTERES                       */
/*============================================================================*/
/* Autor: Victor Barpp Gomes                                                  */
/*                                                                            */
/* 2018-08-15                                                                 */
/*============================================================================*/
/** Este programa computa a frequência de cada caractere em um texto cifrado
 *  por Cifra de César e identifica qual chave foi utilizada, a partir de uma
 *  tabela de frequências das letras na Língua Portuguesa.
 *
 *  Uso: analisador-freq < texto1 > texto2
 *
 *  É necessário usar < para input e > para output. */
/*============================================================================*/

#include "caesar_cipher.h"
#include "freq_analyzer.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <unistd.h>
#include <vector>

using namespace std;

/*============================================================================*/

int main(int argc, char* argv[]) {
	// Cria o analisador de frequência
	FreqAnalyzer freq;

	// Guarda as linhas em um vetor para decifrar depois
	vector<string> text;

	for (string line; getline(cin, line);) {
		text.push_back(line);
		freq.feed(line);
	}

	freq.computeFrequencies();
	freq.printFrequencies();

	short key = freq.findKey();	
	cout << endl << "Chave: " << key << endl << endl;

	CaesarCipher cesar(key);	

	for (string& str : text) {
		for (char& c : str) {
			cout << cesar.decipherChar(c);
		}
		cout << endl;
	}

	return 0;
}

/*============================================================================*/
