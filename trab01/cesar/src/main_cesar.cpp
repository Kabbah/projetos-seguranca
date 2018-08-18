/*============================================================================*/
/* main_cesar.cpp                                                             */
/*                                                                            */
/* PROGRAMA QUE IMPLEMENTA UM CIFRADOR E DECIFRADOR DE CÉSAR                  */
/*============================================================================*/
/* Autor: Victor Barpp Gomes                                                  */
/*                                                                            */
/* 2018-08-15                                                                 */
/*============================================================================*/
/** Este programa executa a cifra de César em um arquivo de texto.
 *  Uso: cesar [-c|-d] -k number < texto1 > texto2
 *
 *  É necessário usar < para input e > para output.
 *
 *  Argumentos:
 *    -c           Cifra texto1 e salva o texto cifrado em texto2.
 *    -d           Decifra texto1 e salva o texto decifrado em texto2.
 *    -k number    Especifica o número a utilizar como chave. */
/*============================================================================*/

#include "caesar_cipher.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <unistd.h>

using namespace std;

/*============================================================================*/

int main(int argc, char* argv[]) {
	// Verifica número de argumentos
	if (argc != 4) {
		cerr << "Uso: cesar [-c|-d] -k number < texto1 > texto2" << endl;
		cerr << "Argumentos:" << endl;
		cerr << "  -c           Cifra texto1 e salva o texto cifrado em texto2." << endl;
		cerr << "  -d           Decifra texto1 e salva o texto decifrado em texto2." << endl;
		cerr << "  -k number    Especifica o número a utilizar como chave." << endl;
		return -1;
	}

	bool cipher = false;
	bool decipher = false;
	unsigned short key = 0;

	// Processa argumentos
	int opt;
	while ((opt = getopt(argc, argv, "cdk:")) != -1) {
		switch (opt) {
		case 'c':
			cipher = true;
			break;
		case 'd':
			decipher = true;
			break;
		case 'k':
			key = std::atoi(optarg);
			break;
		}
	}

	// Verifica entradas inválidas
	if (!cipher && !decipher) {
		cerr << "Erro: Não foi fornecida uma das opções obrigatórias -c ou -d." << endl;
		return -1;
	}
	if (cipher && decipher) {
		cerr << "Erro: foram fornecidas ambas as opções -c e -d. Forneça apenas uma delas." << endl;
		return -1;
	}

	// Cria o cifrador
	CaesarCipher cesar(key);

	for (string line; getline(cin, line); cout << endl) {
		for (char& c : line) {
			if (cipher) {
				cout << cesar.cipherChar(c);
			}
			else if (decipher) {
				cout << cesar.decipherChar(c);
			}
		}
	}

	return 0;
}

/*============================================================================*/
