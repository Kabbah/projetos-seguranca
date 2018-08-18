/*============================================================================*/
/* main_vernam.cpp                                                            */
/*                                                                            */
/* PROGRAMA QUE IMPLEMENTA UM CIFRADOR E DECIFRADOR DE VERNAM                 */
/*============================================================================*/
/* Autor: Victor Barpp Gomes                                                  */
/*                                                                            */
/* 2018-08-15                                                                 */
/*============================================================================*/
/** Este programa executa a cifra de Vernam em um arquivo de texto.
 *  Uso: vernam [-c|-d] chave.dat < texto1 > texto2
 *
 *  É necessário usar < para input e > para output.
 *
 *  Argumentos:
 *    -c           Cifra texto1 e salva o texto cifrado em texto2.
 *    -d           Decifra texto1 e salva o texto decifrado em texto2.
 *    chave.dat    Arquivo em que será salva a chave gerada aleatoriamente
 *                   (no caso do -c) ou de onde será importada a chave (no
 *                   caso do -d). */
/*============================================================================*/

#include "vernam_cipher.h"

#include <cstdlib>
#include <iostream>
#include <iterator>
#include <string>
#include <unistd.h>

using namespace std;

/*============================================================================*/

int main(int argc, char* argv[]) {
	// Verifica número de argumentos
	if (argc != 3) {
		cerr << "Uso: vernam [-c|-d] chave.dat < texto1 > texto2" << endl;
		cerr << "Argumentos:" << endl;
		cerr << "  -c           Cifra texto1 e salva o texto cifrado em texto2." << endl;
		cerr << "  -d           Decifra texto1 e salva o texto decifrado em texto2." << endl;
		cerr << "  chave.dat    Arquivo em que será salva a chave gerada aleatoriamente" << endl;
		cerr << "                 (no caso do -c) ou de onde será importada a chave (no" << endl;
		cerr << "                 caso do -d)." << endl;
		return -1;
	}

	bool cipher = false;
	bool decipher = false;
	string keyFile = "";

	// Processa argumentos
	int opt;
	while ((opt = getopt(argc, argv, "c:d:")) != -1) {
		switch (opt) {
		case 'c':
			cipher = true;
			keyFile = optarg;
			break;
		case 'd':
			decipher = true;
			keyFile = optarg;
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
	if (keyFile == "") {
		cerr << "Erro: não foi fornecido um nome de arquivo de chave." << endl;
		return -1;
	}

	// Lê o stdin
	cin >> noskipws; // Não ignora whitespace
	istream_iterator<char> it(cin);
	istream_iterator<char> end;
	vector<char> data(it, end);
	
	if (cipher) {
		// Cria um buffer para guardar o texto cifrado
		vector<char> ciphered(data.size());
		
		// Cria o cifrador (isso gera uma chave aleatória)
		VernamCipher vernam(data.size());
		
		// Cifra o texto
		vernam.cipherBytes(data, ciphered);
		
		// Guarda a chave no arquivo especificado
		vernam.saveKeyToFile(keyFile);
		
		// Agora fazemos cout em todos os caracteres
		for (int i = 0; i < ciphered.size(); ++i) {
			cout << ciphered[i];
		}
	}
	
	else {
		// Cria o cifrador com o arquivo de chave fornecido
		VernamCipher vernam(keyFile);
		
		// Confere o tamanho da chave
		if (vernam.getKeySize() < data.size()) {
			cerr << "Erro: a chave é menor que o texto" < endl;
			return -1;
		}
		
		vector<char> deciphered(data.size());
		
		vernam.decipherBytes(data, deciphered);
		
		// Agora fazemos cout em todos os caracteres
		for (int i = 0; i < deciphered.size(); ++i) {
			cout << deciphered[i];
		}
	}

	return 0;
}

/*============================================================================*/
