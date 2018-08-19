/*============================================================================*/
/* freq_analyzer.h                                                            */
/*                                                                            */
/* CLASSE QUE COMPUTA A FREQUÊNCIA DE CARACTERES EM UM TEXTO, COMPARA COM A   */
/* FREQUÊNCIA NORMAL PARA A LÍNGUA PORTUGUESA, E "QUEBRA" A CHAVE USADA PARA  */
/* CIFRAR O TEXTO (CIFRA DE CÉSAR).                                           */
/*============================================================================*/
/* Autor: Victor Barpp Gomes                                                  */
/*                                                                            */
/* 2018-08-16                                                                 */
/*============================================================================*/
/** Esta classe apenas implementa o cálculo de frequência de caracteres e
 *  a comparação com as frequências normalmente encontradas para aquela
 *  linguagem.
 *  A contagem não é case-sensitive, e não considera caracteres que não sejam
 *  letras. */
/*============================================================================*/

#include "freq_analyzer.h"

#include <iostream>
#include <string>

/*============================================================================*/

using namespace std;

/*============================================================================*/

FreqAnalyzer::FreqAnalyzer() {
	fill(charCount, charCount + (2*LETTER_COUNT + NUMBER_COUNT), 0);
	fill(charFreq, charFreq + (2*LETTER_COUNT + NUMBER_COUNT), 0);
	totalCount = 0;
}

/*----------------------------------------------------------------------------*/

void FreqAnalyzer::feed(std::string& str) {
	for (char& c : str) {
		// Converte char -> índice
		short index = CaesarCipher::charToIndex(c);

		// Incrementa vetor no índice e contagem total
		if (index > 0) {
			++charCount[index];
			++totalCount;
		}
	}
}

/*----------------------------------------------------------------------------*/

void FreqAnalyzer::computeFrequencies() {
	for (short i = 0; i < 2*LETTER_COUNT + NUMBER_COUNT; ++i) {
		charFreq[i] = (float) charCount[i] / totalCount;
	}
}

/*----------------------------------------------------------------------------*/

void FreqAnalyzer::printFrequencies() {
	for (short i = 0; i < 2*LETTER_COUNT + NUMBER_COUNT; ++i) {
		cout << CaesarCipher::indexToChar(i) << ": ";
		cout << charFreq[i] << endl;
	}
}

/*----------------------------------------------------------------------------*/

short FreqAnalyzer::findKey() {
	bool start = true;

	// Encontra o caractere (cifrado) mais frequente
	unsigned int mostFreqCount;
	short mostFreqIndex;
	for (short i = 0; i < 2*LETTER_COUNT + NUMBER_COUNT; ++i) {
		if (start) {
			start = false;
			mostFreqCount = charCount[i];
			mostFreqIndex = i;
			continue;
		}
		if (mostFreqCount < charCount[i]) {
			mostFreqCount = charCount[i];
			mostFreqIndex = i;
		}
	}

	// Agora consideramos que o caractere mais frequente é o 'a'
	return mostFreqIndex - CaesarCipher::charToIndex('a');
}

/*============================================================================*/
