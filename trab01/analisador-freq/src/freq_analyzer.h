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
 *  linguagem. */
/*============================================================================*/

#ifndef __FREQ_ANALYZER_H
#define __FREQ_ANALYZER_H

/*============================================================================*/

#include "caesar_cipher.h"

#include <string>

/*============================================================================*/

class FreqAnalyzer {
public:
	FreqAnalyzer();

	void feed(std::string str);
	void computeFrequencies();
	void printFrequencies();
	short findKey();
	
private:
	unsigned int charCount[2*LETTER_COUNT + NUMBER_COUNT];
	float charFreq[2*LETTER_COUNT + NUMBER_COUNT];
	unsigned int totalCount;
};

/*============================================================================*/

#endif // __FREQ_ANALYZER_H
