#ifndef __CRYPTO_H

#define __CRYPTO_H



//#include <msp430.h>

#include <string.h> 
#include <stdint.h> //Not quite sure if we need this, but I needed this when running the c program on the computer.

//#include <driverlib.h>


/*
 *  In the C Programming Language, the #define directive allows the definition of macros within your source code. 
 * These macro definitions allow constant values to be declared for use throughout your code.
 * Macro definitions are not variables and cannot be changed by your program code like variables. 
 * You generally use this syntax when creating constants that represent numbers, strings or expressions.
 */
 
 // Define basic parameters

#define CRYPTO_IN_SIZE  8 	// PRESENT has 64-bit blocks

#define CRYPTO_KEY_SIZE 10  // PRESENT has 80-bit key

#define CRYPTO_OUT_SIZE 8   // PRESENT has 64-bit blocks



// The function to test
/*
 * pt ==> plainText
 * key ==> key =P
 * unit_8 ==> unit_8 is an unsigned integer with 8 bits 
 * unit_8 pt [8] ==> array of 8 elements of type unit_8 ( 8*8 = 64 bits, which is the size of the PlainText)
 * unit_8 key [10] ==> array of 10 elements of type unit_8 ( 10 * 8 = 80 bits , which is the size of the PRESENT's Key)
 */
 
 /* This function is doing the whole crypto stuff by calling the inner functions for PRESENT such that: 
      1- Loop 32 times: 
                                    add_round_key(pt, key);
                                    sbox_layer(pt);
                                    pbox_layer(pt);
                                    update_round_key(key);
        2- add_round_key(pt, key);
  * */
void crypto_func(uint8_t pt[CRYPTO_IN_SIZE], uint8_t key[CRYPTO_KEY_SIZE]);



#endif
