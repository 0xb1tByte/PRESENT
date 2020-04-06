#ifndef __CRYPTO_H
#define __CRYPTO_H

#include <msp430.h> 
#include <driverlib.h> 
#include <string.h>
 #include <stdint.h>
 #include <stdbool.h>


// Define basic parameters
#define CRYPTO_IN_SIZE  8 	// Present has 64-bit blocks
#define CRYPTO_KEY_SIZE 10  // Present has 80-bit key
#define CRYPTO_OUT_SIZE 8   // Present has 64-bit blocks

// Block size in bit
#define CRYPTO_IN_SIZE_BIT (CRYPTO_IN_SIZE * 8)

// Do 16-bit bitslicing
#define BITSLICE_WIDTH 16

// Bitslicing register typedef
// The C programming language provides a keyword called typedef, which you can use to give a type a new name
typedef uint16_t bs_reg_t;

/// main functions 
static void enslice(const uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH], bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT]);
static void unslice(const bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT], uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH]);
void pbox_layer(bs_reg_t s[CRYPTO_IN_SIZE_BIT]);
void sbox_layer(bs_reg_t s[CRYPTO_IN_SIZE_BIT]);
bs_reg_t sbox1(bs_reg_t in0, bs_reg_t in1, bs_reg_t in2, bs_reg_t in3);
bs_reg_t sbox2(bs_reg_t in0, bs_reg_t in1, bs_reg_t in2, bs_reg_t in3);
bs_reg_t sbox3(bs_reg_t in0, bs_reg_t in1, bs_reg_t in2, bs_reg_t in3);
void crypto_func(uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH], uint8_t key[CRYPTO_KEY_SIZE]);
static void add_round_key(bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT], uint8_t roundkey[CRYPTO_IN_SIZE]);
static void update_round_key(uint8_t key[CRYPTO_KEY_SIZE], const uint8_t r);
uint8_t getBitForEnslice(uint8_t state  , uint8_t bitPosition);
uint16_t getBitForUnslice(uint16_t state  , uint8_t bitPosition);
uint16_t getBitFor16 (uint16_t state  , uint16_t bitPosition);
uint16_t copyBit(uint16_t state , int bitPosition , uint8_t bitValue);

#endif

