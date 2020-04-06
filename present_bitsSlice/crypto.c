#include "crypto.h"

#define SBOXOPTIMIZED

/**
 * Bring normal buffer into bitsliced form
 * @param pt Input: state_bs in normal form
 * @param state_bs Output: Bitsliced state
 */

uint8_t getBitForEnslice(uint8_t state  , uint8_t bitPosition)
{
return (state >> bitPosition ) & 0x1;
} // end getBit

uint16_t getBitForUnslice(uint16_t state  , uint8_t bitPosition)
{
return (state >> bitPosition ) & 0x1;
} // end getBitForUnslice

uint16_t copyBit(uint16_t state , int bitPosition , uint8_t bitValue)
{
    uint16_t mask = ~(1 << bitPosition);
    state = (state & mask); // clear bit
    return (state | ((bitValue << bitPosition)));
} // end copyBit

// =============== Enslice =============== //

static void enslice(const uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH], bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT])
{
     uint16_t i = 0;
     uint16_t j = 0;
     uint8_t getBitValue = 0; // to store the bit value
     uint8_t bitInByte =0; // to count bits in each Byte , 0-7
     uint8_t ByteInPlainText =0; // to count Byte in each PlainText , 0-7
     uint8_t * pointer; // This pointer is for poiting for the processed Byte in the PlainText

    for (;i < BITSLICE_WIDTH;i++) // looping over each PlainText , 16 times
    {   
    pointer = &pt[i*CRYPTO_IN_SIZE]; // set pointer to the location allocated for the value of first element in each PlainText
    for (;j < CRYPTO_IN_SIZE_BIT ;j++) // looping over each element of state_bs , 64 times
    {
                getBitValue = getBitForEnslice(*pointer,bitInByte); 
                state_bs[j] = copyBit(state_bs[j],i,getBitValue);     
                bitInByte++; // incrementing the counter to get the position of the next bit in the Byte
                 if (bitInByte == 8)  // if we reach the max bits in 1 Byte, move the pointer to the next Byte
                 {
                    pointer = &pt[ByteInPlainText+1]; // Moving the Pointer to the next Byte in the Plaintext
                    bitInByte = 0;  // set the counter to 0 to start counting bits for the next Byte in the PlainText
                    ByteInPlainText++; // increment the Byte Counter
                  } 
    } // end inner for   
        j = 0; // resetting j to 0 to start copying for the second row in state_bs
       pointer = &pt[i*8];  // re-setting the pointer to the first Byte in the current PlainText
    }  // end outer for 
}

// =============== Unslice =============== //
/**
 * Bring bitsliced buffer into normal form
 * @param state_bs Input: Bitsliced state
 * @param pt Output: state_bs in normal form
 */
static void unslice(const bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT], uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH])
{
     uint16_t i = 0;
     uint16_t j = 0;
     uint8_t getBitValue = 0; // to store the bit value
     uint8_t bitInByte =0; // to count bits in each Byte , 0-7
     uint8_t ByteInPlainText =0; // to count Byte in each PlainText , 0-7
     uint8_t * pointer; // This pointer is for poiting for the processed Byte in the PlainText
    
     for (;i < BITSLICE_WIDTH;i++) // looping over each PlainText , 16 times
    {
    pointer = &pt[i*CRYPTO_IN_SIZE]; // set pointer to the location allocated for the value of first element in each PlainText
	    for (;j < CRYPTO_IN_SIZE_BIT ;j++) // looping over each element of state_bs , 64 times 
	    { 
			getBitValue = getBitForUnslice(state_bs[j],i); 
			pt[ByteInPlainText] = copyBit(pt[ByteInPlainText],bitInByte,getBitValue);  
			bitInByte++; // incrementing the counter to get the position of the next bit in the Byte
			 if (bitInByte == 8)  // if we reach the max bits in 1 Byte, move the pointer to the next Byte
			 {
			    pointer = &pt[ByteInPlainText+1]; // Moving the Pointer to the next Byte in the Plaintext
			    bitInByte = 0;  // set the counter to 0 to start counting bits for the next Byte in the PlainText
			    ByteInPlainText++; // increment the Byte Counter
			  } 
	    } // end inner for   
        j = 0; // resetting j to 0 to start copying for the second row in state_bs
       pointer = &pt[i*8];  // re-setting the pointer to the first Byte in the current PlainText
    }  // end outer for     
}



// =============== Key Addition Layer =============== //
static void add_round_key(bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT], uint8_t roundkey[CRYPTO_IN_SIZE])
{
    uint16_t lut[2] = {0x0000, 0xFFFF}; 
    int temp = 0;
    uint8_t bitInByte =0; // to count bits in each Byte , 0-7
    uint8_t ByteInPlainText =0; // to count Byte in each PlainText , 0-7
    uint8_t * pointer; // This pointer is for poiting for the processed Byte in the key
    pointer = &roundkey[0]; // set pointer to the location allocated for the value of first element in the roundkey
	uint8_t i;
    for (i = 0;i<CRYPTO_IN_SIZE_BIT;i++)
    {
        temp = getBitForEnslice(*pointer,bitInByte);
        state_bs[i] = state_bs[i] ^ lut[temp];
        bitInByte++;
        if (bitInByte == 8) 
        {  pointer = &roundkey[ByteInPlainText+1]; // Moving the Pointer to the next Byte in the key
            bitInByte = 0;  // set the counter to 0 to start counting bits for the next Byte in the key
            ByteInPlainText++; // increment the Byte Counter
        } 
    } // end for 
} // end  add_round_key

// =============== Permutations Layer ================ //
void pbox_layer(bs_reg_t s[CRYPTO_IN_SIZE_BIT])
{
	bs_reg_t state_out[CRYPTO_IN_SIZE_BIT];
	uint8_t iNew;
	uint8_t i = 0;
	for (; i < CRYPTO_IN_SIZE_BIT; i++) {
		iNew =  (uint8_t)(i/4) + (i % 4) * 16;
		state_out[iNew] = s[i];
	}
	for (i = 0;i < CRYPTO_IN_SIZE_BIT; i++) {
		s[i] = state_out[i];
	}
}

// ================= S-Box Layer ================== //
/*
 * The PRESENT S-Box in Hexadecimal notation
 ------------------------------------------------------------------------
x ======> 0 || 1 || 2 || 3 || 4 || 5 || 6 || 7 || 8 || 9 || A || B || C || D || E || F 
s[x] ====> C || 5 || 6 || B || 9 || 0 || A || D || 3 || E || F || 8 || 4 || 7 || 1 || 2    
-------------------------------------------------------------------------
 */
 
 // This is 4-bits S-box
static const uint8_t sbox[16] = 
{
	0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
};


static void sbox_layer(uint8_t s[CRYPTO_IN_SIZE])
{
    
     uint8_t lower_nibble;
     uint8_t upper_nibble;
     for (uint8_t i = 0;i<8;i++)
    {
        lower_nibble = s[i] & 0xF;
        upper_nibble = (s[i] >> 4 ) & 0xF;
        s[i] = sbox[lower_nibble] | (sbox[upper_nibble] << 4 );
    } 
}

// ================= Key Schedule ================== //

/**
 * Perform next key schedule step
 * @param key Key register to be updated
 * @param r Round counter
 * @warning For correct function, has to be called with incremented r each time
 * @note You are free to change or optimize this function
 */
static void update_round_key(uint8_t key[CRYPTO_KEY_SIZE], const uint8_t r)
{
	const uint8_t sbox[16] = {
		0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
	};

	uint8_t tmp = 0;
	const uint8_t tmp2 = key[2];
	const uint8_t tmp1 = key[1];
	const uint8_t tmp0 = key[0];
	
	// rotate right by 19 bit
	key[0] = key[2] >> 3 | key[3] << 5;
	key[1] = key[3] >> 3 | key[4] << 5;
	key[2] = key[4] >> 3 | key[5] << 5;
	key[3] = key[5] >> 3 | key[6] << 5;
	key[4] = key[6] >> 3 | key[7] << 5;
	key[5] = key[7] >> 3 | key[8] << 5;
	key[6] = key[8] >> 3 | key[9] << 5;
	key[7] = key[9] >> 3 | tmp0 << 5;
	key[8] = tmp0 >> 3   | tmp1 << 5;
	key[9] = tmp1 >> 3   | tmp2 << 5;
	
	// perform sbox lookup on MSbits
	tmp = sbox[key[9] >> 4];
	key[9] &= 0x0F;
	key[9] |= tmp << 4;
	
	// XOR round counter k19 ... k15
	key[1] ^= r << 7;
	key[2] ^= r >> 1;
}

// ==================== Encryption ==================== //

void crypto_func(uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH], uint8_t key[CRYPTO_KEY_SIZE])
{
	// State buffer and additional backbuffer of same size (you can remove the backbuffer if you do not need it)
	bs_reg_t state[CRYPTO_IN_SIZE_BIT];
	
	// Bring into bitslicing form
	enslice(pt, state);
	
 uint8_t i = 0;
    for(i = 1; i <= 31; i++)
    {
        // Note +2 offset on key since output of keyschedule are upper 8 byte
        add_round_key(state, key + 2); 
        sbox_layer(state);
        pbox_layer(state);
        update_round_key(key, i);
    }
    // Note +2 offset on key since output of keyschedule are upper 8 byte
    add_round_key(state, key + 2);
	
	// Convert back to normal form
	unslice(state, pt);
}
