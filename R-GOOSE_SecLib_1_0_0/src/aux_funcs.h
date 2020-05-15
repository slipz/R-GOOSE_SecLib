/**
 * @file aux_funcs.h
 * @author Eduardo Andrade
 * @date Mar 2020
 * @brief File containing auxiliary functions.
 * 
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

/**
 * @brief Function that converts an hexadecimal string to a byte array.
 * 
 * This function receives an hexadecimal string (<tt>char[]</tt>@p hex) and returns a pointer 
 * to a byte array (<tt>uint8_t*</tt>). 
 *
 * Below is and example of usage:
 * @code
 *
 * char keyHex[] = "219bcef0cd0f89a5e1297b99d956150f3128459f65312fdd71618f1177393e3f";
 * uint8_t* key = hexStringToBytes(keyHex, 64);
 *
 * @endcode
 *
 * @param hex Pointer (<tt>char[]</tt>) containg the hexadecimal string
 * @param len Variable (<tt>size_t</tt>) containg the length of the string 
 * @return The function returns a pointer to the byte array
 */
uint8_t* hexStringToBytes(char hex[], size_t len);

/**
 * @brief Function that encodes an Integer into 4 bytes on a given buffer, at a specific index.
 * 
 * This function receives the target buffer (@p buffer) and position (@p index), and encodes the value (@p value)
 * in 4 bytes, starting from the given position. No input validation is done. 
 *
 * Below is and example of usage:
 * @code
 *
 * int timeOfCurrentKey;
 * 
 * encodeInt4Bytes(buffer,timeOfCurrentKey,INDEX_TIMECURKEY);
 *
 * @endcode
 *
 * @param buffer Pointer (<tt>uint8_t*</tt>) containg the target buffer
 * @param value Variable (<tt>uint32_t</tt>) containg the value to be encoded 
 * @param index Variable (<tt>int</tt>) containg the starting index of buffer where the value should be enconded
 * @return The function doesn't return any value
 * @warning This functions doesn't perform any kind of input validation, more precisely on @p value and @p index. 
 */
void encodeInt4Bytes(uint8_t* buffer, uint32_t value, int index);


/**
 * @brief Function that encodes an Integer into 2 bytes on a given buffer, at a specific index.
 * 
 * This function receives the target buffer (@p buffer) and position (@p index), and encodes the value (@p value)
 * in 2 bytes, starting from the given position. No input validation is done. 
 *
 * Below is and example of usage:
 * @code
 *
 * int timeToNextKey;
 * 
 * encodeInt2Bytes(buffer,timeToNextKey,INDEX_TIMENEXTKEY);
 *
 * @endcode
 *
 * @param buffer Pointer (<tt>uint8_t*</tt>) containg the target buffer
 * @param value Variable (<tt>uint16_t</tt>) containg the value to be encoded 
 * @param index Variable (<tt>int</tt>) containg the starting index of buffer where the value should be enconded
 * @return The function doesn't return any value
 * @warning This functions doesn't perform any kind of input validation, more precisely on @p value and @p index. 
 */
void encodeInt2Bytes(uint8_t* buffer, uint16_t value, int index);


/**
 * @brief Function that decodes 4 bytes from a specific index to an integer.
 * 
 * This function receives the target buffer (@p buffer) and position (@p index), and decodes the value the following
 * 4 bytes, returning its value as an integer. 
 *
 * Below is and example of usage:
 * @code
 *
 * int timeOfCurrentKey;
 * 
 * timeOfCurrentKey = decode_4bytesToInt(buffer, INDEX_TIMECURKEY);
 *
 * @endcode
 *
 * @param buffer Pointer (<tt>uint8_t*</tt>) containg the target buffer
 * @param index Variable (<tt>int</tt>) containg the starting index of buffer from where the integer should be decoded
 * @return The function returns an integer containing the value decoded
 * @warning This functions doesn't perform any kind of input validation, more precisely on @p index. 
 */
int decode_4bytesToInt(uint8_t* buffer, int index);


/**
 * @brief Function that decodes 2 bytes from a specific index to an integer.
 * 
 * This function receives the target buffer (@p buffer) and position (@p index), and decodes the value the following
 * 2 bytes, returning its value as an integer. 
 *
 * Below is and example of usage:
 * @code
 *
 * int timeToNextKey;
 * 
 * timeToNextKey = decode_2bytesToInt(buffer, INDEX_TIMENEXTKEY);
 *
 * @endcode
 *
 * @param buffer Pointer (<tt>uint8_t*</tt>) containg the target buffer
 * @param index Variable (<tt>int</tt>) containg the starting index of buffer from where the integer should be decoded
 * @return The function returns an integer containing the value decoded
 * @warning This functions doesn't perform any kind of input validation, more precisely on @p index. 
 */
int decode_2bytesToInt(uint8_t* buffer, int index);

