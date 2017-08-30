#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "AES_common.h"
#include "AES_smallScale_sbox.h"
#include "multiplication.h"

word8 randomByte2(){
  return (word8) randomInRange(0, 15);
}

//EXAMPLE encryption

int main(){

  //plaintext
  const word8 initialMessage[4][4] = {
    0x0, 0x4, 0x8, 0xc,
    0x1, 0x5, 0x9, 0xd,
    0x2, 0x6, 0xa, 0xe,
    0x3, 0x7, 0xb, 0xf
  };

  //key
  const word8 initialKey[4][4] = {
    0x00, 0x04, 0x08, 0x0c,
    0x01, 0x05, 0x09, 0x0d,
    0x02, 0x06, 0x0a, 0x0e,
    0x03, 0x07, 0x0b, 0x0f
  };

  word8 ciphertext[4][4];

  encryption(initialMessage, initialKey, ciphertext);

  printf("plaintext\n");
  printtt(initialMessage);
  printf("\n");

  printf("key\n");
  printtt(initialKey);
  printf("\n");

  printf("ciphertext\n");
  printtt(ciphertext);
  printf("\n");

  return 0;

}
