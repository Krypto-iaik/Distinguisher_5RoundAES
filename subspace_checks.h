#ifndef __SUBSPACE_CHECKS_H__
#define __SUBSPACE_CHECKS_H__

int belongToU(const word8 p[4][4]);
int belongToV(const word8 p[4][4]);
int belongToW(const word8 p[4][4]);
int belongToW1(word8 p[][4]);
int belongToW2(word8 p[][4]);
int belongToW3(word8 p[][4]);
int belongToW4(word8 p[][4]);
int belongToW_2(word8 p[][4], int coset);

#endif // __SUBSPACE_CHECKS_H__
