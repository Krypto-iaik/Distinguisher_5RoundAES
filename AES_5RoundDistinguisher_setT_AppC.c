
/**The Random Generator used in this code is the "Mersenne Twister" one, developed by 1997 by Makoto Matsumoto
and Takuji Nishimura - MT19937.
The complete source code of the random generator can be found in http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/CODES/mt19937ar.c
We also attach the following:
"A C-program for MT19937, with initialization improved 2002/1/26.
   Coded by Takuji Nishimura and Makoto Matsumoto.
   Before using, initialize the state by using init_genrand(seed)
   or init_by_array(init_key, key_length).
   Copyright (C) 1997 - 2002, Makoto Matsumoto and Takuji Nishimura,
   All rights reserved.
   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:
     1. Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.
     2. Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.
     3. The names of its contributors may not be used to endorse or promote
        products derived from this software without specific prior written
        permission.
   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   Any feedback is very welcome.
   http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
   email: m-mat @ math.sci.hiroshima-u.ac.jp (remove space)"
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "AES_common.h"
#include "AES_smallScale_sbox.h"
#include "multiplication.h"
#include "subspace_checks.h"

#define NUMBER_CP 65536
//number of cosets for each test
#define N_TEST 8
//number of test
#define numerbPROVE 32768
/**The results of the program are stored in .txt file.
The actual number of tests = initial cosets analyzed is: numerbPROVE * N_TEST
The results of the program are stored only when the number of tests is a multiple of N_TEST, that is for N_TEST = 256, after 256, 512, 768, 1024, ... tests*/

word8 play[NUMBER_CP][16], cipher[NUMBER_CP][16], initialplay[NUMBER_CP][16], initialCipher[NUMBER_CP][16], cipher2copy[NUMBER_CP][16], play2copy[NUMBER_CP][16];

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int logarithm2(long int n)
{
    long int i = 1;
    int j = 1;

    if (n<=0)
        return -1;

    if (n == 1)
        return 0;

    while(i<n)
    {
        i = i * 2;
        j++;
    }

    return j;

}

long int pow2(int n)
{
    long int i = 1;
    int j;

    if(n == 0)
        return 1;

    for(j=0; j<n;j++)
    {
        i = i * 2;
    }

    return i;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**Merge-Sort Algorithm*/

/*given two ciphertexts a and b, it returns 0 if a<=b (in the classical sense), 1 otherwise */
int lessOrEqual2(word8 a[], word8 b[])
{
    int i, aaa, bbb;

    for(i=0;i<16;i++)
    {
        aaa = (int) a[i];
        bbb = (int) b[i];

        if(aaa>bbb)
            return 1;

        if(aaa<bbb)
            return 0;
    }

    return 0;
}

/*given two ciphertexts a and b, it return 0 if a<=b, 1 otherwise */
int lessOrEqual(word8 a[], word8 b[], int coset)
{
    int i, temp, aaa, bbb;

    for(i=3;i>-1;i--)
    {
        temp = 4*coset - 3 * i;

        if(temp < 0)
            temp = temp + 16;

        aaa = (int) a[temp];
        bbb = (int) b[temp];

        if(aaa>bbb)
            return 1;

        if(aaa<bbb)
            return 0;
    }

    return lessOrEqual2(a, b);
}

double merging2(int low, int mid, int high, int coset, double numberTableLook) {

    int l1, l2, i, j;
    word8 text1[16], text2[16], tttext1[16], tttext2[16];

    l1 = low;
    l2 = mid;

    for(j = 0; j<16; j++)
    {
        text1[j] = cipher[l1][j];
        text2[j] = cipher[l2][j];

        tttext1[j] = play[l1][j];
        tttext2[j] = play[l2][j];
    }

    numberTableLook = numberTableLook + 2.0;

    for(i = low; ((l1 < mid) && (l2 < high)); i++)
    {
        numberTableLook = numberTableLook + 1.0;

        if(lessOrEqual(text1, text2, coset) == 0)
        {
            for(j = 0; j<16; j++)
            {
                cipher2copy[i][j] = text1[j];
                play2copy[i][j] = tttext1[j];
            }
            l1++;
            for(j = 0; j<16; j++)
            {
                text1[j] = cipher[l1][j];
                tttext1[j] = play[l1][j];
            }
        }
        else
        {
            for(j = 0; j<16; j++)
            {
                cipher2copy[i][j] = text2[j];
                play2copy[i][j] = tttext2[j];
            }
            l2++;
            for(j = 0; j<16; j++)
            {
                text2[j] = cipher[l2][j];
                tttext2[j] = play[l2][j];
            }
        }
    }

    while(l1 < mid)
    {
       numberTableLook = numberTableLook + 1.0;

       for(j = 0; j<16; j++)
        {
            cipher2copy[i][j] = cipher[l1][j];
            play2copy[i][j] = play[l1][j];
        }
        i++;
        l1++;
    }

    while(l2 < high)
    {
        numberTableLook = numberTableLook + 1.0;

       for(j = 0; j<16; j++)
        {
            cipher2copy[i][j] = cipher[l2][j];
            play2copy[i][j] = play[l2][j];
        }
        i++;
        l2++;
    }

    for(i = low; i < high; i++)
    {
        numberTableLook = numberTableLook + 1.0;

        for(j = 0; j<16; j++)
        {
            cipher[i][j] = cipher2copy[i][j];
            play[i][j] = play2copy[i][j];
        }
    }

    return numberTableLook;
}

double sort2(int coset, double numberTableLook)
{
    int log, i, j, division, high, low, middle, a, b;
    word8 t1[16], t2[16], ttt1[16], ttt2[16];

    log = logarithm2(NUMBER_CP);

    for(i=0; i<NUMBER_CP; i = i+2)
    {
        for(j=0;j<16;j++)
        {
            t1[j] = cipher[i][j];
            t2[j] = cipher[i+1][j];

            ttt1[j] = play[i][j];
            ttt2[j] = play[i+1][j];
        }

        numberTableLook = numberTableLook + 2.0;

        if(lessOrEqual(t1, t2, coset) == 1)
        {
            for(j=0;j<16;j++)
            {
                cipher[i][j] = t2[j];
                cipher[i+1][j] = t1[j];

                //Note: I re-order the plaintexts in the same way in which the ciphertexts are ordered!!!
                play[i][j] = ttt2[j];
                play[i+1][j] = ttt1[j];

            }

            numberTableLook = numberTableLook + 2.0;
        }
    }

    for(i = 2; i < log; i++)
    {
        a = pow2(i);
        b = a/2;
        division = NUMBER_CP / a;

        for(j = 0; j < division; j++)
        {
            high = a * (j+1);
            low = a * j;
            middle = low + b;

            numberTableLook = merging2(low, middle, high, coset, numberTableLook);

        }
    }

    return numberTableLook;

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


/**Random Function create as 30-round of AES*/
void randEncryption(word8 temp[][4], word8 key[][4], word8* c1)
{
    word8 temp2[4][4];
    int i, j;

    encryption(temp, key, &(temp2[0][0]));
    encryption(temp2, key, &(temp2[0][0]));
    encryption(temp2, key, &(temp2[0][0]));
    encryption(temp2, key, &(temp2[0][0]));
    encryption(temp2, key, &(temp2[0][0]));
    encryption(temp2, key, &(temp2[0][0]));


    for(i=0;i<4;i++)
    {
        for(j=0;j<4;j++)
            *(c1+j+4*i)=temp2[i][j];
    }

}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int leseq(word8 a[], word8 b[], word8 c[], word8 d[], int coset)
{
    int flag, i;

    flag = 1;

    for(i = 0; i<16; i++)
    {
        if(d[i] != b[i])
        {
            flag = 0;
        }
    }

    if(flag == 1)
       return lessOrEqual(a, c, coset);

    return lessOrEqual(b, d, coset);
}

/**Strategy not to count the same set more than a single time.
All the details can be found in the text - see Algorithm 2 for details.*/
double superTest(int indice1, int indice2, int coset)
{
    int set1[64], set2[64], index, i, p1[4], p2[4], j, k, l, indiceSet, flag, conttt;
    word8 test[4][4], c1[64][16], c2[64][16], ccc1[16], ccc2[16], ccc3[16], ccc4[16], temp;

    for(i = 0; i<4; i++)
    {
        p1[i] = (int) play[indice1][i];
        p2[i] = (int) play[indice2][i];
    }

    if(p1[0] == p2[0])
    {
        for(conttt = 0; conttt < 16; conttt++)
        {

            if(p1[0] == conttt)
            {
                indiceSet = 4*conttt;
            }

            //create the set S
            set1[0 + 4*conttt] = p1[3] + 16 * p1[2] + 256 * p1[1] + 4096 * conttt;
            set2[0 + 4*conttt] = p2[3] + 16 * p2[2] + 256 * p2[1] + 4096 * conttt;

            set1[1 + 4*conttt] = p2[3] + 16 * p1[2] + 256 * p1[1] + 4096 * conttt;
            set2[1 + 4*conttt] = p1[3] + 16 * p2[2] + 256 * p2[1] + 4096 * conttt;

            set1[2 + 4*conttt] = p1[3] + 16 * p2[2] + 256 * p1[1] + 4096 * conttt;
            set2[2 + 4*conttt] = p2[3] + 16 * p1[2] + 256 * p2[1] + 4096 * conttt;

            set1[3 + 4*conttt] = p1[3] + 16 * p1[2] + 256 * p2[1] + 4096 * conttt;
            set2[3 + 4*conttt] = p2[3] + 16 * p2[2] + 256 * p1[1] + 4096 * conttt;
        }
    }

    if(p1[1] == p2[1])
    {
        for(conttt = 0; conttt < 16; conttt++)
        {

            if(p1[1] == conttt)
            {
                indiceSet = 4*conttt;
            }

            //create the set S
            set1[0 + 4*conttt] = p1[3] + 16 * p1[2] + 256 * conttt + 4096 * p1[0];
            set2[0 + 4*conttt] = p2[3] + 16 * p2[2] + 256 * conttt + 4096 * p2[0];

            set1[1 + 4*conttt] = p2[3] + 16 * p1[2] + 256 * conttt + 4096 * p1[0];
            set2[1 + 4*conttt] = p1[3] + 16 * p2[2] + 256 * conttt + 4096 * p2[0];

            set1[2 + 4*conttt] = p1[3] + 16 * p2[2] + 256 * conttt + 4096 * p1[0];
            set2[2 + 4*conttt] = p2[3] + 16 * p1[2] + 256 * conttt + 4096 * p2[0];

            set1[3 + 4*conttt] = p1[3] + 16 * p1[2] + 256 * conttt + 4096 * p2[0];
            set2[3 + 4*conttt] = p2[3] + 16 * p2[2] + 256 * conttt + 4096 * p1[0];
        }
    }

    if(p1[2] == p2[2])
    {
        for(conttt = 0; conttt < 16; conttt++)
        {

            if(p1[2] == conttt)
            {
                indiceSet = 4*conttt;
            }

            //create the set S
            set1[0 + 4*conttt] = p1[3] + 16 * conttt + 256 * p1[1] + 4096 * p1[0];
            set2[0 + 4*conttt] = p2[3] + 16 * conttt + 256 * p2[1] + 4096 * p2[0];

            set1[1 + 4*conttt] = p2[3] + 16 * conttt + 256 * p1[1] + 4096 * p1[0];
            set2[1 + 4*conttt] = p1[3] + 16 * conttt + 256 * p2[1] + 4096 * p2[0];

            set1[2 + 4*conttt] = p1[3] + 16 * conttt + 256 * p2[1] + 4096 * p1[0];
            set2[2 + 4*conttt] = p2[3] + 16 * conttt + 256 * p1[1] + 4096 * p2[0];

            set1[3 + 4*conttt] = p1[3] + 16 * conttt + 256 * p1[1] + 4096 * p2[0];
            set2[3 + 4*conttt] = p2[3] + 16 * conttt + 256 * p2[1] + 4096 * p1[0];
        }
    }

    if(p1[3] == p2[3])
    {

        for(conttt = 0; conttt < 16; conttt++)
        {

            if(p1[3] == conttt)
            {
                indiceSet = 4*conttt;
            }

            //create the set S
            set1[0 + 4*conttt] = conttt + 16 * p1[2] + 256 * p1[1] + 4096 * p1[0];
            set2[0 + 4*conttt] = conttt + 16 * p2[2] + 256 * p2[1] + 4096 * p2[0];

            set1[1 + 4*conttt] = conttt + 16 * p2[2] + 256 * p1[1] + 4096 * p1[0];
            set2[1 + 4*conttt] = conttt + 16 * p1[2] + 256 * p2[1] + 4096 * p2[0];

            set1[2 + 4*conttt] = conttt + 16 * p1[2] + 256 * p2[1] + 4096 * p1[0];
            set2[2 + 4*conttt] = conttt + 16 * p2[2] + 256 * p1[1] + 4096 * p2[0];

            set1[3 + 4*conttt] = conttt + 16 * p1[2] + 256 * p1[1] + 4096 * p2[0];
            set2[3 + 4*conttt] = conttt + 16 * p2[2] + 256 * p2[1] + 4096 * p1[0];
        }
    }

    for(index = coset + 1; index < 4; index++)
    {
        for(i = 0; i<64; i++)
        {
            for(k = 0; k<4; k++)
            {
                for(l = 0; l<4; l++)
                {
                    test[k][l] = initialCipher[set1[i]][k + l*4] ^ initialCipher[set2[i]][k + l*4];
                }
            }
            if(belongToW_2(test, index) == 1)
                return 0.;
        }
    }

    for(i=0;i<64;i++)
    {
        for(j=0;j<16;j++)
        {
            c1[i][j] = initialCipher[set1[i]][j];
            c2[i][j] = initialCipher[set2[i]][j];
        }
    }

    //DA QUI IN POI E DA MODIFICARE!!!!

        //FIRST YOU HAVE TO RE-ORDER THE INDEX!!!!!
        for(i=0;i<64;i++)
        {
            for(j=0;j<16;j++)
            {
                ccc1[j] = c1[i][j];
                ccc2[j] = c2[i][j];
            }
            if(lessOrEqual(ccc1, ccc2, coset) == 1)
            {
                for(j=0;j<16;j++)
                {
                    temp = c1[i][j];
                    c1[i][j] = c2[i][j];
                    c2[i][j] = temp;
                }
            }
        }

        for(i=0; i<64; i++)
        {
            for(j=i+1; j<64; j++)
            {
                for(k=0;k<16;k++)
                {
                    ccc1[k] = c1[i][k];
                    ccc2[k] = c2[i][k];
                    ccc3[k] = c1[j][k];
                    ccc4[k] = c2[j][k];
                }
                flag  = leseq(ccc1, ccc2, ccc3, ccc4, coset);
                if(flag == 1)
                {
                    for(k=0;k<16;k++)
                    {
                        temp = c1[i][k];
                        c1[i][k] = c1[j][k];
                        c1[j][k] = temp;
                        temp = c2[i][k];
                        c2[i][k] = c2[j][k];
                        c2[j][k] = temp;
                    }
                }
            }
        }

        for(i = 0; i<64; i++)
        {
            flag = 0;

            for(k=0;k<16;k++)
            {
                if((c1[i][k] != initialCipher[set1[indiceSet]][k] )||(c2[i][k] != initialCipher[set2[indiceSet]][k]))
                {
                    flag = 1;
                }
            }

            if(flag == 0)
            {
                indiceSet = i;
                break;
            }
        }


        //test on the sets for the same J
        for(i = indiceSet + 1; i<64; i++)
        {
            for(k = 0; k<4; k++)
            {
                for(l = 0; l<4; l++)
                {
                    test[k][l] = c1[i][k + l*4] ^ c2[i][k + l*4];
                }
            }
            if(belongToW_2(test, coset) == 1)
                return 0.;
        }

    return 1.;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**Count number of sets that satisfy the required property.
A complete description of the procedure can be found in the text - see Algorithm 2 for details.
PS: modeOfOperation = 0 for AES, = 1 for random */

double subspaceTest(word8 key[][4], int modeOfOperation)
{
    unsigned long int i, j;
    int l, k, indice1, indice2, indice3, indice4, coset, num_Coset, flag = 0;

    double numberTableLook = 0.0, finalRes = 0.0, esito;

    word8 p1[4][4], c1[4][4], temp[4][4];

    finalRes = 0.0;

    for(num_Coset = 0; num_Coset < N_TEST; num_Coset++)
    {

        for(k=0;k<4;k++)
        {
            for(l=0;l<4;l++)
                temp[l][k]=randomNibble();
        }

        i = 0;

        for(indice1 =0; indice1<16; indice1++)
        {
            for(indice2=0; indice2 <16; indice2++)
            {
                for(indice3 =0; indice3<16; indice3++)
                {
                    for(indice4=0; indice4 <16; indice4++)
                    {
                        temp[0][0] = (word8) indice1;
                        temp[1][0] = (word8) indice2;
                        temp[2][0] = (word8) indice3;
                        temp[3][0] = (word8) indice4;

                        for(k = 0; k<4; k++)
                        {
                            for(l=0;l<4;l++)
                            {
                                play[i][k + l*4] = temp[k][l];
                                initialplay[i][k + l*4] = temp[k][l];
                            }
                        }

                        if(modeOfOperation == 0)
                            encryption(temp, key, &(c1[0][0]));
                        else
                            randEncryption(temp, key, &(c1[0][0]));

                        for(k = 0; k<4; k++)
                        {
                            for(l=0;l<4;l++)
                            {
                                cipher[i][k + l*4] = c1[k][l];
                                //Note: this increase the memory of a factor 2, but decrease the computational cost - CHECK!!!
                                initialCipher[i][k + l*4] = c1[k][l];
                            }
                        }

                        i++;
                    }
                }
            }
        }

        //Four times!

        for(coset = 0; coset < 4; coset++)
        {
            //re-order the ciphertexts!
            numberTableLook = sort2(coset, numberTableLook);

            //count the number of collision
            i = 0;

            //numberTableLook = numberTableLook + 1.0;

            while(i < (NUMBER_CP-1))
            {
                j = i;
                flag = 0;

                do
                {
                    flag = 0;

                    for(k = 0; k<4; k++)
                    {
                        for(l = 0; l<4; l++)
                        {
                            p1[k][l] = cipher[j+1][k + l*4] ^ cipher[j][k + l*4];
                        }
                    }

                    if(belongToW_2(p1, coset) == 1)
                    {
                        flag = 1;
                        j = j + 1;
                    }
                }while(flag == 1);

		//We check not to count two or more times the same set!
                if((j-i)>0)
                {
                     for(l=i; l<j; l++)
                    {
                        for(k = l + 1; k < j+1; k++)
                        {
                            if((play[l][0]==play[k][0])&&(play[l][1]!=play[k][1])&&(play[l][2]!=play[k][2])&&(play[l][3]!=play[k][3]))
                            {
                                esito = superTest(l, k, coset);
                                finalRes += esito;
                            }
                            if((play[l][0]!=play[k][0])&&(play[l][1]==play[k][1])&&(play[l][2]!=play[k][2])&&(play[l][3]!=play[k][3]))
                            {
                                esito = superTest(l, k, coset);
                                finalRes += esito;
                            }
                            if((play[l][0]!=play[k][0])&&(play[l][1]!=play[k][1])&&(play[l][2]==play[k][2])&&(play[l][3]!=play[k][3]))
                            {
                                esito = superTest(l, k, coset);
                                finalRes += esito;
                            }
                            if((play[l][0]!=play[k][0])&&(play[l][1]!=play[k][1])&&(play[l][2]!=play[k][2])&&(play[l][3]==play[k][3]))
                            {
                                esito = superTest(l, k, coset);
                                finalRes += esito;
                            }
                        }
                    }
                }


                i = j + 1;

            }
        }

    }

    return finalRes;

}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**The 5-round secret key distinguisher of App. C is based on the following fact.
Given all the couples, one divides them is sets. Given a set, it is possible to prove that the probability that there exists J
with |J|=3 such that for at least one couple the two ciphertexts belong to the same coset of M_J is (a little) lower for 5-round
AES than for a random permutation.
The exact values of these two probabilities are given in the text.
In the following, we simply test these values for small-scale AES and we compare the practical results with the theoreotical ones.
A complete discussion on this topic can be found in App. C - Sect. 6.
 */

//TIME of EXECUTION: 2 weeks on normal PC

int main()
{
    FILE *fpAES, *fpRAND;

    //Secret key
    word8 key[4][4];

    int j, l;
    unsigned long int i;
    unsigned long init[10], length=10;

    int numero;

    double res1, res2, tot1 = 0., tot2 = 0., average1, average2;

    printf("VERIFICATION OF PROBABILITIES for 5-round secret-key distinguisher AES (small scale) using T set (App. C).\n\n");
    printf("The program verifies the probabilities given in App. C both for a random permutation and for a small-scale AES.\n");
    printf("The time of execution of the program is quite long (approximately 2 weeks on a normal PC).\n\n");

    fpAES = fopen("NumberSets_5AES.txt","w+");
    fpRAND = fopen("NumberSets_5RAND.txt","w+");

    fprintf(fpAES, "AES CASE\nDistinguisher 5 rounds - Number of sets with required property\n");
    fprintf(fpRAND, "RANDOM CASE (= 30 rounds AES)\nDistinguisher 5 rounds - Number of sets with required property\n");

    fprintf(fpAES, "Average number of sets --- Test: Number Positive sets of the tests - Total - Positive Test\n\n");
    fprintf(fpRAND, "Average number of sets --- Test: Number Positive sets of the tests - Total - Positive Test\n\n");

    //words of 4 bits!
    srand (time(NULL));

    for(j=0;j<length;j++)
    {
        init[j] = rand();
    }
    init_by_array(init, length);

    printf("In order to increase the speed of the program, nothing is printed on the screen (except the number of tests already done). The results are stored and saved in .txt files.\n");
    printf("For more details, see the README.txt file.\n\n");

    for(i = 0; i< numerbPROVE; i++)
    {
        for(j=0;j<4;j++)
        {
            for(l=0;l<4;l++)
            {
                key[j][l] = randomNibble();
            }
        }

        printf("After %d test...\n", i);
        numero = 1;

        //RANDOM case

        res1 = subspaceTest(key, numero);
        tot1 += res1;

        average1 = tot1 / ((double) (i+1));
        average1 = average1 / ((double) N_TEST);

        numero = 0;

        //AES case

        res2 = subspaceTest(key, numero);
        tot2 += res2;

        average2 = tot2 / ((double) (i+1));
        average2 = average2 / ((double) N_TEST);

        fprintf(fpRAND, "%lf --- %d: %lf - %lf \n", average1, i+1, res1, tot1);
        fflush(fpRAND);
        fprintf(fpAES, "%lf --- %d: %lf - %lf \n", average2, i+1, res2, tot2);
        fflush(fpAES);

        printf("RAND --- %lf --- %d: %lf - %lf \n", average1, i+1, res1, tot1);
        printf("AES --- %lf --- %d: %lf - %lf \n", average2, i+1, res2, tot2);
    }

    fclose(fpAES);
    fclose(fpRAND);

    return 0;
}

