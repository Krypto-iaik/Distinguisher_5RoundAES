#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "AES_common.h"
#include "AES_sbox.h"
#include "multiplication.h"
#include "subspace_checks.h"

#define NUMBER_CP 65536 //Don't change this value!!
#define N_Repetitions 2
/* About N_Repetitions:
it denotes the numer of tests = Initial coset. In order to have a probability of success higher than 95%,
we suggest to use N_Repetitions >= 2 */

word8 play[NUMBER_CP][16], cipher[NUMBER_CP][16], initialplay[NUMBER_CP][16], initialCipher[NUMBER_CP][16], cipher2copy[NUMBER_CP][16], play2copy[NUMBER_CP][16];

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**Merge-Sort Algorithm*/

/*given two ciphertexts a and b, it return 0 if a<=b, 1 otherwise */
int lessOrEqual(word8 a[], word8 b[], int coset)
{
    int i, temp, aaa, bbb;

    for(i=0;i<4;i++)
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

    return 0;
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
    int log, i, j, division, high, low, middle, a, b, c;
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
                //moreover, the way used here can be improved!!
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

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//**The random encryption is simulated using 25-round AES*/

void randEncryption(word8 temp[][4], word8 key[][4], word8* c1)
{
    word8 temp2[4][4];
    int i, j;

    encryption(temp, key, &(temp2[0][0]));
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


//**When a collision is found, the corresponding set is constructed and the property verified*/
int superCheck(int initalN, int finalN, int coset)
{
    int i, k, l, j, num1, num2;

    word8 t[4][4], a, b, c, d;



    for(k = initalN; k<finalN; k++)
    {
        a = play[k][0];
        b = play[k][1];


        for(i = k + 1; i < finalN; i++)
        {
            c = play[i][0];
            d = play[i][1];

            num1 = (int) d + 256 * (int) a;
            num2 = (int) b + 256 * (int) c;

            for(j=0;j<4;j++)
            {
                for(l=0;l<4;l++)
                {
                    t[j][l]= initialCipher[num1][j + l*4] ^ initialCipher[num2][j + l*4];
                }
            }

            if(belongToW_2(t, coset) == 0)
                return 1;
        }
    }

    return 0;
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**Implementation of the distinguisher - we refer to Sect. 5 for all the details.
Instead to construct all the sets, the ciphertexts are re-ordered with respect to a particular partial order.
The details are given in Algorithm 1.
PS: modeOfOperation = 0 for Random, = 1 for AES
*/

void subspaceTest(word8 key[][4], int modeOfOperation)
{
    unsigned long int i, j;
    int l, k, indice1, indice2, coset, num_Coset, finalRes = 0, flag = 0, superFlag = 0, initialN, finalN;

    double numberTableLook = 0.0;

    word8 p1[4][4], c1[4][4], temp[4][4];

    //Tests repeated for the Number of initial Coset prefixed in advance.
    for(num_Coset = 0; num_Coset < N_Repetitions; num_Coset++)
    {

        printf("After %d test(s)...\n", (num_Coset+1));

        for(k=0;k<4;k++)
        {
            for(l=0;l<4;l++)
                temp[l][k]=randomByte();
        }

        i = 0;

        for(indice1 =0; indice1<256; indice1++)
        {
            for(indice2=0; indice2 <256; indice2++)
            {
                temp[0][0] = (word8) indice1;
                temp[1][0] = (word8) indice2;

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
                        //Note: this increase the memory of a factor 2, but decrease the computational cost!
                        initialCipher[i][k + l*4] = c1[k][l];
                    }
                }

                i++;

            }
        }

        superFlag = 0;

        //Four times!

        for(coset = 0; coset < 4; coset++)
        {
            //re-order the ciphertexts!
            numberTableLook = sort2(coset, numberTableLook);

            //count the number of collision
            i = 0;

            numberTableLook = numberTableLook + 1.0;

            while(i < (NUMBER_CP-1))
            {
                j = i;
                flag = 0;

                initialN = i;

                do
                {
                    flag = 0;

                    numberTableLook = numberTableLook + 1.0;

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

                if((j-i)>0)
                {
                    finalN = j + 1;

                    //when a collision is found, the corresponding set is constructed and the property is verified
                    superFlag = superCheck(initialN, finalN, coset);

		    //cost of the distinguisher
                    numberTableLook = numberTableLook + 2*(j-i)*(j-i+1);

                    if(superFlag == 1)
                    {
                        printf("\nResult: RANDOM Permutation.\n");
                        printf("Number of Look-ups: %f - Theoretical: 9 635 980 = 2^23.2 \n", numberTableLook);
                        if (modeOfOperation == 0)
                            printf("Something FAILS...\n");
                        else
                            printf("Right Result!\n");
                        return;
                    }
                }


                i = j + 1;

            }
        }

    }

    printf("\nResult: AES Permutation.\n");

    printf("Number of Look-ups: %f - Theoretical: 9 635 980 = 2^23.2 . \n", numberTableLook);
    if (modeOfOperation == 1)
        printf("Something FAILS... USE MORE TEXTS!\n");
    else
        printf("Right Result!\n");
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**The program verifies the differential structural distinguisher on 4-round AES.
Given all the couples, they are divided in sets:
- for an AES permutation, only two events are possible: for all the couples in the same set, the two ciphertexts (1) belong or (2) not to the same coset of M_J;
- for a random permtuation, other events are possible: for some couples the two ciphertexts belong, while for others not.
The plaintexts are chosen in the same coset of D_0 cap C_0,1.
The index J is taken with |J|=3. */

//TIME OF EXECUTIONs: 1.5 sec.

int main()
{
    //Secret key
    word8 key[4][4] = {
        0x00, 0x44, 0x88, 0xcc,
        0x11, 0x55, 0x99, 0xdd,
        0x22, 0x66, 0xaa, 0xee,
        0x33, 0x77, 0xbb, 0xff
    };

    unsigned long int i;

    int numero;

    printf("DIFFERENTIAL STRUCTURAL DISTINGUISHER on 4-Round AES.\n\n");
    printf("The program verifies the distinguisher proposed in Sect. 5.");

    srand (time(NULL));

    printf("RANDOM test:\n");

    numero = 1;

    subspaceTest(key, numero);

    printf("\nAES test:\n");

    numero = 0;

    subspaceTest(key, numero);

    return 0;
}

