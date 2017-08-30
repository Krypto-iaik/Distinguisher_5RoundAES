#include <stdio.h>
#include <stdlib.h>
#include <time.h>


#include "AES_common.h"
#include "AES_smallScale_sbox.h"
#include "multiplication.h"
#include "subspace_checks.h"

#define NUMBER_CP 65536
#define N_COSET 1
#define N_TestTest 8
/** Don't modify the previous number!
N_TestTest denotes the number of collisions among ciphertexts, used to detect wrong keys - Usually 1 is sufficient*/

//salvo i plaintexts buoni!!

int cosetcoset[N_TestTest];
word8 testplaintexts1[N_TestTest][4], testplaintexts2[N_TestTest][4];

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

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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

int superCheck(int initalN, int finalN, int coset)
{
    int i, k, l, j, num1, num2;

    word8 t[4][4], a, b, c, d;



    for(k = initalN; k<finalN; k++)
    {
        a = play[k][0];
        b = play[k][1];

        //printf("first play: %x - %x\n", a, b);

        for(i = k + 1; i < finalN; i++)
        {
            c = play[i][0];
            d = play[i][1];

            //printf("second play: %x - %x\n", c, d);

            num1 = (int) d + 16 * (int) a;
            num2 = (int) b + 16 * (int) c;

//            printf("Combination:\n");
//            printf("2 - first play: %x - %x\n", initialplay[num1][0], initialplay[num1][1]);
//            printf("2 - second play: %x - %x\n", initialplay[num2][0], initialplay[num2][1]);

            //you can use cipher and a research: cost 2*n invece di 1, ma risparmi memoria!

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

void mixColonna2(word8 *colonna)
{
    word8 nuovaColonna[4];
    int j;

    nuovaColonna[0]= multiplicationX(colonna[0]) ^ multiplicationX(colonna[1]) ^ colonna[1] ^ colonna[2] ^ colonna[3];
    nuovaColonna[1]= colonna[0] ^ multiplicationX(colonna[1]) ^ multiplicationX(colonna[2]) ^ colonna[2] ^ colonna[3];
    nuovaColonna[2]= colonna[0] ^ colonna[1] ^ multiplicationX(colonna[2]) ^ multiplicationX(colonna[3]) ^ colonna[3];
    nuovaColonna[3]= multiplicationX(colonna[0]) ^ colonna[0] ^ colonna[1] ^ colonna[2] ^ multiplicationX(colonna[3]);

    //reinserisco colonna
    for(j=0;j<4;j++)
    {
      *(colonna + j)=nuovaColonna[j];
    }

}

void inverseMixColumn2(word8 *colonna)
{
    word8 nuovaColonna[4];
    int j;

    nuovaColonna[0]= multiplicationXN(colonna[0], 3) ^ multiplicationXN(colonna[0], 2) ^ multiplicationX(colonna[0]) ^
        multiplicationXN(colonna[1], 3) ^ multiplicationX(colonna[1]) ^ colonna[1] ^ multiplicationXN(colonna[2], 3) ^
        multiplicationXN(colonna[2], 2) ^ colonna[2] ^ multiplicationXN(colonna[3], 3) ^ colonna[3];

    nuovaColonna[1]= multiplicationXN(colonna[0], 3) ^ colonna[0] ^ multiplicationXN(colonna[1], 3) ^ multiplicationXN(colonna[1], 2) ^
        multiplicationX(colonna[1]) ^ multiplicationXN(colonna[2], 3) ^ multiplicationX(colonna[2]) ^ colonna[2] ^
        multiplicationXN(colonna[3], 3) ^ multiplicationXN(colonna[3], 2) ^ colonna[3];

    nuovaColonna[2]= multiplicationXN(colonna[0], 3) ^ multiplicationXN(colonna[0], 2) ^ colonna[0] ^ multiplicationXN(colonna[1], 3) ^
        colonna[1] ^ multiplicationXN(colonna[2], 3) ^ multiplicationXN(colonna[2], 2) ^ multiplicationX(colonna[2]) ^
        multiplicationXN(colonna[3], 3)^multiplicationX(colonna[3]) ^ colonna[3];

    nuovaColonna[3]= multiplicationXN(colonna[0], 3)^ multiplicationX(colonna[0]) ^ colonna[0] ^ multiplicationXN(colonna[1], 3) ^
        multiplicationXN(colonna[1], 2)^colonna[1] ^ multiplicationXN(colonna[2], 3)^colonna[2] ^ multiplicationXN(colonna[3], 3)^
        multiplicationXN(colonna[3], 2)^multiplicationX(colonna[3]);

    //reinserisco colonna
    for(j=0;j<4;j++)
    {
        *(colonna + j)=nuovaColonna[j];
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int testestest(word8 *ppp1, word8 *ppp2, word8 *keykey, int cos)
{
    int j, pp1[4], pp2[4], place1, place2, k, l;
    word8 test[4][4];

    for(j= 0; j<4; j++)
    {
        pp1[j] = (int) (inverseByteTransformation(ppp1[j]) ^ keykey[j]);
        pp2[j] = (int) (inverseByteTransformation(ppp2[j]) ^ keykey[j]);
    }

    place1 = pp1[3] + 16 * pp1[2] + 256 * pp1[1] + 4096 * pp1[0];
    place2 = pp2[3] + 16 * pp2[2] + 256 * pp2[1] + 4096 * pp2[0];

    for(k = 0; k<4; k++)
    {
        for(l = 0; l<4; l++)
        {
            test[k][l] = initialCipher[place1][k + l*4] ^ initialCipher[place2][k + l*4];
        }
    }

    if(belongToW_2(test, cos) == 0)
        return 1;

    return 0;
}


/**When a collision is found, the corresponding set is constructed.
Using the distinguisher of Sect. 5, one detectes if the key is wrong.
*/

void checkKey(word8 key[][4], double numberTableLook)
{
    int keyTest, i, j, k, l, flag, temp, place1, place2, superflag = 0, numero;

    word8 p1[4], p2[4], keykey[4], test[4][4], ppp1[4], ppp2[4];

    printf("\nSecret Key - First diagonal:\n");
    printf("0x%01x - 0x%01x - 0x%01x - 0x%01x\n\n", key[0][0], key[1][1], key[2][2], key[3][3]);

    for(keyTest = 0; keyTest <= 65535; keyTest++)
    {
        temp = (int) (keyTest/4096);
        keykey[0] = (word8) temp;

        temp = keyTest % 4096;
        temp = (int) (temp/256);
        keykey[1] = (word8) temp;

        temp = keyTest % 256;
        temp = (int) temp/16;
        keykey[2] = (word8) temp;

        keykey[3] = (word8) (keyTest % 16);

        flag = 0;

        for(i = 0; (i<N_TestTest)&&(flag == 0); i++)
        {
            for(j= 0; j<4; j++)
            {
                p1[j] = byteTransformation(testplaintexts1[i][j] ^ keykey[j]);
                p2[j] = byteTransformation(testplaintexts2[i][j] ^ keykey[j]);
            }

            numberTableLook = numberTableLook + 10.;

            mixColonna2(&(p1[0]));
            mixColonna2(&(p2[0]));

            //1 combination
            ppp1[0] = p2[0];
            ppp1[1] = p1[1];
            ppp1[2] = p1[2];
            ppp1[3] = p1[3];

            ppp2[0] = p1[0];
            ppp2[1] = p2[1];
            ppp2[2] = p2[2];
            ppp2[3] = p2[3];

            inverseMixColumn2(&(ppp1[0]));
            inverseMixColumn2(&(ppp2[0]));

            flag = testestest(ppp1, ppp2, keykey, cosetcoset[i]);

            numberTableLook = numberTableLook + 10.;

            //2 combination
            if(flag == 0)
            {
                ppp1[0] = p1[0];
                ppp1[1] = p2[1];
                ppp1[2] = p1[2];
                ppp1[3] = p1[3];

                ppp2[0] = p2[0];
                ppp2[1] = p1[1];
                ppp2[2] = p2[2];
                ppp2[3] = p2[3];

                inverseMixColumn2(&(ppp1[0]));
                inverseMixColumn2(&(ppp2[0]));
                flag = testestest(ppp1, ppp2, keykey, cosetcoset[i]);

                numberTableLook = numberTableLook + 10.;

            }

            //3 combination
            if(flag == 0)
            {
                ppp1[0] = p1[0];
                ppp1[1] = p1[1];
                ppp1[2] = p2[2];
                ppp1[3] = p1[3];

                ppp2[0] = p2[0];
                ppp2[1] = p2[1];
                ppp2[2] = p1[2];
                ppp2[3] = p2[3];

                inverseMixColumn2(&(ppp1[0]));
                inverseMixColumn2(&(ppp2[0]));
                flag = testestest(ppp1, ppp2, keykey, cosetcoset[i]);

                numberTableLook = numberTableLook + 10.;
            }

            //4 combination
            if(flag == 0)
            {
                ppp1[0] = p1[0];
                ppp1[1] = p1[1];
                ppp1[2] = p1[2];
                ppp1[3] = p2[3];

                ppp2[0] = p2[0];
                ppp2[1] = p2[1];
                ppp2[2] = p2[2];
                ppp2[3] = p1[3];

                inverseMixColumn2(&(ppp1[0]));
                inverseMixColumn2(&(ppp2[0]));
                flag = testestest(ppp1, ppp2, keykey, cosetcoset[i]);

                numberTableLook = numberTableLook + 10.;
            }

            //5 combination
            if(flag == 0)
            {
                ppp1[0] = p1[0];
                ppp1[1] = p1[1];
                ppp1[2] = p2[2];
                ppp1[3] = p2[3];

                ppp2[0] = p2[0];
                ppp2[1] = p2[1];
                ppp2[2] = p1[2];
                ppp2[3] = p1[3];

                inverseMixColumn2(&(ppp1[0]));
                inverseMixColumn2(&(ppp2[0]));
                flag = testestest(ppp1, ppp2, keykey, cosetcoset[i]);

                numberTableLook = numberTableLook + 10.;

            }

            //6 combination
            if(flag == 0)
            {
                ppp1[0] = p1[0];
                ppp1[1] = p2[1];
                ppp1[2] = p1[2];
                ppp1[3] = p2[3];

                ppp2[0] = p2[0];
                ppp2[1] = p1[1];
                ppp2[2] = p2[2];
                ppp2[3] = p1[3];

                inverseMixColumn2(&(ppp1[0]));
                inverseMixColumn2(&(ppp2[0]));
                flag = testestest(ppp1, ppp2, keykey, cosetcoset[i]);

                numberTableLook = numberTableLook + 10.;

            }

             //7 combination
            if(flag == 0)
            {
                ppp1[0] = p1[0];
                ppp1[1] = p2[1];
                ppp1[2] = p2[2];
                ppp1[3] = p1[3];

                ppp2[0] = p2[0];
                ppp2[1] = p1[1];
                ppp2[2] = p1[2];
                ppp2[3] = p2[3];

                inverseMixColumn2(&(ppp1[0]));
                inverseMixColumn2(&(ppp2[0]));
                flag = testestest(ppp1, ppp2, keykey, cosetcoset[i]);

                numberTableLook = numberTableLook + 10.;
            }
        }

        if(flag == 0)
        {
            printf("Possible Key - First diagonal:\n");
            printf("0x%01x - 0x%01x - 0x%01x - 0x%01x", keykey[0], keykey[1], keykey[2], keykey[3]);
            if((keykey[0] == key[0][0])&&(keykey[1] == key[1][1])&&(keykey[2] == key[2][2])&&(keykey[3] == key[3][3]))
            {
                printf(" -> CORRECT!!!\n");
                superflag = 1;
            }
            else
                printf("\n");
        }
    }

    if(superflag == 1)
        printf("\n PERFECT ATTACK!\n");
    else
        printf("\n Something FAILS...\n");

    printf("\n Computational cost: %f - Theoretical: 3 750 000 = 2^21.8 \n", numberTableLook);

}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**Implementation of the attack:
the attacker guesses one diagonal of the key, encrypts and exploits the distinguisher of Sect. 5 to detect wrong keys.
Remember that the behavior for a wrong key is similar to the random one. */

void subspaceTest(word8 key[][4])
{
    unsigned long int i, j;

    int keyTest, resultTest, l, k, indice1, indice2, indice3, indice4, coset, num_Coset, finalRes = 0;
    int flag = 0, superFlag = 0, posizione;

    double numberTableLook = 0.0;

    word8 p1[4][4], c1[4][4], temp[4][4];

    for(k=0;k<4;k++)
    {
        for(l=0;l<4;l++)
            temp[l][k]=randomNibble();
    }

    i = 0;

    //Guessed key
    for(indice1 =0; indice1<16; indice1++)
    {
        for(indice2=0; indice2 <16; indice2++)
        {
            for(indice3 =0; indice3<16; indice3++)
            {
                for(indice4=0; indice4 <16; indice4++)
                {

                    temp[0][0] = (word8) indice1;
                    temp[1][1] = (word8) indice2;
                    temp[2][2] = (word8) indice3;
                    temp[3][3] = (word8) indice4;

                    for(k = 0; k<4; k++)
                    {
                        for(l=0;l<4;l++)
                        {
                            play[i][k + l*4] = temp[k][l];
                            initialplay[i][k + l*4] = temp[k][l];
                        }
                    }

                    encryption(temp, key, &(c1[0][0]));

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
        }
    }

    posizione = 0;

    //FIND PAIRS OF PLAINTEXTS!!!
    for(coset = 0; (coset < 4)&&(posizione < N_TestTest); coset++)
    {
        //re-order the ciphertexts!
        numberTableLook = sort2(coset, numberTableLook);

        //count the number of collision
        i = 0;

        numberTableLook = numberTableLook + 1.0;

        while((i < (NUMBER_CP-1))&&(posizione < N_TestTest))
        {

            j = i;
            flag = 0;

            do
            {
                flag = 0;

                numberTableLook = numberTableLook + 1.0;

                //find the collision
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

                if(posizione<N_TestTest)
                {
                    for(l = i; l < j; l++)
                    {
                        for(k = l+1; k < j+1; k++)
                        {

			    //When a collision is found, the corresponding texts are stored and used for the attack
                            for(indice1 = 0; indice1<4; indice1++)
                            {
                                testplaintexts1[posizione][indice1] = play[l][5*indice1];
                                testplaintexts2[posizione][indice1] = play[k][5*indice1];
                                cosetcoset[posizione] = coset;
                            }
                        }
                    }
                }
                posizione++;
            }

            i = j + 1;

        }
    }

    /*when a collision is found, the corrisponding set is constructed and the guessed key is analyzed.
 	"numberTableLook" used to check the computational cost*/
    checkKey(key, numberTableLook);

}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**The program implement the NEW Key-Recover ATTACK on 5-Round Reduced (Small Scale) AES described in Sect. 5.3, that exploits the
distinguisher of Sect. 5.
The idea is the following. Given a coset of a diagonal space D_0, the attacker guesses one diagonal of the key and partially encrypts one round.
The plaintexts are mapped in a coset of a column space C_0. Then, the attacker exploits the distinguisher of Sect. 5 to detect the right/wrong key.
Indeed, the way in which the couples of texts are divided in sets depends on the guessed key:
for a wrong one, the behavior is like the random one.
*/

//TIME of EXECUTION: approx 0.25 sec

int main()
{
    //Secret key
    word8 key[4][4] = {
        0x00, 0x04, 0x08, 0x0c,
        0x01, 0x01, 0x09, 0x0d,
        0x02, 0x06, 0x01, 0x0e,
        0x03, 0x07, 0x0b, 0x00
    };

    int j, l;
    unsigned long int i;

    //words of 4 bits!
    for(j=0;j<4;j++)
    {
        for(l=0;l<4;l++)
        {
            key[j][l] = key[j][l] & 0x0f;
        }
    }

    printf("NEW Key-Recover ATTACK on 5-Round Reduced (Small Scale) AES.\n\n");
    printf("Implementation of the attack on 5-round small-scale AES described on Sect. 5.3, that exploits the distinguisher of Sect. 5.\n");
    printf("Only for simplicity, the aim of the attack is not to find the entire key, but only part of it (i.e. the first 4 nibbles in the first diagonal of the key).\n");
    printf("We emphasize that the same attack can be used to find the rest of the key.\n");

    srand (time(NULL));

    subspaceTest(key);

    return 0;
}

