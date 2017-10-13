New Secret-Key Distinguishers and Key-Recovery Attacks on AES up to 5 rounds

Programs:

0) AES.c and AES_smallScaleVersion.c

Key-Recovery Attacks and Secret-Key Distinguishers on AES:

1) AES_4RoundDistinguisher.c

2) AES_4RoundDistinguisher_SmallScale.c

3) AES_5RoundAttack_SmallScale.c

4a) AES_5RoundDistinguisher_setS.c

4b) AES_5RoundDistinguisher_setT_AppC.c

4c) AES_5RoundDistinguisher_setT_AppD.c

The programs should run with almost C-compilers (we have used gcc version 4.8.1). None of these programs is speed-optimized, they are for verification purposes only.

In all the programs, the main function is always the last one.

The first two programs contain our implementation of AES and of small-scale AES (encryption and decryption). They have been verified against test-vectors.

A complete description of this small scale variant of AES can be found in "Small Scale Variants of the AES" - Authors: C. Cid, S. Murphy, and M.J.B. Robshaw The program "AES_smallScaleVersion.c" provides an implementation of this small scale AES (verified against test-vectors).

All the distinguishers/attack have been verified on small-scale AES (due to the high complexity of the attacks for real AES).
However, since the properties that they exploit are independent of the fact that the words are composed of 4 or 8 bits, our verification on small-scale AES is strong evidence for it to hold for real AES.

1) "AES_4RoundDistinguisher.c" verifies the 4-round AES secret-key distinguisher presented in Sect. 5. 
The idea is the following. Given plaintexts in the same coset of C_0 \cap D_0,1, one divides the couples in sets as defined in the paper.
For AES, only two events can happen: for all the couples in the same set, the two ciphertexts (1) belong or (2) not to the same coset of M_J.
For a random permutation, other events are possible: for some couples the two ciphertexts belong in the same coset of M_J, while for others not.
All the details of the strategy used to set up the distinguisher are described in Algorithm 1.
The secret key can be chosen in the main function. The number of tests (or equivalent of initial sets used for the attack) can be chosen by the parameter N_Repetitions (line 7) - we suggest to choose NUMBER_TEST >=2 to distinguish the two cases with probability higher than 95%.
Time of execution: 1.5 sec.

2) "AES_4RoundDistinguisher_smallScale.c" verifies the 4-round AES secret-key distinguisher presented in Sect. 5 (and just described) on a small-scale AES. 
The reason why we implement it on a small scale is that the key-recovery attack that exploits this distinguisher is implemented only for small-scale AES (the computational cost of the attack for real AES is too high).
The secret key can be chosen in the main function. The number of tests (or equivalent of initial sets used for the attack) can be chosen by the parameter N_Repetitions (line 7) - we suggest to choose NUMBER_TEST >=2 to distinguish the two cases with probability higher than 95%.
Time of execution: <0.01 sec.

3) "AES_5RoundAttack_SmallScale.c" verifies the 5-round AES key-recovery attack presented in Sect. 5.3 on a small-scale AES (the computational cost of the attack for real AES is too high). 
It exploits the 4-round secret-key distinguisher just described - point 2.
The idea is the following. A coset of a diagonal space D is always mapped in a column space C after one round.
The attacker guesses the diagonal of the key, and partially encrypts D. Then she constructs the sets, and she is able to detect wrong keys using the previous distinguisher.
Indeed, the way in which the couples are divided in sets depends on the guessed key. If the guessed key is wrong, the behavior is like a random permutation.
For simplicity, the aim of the attacks is to find part of the key, but the same procedure can be used to find all the key.
The details of the procedure of the attack can be found in App. C - Algorithm 4.
The secret key can be chosen in the main function. The number of tests (or equivalent of ciphertexts that collide) can be chosen by the parameter N_TestTest (line 8) - we suggest to choose NUMBER_TEST >=8 to discard all the wrong keys with probability higher than 95%.
Time of execution: 0.25 sec.

4) "AES_5RoundDistinguisher_setS.c", "AES_5RoundDistinguisher_setT_AppC.c and AES_5RoundDistinguisher_setT_AppD.c" verify the probabilities given in Sect. 6 and App. C-D on small-scale AES and exploited by our 5-round AES secret-key distinguisher.
As before, given plaintexts in the same coset of a column space, one divides all the possible couples in set as defined in the paper.
The program computes the average probability that for a given set there exists J with |J|=3 such that for at least one couple in the set the two ciphertexts belong to the same coset of M_J.
For all the three cases, this probability is a little lower for AES than for a random permutation: this fact is exploited by the distinguisher.
We emphasize that since the theory on which this distinguisher is based is independent of the fact that the words are of 4 or 8 bits, our verification on small-scale AES is strong evidence for it to hold for real AES.
The program can also be used as distinguisher.

Time of execution: set T (App. C) and/or S: > 2 weeks (on a normal PC) - set T (app. D): > 1 month (on a normal PC).  
Due to the long time of execution, we refer to the paper for a discussion about the practical obtained results.
(In order to improve the speed, we store all the results/output of the program in .txt files.)

Finally, the pseudo-random generator used in these programs is the "Mersenne Twister" one, developed by 1997 by Makoto Matsumoto and Takuji Nishimura - MT19937. The complete source code and explanation of this random generator can be found in: http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html

