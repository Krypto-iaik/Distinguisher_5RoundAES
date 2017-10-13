CFLAGS=-O3 -Wall

all: AES AES_smallScale AES_4RoundDistinguisher AES_4RoundDistinguisher_SmallScale AES_5RoundAttack_SmallScale AES_5RoundDistinguisher_setS AES_5RoundDistinguisher_setT_AppC AES_5RoundDistinguisher_setT_AppD

multiplication: multiplication.h multiplication.c multiplication_smallScale.c
	$(CC) $(CFLAGS) -c -o multiplication.o multiplication.c
	$(CC) $(CFLAGS) -c -o multiplication_smallScale.o multiplication_smallScale.c
	
subspace_checks: subspace_checks.h subspace_checks.c
	$(CC) $(CFLAGS) -c -o subspace_checks.o subspace_checks.c

aes_common: AES_common.h AES_common.c
	$(CC) $(CFLAGS) -c -o AES_common10.o AES_common.c -DN_Round=10
	$(CC) $(CFLAGS) -c -o AES_common4.o AES_common.c -DN_Round=4
	$(CC) $(CFLAGS) -c -o AES_common5.o AES_common.c -DN_Round=5

AES: aes_common multiplication AES.c
	$(CC) $(CFLAGS) -o AES AES.c AES_common10.o multiplication.o

AES_smallScale: aes_common multiplication AES_smallScaleVersion.c
	$(CC) $(CFLAGS) -o AES_smallScale AES_smallScaleVersion.c AES_common10.o multiplication_smallScale.o

AES_4RoundDistinguisher: aes_common multiplication subspace_checks AES_4RoundDistinguisher.c
	$(CC) $(CFLAGS) -o AES_4RoundDistinguisher AES_4RoundDistinguisher.c AES_common4.o subspace_checks.o multiplication.o

AES_4RoundDistinguisher_SmallScale: aes_common multiplication subspace_checks AES_4RoundDistinguisher_SmallScale.c
	$(CC) $(CFLAGS) -o AES_4RoundDistinguisher_SmallScale AES_4RoundDistinguisher_SmallScale.c AES_common4.o subspace_checks.o multiplication_smallScale.o

AES_5RoundAttack_SmallScale: aes_common multiplication subspace_checks AES_5RoundAttack_SmallScale.c
	$(CC) $(CFLAGS) -o AES_5RoundAttack_SmallScale AES_5RoundAttack_SmallScale.c AES_common5.o subspace_checks.o multiplication_smallScale.o

AES_5RoundDistinguisher_setS: aes_common multiplication subspace_checks AES_5RoundDistinguisher_setS.c
	$(CC) $(CFLAGS) -o AES_5RoundDistinguisher_setS AES_5RoundDistinguisher_setS.c AES_common5.o subspace_checks.o multiplication_smallScale.o

AES_5RoundDistinguisher_setT_AppC: aes_common multiplication subspace_checks AES_5RoundDistinguisher_setT_AppC.c
	$(CC) $(CFLAGS) -o AES_5RoundDistinguisher_setT_AppC AES_5RoundDistinguisher_setT_AppC.c AES_common5.o subspace_checks.o multiplication_smallScale.o

AES_5RoundDistinguisher_setT_AppD: aes_common multiplication subspace_checks AES_5RoundDistinguisher_setT_AppD.c
	$(CC) $(CFLAGS) -o AES_5RoundDistinguisher_setT_AppD AES_5RoundDistinguisher_setT_AppD.c AES_common5.o subspace_checks.o multiplication_smallScale.o

clean:
	$(RM) -f AES_common10.o AES_common4.o AES_common5.o 
	$(RM) -f multiplication.o multiplication_smallScale.o 
	$(RM) -f subspace_checks.o
	$(RM) -f AES AES_smallScale
	$(RM) -f AES_4RoundDistinguisher
	$(RM) -f AES_4RoundDistinguisher_SmallScale
	$(RM) -f AES_5RoundAttack_SmallScale
	$(RM) -f AES_5RoundDistinguisher_setS
	$(RM) -f AES_5RoundDistinguisher_setT_AppC
	$(RM) -f AES_5RoundDistinguisher_setT_AppD
	
.PHONY: clean
