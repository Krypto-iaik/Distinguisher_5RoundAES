typedef unsigned char word8;

// check if p = p1 xor p2 belongs to a Diagonal space D_i
int belongToU(const word8 p[4][4])
{
    if (((p[0][0] == 0) && (p[1][1] == 0) && (p[2][2] == 0) && (p[3][3] == 0)) ||
        ((p[1][0] == 0) && (p[2][1] == 0) && (p[3][2] == 0) && (p[0][3] == 0)) ||
        ((p[2][0] == 0) && (p[3][1] == 0) && (p[0][2] == 0) && (p[1][3] == 0)) ||
        ((p[3][0] == 0) && (p[0][1] == 0) && (p[1][2] == 0) && (p[2][3] == 0)))
        return 1;

    return 0;
}

// check if p = p1 xor p2 belongs to a Column space C_i
int belongToV(const word8 p[4][4])
{
    if (((p[0][0] == 0) && (p[1][0] == 0) && (p[2][0] == 0) && (p[3][0] == 0)) ||
        ((p[0][1] == 0) && (p[1][1] == 0) && (p[2][1] == 0) && (p[3][1] == 0)) ||
        ((p[0][2] == 0) && (p[1][2] == 0) && (p[2][2] == 0) && (p[3][2] == 0)) ||
        ((p[0][3] == 0) && (p[1][3] == 0) && (p[2][3] == 0) && (p[3][3] == 0)))
        return 1;

    return 0;
}

// check if p = p1 xor p2 belongs to a Mixed space M_i
int belongToW(const word8 p[4][4])
{
    /*Consider MC^-1(W) since no mixcolumns at the end!*/

    if (((p[0][0] == 0) && (p[3][1] == 0) && (p[2][2] == 0) && (p[1][3] == 0)) ||
        ((p[1][0] == 0) && (p[0][1] == 0) && (p[3][2] == 0) && (p[2][3] == 0)) ||
        ((p[2][0] == 0) && (p[1][1] == 0) && (p[0][2] == 0) && (p[3][3] == 0)) ||
        ((p[3][0] == 0) && (p[2][1] == 0) && (p[1][2] == 0) && (p[0][3] == 0)))
       return 1;

    return 0;
}

int belongToW1(word8 p[][4])
{
    /*Consider MC^-1(M_0) since no mixcolumns at the end!*/

    if ((p[0][0] == 0) && (p[3][1] == 0) && (p[2][2] == 0) && (p[1][3] == 0))
       return 1;

    return 0;
}

int belongToW2(word8 p[][4])
{
    /*Consider MC^-1(M_1) since no mixcolumns at the end!*/

   if ((p[1][0] == 0) && (p[0][1] == 0) && (p[3][2] == 0) && (p[2][3] == 0))
       return 1;

   return 0;
}

int belongToW3(word8 p[][4])
{
    /*Consider MC^-1(M_2) since no mixcolumns at the end!*/

    if ((p[2][0] == 0) && (p[1][1] == 0) && (p[0][2] == 0) && (p[3][3] == 0))
       return 1;

   return 0;
}

int belongToW4(word8 p[][4])
{
    /*Consider MC^-1(M_3) since no mixcolumns at the end!*/

    if ((p[3][0] == 0) && (p[2][1] == 0) && (p[1][2] == 0) && (p[0][3] == 0))
       return 1;

    return 0;
}

int belongToW_2(word8 p[][4], int coset)
{
    if(coset == 0)
        return belongToW1(p);

    if(coset == 1)
        return belongToW2(p);

    if(coset == 2)
        return belongToW3(p);

    return belongToW4(p);

}
