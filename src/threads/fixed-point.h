#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#define Q 14
#define F (1<<Q)

typedef int fp;

fp convert_to_fp(int n);
int toInt_round_down(fp x);
int toInt_round_nearest(fp x);
fp fp_add(fp x, fp y);
fp fp_subtract(fp x, fp y);
fp add_int(fp x, int n);
fp subtract_int(fp x, int n);
fp fp_multiply(fp x, fp y);
fp int_multiply(fp x, int n);
fp fp_divide (fp x , fp y);
fp int_divide(fp x, int n);

int convert_to_fp(int n)
{
    return n*F;
}
int toInt_round_down(fp x)
{
    return x/F;
}
int toInt_round_nearest(fp x)
{
    return (x>=0) ? (x+F/2)/F : (x-F/2)/F ;
}
fp fp_add(fp x, fp y)
{
    return x+y;
}
fp fp_subtract(fp x, fp y)
{
    return x-y;
}
fp add_int(fp x, int n)
{
    return x+(n*F);
}
fp subtract_int(fp x, int n){
    return x-(n*F);
}
fp fp_multiply(fp x , fp y)
{
    return ((int64_t)x)*y / F;
}
fp int_multiply(fp x, int n)
{
    return x*n;
}

fp fp_divide(fp x, fp y)
{
    return ((int64_t)x)*F / y;
}
fp int_divide(fp x, int n){
    return x/n;
}
#endif  /* threads/fixed-point.h */
