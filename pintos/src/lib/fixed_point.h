#define q 14
#define p 17
#define f (1 << q)
#define int_real(n)  n << q
#define real_int_0(x)  x >> q
#define real_int(x)  (x >= 0) ? ((x + (1 << (q-1))) >> q) : ((x - (1 << (q-1))) >> q)
#define real_sum(x,y)  (x+y)
#define real_diff(x,y)  (x-y)
#define real_mixsum(x,n)  (x+(int_real(n)))
#define real_mixdiff(x,n)  (x-(int_real(n)))
#define real_mixproduct(x,n)  (x*n)
#define real_mixdiv(x,n)  (x/n)
#define real_product(x,y)  (((int64_t) x) * y/f)
#define real_div(x,y)  (((int64_t) x)*f/ y)
