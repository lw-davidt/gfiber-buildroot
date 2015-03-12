#if TARGET_MAC
#pragma global_optimizer off
#pragma optimization_level 0
#endif

#include "openssl/bn.h"

void blue_server_1(BIGNUM *m, BIGNUM *r, BIGNUM *g) {
#if defined (USE_BUILT_OPENSSL) || defined(SAMSUNG_TV) || defined(SAMSUNG_HTS)
    BN_CTX *bn_pctx = BN_CTX_new();
#else
    BN_CTX bn_ctx;
    BN_CTX *bn_pctx = &bn_ctx;
    BN_CTX_init(bn_pctx);
#endif

#define X(m, r, g) \
    BN_mul(r, m, r, bn_pctx);\
    BN_mod(r, r, g, bn_pctx)

#define Y(m, r, g) \
    BN_mul(m, m, m, bn_pctx);\
    BN_mod(m, m, g, bn_pctx)

#define SWAP(i, j) \
    { \
      BIGNUM tmp; \
      tmp = m[i]; m[i] = m[j]; m[j] = tmp; \
      tmp = r[i]; r[i] = r[j]; r[j] = tmp; \
    }

    /* real_j is 1, bit 25 is 0 */
    Y(&m[0], &r[0], g);
    Y(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    /* real_j is 1, bit 26 is 0 */
    X(&m[0], &r[0], g);
    X(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    SWAP(0, 0);
    SWAP(1, 0);
    SWAP(2, 2);
    /* real_j is 0, bit 27 is 0 */
    X(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    /* real_j is 0, bit 28 is 1 */
    X(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    /* real_j is 0, bit 29 is 1 */
    X(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    /* real_j is 0, bit 30 is 0 */
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    /* real_j is 0, bit 31 is 0 */
    X(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    /* real_j is 0, bit 32 is 0 */
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    SWAP(0, 0);
    SWAP(1, 0);
    SWAP(2, 0);
    /* real_j is 1, bit 33 is 0 */
    X(&m[0], &r[0], g);
    Y(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    /* real_j is 1, bit 34 is 0 */
    Y(&m[0], &r[0], g);
    Y(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    /* real_j is 1, bit 35 is 1 */
    X(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    X(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    /* real_j is 1, bit 36 is 1 */
    X(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    X(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    /* real_j is 1, bit 37 is 1 */
    Y(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    /* real_j is 1, bit 38 is 1 */
    Y(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    SWAP(0, 0);
    SWAP(1, 0);
    SWAP(2, 1);
    /* real_j is 0, bit 39 is 1 */
    X(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    /* real_j is 0, bit 40 is 0 */
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    /* real_j is 0, bit 41 is 0 */
    X(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    /* real_j is 0, bit 42 is 1 */
    X(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    /* real_j is 0, bit 43 is 1 */
    X(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    /* real_j is 0, bit 44 is 1 */
    X(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    SWAP(0, 0);
    SWAP(1, 1);
    SWAP(2, 1);
    /* real_j is 0, bit 45 is 0 */
    Y(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    SWAP(0, 0);
    SWAP(1, 1);
    SWAP(2, 2);
    /* real_j is 0, bit 46 is 0 */
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    /* real_j is 0, bit 47 is 0 */
    X(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    SWAP(0, 0);
    SWAP(1, 1);
    SWAP(2, 2);
    /* real_j is 0, bit 48 is 0 */
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    /* real_j is 0, bit 49 is 1 */
    X(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    SWAP(0, 0);
    SWAP(1, 0);
    SWAP(2, 2);

    BN_CTX_free(bn_pctx);
}

#if TARGET_MAC
#pragma global_optimizer reset
#pragma optimization_level reset
#endif
