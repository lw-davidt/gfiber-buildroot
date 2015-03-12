#if TARGET_MAC
#pragma global_optimizer off
#pragma optimization_level 0
#endif

#include "openssl/bn.h"

void blue_server_3(BIGNUM *m, BIGNUM *r, BIGNUM *g) {
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

    /* real_j is 1, bit 79 is 1 */
    Y(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    X(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    /* real_j is 1, bit 80 is 0 */
    Y(&m[0], &r[0], g);
    Y(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    /* real_j is 1, bit 81 is 1 */
    X(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    /* real_j is 1, bit 82 is 1 */
    X(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    SWAP(0, 0);
    SWAP(1, 1);
    SWAP(2, 1);
    /* real_j is 2, bit 83 is 1 */
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    SWAP(0, 0);
    SWAP(1, 1);
    SWAP(2, 1);
    /* real_j is 1, bit 84 is 0 */
    X(&m[0], &r[0], g);
    X(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    /* real_j is 1, bit 85 is 0 */
    X(&m[0], &r[0], g);
    Y(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    /* real_j is 1, bit 86 is 1 */
    X(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    /* real_j is 1, bit 87 is 0 */
    Y(&m[0], &r[0], g);
    Y(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    SWAP(0, 0);
    SWAP(1, 0);
    SWAP(2, 0);
    /* real_j is 2, bit 88 is 1 */
    Y(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    X(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    /* real_j is 2, bit 89 is 1 */
    X(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    /* real_j is 2, bit 90 is 0 */
    Y(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    X(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    /* real_j is 2, bit 91 is 0 */
    Y(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    SWAP(0, 0);
    SWAP(1, 0);
    SWAP(2, 2);
    /* real_j is 2, bit 92 is 1 */
    Y(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    X(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    /* real_j is 2, bit 93 is 1 */
    X(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    X(&m[2], &r[2], g);
    Y(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);
    /* real_j is 2, bit 94 is 0 */
    X(&m[0], &r[0], g);
    X(&m[1], &r[1], g);
    X(&m[0], &r[0], g);
    Y(&m[1], &r[1], g);
    Y(&m[2], &r[2], g);

    BN_CTX_free(bn_pctx);
}

#if TARGET_MAC
#pragma global_optimizer reset
#pragma optimization_level reset
#endif
