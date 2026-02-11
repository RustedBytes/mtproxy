#ifndef XYSSL_MD5_H
#define XYSSL_MD5_H

#ifdef __cplusplus
extern "C" {
#endif

void md5(unsigned char *input, int ilen, unsigned char output[16]);

void md5_hex(char *input, int ilen, char output[32]);

#ifdef __cplusplus
}
#endif

#endif /* md5.h */
