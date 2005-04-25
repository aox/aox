/*
 ---------------------------------------------------------------------------
 Copyright (c) 2002, Dr Brian Gladman, Worcester, UK.   All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software in both source and binary
 form is allowed (with or without changes) provided that:

   1. distributions of this source code include the above copyright
      notice, this list of conditions and the following disclaimer;

   2. distributions in binary form include the above copyright
      notice, this list of conditions and the following disclaimer
      in the documentation and/or other associated materials;

   3. the copyright holder's name is not used to endorse products
      built using this software without specific written permission.

 ALTERNATIVELY, provided that this notice is retained in full, this product
 may be distributed under the terms of the GNU General Public License (GPL),
 in which case the provisions of the GPL apply INSTEAD OF those given above.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 23/02/2005
*/

#ifndef _SHA2_H
#define _SHA2_H

#include <limits.h>

/* #define SHA_64BIT */

/* define the hash functions that you need  */
#define SHA_2   /* for dynamic hash length  */
#define SHA_224
#define SHA_256
#ifdef SHA_64BIT
#  define SHA_384
#  define SHA_512
#endif

#if defined(__cplusplus)
extern "C"
{
#endif

#define SHA2_GOOD   0
#define SHA2_BAD    1

#ifndef SHA2_DLL    /* implement normal or DLL functions   */
#define sha2_void   void
#define sha2_int    int
#else
#define sha2_void   void __declspec(dllexport) _stdcall
#define sha2_int    int  __declspec(dllexport) _stdcall
#endif

/* Note that the following function prototypes are the same */
/* for both the bit and byte oriented implementations.  But */
/* the length fields are in bytes or bits as is appropriate */
/* for the version used.  Bit sequences are arrays of bytes */
/* in which bit sequence indexes increase from the most to  */
/* the least significant end of each byte                   */

#define SHA224_DIGEST_SIZE  28
#define SHA224_BLOCK_SIZE   64
#define SHA256_DIGEST_SIZE  32
#define SHA256_BLOCK_SIZE   64

/* define an unsigned 32-bit type */

#if defined(_MSC_VER)
  typedef   unsigned long    sha2_32t;
#elif defined(ULONG_MAX) && ULONG_MAX == 4294967295ul
  typedef   unsigned long    sha2_32t;
#elif defined(UINT_MAX) && UINT_MAX == 4294967295
  typedef   unsigned int     sha2_32t;
#elif defined(_CRAY)
  /* USE_SHA-2 is undefined on Crays, however we define a dummy data type
     to get the code to compile */
/*#error Crays don't support 32-bit data types, this code won't compile on a Cray*/
  typedef   unsigned int     sha2_32t;
#else
# error Please define sha2_32t as an unsigned 32 bit type in sha2.h
#endif

/* type to hold the SHA256 (and SHA224) context */

typedef struct
{   sha2_32t count[2];
    sha2_32t hash[8];
    sha2_32t wbuf[16];
} sha256_ctx;

typedef sha256_ctx  sha224_ctx;

sha2_void sha256_compile(sha256_ctx ctx[1]);

sha2_void sha224_begin(sha224_ctx ctx[1]);
#define sha224_hash sha256_hash
sha2_void sha224_end(unsigned char hval[], sha224_ctx ctx[1]);
sha2_void sha224(unsigned char hval[], const unsigned char data[], unsigned long len);

sha2_void sha256_begin(sha256_ctx ctx[1]);
sha2_void sha256_hash(const unsigned char data[], unsigned long len, sha256_ctx ctx[1]);
sha2_void sha256_end(unsigned char hval[], sha256_ctx ctx[1]);
sha2_void sha256(unsigned char hval[], const unsigned char data[], unsigned long len);

#ifndef SHA_64BIT

typedef struct
{   union
    { sha256_ctx  ctx256[1];
    } uu[1];
    sha2_32t    sha2_len;
} sha2_ctx;

#define SHA2_MAX_DIGEST_SIZE    SHA256_DIGEST_SIZE

#else

#define SHA384_DIGEST_SIZE  48
#define SHA384_BLOCK_SIZE  128
#define SHA512_DIGEST_SIZE  64
#define SHA512_BLOCK_SIZE  128
#define SHA2_MAX_DIGEST_SIZE    SHA512_DIGEST_SIZE

/* define an unsigned 64-bit type (thanks go to Mark Shelor */
/* and Olaf Pors for their help in developing and testing   */
/* this). Note that li_64(h) is needed to substitute 'ui64' */
/* for 'ull' as the suffix for defining 64-bit literals in  */
/* Microsoft VC++ versions below 7.1 (with _MSCVER < 1310)  */

#define li_64(h)    0x##h##ull

#if defined( _MSC_VER )
# if _MSC_VER < 1310
    typedef unsigned __int64   sha2_64t;
#   undef  li_64
#   define li_64(h) 0x##h##ui64
# else
    typedef unsigned long long sha2_64t;
# endif
#elif defined( __sun ) && defined(ULONG_MAX) && ULONG_MAX == 0xfffffffful
  typedef unsigned long long    sha2_64t;   /* hack for Sun 32-bit case */
#elif defined( ULONG_LONG_MAX ) && ULONG_LONG_MAX == 0xffffffffffffffffull
  typedef unsigned long long    sha2_64t;
#elif defined( ULLONG_MAX ) && ULLONG_MAX == 0xffffffffffffffffull
  typedef unsigned long long    sha2_64t;
#elif defined( ULONG_MAX ) && ULONG_MAX == 0xfffffffffffffffful
  typedef unsigned long         sha2_64t;
#elif defined( UINT_MAX ) && UINT_MAX == 0xffffffffffffffff
  typedef unsigned int          sha2_64t;
#else
# error Please define sha2_64t as an unsigned 64 bit type in sha2.h
#endif

/* type to hold the SHA384 (and SHA512) context */

typedef struct
{   sha2_64t count[2];
    sha2_64t hash[8];
    sha2_64t wbuf[16];
} sha512_ctx;

typedef sha512_ctx  sha384_ctx;

typedef struct
{   union
    { sha256_ctx  ctx256[1];
      sha512_ctx  ctx512[1];
    } uu[1];
    sha2_32t    sha2_len;
} sha2_ctx;

sha2_void sha512_compile(sha512_ctx ctx[1]);

sha2_void sha384_begin(sha384_ctx ctx[1]);
#define sha384_hash sha512_hash
sha2_void sha384_end(unsigned char hval[], sha384_ctx ctx[1]);
sha2_void sha384(unsigned char hval[], const unsigned char data[], unsigned long len);

sha2_void sha512_begin(sha512_ctx ctx[1]);
sha2_void sha512_hash(const unsigned char data[], unsigned long len, sha512_ctx ctx[1]);
sha2_void sha512_end(unsigned char hval[], sha512_ctx ctx[1]);
sha2_void sha512(unsigned char hval[], const unsigned char data[], unsigned long len);

sha2_int  sha2_begin(unsigned long size, sha2_ctx ctx[1]);
sha2_void sha2_hash(const unsigned char data[], unsigned long len, sha2_ctx ctx[1]);
sha2_void sha2_end(unsigned char hval[], sha2_ctx ctx[1]);
sha2_int  sha2(unsigned char hval[], unsigned long size, const unsigned char data[], unsigned long len);

#endif

#if defined(__cplusplus)
}
#endif

#endif
