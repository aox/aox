/****************************************************************************
*																			*
*								cryptlib Test Code							*
*						Copyright Peter Gutmann 1995-2003					*
*																			*
****************************************************************************/

#ifdef _MSC_VER
  #include "../cryptlib.h"
  #include "../test/test.h"
#else
  #include "cryptlib.h"
  #include "test/test.h"
#endif /* Braindamaged VC++ include handling */

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII. */
  #pragma convlit( suspend )
#endif /* EBCDIC systems */

/* Define the following to perform a smoke test on the cryptlib kernel */

/* #define SMOKE_TEST */

/* Whether various keyset tests worked, the results are used later to test
   other routines.  We initially set the key read result to TRUE in case the
   keyset read tests are never called, so we can still trying reading the
   keys in other tests */

int keyReadOK = TRUE, doubleCertOK = FALSE;

/* The keys for testing the RSA, DSA, and Elgamal implementations. These are
   the same 512-bit keys as the one used for the lib_xxx.c self-tests.  The
   key values may be extracted with the following code */

#if 0
{
#include <stdio.h>

BYTE buffer[ CRYPT_MAX_PKCSIZE ];
int length, i;

length = BN_bn2bin( cryptInfo->ctxPKC.rsaParam_n, buffer );
printf( "\t/* n */\r\n\t%d,", BN_num_bits( cryptInfo->ctxPKC.rsaParam_n ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( cryptInfo->ctxPKC.rsaParam_e, buffer );
printf( "\r\n\r\n\t/* e */\r\n\t%d,", BN_num_bits( cryptInfo->ctxPKC.rsaParam_e ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( cryptInfo->ctxPKC.rsaParam_d, buffer );
printf( "\r\n\r\n\t/* d */\r\n\t%d,", BN_num_bits( cryptInfo->ctxPKC.rsaParam_d ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( cryptInfo->ctxPKC.rsaParam_p, buffer );
printf( "\r\n\r\n\t/* p */\r\n\t%d,", BN_num_bits( cryptInfo->ctxPKC.rsaParam_p ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( cryptInfo->ctxPKC.rsaParam_q, buffer );
printf( "\r\n\r\n\t/* q */\r\n\t%d,", BN_num_bits( cryptInfo->ctxPKC.rsaParam_q ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( cryptInfo->ctxPKC.rsaParam_u, buffer );
printf( "\r\n\r\n\t/* u */\r\n\t%d,", BN_num_bits( cryptInfo->ctxPKC.rsaParam_u ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( cryptInfo->ctxPKC.rsaParam_exponent1, buffer );
printf( "\r\n\r\n\t/* exponent1 */\r\n\t%d,", BN_num_bits( cryptInfo->ctxPKC.rsaParam_exponent1 ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( cryptInfo->ctxPKC.rsaParam_exponent2, buffer );
printf( "\r\n\r\n\t/* exponent2 */\r\n\t%d,", BN_num_bits( cryptInfo->ctxPKC.rsaParam_exponent2 ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
puts( "\r\n\t};" );
}
#endif

typedef struct {
	const int nLen; const BYTE n[ 128 ];
	const int eLen; const BYTE e[ 3 ];
	const int dLen; const BYTE d[ 128 ];
	const int pLen; const BYTE p[ 64 ];
	const int qLen; const BYTE q[ 64 ];
	const int uLen; const BYTE u[ 64 ];
	const int e1Len; const BYTE e1[ 64 ];
	const int e2Len; const BYTE e2[ 64 ];
	} RSA_KEY;

static const RSA_KEY rsa512TestKey = {
	/* n */
	512,
	{ 0xE1, 0x95, 0x41, 0x17, 0xB4, 0xCB, 0xDC, 0xD0,
	  0xCB, 0x9B, 0x11, 0x19, 0x9C, 0xED, 0x04, 0x6F,
	  0xBD, 0x70, 0x2D, 0x5C, 0x8A, 0x32, 0xFF, 0x16,
	  0x22, 0x57, 0x30, 0x3B, 0xD4, 0x59, 0x9C, 0x01,
	  0xF0, 0xA3, 0x70, 0xA1, 0x6C, 0x16, 0xAC, 0xCC,
	  0x8C, 0xAD, 0xB0, 0xA0, 0xAF, 0xC7, 0xCC, 0x49,
	  0x4F, 0xD9, 0x5D, 0x32, 0x1C, 0x2A, 0xE8, 0x4E,
	  0x15, 0xE1, 0x26, 0x6C, 0xC4, 0xB8, 0x94, 0xE1 },
	/* e */
	5,
	{ 0x11 },
	/* d */
	509,
	{ 0x13, 0xE7, 0x85, 0xBE, 0x53, 0xB7, 0xA2, 0x8A,
	  0xE4, 0xC9, 0xEA, 0xEB, 0xAB, 0xF6, 0xCB, 0xAF,
	  0x81, 0xA8, 0x04, 0x00, 0xA2, 0xC8, 0x43, 0xAF,
	  0x21, 0x25, 0xCF, 0x8C, 0xCE, 0xF8, 0xD9, 0x0F,
	  0x10, 0x78, 0x4C, 0x1A, 0x26, 0x5D, 0x90, 0x18,
	  0x79, 0x90, 0x42, 0x83, 0x6E, 0xAE, 0x3E, 0x20,
	  0x0B, 0x0C, 0x5B, 0x6B, 0x8E, 0x31, 0xE5, 0xCF,
	  0xD6, 0xE0, 0xBB, 0x41, 0xC1, 0xB8, 0x2E, 0x17 },
	/* p */
	256,
	{ 0xED, 0xE4, 0x02, 0x90, 0xA4, 0xA4, 0x98, 0x0D,
	  0x45, 0xA2, 0xF3, 0x96, 0x09, 0xED, 0x7B, 0x40,
	  0xCD, 0xF6, 0x21, 0xCC, 0xC0, 0x1F, 0x83, 0x09,
	  0x56, 0x37, 0x97, 0xFB, 0x05, 0x5B, 0x87, 0xB7 },
	/* q */
	256,
	{ 0xF2, 0xC1, 0x64, 0xE8, 0x69, 0xF8, 0x5E, 0x54,
	  0x8F, 0xFD, 0x20, 0x8E, 0x6A, 0x23, 0x90, 0xF2,
	  0xAF, 0x57, 0x2F, 0x4D, 0x10, 0x80, 0x8E, 0x11,
	  0x3C, 0x61, 0x44, 0x33, 0x2B, 0xE0, 0x58, 0x27 },
	/* u */
	255,
	{ 0x87, 0xB5, 0xEE, 0xA0, 0xC1, 0xF8, 0x27, 0x93,
	  0xCB, 0xE3, 0xD8, 0xA4, 0x5C, 0xF1, 0xBE, 0x17,
	  0xAA, 0x1A, 0xBB, 0xF6, 0x5C, 0x0A, 0x92, 0xEC,
	  0x92, 0xD8, 0x57, 0x53, 0xDC, 0xCA, 0x3D, 0x74 },
	/* exponent1 */
	256,
	{ 0x99, 0xED, 0xE3, 0x8A, 0xC4, 0xE2, 0xF8, 0xF9,
	  0x87, 0x69, 0x70, 0x70, 0x24, 0x8A, 0x9B, 0x0B,
	  0xD0, 0x90, 0x33, 0xFC, 0xF4, 0xC9, 0x18, 0x8D,
	  0x92, 0x23, 0xF8, 0xED, 0xB8, 0x2C, 0x2A, 0xA3 },
	/* exponent2 */
	256,
	{ 0xB9, 0xA2, 0xF2, 0xCF, 0xD8, 0x90, 0xC0, 0x9B,
	  0x04, 0xB2, 0x82, 0x4E, 0xC9, 0xA2, 0xBA, 0x22,
	  0xFE, 0x8D, 0xF6, 0xFE, 0xB2, 0x44, 0x30, 0x67,
	  0x88, 0x86, 0x9D, 0x90, 0x8A, 0xF6, 0xD9, 0xFF }
	};

static const RSA_KEY rsa1024TestKey = {
	/* n */
	1024,
	{ 0x9C, 0x4D, 0x98, 0x18, 0x67, 0xF9, 0x45, 0xBC,
	  0xB6, 0x75, 0x53, 0x5D, 0x2C, 0xFA, 0x55, 0xE4,
	  0x51, 0x54, 0x9F, 0x0C, 0x16, 0xB1, 0xAF, 0x89,
	  0xF6, 0xF3, 0xE7, 0x78, 0xB1, 0x2B, 0x07, 0xFB,
	  0xDC, 0xDE, 0x64, 0x23, 0x34, 0x87, 0xDA, 0x0B,
	  0xE5, 0xB3, 0x17, 0x16, 0xA4, 0xE3, 0x7F, 0x23,
	  0xDF, 0x96, 0x16, 0x28, 0xA6, 0xD2, 0xF0, 0x0A,
	  0x59, 0xEE, 0x06, 0xB3, 0x76, 0x6C, 0x64, 0x19,
	  0xD9, 0x76, 0x41, 0x25, 0x66, 0xD1, 0x93, 0x51,
	  0x52, 0x06, 0x6B, 0x71, 0x50, 0x0E, 0xAB, 0x30,
	  0xA5, 0xC8, 0x41, 0xFC, 0x30, 0xBC, 0x32, 0xD7,
	  0x4B, 0x22, 0xF2, 0x45, 0x4C, 0x94, 0x68, 0xF1,
	  0x92, 0x8A, 0x4C, 0xF9, 0xD4, 0x5E, 0x87, 0x92,
	  0xA8, 0x54, 0x93, 0x92, 0x94, 0x48, 0xA4, 0xA3,
	  0xEE, 0x19, 0x7F, 0x6E, 0xD3, 0x14, 0xB1, 0x48,
	  0xCE, 0x93, 0xD1, 0xEA, 0x4C, 0xE1, 0x9D, 0xEF },

	/* e */
	17,
	{ 0x01, 0x00, 0x01 },

	/* d */
	1022,
	{ 0x37, 0xE2, 0x66, 0x67, 0x13, 0x85, 0xC4, 0xB1,
	  0x5C, 0x6B, 0x46, 0x8B, 0x21, 0xF1, 0xBF, 0x94,
	  0x0A, 0xA0, 0x3E, 0xDD, 0x8B, 0x9F, 0xAC, 0x2B,
	  0x9F, 0xE8, 0x44, 0xF2, 0x9A, 0x25, 0xD0, 0x8C,
	  0xF4, 0xC3, 0x6E, 0xFA, 0x47, 0x65, 0xEB, 0x48,
	  0x25, 0xB0, 0x8A, 0xA8, 0xC5, 0xFB, 0xB1, 0x11,
	  0x9A, 0x77, 0x87, 0x24, 0xB1, 0xC0, 0xE9, 0xA2,
	  0x49, 0xD5, 0x19, 0x00, 0x41, 0x6F, 0x2F, 0xBA,
	  0x9F, 0x28, 0x47, 0xF9, 0xB8, 0xBA, 0xFF, 0xF4,
	  0x8B, 0x20, 0xC9, 0xC9, 0x39, 0xAB, 0x52, 0x0E,
	  0x8A, 0x5A, 0xAF, 0xB3, 0xA3, 0x93, 0x4D, 0xBB,
	  0xFE, 0x62, 0x9B, 0x02, 0xCC, 0xA7, 0xB4, 0xAE,
	  0x86, 0x65, 0x88, 0x19, 0xD7, 0x44, 0xA7, 0xE4,
	  0x18, 0xB6, 0xCE, 0x01, 0xCD, 0xDF, 0x36, 0x81,
	  0xD5, 0xE1, 0x62, 0xF8, 0xD0, 0x27, 0xF1, 0x86,
	  0xA8, 0x58, 0xA7, 0xEB, 0x39, 0x79, 0x56, 0x41 },

	/* p */
	512,
	{ 0xCF, 0xDA, 0xF9, 0x99, 0x6F, 0x05, 0x95, 0x84,
	  0x09, 0x90, 0xB3, 0xAB, 0x39, 0xB7, 0xDD, 0x1D,
	  0x7B, 0xFC, 0xFD, 0x10, 0x35, 0xA0, 0x18, 0x1D,
	  0x9A, 0x11, 0x30, 0x90, 0xD4, 0x3B, 0xF0, 0x5A,
	  0xC1, 0xA6, 0xF4, 0x53, 0xD0, 0x94, 0xA0, 0xED,
	  0xE0, 0xE4, 0xE0, 0x8E, 0x44, 0x18, 0x42, 0x42,
	  0xE1, 0x2C, 0x0D, 0xF7, 0x30, 0xE2, 0xB8, 0x09,
	  0x73, 0x50, 0x28, 0xF6, 0x55, 0x85, 0x57, 0x03 },

	/* q */
	512,
	{ 0xC0, 0x81, 0xC4, 0x82, 0x6E, 0xF6, 0x1C, 0x92,
	  0x83, 0xEC, 0x17, 0xFB, 0x30, 0x98, 0xED, 0x6E,
	  0x89, 0x92, 0xB2, 0xA1, 0x21, 0x0D, 0xC1, 0x95,
	  0x49, 0x99, 0xD3, 0x79, 0xD3, 0xBD, 0x94, 0x93,
	  0xB9, 0x28, 0x68, 0xFF, 0xDE, 0xEB, 0xE8, 0xD2,
	  0x0B, 0xED, 0x7C, 0x08, 0xD0, 0xD5, 0x59, 0xE3,
	  0xC1, 0x76, 0xEA, 0xC1, 0xCD, 0xB6, 0x8B, 0x39,
	  0x4E, 0x29, 0x59, 0x5F, 0xFA, 0xCE, 0x83, 0xA5 },

	/* u */
	511,
	{ 0x4B, 0x87, 0x97, 0x1F, 0x27, 0xED, 0xAA, 0xAF,
	  0x42, 0xF4, 0x57, 0x82, 0x3F, 0xEC, 0x80, 0xED,
	  0x1E, 0x91, 0xF8, 0xB4, 0x33, 0xDA, 0xEF, 0xC3,
	  0x03, 0x53, 0x0F, 0xCE, 0xB9, 0x5F, 0xE4, 0x29,
	  0xCC, 0xEE, 0x6A, 0x5E, 0x11, 0x0E, 0xFA, 0x66,
	  0x85, 0xDC, 0xFC, 0x48, 0x31, 0x0C, 0x00, 0x97,
	  0xC6, 0x0A, 0xF2, 0x34, 0x60, 0x6B, 0xF7, 0x68,
	  0x09, 0x4E, 0xCF, 0xB1, 0x9E, 0x33, 0x9A, 0x41 },

	/* exponent1 */
	511,
	{ 0x6B, 0x2A, 0x0D, 0xF8, 0x22, 0x7A, 0x71, 0x8C,
	  0xE2, 0xD5, 0x9D, 0x1C, 0x91, 0xA4, 0x8F, 0x37,
	  0x0D, 0x5E, 0xF1, 0x26, 0x73, 0x4F, 0x78, 0x3F,
	  0x82, 0xD8, 0x8B, 0xFE, 0x8F, 0xBD, 0xDB, 0x7D,
	  0x1F, 0x4C, 0xB1, 0xB9, 0xA8, 0xD7, 0x88, 0x65,
	  0x3C, 0xC7, 0x24, 0x53, 0x95, 0x1E, 0x20, 0xC3,
	  0x94, 0x8E, 0x7F, 0x20, 0xCC, 0x2E, 0x88, 0x0E,
	  0x2F, 0x4A, 0xCB, 0xE3, 0xBD, 0x52, 0x02, 0xFB },

	/* exponent2 */
	509,
	{ 0x10, 0x27, 0xD3, 0xD2, 0x0E, 0x75, 0xE1, 0x17,
	  0xFA, 0xB2, 0x49, 0xA0, 0xEF, 0x07, 0x26, 0x85,
	  0xEC, 0x4D, 0xBF, 0x67, 0xFE, 0x5A, 0x25, 0x30,
	  0xDE, 0x28, 0x66, 0xB3, 0x06, 0xAE, 0x16, 0x55,
	  0xFF, 0x68, 0x00, 0xC7, 0xD8, 0x71, 0x7B, 0xEC,
	  0x84, 0xCB, 0xBD, 0x69, 0x0F, 0xFD, 0x97, 0xB9,
	  0xA1, 0x76, 0xD5, 0x64, 0xC6, 0x5A, 0xD7, 0x7C,
	  0x4B, 0xAE, 0xF4, 0xAD, 0x35, 0x63, 0x37, 0x71 }
	};

typedef struct {
	const int pLen; const BYTE p[ 64 ];
	const int qLen; const BYTE q[ 20 ];
	const int gLen; const BYTE g[ 64 ];
	const int xLen; const BYTE x[ 20 ];
	const int yLen; const BYTE y[ 64 ];
	} DLP_PRIVKEY;

static const DLP_PRIVKEY dlpTestKey = {
	/* p */
	512,
	{ 0x8D, 0xF2, 0xA4, 0x94, 0x49, 0x22, 0x76, 0xAA,
	  0x3D, 0x25, 0x75, 0x9B, 0xB0, 0x68, 0x69, 0xCB,
	  0xEA, 0xC0, 0xD8, 0x3A, 0xFB, 0x8D, 0x0C, 0xF7,
	  0xCB, 0xB8, 0x32, 0x4F, 0x0D, 0x78, 0x82, 0xE5,
	  0xD0, 0x76, 0x2F, 0xC5, 0xB7, 0x21, 0x0E, 0xAF,
	  0xC2, 0xE9, 0xAD, 0xAC, 0x32, 0xAB, 0x7A, 0xAC,
	  0x49, 0x69, 0x3D, 0xFB, 0xF8, 0x37, 0x24, 0xC2,
	  0xEC, 0x07, 0x36, 0xEE, 0x31, 0xC8, 0x02, 0x91 },
	/* q */
	160,
	{ 0xC7, 0x73, 0x21, 0x8C, 0x73, 0x7E, 0xC8, 0xEE,
	  0x99, 0x3B, 0x4F, 0x2D, 0xED, 0x30, 0xF4, 0x8E,
	  0xDA, 0xCE, 0x91, 0x5F },
	/* g */
	512,
	{ 0x62, 0x6D, 0x02, 0x78, 0x39, 0xEA, 0x0A, 0x13,
	  0x41, 0x31, 0x63, 0xA5, 0x5B, 0x4C, 0xB5, 0x00,
	  0x29, 0x9D, 0x55, 0x22, 0x95, 0x6C, 0xEF, 0xCB,
	  0x3B, 0xFF, 0x10, 0xF3, 0x99, 0xCE, 0x2C, 0x2E,
	  0x71, 0xCB, 0x9D, 0xE5, 0xFA, 0x24, 0xBA, 0xBF,
	  0x58, 0xE5, 0xB7, 0x95, 0x21, 0x92, 0x5C, 0x9C,
	  0xC4, 0x2E, 0x9F, 0x6F, 0x46, 0x4B, 0x08, 0x8C,
	  0xC5, 0x72, 0xAF, 0x53, 0xE6, 0xD7, 0x88, 0x02 },
	/* x */
	160,
	{ 0x20, 0x70, 0xB3, 0x22, 0x3D, 0xBA, 0x37, 0x2F,
	  0xDE, 0x1C, 0x0F, 0xFC, 0x7B, 0x2E, 0x3B, 0x49,
	  0x8B, 0x26, 0x06, 0x14 },
	/* y */
	512,
	{ 0x19, 0x13, 0x18, 0x71, 0xD7, 0x5B, 0x16, 0x12,
	  0xA8, 0x19, 0xF2, 0x9D, 0x78, 0xD1, 0xB0, 0xD7,
	  0x34, 0x6F, 0x7A, 0xA7, 0x7B, 0xB6, 0x2A, 0x85,
	  0x9B, 0xFD, 0x6C, 0x56, 0x75, 0xDA, 0x9D, 0x21,
	  0x2D, 0x3A, 0x36, 0xEF, 0x16, 0x72, 0xEF, 0x66,
	  0x0B, 0x8C, 0x7C, 0x25, 0x5C, 0xC0, 0xEC, 0x74,
	  0x85, 0x8F, 0xBA, 0x33, 0xF4, 0x4C, 0x06, 0x69,
	  0x96, 0x30, 0xA7, 0x6B, 0x03, 0x0E, 0xE3, 0x33 }
	};

#ifdef TEST_CONFIG

/* The names of the configuration options we check for */

static struct {
	const CRYPT_ATTRIBUTE_TYPE option;	/* Option */
	const char *name;					/* Option name */
	const BOOLEAN isNumeric;			/* Whether it's a numeric option */
	} configOption[] = {
	{ CRYPT_OPTION_INFO_DESCRIPTION, "CRYPT_OPTION_INFO_DESCRIPTION", FALSE },
	{ CRYPT_OPTION_INFO_COPYRIGHT, "CRYPT_OPTION_INFO_COPYRIGHT", FALSE },
	{ CRYPT_OPTION_INFO_MAJORVERSION, "CRYPT_OPTION_INFO_MAJORVERSION", TRUE },
	{ CRYPT_OPTION_INFO_MINORVERSION, "CRYPT_OPTION_INFO_MINORVERSION", TRUE },
	{ CRYPT_OPTION_INFO_STEPPING, "CRYPT_OPTION_INFO_STEPPING", TRUE },

	{ CRYPT_OPTION_ENCR_ALGO, "CRYPT_OPTION_ENCR_ALGO", TRUE },
	{ CRYPT_OPTION_ENCR_HASH, "CRYPT_OPTION_ENCR_HASH", TRUE },
	{ CRYPT_OPTION_ENCR_MAC, "CRYPT_OPTION_ENCR_MAC", TRUE },

	{ CRYPT_OPTION_PKC_ALGO, "CRYPT_OPTION_PKC_ALGO", TRUE },
	{ CRYPT_OPTION_PKC_KEYSIZE, "CRYPT_OPTION_PKC_KEYSIZE", TRUE },

	{ CRYPT_OPTION_SIG_ALGO, "CRYPT_OPTION_SIG_ALGO", TRUE },
	{ CRYPT_OPTION_SIG_KEYSIZE, "CRYPT_OPTION_SIG_KEYSIZE", TRUE },

	{ CRYPT_OPTION_KEYING_ALGO, "CRYPT_OPTION_KEYING_ALGO", TRUE },
	{ CRYPT_OPTION_KEYING_ITERATIONS, "CRYPT_OPTION_KEYING_ITERATIONS", TRUE },

	{ CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, "CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES", TRUE },
	{ CRYPT_OPTION_CERT_VALIDITY, "CRYPT_OPTION_CERT_VALIDITY", TRUE },
	{ CRYPT_OPTION_CERT_UPDATEINTERVAL, "CRYPT_OPTION_CERT_UPDATEINTERVAL", TRUE },
	{ CRYPT_OPTION_CERT_COMPLIANCELEVEL, "CRYPT_OPTION_CERT_COMPLIANCELEVEL", TRUE },

	{ CRYPT_OPTION_CMS_DEFAULTATTRIBUTES, "CRYPT_OPTION_CMS_DEFAULTATTRIBUTES", TRUE },

	{ CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS, "CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE, "CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE", TRUE },
	{ CRYPT_OPTION_KEYS_LDAP_FILTER, "CRYPT_OPTION_KEYS_LDAP_FILTER", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CACERTNAME, "CRYPT_OPTION_KEYS_LDAP_CACERTNAME", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CERTNAME, "CRYPT_OPTION_KEYS_LDAP_CERTNAME", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CRLNAME, "CRYPT_OPTION_KEYS_LDAP_CRLNAME", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_EMAILNAME, "CRYPT_OPTION_KEYS_LDAP_EMAILNAME", FALSE },

	{ CRYPT_OPTION_DEVICE_PKCS11_DVR01, "CRYPT_OPTION_DEVICE_PKCS11_DVR01", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR02, "CRYPT_OPTION_DEVICE_PKCS11_DVR02", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR03, "CRYPT_OPTION_DEVICE_PKCS11_DVR03", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR04, "CRYPT_OPTION_DEVICE_PKCS11_DVR04", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR05, "CRYPT_OPTION_DEVICE_PKCS11_DVR05", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY, "CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY", TRUE },

	{ CRYPT_OPTION_NET_SOCKS_SERVER, "CRYPT_OPTION_NET_SOCKS_SERVER", FALSE },
	{ CRYPT_OPTION_NET_SOCKS_USERNAME, "CRYPT_OPTION_NET_SOCKS_USERNAME", FALSE },
	{ CRYPT_OPTION_NET_HTTP_PROXY, "CRYPT_OPTION_NET_HTTP_PROXY", FALSE },
	{ CRYPT_OPTION_NET_CONNECTTIMEOUT, "CRYPT_OPTION_NET_TIMEOUT", TRUE },
	{ CRYPT_OPTION_NET_TIMEOUT, "CRYPT_OPTION_NET_TIMEOUT", TRUE },

	{ CRYPT_OPTION_MISC_ASYNCINIT, "CRYPT_OPTION_MISC_ASYNCINIT", TRUE },
	{ CRYPT_OPTION_MISC_SIDECHANNELPROTECTION, "CRYPT_OPTION_MISC_SIDECHANNELPROTECTION", TRUE },

	{ CRYPT_ATTRIBUTE_NONE, NULL, 0 }
	};
#endif /* TEST_CONFIG */

/* There are some sizeable (for DOS) data structures used, so we increase the
   stack size to allow for them */

#if defined( __MSDOS16__ ) && defined( __TURBOC__ )
  extern unsigned _stklen = 16384;
#endif /* __MSDOS16__ && __TURBOC__ */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Some algorithms can be disabled to eliminate patent problems or reduce the
   size of the code.  The following functions are used to select generally
   equivalent alternatives if the required algorithm isn't available.  These
   selections make certain assumptions (that the given algorithms are always
   available, which is virtually guaranteed, and that they have the same
   general properties as the algorithms they're replacing, which is also
   usually the case - Blowfish for IDEA, RC2, or RC5, and MD5 for MD4) */

CRYPT_ALGO_TYPE selectCipher( const CRYPT_ALGO_TYPE algorithm )
	{
	if( cryptStatusOK( cryptQueryCapability( algorithm, NULL ) ) )
		return( algorithm );
	return( CRYPT_ALGO_BLOWFISH );
	}

#if defined( __BORLANDC__ ) && ( __BORLANDC__ <= 0x310 )

/* BC++ 3.x doesn't have mbstowcs() in the default library, and also defines
   wchar_t as char (!!) so we fake it here */

size_t mbstowcs( char *pwcs, const char *s, size_t n )
	{
	memcpy( pwcs, s, n );
	return( n );
	}
#endif /* BC++ 3.1 or lower */

/* When using multiple threads we need to delay one thread for a small
   amount of time, unfortunately there's no easy way to do this with pthreads
   so we have to provide the following wrapper function that makes an
   (implementation-specific) attempt at it */

#if defined( UNIX_THREADS ) || defined( WINDOWS_THREADS ) || defined( OS2_THREADS )

#if defined( UNIX_THREADS )
  /* This include must be outside the function to avoid weird compiler errors
	 on some systems */
  #include <sys/time.h>
#endif /* UNIX_THREADS */

void delayThread( const int seconds )
	{
#if defined( UNIX_THREADS )
	struct timeval tv = { 0 };

	/* The following should put a thread to sleep for a second on most
	   systems since the select() should be a thread-safe one in the
	   presence of pthreads */
	tv.tv_sec = seconds;
	select( 1, NULL, NULL, NULL, &tv );
#elif defined( WINDOWS_THREADS )
	Sleep( seconds * 1000 );
#endif /* Threading system-specific delay functions */
	}
#endif /* Systems with threading support */

/* The tests that use databases and cert stores require that the user set
   up a suitable ODBC data source (at least when running under Windows).  To
   help people who don't read documentation, we try and create the data
   source if it isn't present */

#if defined( _MSC_VER ) && defined( _WIN32 )

#define DATABASE_AUTOCONFIG

#include <odbcinst.h>

#define DATABASE_ATTR_NAME		"DSN=" DATABASE_KEYSET_NAME "\0" \
								"DESCRIPTION=cryptlib test key database\0" \
								"DBQ="
#define DATABASE_ATTR_CREATE	"DSN=" DATABASE_KEYSET_NAME "\0" \
								"DESCRIPTION=cryptlib test key database\0" \
								"CREATE_DB="
#define DATABASE_ATTR_TAIL		DATABASE_KEYSET_NAME ".mdb\0"
#define CERTSTORE_ATTR_NAME		"DSN=" CERTSTORE_KEYSET_NAME "\0" \
								"DESCRIPTION=cryptlib test key database\0" \
								"DBQ="
#define CERTSTORE_ATTR_CREATE	"DSN=" CERTSTORE_KEYSET_NAME "\0" \
								"DESCRIPTION=cryptlib test key database\0" \
								"CREATE_DB="
#define CERTSTORE_ATTR_TAIL		CERTSTORE_KEYSET_NAME ".mdb\0"
#ifdef USE_SQLSERVER
  #define DRIVER_NAME			"SQL Server"
#else
  #define DRIVER_NAME			"Microsoft Access Driver (*.MDB)"
#endif /* USE_SQLSERVER */

static void buildDBString( char *buffer, const char *attrName,
						   const int attrNameSize,
						   const char *attrTail, const char *path )
	{
	const int attrTailSize = strlen( attrTail ) + 2;
	const int pathSize = strlen( path );

	memcpy( buffer, attrName, attrNameSize + 1 );
	memcpy( buffer + attrNameSize - 1, path, pathSize );
	memcpy( buffer + attrNameSize - 1 + pathSize, attrTail, attrTailSize );
	}

static void checkCreateDatabaseKeysets( void )
	{
	CRYPT_KEYSET cryptKeyset;
	char tempPathBuffer[ 512 ];
	int length, status;

	if( !( length = GetTempPath( 512, tempPathBuffer ) ) )
		{
		strcpy( tempPathBuffer, "C:\\Temp\\" );
		length = 8;
		}

	/* Try and open the test keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
							  CRYPT_KEYSET_ODBC, DATABASE_KEYSET_NAME,
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		cryptKeysetClose( cryptKeyset );
	else
		{
		if( status == CRYPT_ERROR_OPEN )
			{
			char attrBuffer[ 1024 ];

			/* Try and create the DSN.  This is a two-step process, first we
			   create the DSN and then the underlying file that contains the
			   database */
			puts( "Database keyset " DATABASE_KEYSET_NAME " not found, "
				  "attempting to create data source..." );
			buildDBString( attrBuffer, DATABASE_ATTR_NAME,
						   sizeof( DATABASE_ATTR_NAME ),
						   DATABASE_ATTR_TAIL, tempPathBuffer );
			status = SQLConfigDataSource( NULL, ODBC_ADD_DSN, DRIVER_NAME,
										  attrBuffer );
			if( status == 1 )
				{
				buildDBString( attrBuffer, DATABASE_ATTR_CREATE,
							   sizeof( DATABASE_ATTR_CREATE ),
							   DATABASE_ATTR_TAIL, tempPathBuffer );
				status = SQLConfigDataSource( NULL, ODBC_ADD_DSN,
											  DRIVER_NAME, attrBuffer );
				}
			puts( ( status == 1 ) ? "Data source creation succeeded." : \
				  "Data source creation failed.\n\nYou need to create the "
				  "keyset data source as described in the cryptlib manual\n"
				  "for the database keyset tests to run." );
			}
		}

	/* Try and open the test cert store.  This can return a
	   CRYPT_ARGERROR_PARAM3 as a normal condition since a freshly-created
	   database is empty and therefore can't be identified as a cert store
	   until data is written to it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
							  CRYPT_KEYSET_ODBC_STORE, CERTSTORE_KEYSET_NAME,
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		cryptKeysetClose( cryptKeyset );
	else
		{
		if( status == CRYPT_ERROR_OPEN )
			{
			char attrBuffer[ 1024 ];

			/* Try and create the DSN.  As before, this is a two-step
			   process */
			puts( "Certificate store " CERTSTORE_KEYSET_NAME " not found, "
				  "attempting to create data source..." );
			buildDBString( attrBuffer, CERTSTORE_ATTR_NAME,
						   sizeof( CERTSTORE_ATTR_NAME ),
						   CERTSTORE_ATTR_TAIL, tempPathBuffer );
			status = SQLConfigDataSource( NULL, ODBC_ADD_DSN, DRIVER_NAME,
										  attrBuffer );
			if( status == 1 )
				{
				buildDBString( attrBuffer, CERTSTORE_ATTR_CREATE,
							   sizeof( CERTSTORE_ATTR_CREATE ),
							   CERTSTORE_ATTR_TAIL, tempPathBuffer );
				status = SQLConfigDataSource( NULL, ODBC_ADD_DSN,
											  DRIVER_NAME, attrBuffer );
				}
			puts( ( status == 1 ) ? "Data source creation succeeded.\n" : \
				  "Data source creation failed.\n\nYou need to create the "
				  "certificate store data source as described in the\n"
				  "cryptlib manual for the certificate management tests to "
				  "run.\n" );
			}
		}
	}
#endif /* Win32 with VC++ */

/****************************************************************************
*																			*
*								Key Load Routines							*
*																			*
****************************************************************************/

/* Set the label for a device object */

static BOOLEAN setLabel( const CRYPT_CONTEXT cryptContext, const char *label )
	{
	if( cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL,
								 label, strlen( label ) ) == CRYPT_ERROR_DUPLICATE )
		{
		printf( "A key object with the label '%s' already exists inside the\n"
				"device.  To perform this test, you need to delete the "
				"existing object so\nthat cryptlib can create a new one.\n",
				label );
		return( FALSE );
		}

	return( TRUE );
	}

/* Load RSA, DSA, and Elgamal PKC encrytion contexts */

static int loadRSAPublicKey( const CRYPT_DEVICE cryptDevice,
							 CRYPT_CONTEXT *cryptContext,
							 const char *cryptContextLabel,
							 CRYPT_PKCINFO_RSA *rsaKey,
							 const BOOLEAN isDevice,
							 const BOOLEAN useLargeKey )
	{
	const RSA_KEY *rsaKeyTemplate = useLargeKey ? \
								&rsa1024TestKey : &rsa512TestKey;
	int status;

	if( isDevice )
		status = cryptDeviceCreateContext( cryptDevice, cryptContext,
										   CRYPT_ALGO_RSA );
	else
		status = cryptCreateContext( cryptContext, CRYPT_UNUSED,
									 CRYPT_ALGO_RSA );
	if( cryptStatusError( status ) )
		{
		printf( "crypt%sCreateContext() failed with error code %d.\n",
				isDevice ? "Device" : "", status );
		return( status );
		}
	if( !setLabel( *cryptContext, cryptContextLabel ) )
		{
		cryptDestroyContext( *cryptContext );
		return( status );
		}
	cryptInitComponents( rsaKey, CRYPT_KEYTYPE_PUBLIC );
	cryptSetComponent( rsaKey->n, rsaKeyTemplate->n, rsaKeyTemplate->nLen );
	cryptSetComponent( rsaKey->e, rsaKeyTemplate->e, rsaKeyTemplate->eLen );
	status = cryptSetAttributeString( *cryptContext,
								CRYPT_CTXINFO_KEY_COMPONENTS, rsaKey,
								sizeof( CRYPT_PKCINFO_RSA ) );
	cryptDestroyComponents( rsaKey );
	if( cryptStatusError( status ) )
		cryptDestroyContext( *cryptContext );
	return( status );
	}

BOOLEAN loadRSAContextsEx( const CRYPT_DEVICE cryptDevice,
						   CRYPT_CONTEXT *cryptContext,
						   CRYPT_CONTEXT *decryptContext,
						   const char *cryptContextLabel,
						   const char *decryptContextLabel )
	{
	CRYPT_PKCINFO_RSA *rsaKey;
	const RSA_KEY *rsaKeyTemplate = &rsa512TestKey;
	const BOOLEAN isDevice = ( cryptDevice != CRYPT_UNUSED ) ? TRUE : FALSE;
	BOOLEAN useLargeKey = FALSE;
	int status;

	/* Allocate room for the public-key components */
	if( ( rsaKey = ( CRYPT_PKCINFO_RSA * ) malloc( sizeof( CRYPT_PKCINFO_RSA ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Some devices only support a single key size that isn't the same as
	   the built-in one so we adjust the key size being used if necessary */
	if( isDevice )
		{
		CRYPT_QUERY_INFO cryptQueryInfo;

		status = cryptDeviceQueryCapability( cryptDevice, CRYPT_ALGO_RSA,
											 &cryptQueryInfo );
		if( cryptStatusError( status ) )
			return( FALSE );
		if( cryptQueryInfo.keySize != 64 )
			{
			if( cryptQueryInfo.keySize != 128 )
				{
				printf( "Device requires a %d-bit key, which doesn't "
						"correspond to any built-in\ncryptlib key.\n",
						cryptQueryInfo.keySize );
				return( FALSE );
				}
			rsaKeyTemplate = &rsa1024TestKey;
			useLargeKey = TRUE;
			}
		}

	/* Create the encryption context */
	if( cryptContext != NULL )
		{
		status = loadRSAPublicKey( cryptDevice, cryptContext,
								   cryptContextLabel, rsaKey, isDevice,
								   useLargeKey );
		if( status == CRYPT_ERROR_NOTAVAIL && isDevice )
			{
			/* The device doesn't support public-key ops, use a native
			   context for the public key */
			puts( "  Warning: Device doesn't support public-key operations, "
				  "using a cryptlib\n  native context instead." );
			status = loadRSAPublicKey( CRYPT_UNUSED, cryptContext,
									   cryptContextLabel, rsaKey, FALSE,
									   useLargeKey );
			}
		if( cryptStatusError( status ) )
			{
			free( rsaKey );
			printf( "Key load failed with error code %d.\n", status );
			return( FALSE );
			}
		if( decryptContext == NULL )
			{
			/* We're only using a public-key context, return */
			free( rsaKey );
			return( TRUE );
			}
		}

	/* Create the decryption context */
	if( isDevice )
		status = cryptDeviceCreateContext( cryptDevice, decryptContext,
										   CRYPT_ALGO_RSA );
	else
		status = cryptCreateContext( decryptContext, CRYPT_UNUSED,
									 CRYPT_ALGO_RSA );
	if( cryptStatusError( status ) )
		{
		free( rsaKey );
		if( cryptContext != NULL )
			{
			cryptDestroyContext( *cryptContext );
			if( isDevice )
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
								cryptContextLabel );
			}
		printf( "crypt%sCreateContext() failed with error code %d.\n",
				isDevice ? "Device" : "", status );
		return( FALSE );
		}
	if( !setLabel( *decryptContext, decryptContextLabel ) )
		{
		free( rsaKey );
		cryptDestroyContext( *decryptContext );
		if( cryptContext != NULL )
			{
			cryptDestroyContext( *cryptContext );
			if( isDevice )
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
								cryptContextLabel );
			}
		return( FALSE );
		}
	cryptInitComponents( rsaKey, CRYPT_KEYTYPE_PRIVATE );
	cryptSetComponent( rsaKey->n, rsaKeyTemplate->n, rsaKeyTemplate->nLen );
	cryptSetComponent( rsaKey->e, rsaKeyTemplate->e, rsaKeyTemplate->eLen );
	cryptSetComponent( rsaKey->d, rsaKeyTemplate->d, rsaKeyTemplate->dLen );
	cryptSetComponent( rsaKey->p, rsaKeyTemplate->p, rsaKeyTemplate->pLen );
	cryptSetComponent( rsaKey->q, rsaKeyTemplate->q, rsaKeyTemplate->qLen );
	cryptSetComponent( rsaKey->u, rsaKeyTemplate->u, rsaKeyTemplate->uLen );
	cryptSetComponent( rsaKey->e1, rsaKeyTemplate->e1, rsaKeyTemplate->e1Len );
	cryptSetComponent( rsaKey->e2, rsaKeyTemplate->e2, rsaKeyTemplate->e2Len );
	status = cryptSetAttributeString( *decryptContext,
									  CRYPT_CTXINFO_KEY_COMPONENTS, rsaKey,
									  sizeof( CRYPT_PKCINFO_RSA ) );
	cryptDestroyComponents( rsaKey );
	free( rsaKey );
	if( cryptStatusError( status ) )
		{
		if( cryptContext != NULL )
			{
			cryptDestroyContext( *cryptContext );
			if( isDevice )
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
								cryptContextLabel );
			}
		cryptDestroyContext( *decryptContext );
		if( isDevice )
			cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
							decryptContextLabel );
		printf( "Key load failed with error code %d.\n", status );
		return( FALSE );
		}

	return( TRUE );
	}

BOOLEAN loadRSAContexts( const CRYPT_DEVICE cryptDevice,
						 CRYPT_CONTEXT *cryptContext,
						 CRYPT_CONTEXT *decryptContext )
	{
	return( loadRSAContextsEx( cryptDevice, cryptContext, decryptContext,
							   RSA_PUBKEY_LABEL, RSA_PRIVKEY_LABEL ) );
	}

BOOLEAN loadDSAContextsEx( const CRYPT_DEVICE cryptDevice,
						   CRYPT_CONTEXT *signContext,
						   CRYPT_CONTEXT *sigCheckContext,
						   const char *signContextLabel,
						   const char *sigCheckContextLabel )
	{
	CRYPT_PKCINFO_DLP *dsaKey;
	const BOOLEAN isDevice = ( cryptDevice != CRYPT_UNUSED ) ? TRUE : FALSE;
	int status;

	/* Allocate room for the public-key components */
	if( ( dsaKey = ( CRYPT_PKCINFO_DLP * ) malloc( sizeof( CRYPT_PKCINFO_DLP ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Create the encryption context */
	if( signContext != NULL )
		{
		if( isDevice )
			status = cryptDeviceCreateContext( cryptDevice, signContext,
											   CRYPT_ALGO_DSA );
		else
			status = cryptCreateContext( signContext, CRYPT_UNUSED,
										 CRYPT_ALGO_DSA );
		if( cryptStatusError( status ) )
			{
			free( dsaKey );
			printf( "cryptCreateContext() failed with error code %d.\n",
					status );
			return( FALSE );
			}
		if( !setLabel( *signContext, signContextLabel ) )
			{
			free( dsaKey );
			cryptDestroyContext( *signContext );
			return( FALSE );
			}
		cryptInitComponents( dsaKey, CRYPT_KEYTYPE_PRIVATE );
		cryptSetComponent( dsaKey->p, dlpTestKey.p, dlpTestKey.pLen );
		cryptSetComponent( dsaKey->q, dlpTestKey.q, dlpTestKey.qLen );
		cryptSetComponent( dsaKey->g, dlpTestKey.g, dlpTestKey.gLen );
		cryptSetComponent( dsaKey->x, dlpTestKey.x, dlpTestKey.xLen );
		cryptSetComponent( dsaKey->y, dlpTestKey.y, dlpTestKey.yLen );
		status = cryptSetAttributeString( *signContext,
									CRYPT_CTXINFO_KEY_COMPONENTS, dsaKey,
									sizeof( CRYPT_PKCINFO_DLP ) );
		cryptDestroyComponents( dsaKey );
		if( cryptStatusError( status ) )
			{
			free( dsaKey );
			cryptDestroyContext( *signContext );
			printf( "Key load failed with error code %d.\n", status );
			return( FALSE );
			}
		if( sigCheckContext == NULL )
			{
			free( dsaKey );
			return( TRUE );
			}
		}

	/* Create the decryption context */
	if( isDevice )
		status = cryptDeviceCreateContext( cryptDevice, sigCheckContext,
										   CRYPT_ALGO_DSA );
	else
		status = cryptCreateContext( sigCheckContext, CRYPT_UNUSED,
									 CRYPT_ALGO_DSA );
	if( cryptStatusError( status ) )
		{
		free( dsaKey );
		if( signContext != NULL )
			{
			cryptDestroyContext( *signContext );
			if( isDevice )
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
								signContextLabel );
			}
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	if( !setLabel( *sigCheckContext, sigCheckContextLabel ) )
		{
		if( signContext != NULL )
			{
			cryptDestroyContext( *signContext );
			if( isDevice )
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
								signContextLabel );
			}
		cryptDestroyContext( *sigCheckContext );
		return( FALSE );
		}
	cryptInitComponents( dsaKey, CRYPT_KEYTYPE_PUBLIC );
	cryptSetComponent( dsaKey->p, dlpTestKey.p, dlpTestKey.pLen );
	cryptSetComponent( dsaKey->q, dlpTestKey.q, dlpTestKey.qLen );
	cryptSetComponent( dsaKey->g, dlpTestKey.g, dlpTestKey.gLen );
	cryptSetComponent( dsaKey->y, dlpTestKey.y, dlpTestKey.yLen );
	status = cryptSetAttributeString( *sigCheckContext,
									  CRYPT_CTXINFO_KEY_COMPONENTS, dsaKey,
									  sizeof( CRYPT_PKCINFO_DLP ) );
	cryptDestroyComponents( dsaKey );
	free( dsaKey );
	if( cryptStatusError( status ) )
		{
		if( signContext != NULL )
			{
			cryptDestroyContext( *signContext );
			if( isDevice )
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
								signContextLabel );
			}
		cryptDestroyContext( *sigCheckContext );
		if( isDevice )
			cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME,
							sigCheckContextLabel );
		printf( "Key load failed with error code %d.\n", status );
		return( FALSE );
		}

	return( TRUE );
	}

BOOLEAN loadDSAContexts( const CRYPT_DEVICE cryptDevice,
						 CRYPT_CONTEXT *signContext,
						 CRYPT_CONTEXT *sigCheckContext )
	{
	return( loadDSAContextsEx( cryptDevice, signContext, sigCheckContext,
							   DSA_PRIVKEY_LABEL, DSA_PUBKEY_LABEL ) );
	}

BOOLEAN loadElgamalContexts( CRYPT_CONTEXT *cryptContext,
							 CRYPT_CONTEXT *decryptContext )
	{
	CRYPT_PKCINFO_DLP *elgamalKey;
	int status;

	/* Allocate room for the public-key components */
	if( ( elgamalKey = ( CRYPT_PKCINFO_DLP * ) malloc( sizeof( CRYPT_PKCINFO_DLP ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Create the encryption context */
	if( cryptContext != NULL )
		{
		status = cryptCreateContext( cryptContext, CRYPT_UNUSED,
									 CRYPT_ALGO_ELGAMAL );
		if( cryptStatusError( status ) )
			{
			free( elgamalKey );
			printf( "cryptCreateContext() failed with error code %d.\n", status );
			return( FALSE );
			}
		if( !setLabel( *cryptContext, ELGAMAL_PUBKEY_LABEL ) )
			{
			free( elgamalKey );
			cryptDestroyContext( *cryptContext );
			return( FALSE );
			}
		cryptInitComponents( elgamalKey, CRYPT_KEYTYPE_PUBLIC );
		cryptSetComponent( elgamalKey->p, dlpTestKey.p, dlpTestKey.pLen );
		cryptSetComponent( elgamalKey->g, dlpTestKey.g, dlpTestKey.gLen );
		cryptSetComponent( elgamalKey->q, dlpTestKey.q, dlpTestKey.qLen );
		cryptSetComponent( elgamalKey->y, dlpTestKey.y, dlpTestKey.yLen );
		status = cryptSetAttributeString( *cryptContext,
									CRYPT_CTXINFO_KEY_COMPONENTS, elgamalKey,
									sizeof( CRYPT_PKCINFO_DLP ) );
		cryptDestroyComponents( elgamalKey );
		if( cryptStatusError( status ) )
			{
			free( elgamalKey );
			cryptDestroyContext( *cryptContext );
			printf( "Key load failed with error code %d.\n", status );
			return( FALSE );
			}
		if( decryptContext == NULL )
			{
			free( elgamalKey );
			return( TRUE );
			}
		}

	/* Create the decryption context */
	status = cryptCreateContext( decryptContext, CRYPT_UNUSED,
								 CRYPT_ALGO_ELGAMAL );
	if( cryptStatusError( status ) )
		{
		free( elgamalKey );
		if( cryptContext != NULL )
			cryptDestroyContext( *cryptContext );
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	if( !setLabel( *decryptContext, ELGAMAL_PRIVKEY_LABEL ) )
		{
		free( elgamalKey );
		if( cryptContext != NULL )
			cryptDestroyContext( *cryptContext );
		cryptDestroyContext( *decryptContext );
		return( FALSE );
		}
	cryptInitComponents( elgamalKey, CRYPT_KEYTYPE_PRIVATE );
	cryptSetComponent( elgamalKey->p, dlpTestKey.p, dlpTestKey.pLen );
	cryptSetComponent( elgamalKey->g, dlpTestKey.g, dlpTestKey.gLen );
	cryptSetComponent( elgamalKey->q, dlpTestKey.q, dlpTestKey.qLen );
	cryptSetComponent( elgamalKey->y, dlpTestKey.y, dlpTestKey.yLen );
	cryptSetComponent( elgamalKey->x, dlpTestKey.x, dlpTestKey.xLen );
	status = cryptSetAttributeString( *decryptContext,
									  CRYPT_CTXINFO_KEY_COMPONENTS, elgamalKey,
									  sizeof( CRYPT_PKCINFO_DLP ) );
	cryptDestroyComponents( elgamalKey );
	free( elgamalKey );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( *cryptContext );
		cryptDestroyContext( *decryptContext );
		printf( "Key load failed with error code %d.\n", status );
		return( FALSE );
		}

	return( TRUE );
	}

/* Load Diffie-Hellman encrytion contexts */

BOOLEAN loadDHContexts( CRYPT_CONTEXT *cryptContext1,
						CRYPT_CONTEXT *cryptContext2, int keySize )
	{
	CRYPT_PKCINFO_DLP *dhKey;
	int status;

	/* Allocate room for the public-key components */
	if( ( dhKey = ( CRYPT_PKCINFO_DLP * ) malloc( sizeof( CRYPT_PKCINFO_DLP ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Create the first encryption context */
	status = cryptCreateContext( cryptContext1, CRYPT_UNUSED, CRYPT_ALGO_DH );
	if( cryptStatusError( status ) )
		{
		free( dhKey );
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	if( !setLabel( *cryptContext1, DH_KEY1_LABEL ) )
		{
		free( dhKey );
		cryptDestroyContext( *cryptContext1 );
		return( FALSE );
		}
	cryptInitComponents( dhKey, CRYPT_KEYTYPE_PUBLIC );
	cryptSetComponent( dhKey->p, dlpTestKey.p, dlpTestKey.pLen );
	cryptSetComponent( dhKey->q, dlpTestKey.q, dlpTestKey.qLen );
	cryptSetComponent( dhKey->g, dlpTestKey.g, dlpTestKey.gLen );
	status = cryptSetAttributeString( *cryptContext1,
									  CRYPT_CTXINFO_KEY_COMPONENTS, dhKey,
									  sizeof( CRYPT_PKCINFO_DLP ) );
	cryptDestroyComponents( dhKey );
	if( cryptStatusError( status ) )
		{
		free( dhKey );
		printf( "Key load failed with error code %d.\n", status );
		return( FALSE );
		}
	if( cryptContext2 == NULL )
		{
		free( dhKey );
		return( TRUE );
		}

	/* Create the second encryption context */
	status = cryptCreateContext( cryptContext2, CRYPT_UNUSED, CRYPT_ALGO_DH );
	if( cryptStatusError( status ) )
		{
		free( dhKey );
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	if( !setLabel( *cryptContext2, DH_KEY2_LABEL ) )
		{
		free( dhKey );
		if( cryptContext1 != NULL )
			cryptDestroyContext( *cryptContext1 );
		cryptDestroyContext( *cryptContext2 );
		return( FALSE );
		}
	cryptInitComponents( dhKey, CRYPT_KEYTYPE_PUBLIC );
	cryptSetComponent( dhKey->p, dlpTestKey.p, dlpTestKey.pLen );
	cryptSetComponent( dhKey->q, dlpTestKey.q, dlpTestKey.qLen );
	cryptSetComponent( dhKey->g, dlpTestKey.g, dlpTestKey.gLen );
	status = cryptSetAttributeString( *cryptContext2,
									  CRYPT_CTXINFO_KEY_COMPONENTS, dhKey,
									  sizeof( CRYPT_PKCINFO_DLP ) );
	cryptDestroyComponents( dhKey );
	free( dhKey );
	if( cryptStatusError( status ) )
		{
		printf( "Key load failed with error code %d.\n", status );
		return( FALSE );
		}

	return( TRUE );
	}

/* Destroy the encryption contexts */

void destroyContexts( const CRYPT_DEVICE cryptDevice,
					  CRYPT_CONTEXT cryptContext,
					  CRYPT_CONTEXT decryptContext )
	{
	int cryptAlgo, status;

	cryptGetAttribute( cryptContext, CRYPT_CTXINFO_ALGO, &cryptAlgo );
	status = cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		printf( "cryptDestroyContext() failed with error code %d.\n", status );
	status = cryptDestroyContext( decryptContext );
	if( cryptStatusError( status ) )
		printf( "cryptDestroyContext() failed with error code %d.\n", status );
	if( cryptDevice == CRYPT_UNUSED )
		return;

	/* If the context is associated with a device then creating the object
	   will generally also create a persistent object in the device, after
	   performing the tests we have to explicitly delete the persistent
	   object */
	if( cryptAlgo == CRYPT_ALGO_RSA )
		{
		cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, RSA_PUBKEY_LABEL );
		cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, RSA_PRIVKEY_LABEL );
		}
	else
		if( cryptAlgo == CRYPT_ALGO_DSA )
			{
			cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, DSA_PUBKEY_LABEL );
			cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, DSA_PRIVKEY_LABEL );
			}
	}

/****************************************************************************
*																			*
*							Generic ACL/Checking Test						*
*																			*
****************************************************************************/

/* Perform various stress/smoke tests on the cryptlib kernel.  These are:

	Stress test: Create 10K objects and read/write some attributes
	Data processing test: Encrypt/hash/MAC a buffer in a variable number
		of variable-size blocks, then decrypt/hash/MAC with different
		blocks and make sure the results match.
	Kernel check test: Run through every possible object type and attribute
		making sure we don't trigger any assertions.
	Threading stress test: DES-encrypt 100 data blocks in threads.
	Threading continuous test: Envelope data in threads until interrupted.

   Note that these are exhaustive tests that check large numbers of objects
   or parameter types and combinations so they can take some time to run to
   completion */

#ifdef SMOKE_TEST

#define NO_OBJECTS	10000		/* Can't exceed MAX_OBJECTS in cryptkrn.h */

static void testStressObjects( void )
	{
	CRYPT_HANDLE *handleArray = malloc( NO_OBJECTS * sizeof( CRYPT_HANDLE ) );
	BYTE hash[ CRYPT_MAX_HASHSIZE ];
	int i, length, status;

	printf( "Running object stress test." );
	assert( handleArray  != NULL );
	for( i = 0; i < NO_OBJECTS; i++ )
		{
		status = cryptCreateContext( &handleArray[ i ], CRYPT_UNUSED,
									 CRYPT_ALGO_SHA );
		if( cryptStatusError( status ) )
			printf( "cryptEncrypt() failed at %d with status %d.\n", i,
					status );
		}
	putchar( '.' );
	for( i = 0; i < NO_OBJECTS; i++ )
		{
		status = cryptEncrypt( handleArray[ i ], "12345678", 8 );
		if( cryptStatusError( status ) )
			printf( "cryptEncrypt() failed at %d with status %d.\n", i, status );
		}
	putchar( '.' );
	for( i = 0; i < NO_OBJECTS; i++ )
		{
		status = cryptEncrypt( handleArray[ i ], "", 0 );
		if( cryptStatusError( status ) )
			printf( "cryptEncrypt() failed at %d with status %d.\n", i,
					status );
		}
	putchar( '.' );
	for( i = 0; i < NO_OBJECTS; i++ )
		{
		status = cryptGetAttributeString( handleArray[ i ],
								CRYPT_CTXINFO_HASHVALUE, hash, &length );
		if( cryptStatusError( status ) )
			printf( "cryptEncrypt() failed at %d with status %d.\n", i,
					status );
		}
	putchar( '.' );
	for( i = 0; i < NO_OBJECTS; i++ )
		{
		status = cryptDestroyContext( handleArray[ i ] );
		if( cryptStatusError( status ) )
			printf( "cryptEncrypt() failed at %d with status %d.\n", i,
					status );
		}
	free( handleArray );
	puts( "." );
	}

/* Data processing test */

#define DATABUFFER_SIZE		2048
#define MAX_BLOCKS			16

#define roundUp( size, roundSize ) \
	( ( ( size ) + ( ( roundSize ) - 1 ) ) & ~( ( roundSize ) - 1 ) )

#ifdef __WINDOWS__
  typedef int ( __stdcall *CRYPT_FUNCTION )( const CRYPT_CONTEXT cryptContext,
											 void *data, const int length );
#else
  typedef int ( *CRYPT_FUNCTION )( const CRYPT_CONTEXT cryptContext,
								   void *data, const int length );
#endif /* __WINDOWS__ */

static int processData( const CRYPT_CONTEXT cryptContext, BYTE *buffer,
						const int noBlocks, const int blockSize,
						CRYPT_FUNCTION cryptFunction )
	{
	int offset = 0, i, status;

	/* Encrypt the data in variable-length blocks.  The technique for
	   selecting lengths isn't perfect since it tends to put large blocks
	   at the start and small ones at the end, but it's good enough for
	   general testing */
	for( i = 0; i < noBlocks - 1; i++ )
		{
		int noBytes = rand() % ( DATABUFFER_SIZE - offset - \
								 ( blockSize * ( noBlocks - i  ) ) );
		if( !noBytes )
			noBytes = 1;
		if( blockSize > 1 )
			noBytes = roundUp( noBytes, blockSize );
		status = cryptFunction( cryptContext, buffer + offset, noBytes );
		if( cryptStatusError( status ) )
			return( status );
		offset += noBytes;
		}
	status = cryptFunction( cryptContext, buffer + offset,
							DATABUFFER_SIZE - offset );
	if( cryptStatusOK( status ) )
		status = cryptFunction( cryptContext, "", 0 );
	return( status );
	}

static int testProcessing( const CRYPT_ALGO_TYPE cryptAlgo,
						   const CRYPT_MODE_TYPE cryptMode,
						   const CRYPT_QUERY_INFO cryptQueryInfo )
	{
	BYTE buffer1[ DATABUFFER_SIZE ], buffer2[ DATABUFFER_SIZE ];
	BYTE hash1[ CRYPT_MAX_HASHSIZE ], hash2[ CRYPT_MAX_HASHSIZE ];
	const int blockSize = ( cryptMode == CRYPT_MODE_ECB || \
							cryptMode == CRYPT_MODE_CBC ) ? \
						  cryptQueryInfo.blockSize : 1;
	int length1, length2, i;

	/* Initialise the buffers with a known data pattern */
	memset( buffer1, '*', DATABUFFER_SIZE );
	memcpy( buffer1, "12345678", 8 );
	memcpy( buffer2, buffer1, DATABUFFER_SIZE );

	/* Process the data using various block sizes */
	printf( "Testing algorithm %d, mode %d, for %d-byte buffer with\n  block "
			"count ", cryptAlgo, ( cryptMode == CRYPT_UNUSED ) ? 0 : cryptMode,
			DATABUFFER_SIZE );
	for( i = 1; i <= MAX_BLOCKS; i++ )
		{
		CRYPT_CONTEXT cryptContext;
		int status;

		memcpy( buffer1, buffer2, DATABUFFER_SIZE );
		printf( "%d%s ", i, ( i == MAX_BLOCKS ) ? "." : "," );

		/* Encrypt the data with random block sizes */
		status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, cryptAlgo );
		if( cryptStatusError( status ) )
			return( status );
		if( cryptMode != CRYPT_UNUSED )
			{
			status = cryptSetAttribute( cryptContext, CRYPT_CTXINFO_MODE,
										cryptMode );
			if( cryptStatusError( status ) )
				return( status );
			if( cryptMode != CRYPT_MODE_ECB && cryptAlgo != CRYPT_ALGO_RC4 )
				{
				status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_IV,
								"1234567887654321", cryptQueryInfo.blockSize );
				if( cryptStatusError( status ) )
					return( status );
				}
			}
		if( cryptQueryInfo.keySize )
			{
			status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEY,
								"12345678876543211234567887654321",
								cryptQueryInfo.keySize );
			if( cryptStatusError( status ) )
				return( status );
			}
		status = processData( cryptContext, buffer1, i, blockSize,
							  cryptEncrypt );
		if( cryptStatusError( status ) )
			return( status );
		if( cryptAlgo >= CRYPT_ALGO_FIRST_HASH )
			{
			status = cryptGetAttributeString( cryptContext,
								CRYPT_CTXINFO_HASHVALUE, hash1, &length1 );
			if( cryptStatusError( status ) )
				return( status );
			}
		status = cryptDestroyContext( cryptContext );
		if( cryptStatusError( status ) )
			return( status );

		/* Decrypt the data again with random block sizes */
		status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, cryptAlgo );
		if( cryptStatusError( status ) )
			return( status );
		if( cryptMode != CRYPT_UNUSED )
			{
			status = cryptSetAttribute( cryptContext, CRYPT_CTXINFO_MODE,
										cryptMode );
			if( cryptStatusError( status ) )
				return( status );
			if( cryptMode != CRYPT_MODE_ECB && cryptAlgo != CRYPT_ALGO_RC4 )
				{
				status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_IV,
								"1234567887654321", cryptQueryInfo.blockSize );
				if( cryptStatusError( status ) )
					return( status );
				}
			}
		if( cryptQueryInfo.keySize )
			{
			status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEY,
								"12345678876543211234567887654321",
								cryptQueryInfo.keySize );
			if( cryptStatusError( status ) )
				return( status );
			}
		status = processData( cryptContext, buffer1, i, blockSize,
							  cryptDecrypt );
		if( cryptStatusError( status ) )
			return( status );
		if( cryptAlgo >= CRYPT_ALGO_FIRST_HASH )
			{
			status = cryptGetAttributeString( cryptContext,
								CRYPT_CTXINFO_HASHVALUE, hash2, &length2 );
			if( cryptStatusError( status ) )
				return( status );
			}
		status = cryptDestroyContext( cryptContext );
		if( cryptStatusError( status ) )
			return( status );

		/* Make sure the values match */
		if( cryptAlgo >= CRYPT_ALGO_FIRST_HASH )
			{
			if( ( length1 != length2 ) || memcmp( hash1, hash2, length1 ) )
				{
				puts( "Error: Hash value of identical buffers differs." );
				return( -1234 );
				}
			}
		else
			if( memcmp( buffer1, buffer2, DATABUFFER_SIZE ) )
				{
				printf( "Decrypted data != encrypted data for algorithm %d.\n",
						cryptAlgo );
				return( -1234 );
				}
		}
	putchar( '\n' );

	return( CRYPT_OK );
	}

static void testDataProcessing( void )
	{
	CRYPT_QUERY_INFO cryptQueryInfo;
	CRYPT_ALGO_TYPE cryptAlgo;
	int errorCount = 0, status;

	for( cryptAlgo = CRYPT_ALGO_FIRST_CONVENTIONAL;
		 cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo,
												 &cryptQueryInfo ) ) )
			{
			if( cryptAlgo != CRYPT_ALGO_RC4 )
				{
				status = testProcessing( cryptAlgo, CRYPT_MODE_ECB,
										 cryptQueryInfo );
				if( cryptStatusError( status ) )
					{
					printf( "\nAlgorithm %d ECB mode processing failed with "
							"status %d.\n", cryptAlgo, status );
					errorCount++;
					}
				status = testProcessing( cryptAlgo, CRYPT_MODE_CBC,
										 cryptQueryInfo );
				if( cryptStatusError( status ) )
					{
					printf( "\nAlgorithm %d CBC mode processing failed with "
							"status %d.\n", cryptAlgo, status );
					errorCount++;
					}
				status = testProcessing( cryptAlgo, CRYPT_MODE_CFB,
										 cryptQueryInfo );
				if( cryptStatusError( status ) )
					{
					printf( "\nAlgorithm %d CFB mode processing failed with "
							"status %d.\n", cryptAlgo, status );
					errorCount++;
					}
				}
			status = testProcessing( cryptAlgo, CRYPT_MODE_OFB,
									 cryptQueryInfo );
			if( cryptStatusError( status ) )
				{
				printf( "\nAlgorithm %d OFB mode processing failed with "
						"status %d.\n", cryptAlgo, status );
				errorCount++;
				}
			}
	for( cryptAlgo = CRYPT_ALGO_FIRST_HASH;
		 cryptAlgo <= CRYPT_ALGO_LAST_HASH; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, &cryptQueryInfo ) ) )
			{
			status = testProcessing( cryptAlgo, CRYPT_UNUSED,
									 cryptQueryInfo );
			if( cryptStatusError( status ) )
				{
				printf( "\nAlgorithm %d processing failed with status %d.\n",
						cryptAlgo, status );
				errorCount++;
				}
			}
	for( cryptAlgo = CRYPT_ALGO_FIRST_MAC;
		 cryptAlgo <= CRYPT_ALGO_LAST_MAC; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, &cryptQueryInfo ) ) )
			{
			status = testProcessing( cryptAlgo, CRYPT_UNUSED,
									 cryptQueryInfo );
			if( cryptStatusError( status ) )
				{
				printf( "\nAlgorithm %d processing failed with status %d.\n",
						cryptAlgo, status );
				errorCount++;
				}
			}
	if( errorCount )
		printf( "%d errors detected.\n", errorCount );
	}

/* Kernel check test */

static void smokeTestAttributes( const CRYPT_HANDLE cryptHandle )
	{
	int attribute;

	putchar( '.' );
	for( attribute = CRYPT_ATTRIBUTE_NONE; attribute < 8000; attribute++ )
		{
		char buffer[ 1024 ];
		int value;

		cryptGetAttribute( cryptHandle, attribute, &value );
		cryptGetAttributeString( cryptHandle, attribute, buffer, &value );
		}
	cryptDestroyObject( cryptHandle );
	}

static void testKernelChecks( void )
	{
	CRYPT_HANDLE cryptHandle;
	int subType;

	printf( "Running kernel smoke test:\n  Contexts" );
	for( subType = 0; subType < 500; subType++ )
		if( cryptStatusOK( cryptCreateContext( &cryptHandle, CRYPT_UNUSED,
											   subType ) ) )
			smokeTestAttributes( cryptHandle );
	printf( "\n  Certs" );
	for( subType = 0; subType < 500; subType++ )
		if( cryptStatusOK( cryptCreateCert( &cryptHandle, CRYPT_UNUSED,
											subType ) ) )
			smokeTestAttributes( cryptHandle );
	printf( "\n  Envelopes" );
	for( subType = 0; subType < 500; subType++ )
		if( cryptStatusOK( cryptCreateEnvelope( &cryptHandle, CRYPT_UNUSED,
												subType ) ) )
			smokeTestAttributes( cryptHandle );
	printf( "\n  Sessions" );
	for( subType = 0; subType < 500; subType++ )
		if( cryptStatusOK( cryptCreateSession( &cryptHandle, CRYPT_UNUSED,
											   subType ) ) )
			smokeTestAttributes( cryptHandle );
	putchar( '\n' );
	}

/* Multi-threaded processing stress test.  In order to add a little
   nondeterminism on single-threaded machines, we need to add some sleep()
   calls between crypto operations.  Even this isn't perfect, there's no
   real way to guarantee that they aren't simply executed in round-robin
   fashion with only one thread in the kernel at a time without modifying
   the kernel to provide diagnostic info */

#ifdef WINDOWS_THREADS

#define NO_THREADS	45

static void randSleep( void )
	{
	Sleep( ( rand() % 150 ) + 1 );
	}

unsigned __stdcall processDataThread( void *arg )
	{
	CRYPT_CONTEXT cryptContext;
	BYTE buffer[ 1024 ];
	int threadNo = ( int ) arg;
	int status;

	randSleep();
	memset( buffer, '*', 1024 );
	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED,
								 CRYPT_ALGO_3DES );
	if( cryptStatusOK( status ) )
		{
		randSleep();
		status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEY,
										  "123456781234567812345678", 24 );
		}
	if( cryptStatusOK( status ) )
		{
		randSleep();
		status = cryptEncrypt( cryptContext, buffer, 1024 );
		}
	if( cryptStatusOK( status ) )
		{
		randSleep();
		status = cryptEncrypt( cryptContext, buffer, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		randSleep();
		status = cryptDestroyContext( cryptContext );
		}
	if( cryptStatusError( status ) )
		printf( "\nEncryption failed with status %d.\n", status );
	else
		printf( "%d ", threadNo );

	_endthreadex( 0 );
	return( 0 );
	}

static void testStressThreads( void )
	{
	HANDLE hThreadArray[ NO_THREADS ];
	int i;

	/* Start the threads */
	for( i = 0; i < NO_THREADS; i++ )
		{
		unsigned threadID;

		hThreadArray[ i ] = ( HANDLE ) \
			_beginthreadex( NULL, 0, &processDataThread, ( void * ) i, 0,
							&threadID );
		if( hThreadArray[ i ] == 0 )
			printf( "Thread %d couldn't be created.\n", i );
		}
	printf( "Threads completed: " );

	/* Wait for all the threads to complete */
	if( WaitForMultipleObjects( NO_THREADS, hThreadArray, TRUE,
								15000 ) == WAIT_TIMEOUT )
		puts( "\nNot all threads completed in 15s." );
	else
		puts( "." );
	for( i = 0; i < NO_THREADS; i++ )
		CloseHandle( hThreadArray[ i ] );
	}
#endif /* WINDOWS_THREADS */

#if defined( UNIX_THREADS ) || defined( WINDOWS_THREADS )

#ifdef UNIX_THREADS
  void *envelopeDataThread( void *arg )
#else
  unsigned __stdcall envelopeDataThread( void *arg )
#endif /* Different threading models */
	{
	static const char *envData = "qwertyuiopasdfghjklzxcvbnm";
	BYTE fileBuffer[ BUFFER_SIZE ];
	const unsigned uThread = ( unsigned ) arg;
	const time_t startTime = time( NULL );
	int count, status;

	printf( "Thread %d started.\n", uThread );
	fflush( stdout );

	filenameFromTemplate( fileBuffer, CERT_FILE_TEMPLATE, 13 );

	for( count = 0; count < 150; count++ )
		{
		CRYPT_ENVELOPE cryptEnvelope;
		CRYPT_CERTIFICATE cryptCert;
		BYTE envBuffer[ BUFFER_SIZE ];
		int bytesCopied;

		/* Create the cert and envelope and add the cert to the envelope */
		status = importCertFile( &cryptCert, fileBuffer );
		if( cryptStatusOK( status ) )
			status = cryptCreateEnvelope( &cryptEnvelope, CRYPT_UNUSED,
										  CRYPT_FORMAT_CRYPTLIB );
		if( cryptStatusOK( status ) )
			status = cryptSetAttribute( cryptEnvelope,
										CRYPT_ENVINFO_PUBLICKEY, cryptCert );
		if( cryptStatusError( status ) )
			break;

		/* Envelope data and destroy the envelope */
		status = cryptPushData( cryptEnvelope, envData, strlen( envData ),
								&bytesCopied );
		if( cryptStatusOK( status ) )
			status = cryptPushData( cryptEnvelope, NULL, 0, NULL );
		if( cryptStatusOK( status ) )
			status = cryptPopData( cryptEnvelope, envBuffer, BUFFER_SIZE,
									&bytesCopied );
		if( cryptStatusOK( status ) )
			status = cryptDestroyEnvelope( cryptEnvelope );
		if( cryptStatusError( status ) )
			break;
		putchar( uThread + '0' );
		}

	printf( "Thread %u exited after %d seconds.\n", uThread,
			time( NULL ) - startTime );
	fflush( stdout );
#ifdef UNIX_THREADS
	pthread_exit( NULL );
#else
	_endthreadex( 0 );
#endif /* Different threading models */
	return( 0 );
	}

static void testContinuousThreads( void )
	{
	unsigned threadID1, threadID2;
#ifdef UNIX_THREADS
	pthread_t thread1, thread2;
#else
	HANDLE hThread1, hThread2;
#endif /* Different threading models */

	cryptAddRandom( "xyzzy", 5 );
#ifdef UNIX_THREADS
	pthread_create( &thread1, NULL, envelopeDataThread, ( void * ) 1 );
	pthread_create( &thread2, NULL, envelopeDataThread, ( void * ) 2 );
#else
	hThread1 = ( HANDLE ) _beginthreadex( NULL, 0, envelopeDataThread,
										  ( void * ) 1, 0, &threadID1 );
	hThread2 = ( HANDLE ) _beginthreadex( NULL, 0, envelopeDataThread,
										  ( void * ) 2, 0, &threadID2 );
#endif /* Different threading models */
	delayThread( 30 );
	printf( "Hit a key..." );
	fflush( stdout );
	getchar();
	cryptEnd();
	exit( EXIT_SUCCESS );
	}
#endif /* UNIX_THREADS || WINDOWS_THREADS */

static void smokeTest( void )
	{
	testDataProcessing();
	testKernelChecks();
	testStressObjects();
#if defined( UNIX_THREADS ) || defined( WINDOWS_THREADS )
	testStressThreads();
#endif /* UNIX_THREADS || WINDOWS_THREADS */
	}
#endif /* SMOKE_TEST */

/****************************************************************************
*																			*
*								Misc.Kludges								*
*																			*
****************************************************************************/

/* Prototypes for general debug routines used to evaluate problems with certs
   and envelopes from other apps */

void xxxCertImport( const char *fileName );
void xxxDataImport( const char *fileName );
void xxxSignedDataImport( const char *fileName );
void xxxEncryptedDataImport( const char *fileName );
void xxxEnvTest( void );

/* Update the cryptlib config file.  This code can be used to set the
   information required to load PKCS #11 device drivers:

	- Set the driver path in the CRYPT_OPTION_DEVICE_PKCS11_DVR01 setting
	  below.
	- Add a call to updateConfig() from somewhere (e.g.the test kludge function).
	- Run the test code until it calls updateConfig().
	- Remove the updateConfig() call, then run the test code as normal.
	  The testDevices() call will report the results of trying to use your
	  driver */

static void updateConfig( void )
	{
#if 0
	const char *driverPath = "c:/winnt/system32/aetpkss1.dll";	/* AET */
	const char *driverPath = "c:/winnt/system32/cryst32.dll";	/* Chrysalis */
	const char *driverPath = "c:/winnt/system32/pkcs201n.dll";	/* Datakey */
	const char *driverPath = "c:/winnt/system32/dkck201.dll";	/* Datakey */
	const char *driverPath = "c:/winnt/system32/dkck232.dll";	/* Datakey/iKey */
	const char *driverPath = "c:/program files/eracom/cprov sw/cryptoki.dll";	/* Eracom */
	const char *driverPath = "c:/winnt/system32/sadaptor.dll";	/* Eutron */
	const char *driverPath = "c:/winnt/system32/pk2priv.dll";	/* Gemplus */
	const char *driverPath = "c:/winnt/system32/nxpkcs11.dll";	/* Nexus */
	const char *driverPath = "c:/winnt/system32/micardoPKCS11.dll";	/* Orga Micardo */
	const char *driverPath = "c:/winnt/system32/cryptoki22.dll";/* Rainbow */
	const char *driverPath = "c:/winnt/system32/p11card.dll";	/* Safelayer */
	const char *driverPath = "c:/winnt/system32/slbck.dll";		/* Schlumberger */
	const char *driverPath = "c:/winnt/system32/SpyPK11.dll";	/* Spyrus Rosetta */
#endif /* 0 */
	const char *driverPath = "c:/program files/eracom/cprov sw/cryptoki.dll";	/* Eracom */

	/* Set the path for a PKCS #11 device driver.  We only enable one of
	   these at a time to speed the startup time */
	cryptSetAttributeString( CRYPT_UNUSED, CRYPT_OPTION_DEVICE_PKCS11_DVR01,
							 driverPath, strlen( driverPath ) );

	/* Update the options */
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED, FALSE );
	}

/* Add trusted certs to the config file and make sure that they're
   persistent.  This can't be done in the normal self-test since it requires
   that cryptlib be restarted as part of the test to re-read the config file,
   and because it modifies the cryptlib config file */

static void updateConfigCert( void )
	{
	CRYPT_CERTIFICATE trustedCert;

	/* Import the first cert, make it trusted, and commit the changes */
	importCertFromTemplate( &trustedCert, CERT_FILE_TEMPLATE, 1 );
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED, FALSE );
	cryptDestroyCert( trustedCert );
	cryptEnd();

	/* Do the same with a second cert.  At the conclusion of this, we should
	   have two trusted certs on disk */
	cryptInit();
	importCertFromTemplate( &trustedCert, CERT_FILE_TEMPLATE, 2 );
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED, FALSE );
	cryptDestroyCert( trustedCert );
	cryptEnd();
	}

/* Generic test code insertion point.  The following routine is called
   before any of the other tests are run and can be used to handle special-
   case tests that aren't part of the main test suite */

void testKludge( void )
	{
	/* Performance-testing test harness */
#if 0
	void performanceTests( const CRYPT_DEVICE cryptDevice );

	performanceTests( CRYPT_UNUSED );
#endif /* 0 */

	/* Memory diagnostic test harness */
#if 0
	testReadFileCertPrivkey();
	testEnvelopePKCCrypt();		/* Use "Datasize, certificate" */
	testEnvelopeSign();			/* Use "Datasize, certificate" */
#endif /* 0 */

	/* Simple (brute-force) server code. NB: Remember to change
	   setLocalConnect() to not bind the server to localhost if expecting
	   external connections */
#if 0
	while( TRUE )
		testSessionTSPServer();
#endif /* 0 */

	/* Functions that can be pressed into service in combination with the
	   special-purpose defines at the start of testkey.c to generate custom
	   certs/keys */
/*	testWriteFileCertChain();	/* To generate user priv.key+cert */
/*	testReadWriteFileKey();
	testUpdateFileCert();		/* To generate CA priv.key+cert */
#if 0
	puts( "Hit a key..." );
	getchar();
	if( cryptEnd() == CRYPT_ERROR_INCOMPLETE )
		{
		puts( "Objects remained allocated." );
		getchar();
		}
	exit( 0 );
#endif /* 0 */
	}

/****************************************************************************
*																			*
*								Main Test Code								*
*																			*
****************************************************************************/

#ifdef __WINDOWS__
  #define INC_CHILD
#endif /* __WINDOWS__ */

/* Comprehensive cryptlib stress test */

int main( int argc, char **argv )
	{
#ifdef TEST_LOWLEVEL
	CRYPT_ALGO_TYPE cryptAlgo;
#endif /* TEST_LOWLEVEL */
#ifdef TEST_CONFIG
	int i;
#endif /* TEST_CONFIG */
#ifdef TEST_SELFTEST
	int value;
#endif /* TEST_SELFTEST */
	int status;
	void testSystemSpecific( void );

	/* Get rid of compiler warnings */
	if( argc || argv );

	/* Make sure various system-specific features are set right */
	testSystemSpecific();

	/* VisualAge C++ doesn't set the TZ correctly.  The check for this isn't
	   as simple as it would seem since most IBM compilers define the same
	   preprocessor values even though it's not documented anywhere, so we
	   have to enable the tzset() call for (effectively) all IBM compilers
	   and then disable it for ones other than VisualAge C++ */
#if ( defined( __IBMC__ ) || defined( __IBMCPP__ ) ) && !defined( __VMCMS__ )
	tzset();
#endif /* VisualAge C++ */

	/* Initialise cryptlib */
	status = cryptInit();
	if( cryptStatusError( status ) )
		{
		printf( "cryptInit() failed with error code %d.\n", status );
		exit( EXIT_FAILURE );
		}

#ifndef TEST_RANDOM
	/* In order to avoid having to do a randomness poll for every test run,
	   we bypass the randomness-handling by adding some junk.  This is only
	   enabled when cryptlib is built in debug mode, so it won't work with
	   any production systems */
	cryptAddRandom( "xyzzy", 5 );
#endif /* TEST_RANDOM */

	/* Perform a general sanity check to make sure that the self-test is
	   being run the right way */
	if( !checkFileAccess() )
		exit( EXIT_FAILURE );

	/* For general testing purposes we can insert test code at this point to
	   test special cases that aren't covered in the general tests below */
	testKludge();

#ifdef SMOKE_TEST
	/* Perform a general smoke test of the kernel */
	smokeTest();
#endif /* SMOKE_TEST */

#ifdef TEST_SELFTEST
	/* Perform the self-test.  First we write the value to true to force a
	   self-test, then we read it back to see whether it succeeded */
	status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_SELFTESTOK, TRUE );
	if( cryptStatusError( status ) )
		{
		printf( "Attempt to perform cryptlib algorithm self-test failed "
				"with error code %d.\n", status );
		exit( EXIT_FAILURE );
		}
	status = cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_SELFTESTOK, &value );
	if( cryptStatusError( status ) || !value )
		{
		puts( "cryptlib algorithm self-test failed." );
		exit( EXIT_FAILURE );
		}
	puts( "cryptlib algorithm self-test succeeded.\n" );
#endif /* TEST_SELFTEST */

#ifdef TEST_LOWLEVEL
	/* Test the conventional encryption routines */
	for( cryptAlgo = CRYPT_ALGO_FIRST_CONVENTIONAL;
		 cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) && \
			!testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
			goto errorExit;

	/* Test the public-key encryption routines */
	for( cryptAlgo = CRYPT_ALGO_FIRST_PKC;
		 cryptAlgo <= CRYPT_ALGO_LAST_PKC; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) && \
			!testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
				goto errorExit;

	/* Test the hash routines */
	for( cryptAlgo = CRYPT_ALGO_FIRST_HASH;
		 cryptAlgo <= CRYPT_ALGO_LAST_HASH; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) && \
			!testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
			goto errorExit;

	/* Test the MAC routines */
	for( cryptAlgo = CRYPT_ALGO_FIRST_MAC;
		 cryptAlgo <= CRYPT_ALGO_LAST_MAC; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) && \
			!testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
			goto errorExit;

	putchar( '\n' );
#else
	puts( "Skipping test of low-level encryption routines...\n" );
#endif /* TEST_LOWLEVEL */

	/* Test the randomness-gathering routines */
#ifdef TEST_RANDOM
	if( !testRandomRoutines() )
		{
		puts( "The self-test will proceed without using a strong random "
			  "number source.\n" );

		/* Kludge the randomness routines so we can continue the self-tests */
		cryptAddRandom( "xyzzy", 5 );
		}
#else
	puts( "Skipping test of randomness routines...\n" );
#endif /* TEST_RANDOM */

	/* Test the configuration options routines */
#ifdef TEST_CONFIG
	for( i = 0; configOption[ i ].option != CRYPT_ATTRIBUTE_NONE; i++ )
		{
		if( configOption[ i ].isNumeric )
			{
			int value;

			cryptGetAttribute( CRYPT_UNUSED, configOption[ i ].option, &value );
			printf( "%s = %d.\n", configOption[ i ].name, value );
			}
		else
			{
			char buffer[ 256 ];
			int length;

			cryptGetAttributeString( CRYPT_UNUSED, configOption[ i ].option,
									 buffer, &length );
			buffer[ length ] = '\0';
			printf( "%s = %s.\n", configOption[ i ].name, buffer );
			}
		}
	putchar( '\n' );
#else
	puts( "Skipping display of config options...\n" );
#endif /* TEST_CONFIG */

	/* Test the crypto device routines */
#ifdef TEST_DEVICE
	status = testDevices();
	if( status == CRYPT_ERROR_NOTAVAIL )
		puts( "Handling for crypto devices doesn't appear to be enabled in "
			  "this build of\ncryptlib.\n" );
	else
		if( !status )
			goto errorExit;
#else
	puts( "Skipping test of crypto device routines...\n" );
#endif /* TEST_DEVICE */

	/* Test the mid-level routines */
#ifdef TEST_MIDLEVEL
	if( !testLargeBufferEncrypt() )
		goto errorExit;
	if( !testDeriveKey() )
		goto errorExit;
	if( !testConventionalExportImport() )
		goto errorExit;
	if( !testMACExportImport() )
		goto errorExit;
	if( !testKeyExportImport() )
		goto errorExit;
	if( !testSignData() )
		goto errorExit;
/*	Disabled for now since there's no useful DH mechanism defined in any
	standard.  Note that KEA is still tested via the Fortezza device test
	if( !testKeyAgreement() )
		goto errorExit; */
	if( !testKeygen() )
		goto errorExit;
	if( !testKeygenAsync() )
		goto errorExit;
	/* No need for putchar, mid-level functions leave a blank line at end */
#else
	puts( "Skipping test of mid-level encryption routines...\n" );
#endif /* TEST_MIDLEVEL */

	/* Test the certificate management routines */
#ifdef TEST_CERT
	if( !testCert() )
		goto errorExit;
	if( !testCACert() )
		goto errorExit;
	if( !testXyzzyCert() )
		goto errorExit;
	if( !testTextStringCert() )
		goto errorExit;
	if( !testComplexCert() )
		goto errorExit;
	if( !testCertExtension() )
		goto errorExit;
	if( !testCustomDNCert() )
		goto errorExit;
	if( !testSETCert() )
		goto errorExit;
	if( !testAttributeCert() )
		goto errorExit;
	if( !testCertRequest() )
		goto errorExit;
	if( !testComplexCertRequest() )
		goto errorExit;
	if( !testCRMFRequest() )
		goto errorExit;
	if( !testComplexCRMFRequest() )
		goto errorExit;
	if( !testCRL() )
		goto errorExit;
	if( !testComplexCRL() )
		goto errorExit;
	if( !testRevRequest() )
		goto errorExit;
	if( !testCertChain() )
		goto errorExit;
	if( !testCMSAttributes() )
		goto errorExit;
	if( !testOCSPReqResp() )
		goto errorExit;
	if( !testCertImport() )
		goto errorExit;
	if( !testCertReqImport() )
		goto errorExit;
	if( !testCRLImport() )
		goto errorExit;
	if( !testCertChainImport() )
		goto errorExit;
	if( !testOCSPImport() )
		goto errorExit;
	if( !testBase64CertImport() )
		goto errorExit;
	if( !testCertComplianceLevel() )
		goto errorExit;
#else
	puts( "Skipping test of certificate managment routines...\n" );
#endif /* TEST_CERT */

	/* Test the keyset read routines */
#ifdef TEST_KEYSET
  #ifdef DATABASE_AUTOCONFIG
	checkCreateDatabaseKeysets();
  #endif /* DATABASE_AUTOCONFIG */
	if( !testGetPGPPublicKey() )
		goto errorExit;
	if( !testGetPGPPrivateKey() )
		goto errorExit;
	if( !testGetBorkenKey() )
		goto errorExit;
	if( !testReadWriteFileKey() )
		goto errorExit;
	if( !testReadBigFileKey() )
		goto errorExit;
	if( !testReadFilePublicKey() )
		goto errorExit;
	if( !testDeleteFileKey() )
		goto errorExit;
	if( !testUpdateFileCert() )
		goto errorExit;
	if( !testReadFileCert() )
		goto errorExit;
	if( !testReadFileCertPrivkey() )
		goto errorExit;
	if( !testWriteFileCertChain() )
		goto errorExit;
	if( !testReadFileCertChain() )
		goto errorExit;
	if( !testWriteFileLongCertChain() )
		goto errorExit;
	if( !testSingleStepFileCert() )
		goto errorExit;
	if( !testDoubleCertFile() )
		goto errorExit;
	if( !testRenewedCertFile() )
		goto errorExit;
	status = testWriteCert();
	if( status == CRYPT_ERROR_NOTAVAIL )
		puts( "Handling for certificate databases doesn't appear to be "
			  "enabled in this\nbuild of cryptlib, skipping the test of "
			  "the certificate database routines.\n" );
	else
		if( status )
			{
			if( !testReadCert() )
				goto errorExit;
			if( !testKeysetQuery() )
				goto errorExit;

			/* The database plugin test will usually fail unless the user has
			   set up a plugin, so we don't check the return value */
			testWriteCertDbx();
			}
	/* For the following tests we may have read access but not write access,
	   so we test a read of known-present certs before trying a write -
	   unlike the local keysets we don't need to add a cert before we can try
	   reading it */
	status = testReadCertLDAP();
	if( status == CRYPT_ERROR_NOTAVAIL )
		puts( "Handling for LDAP certificate directories doesn't appear to "
			  "be enabled in\nthis build of cryptlib, skipping the test of "
			  "the certificate directory\nroutines.\n" );
	else
		/* LDAP access can fail if the directory doesn't use the standard
		   du jour, so we don't treat a failure as a fatal error */
		if( status )
			{
			/* LDAP writes are even worse than LDAP reads, so we don't
			   treat failures here as fatal either */
			testWriteCertLDAP();
			}
	status = testReadCertURL();
	if( status == CRYPT_ERROR_NOTAVAIL )
		puts( "Handling for fetching certificates from web pages doesn't "
			  "appear to be\nenabled in this build of cryptlib, skipping "
			  "the test of the HTTP routines.\n" );
	else
		/* Being able to read a cert from a web page is rather different from
		   access to an HTTP cert store, so we don't treat an error here as
		   fatal */
		if( status )
			testReadCertHTTP();
#else
	puts( "Skipping test of keyset read routines...\n" );
#endif /* TEST_KEYSET */

	/* Test the certificate processing and CA cert management functionality */
#ifdef TEST_CERTPROCESS
	if( !testCertProcess() )
		goto errorExit;
	status = testCertManagement();
	if( status == CRYPT_ERROR_NOTAVAIL )
		puts( "Handling for CA certificate stores doesn't appear to be "
			  "enabled in this\nbuild of cryptlib, skipping the test of "
			  "the certificate management routines.\n" );
	else
		if( !status )
			goto errorExit;
#else
	puts( "Skipping test of certificate handling/CA management...\n" );
#endif /* TEST_CERTPROCESS */

	/* Test the high-level routines (these are similar to the mid-level
	   routines but rely on things like certificate management to work) */
#ifdef TEST_HIGHLEVEL
	if( !testKeyExportImportCMS() )
		goto errorExit;
	if( !testSignDataCMS() )
		goto errorExit;
#endif /* TEST_HIGHLEVEL */

	/* Test the enveloping routines */
#ifdef TEST_ENVELOPE
	if( !testEnvelopeData() )
		goto errorExit;
	if( !testEnvelopeDataLargeBuffer() )
		goto errorExit;
	if( !testEnvelopeCompress() )
		goto errorExit;
	if( !testEnvelopeCompressedDataImport() )
		goto errorExit;
	if( !testEnvelopeSessionCrypt() )
		goto errorExit;
	if( !testEnvelopeSessionCryptLargeBuffer() )
		goto errorExit;
	if( !testEnvelopeCrypt() )
		goto errorExit;
	if( !testEnvelopePasswordCrypt() )
		goto errorExit;
	if( !testEnvelopePasswordCryptImport() )
		goto errorExit;
	if( !testEnvelopePKCCrypt() )
		goto errorExit;
	if( !testEnvelopePKCCryptImport() )
		goto errorExit;
	if( !testEnvelopeSign() )
		goto errorExit;
	if( !testEnvelopeSignOverflow() )
		goto errorExit;
	if( !testEnvelopeSignedDataImport() )
		goto errorExit;
	if( !testEnvelopeAuthenticate() )
		goto errorExit;
	if( !testCMSEnvelopePKCCrypt() )
		goto errorExit;
	if( !testCMSEnvelopePKCCryptDoubleCert() )
		goto errorExit;
	if( !testCMSEnvelopeSign() )
		goto errorExit;
	if( !testCMSEnvelopeDualSign() )
		goto errorExit;
	if( !testCMSEnvelopeDetachedSig() )
		goto errorExit;
	if( !testCMSEnvelopeSignedDataImport() )
		goto errorExit;
#else
	puts( "Skipping test of enveloping routines...\n" );
#endif /* TEST_ENVELOPE */

	/* Test the session routines */
#ifdef TEST_SESSION
	status = testSessionUrlParse();
	if( !status )
		goto errorExit;
	if( status == CRYPT_ERROR_NOTAVAIL )
		puts( "Network access doesn't appear to be enabled in this build of "
			  "cryptlib,\nskipping the test of the secure session routines.\n" );
	else
		{
		if( !testSessionSSHv1() )
			goto errorExit;
		if( !testSessionSSHv2() )
			goto errorExit;
		if( !testSessionSSL() )
			goto errorExit;
		if( !testSessionSSLLocalSocket() )
			goto errorExit;
		if( !testSessionTLS() )
			goto errorExit;
		if( !testSessionTLS11() )
			goto errorExit;
		if( !testSessionOCSP() )
			goto errorExit;
		if( !testSessionTSP() )
			goto errorExit;
		if( !testSessionEnvTSP() )
			goto errorExit;
		if( !testSessionCMP() )
			goto errorExit;

		/* Test loopback client/server sessions.  These require a threaded
		   OS and are aliased to nops on non-threaded systems.  In addition
		   there can be synchronisation problems between the two threads if
		   the server is delayed for some reason, resulting in the client
		   waiting for a socket that isn't opened yet.  This isn't easy to
		   fix without a lot of explicit intra-thread synchronisation, if
		   there's a problem it's easier to just re-run the tests */
		if( !testSessionSSHv1ClientServer() )
			goto errorExit;
		if( !testSessionSSHv2ClientServer() )
			goto errorExit;
		if( !testSessionSSHClientServerFingerprint() )
			goto errorExit;
		if( !testSessionSSLClientServer() )
			goto errorExit;
		if( !testSessionSSLClientCertClientServer() )
			goto errorExit;
		if( !testSessionTLSClientServer() )
			goto errorExit;
		if( !testSessionTLSSharedKeyClientServer() )
			goto errorExit;
		if( !testSessionTLSBulkTransferClientServer() )
			goto errorExit;
		if( !testSessionTLS11ClientServer() )
			goto errorExit;
		if( !testSessionRTCSClientServer() )
			goto errorExit;
		if( !testSessionOCSPClientServer() )
			goto errorExit;
		if( !testSessionTSPClientServer() )
			goto errorExit;
		if( !testSessionTSPClientServerPersistent() )
			goto errorExit;
		if( !testSessionSCEPClientServer() )
			goto errorExit;
		if( !testSessionCMPClientServer() )
			goto errorExit;
		if( !testSessionCMPPKIBootClientServer() )
			goto errorExit;
		if( !testSessionPNPPKIClientServer() )
			goto errorExit;
		}
#endif /* TEST_SESSION */

	/* Test the user routines */
#ifdef TEST_USER
	if( !testUser() )
		goto errorExit;
#endif /* TEST_USER */

	/* Shut down cryptlib */
	status = cryptEnd();
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_INCOMPLETE )
			puts( "cryptEnd() failed with error code CRYPT_ERROR_INCOMPLETE, "
				  "a code path in the\nself-test code resulted in an error "
				  "return without a full cleanup of objects.\nIf you were "
				  "running the multithreaded loopback tests this may be "
				  "because one\nor more threads lost sync with other threads "
				  "and exited without cleaning up\nits objects.  This "
				  "happens occasionally due to network timing issues or\n"
				  "thread scheduling differences." );
		else
			printf( "cryptEnd() failed with error code %d.\n", status );
		goto errorExit1;
		}

	puts( "All tests concluded successfully." );
	return( EXIT_SUCCESS );

	/* All errors end up here */
#if defined( TEST_LOWLEVEL ) || defined( TEST_MIDLEVEL ) || \
	defined( TEST_DEVICE ) || defined( TEST_CERT ) || \
	defined( TEST_KEYSET ) || defined( TEST_CERTPROCESS ) || \
	defined( TEST_CERTMANAGEMENT ) || defined( TEST_HIGHLEVEL ) || \
	defined( TEST_ENVELOPE ) || defined( TEST_SESSION ) || \
	defined( TEST_SESSION ) || defined( TEST_USER )
errorExit:
	cryptEnd();
#endif /* Eliminate compiler warning about unreferenced label */
errorExit1:
	puts( "\nThe test was aborted due to an error being detected.  If you "
		  "want to report\nthis problem, please provide as much information "
		  "as possible to allow it to\nbe diagnosed, for example the call "
		  "stack, the location inside cryptlib where\nthe problem occurred, "
		  "and the values of any variables that might be\nrelevant." );
#ifdef __WINDOWS__
	/* The pseudo-CLI VC++ output windows are closed when the program exits
	   so we need to explicitly wait to allow the user to read them */
	puts( "\nHit a key..." );
	getchar();
#endif /* __WINDOWS__ */
	return( EXIT_FAILURE );
	}

/* Test the system-specific defines in crypt.h.  This is the last function in
   the file because we want to avoid any definitions in crypt.h messing with
   the rest of the test.c code.

   The following include is needed only so we can check whether the defines
   are set right.  crypt.h should never be included in a program that uses
   cryptlib */

#undef __WINDOWS__
#undef __WIN16__
#undef __WIN32__
#undef BOOLEAN
#undef BYTE
#undef FALSE
#undef TRUE
#if defined( __MVS__ ) || defined( __VMCMS__ )
  #pragma convlit( resume )
#endif /* Resume ASCII use on EBCDIC systems */
#ifdef _MSC_VER
  #include "../crypt.h"
#else
  #include "crypt.h"
#endif /* Braindamaged MSC include handling */
#if defined( __MVS__ ) || defined( __VMCMS__ )
  #pragma convlit( suspend )
#endif /* Suspend ASCII use on EBCDIC systems */

void testSystemSpecific( void )
	{
	int bigEndian;

	/* Make sure we've got the endianness set right.  If the machine is
	   big-endian (up to 64 bits) the following value will be signed,
	   otherwise it will be unsigned.  We can't easily test for things like
	   middle-endianness without knowing the size of the data types, but
	   then again it's unlikely we're being run on a PDP-11 */
	bigEndian = ( *( long * ) "\x80\x00\x00\x00\x00\x00\x00\x00" < 0 );
#ifdef DATA_LITTLEENDIAN
	if( bigEndian )
		{
		puts( "The CPU endianness define is set wrong in crypt.h, this "
			  "machine appears to be\nbig-endian, not little-endian.  Edit "
			  "the file and rebuild cryptlib." );
		exit( EXIT_FAILURE );
		}
#else
	if( !bigEndian )
		{
		puts( "The CPU endianness define is set wrong in crypt.h, this "
			  "machine appears to be\nlittle-endian, not big-endian.  Edit "
			  "the file and rebuild cryptlib." );
		exit( EXIT_FAILURE );
		}
#endif /* DATA_LITTLEENDIAN */

	/* Make sure that the compiler doesn't use variable-size enums */
	if( sizeof( CRYPT_ALGO_TYPE ) != sizeof( int ) || \
		sizeof( CRYPT_MODE_TYPE ) != sizeof( int ) ||
		sizeof( CRYPT_ATTRIBUTE_TYPE ) != sizeof( int ) )
		{
		puts( "The compiler you are using treats enumerated types as "
			  "variable-length non-\ninteger values, making it impossible "
			  "to reliably pass the address of an\nenum as a function "
			  "parameter.  To fix this, you need to rebuild cryptlib\nwith "
			  "the appropriate compiler option or pragma to ensure that\n"
			  "sizeof( enum ) == sizeof( int )." );
		exit( EXIT_FAILURE );
		}

	/* If we're compiling under Unix with threading support, make sure the
	   default thread stack size is sensible.  We don't perform the check for
	   UnixWare/SCO since this already has the workaround applied */
#if defined( UNIX_THREADS ) && !defined( __SCO_VERSION__ )
	{
	pthread_attr_t attr;
	size_t stackSize;

	pthread_attr_init( &attr );
	pthread_attr_getstacksize( &attr, &stackSize );
    pthread_attr_destroy( &attr );
  #if ( defined( sun ) && OSVERSION > 4 )
	/* Slowaris uses a special-case value of 0 (actually NULL) to indicate
	   the default stack size of 1MB (32-bit) or 2MB (64-bit), so we have to
	   handle this specially */
	if( stackSize < 32768 && stackSize != 0 )
  #else
	if( stackSize < 32768 )
  #endif /* Slowaris special-case handling */
		{
		printf( "The pthread stack size is defaulting to %d bytes, which is "
				"too small for\ncryptlib to run in.  To fix this, edit the "
				"thread-creation function macro in\ncryptos.h and recompile "
				"cryptlib.\n", stackSize );
		exit( EXIT_FAILURE );
		}
	}
#endif /* UNIX_THREADS */
	}
