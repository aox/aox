/****************************************************************************
*																			*
*							cryptlib Test Key Load Code						*
*						Copyright Peter Gutmann 1995-2004					*
*																			*
****************************************************************************/

#ifdef _MSC_VER
  #include "../cryptlib.h"
  #include "test.h"
#else
  #include "cryptlib.h"
  #include "test/test.h"
#endif /* Braindamaged VC++ include handling */

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII. */
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */

/****************************************************************************
*																			*
*									Key Data								*
*																			*
****************************************************************************/

/* The keys for testing the RSA, DSA, and Elgamal implementations. These are
   the same 512-bit keys as the one used for the lib_xxx.c self-tests.  The
   key values may be extracted with the following code */

#if 0
{
#include <stdio.h>

BYTE buffer[ CRYPT_MAX_PKCSIZE ];
int length, i;

length = BN_bn2bin( &contextInfoPtr->ctxPKC->rsaParam_n, buffer );
printf( "\t/* n */\r\n\t%d,", BN_num_bits( &contextInfoPtr->ctxPKC->rsaParam_n ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->rsaParam_e, buffer );
printf( "\r\n\r\n\t/* e */\r\n\t%d,", BN_num_bits( &contextInfoPtr->ctxPKC->rsaParam_e ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->rsaParam_d, buffer );
printf( "\r\n\r\n\t/* d */\r\n\t%d,", BN_num_bits( &contextInfoPtr->ctxPKC->rsaParam_d ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->rsaParam_p, buffer );
printf( "\r\n\r\n\t/* p */\r\n\t%d,", BN_num_bits( &contextInfoPtr->ctxPKC->rsaParam_p ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->rsaParam_q, buffer );
printf( "\r\n\r\n\t/* q */\r\n\t%d,", BN_num_bits( &contextInfoPtr->ctxPKC->rsaParam_q ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->rsaParam_u, buffer );
printf( "\r\n\r\n\t/* u */\r\n\t%d,", BN_num_bits( &contextInfoPtr->ctxPKC->rsaParam_u ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->rsaParam_exponent1, buffer );
printf( "\r\n\r\n\t/* exponent1 */\r\n\t%d,", BN_num_bits( &contextInfoPtr->ctxPKC->rsaParam_exponent1 ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->rsaParam_exponent2, buffer );
printf( "\r\n\r\n\t/* exponent2 */\r\n\t%d,", BN_num_bits( &contextInfoPtr->ctxPKC->rsaParam_exponent2 ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
puts( "\r\n\t};" );
}
#endif
#if 0
{
#include <stdio.h>

BYTE buffer[ CRYPT_MAX_PKCSIZE ];
int length, i;

length = BN_bn2bin( &contextInfoPtr->ctxPKC->dlpParam_p, buffer );
printf( "\t/* p */\r\n\t%d,", BN_num_bits( &contextInfoPtr->ctxPKC->dlpParam_p ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->dlpParam_q, buffer );
printf( "\r\n\r\n\t/* q */\r\n\t%d,", BN_num_bits( &contextInfoPtr->ctxPKC->dlpParam_q ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->dlpParam_g, buffer );
printf( "\r\n\r\n\t/* g */\r\n\t%d,", BN_num_bits( &contextInfoPtr->ctxPKC->dlpParam_g ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->dlpParam_x, buffer );
printf( "\r\n\r\n\t/* x */\r\n\t%d,", BN_num_bits( &contextInfoPtr->ctxPKC->dlpParam_x ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t  " );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( &contextInfoPtr->ctxPKC->dlpParam_y, buffer );
printf( "\r\n\r\n\t/* y */\r\n\t%d,", BN_num_bits( &contextInfoPtr->ctxPKC->dlpParam_y ) );
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

/* The DH key uses cryptlib-internal mechanisms, the following data and
   associated test can't be used with an unmodified version of cryptlib */

#ifdef TEST_DH

#define CRYPT_IATTRIBUTE_KEY_SPKI	8015

static const BYTE dh1024SPKI[] = {
	0x30, 0x82, 0x01, 0x21,
		0x30, 0x82, 0x01, 0x17,
			0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01,
			0x30, 0x82, 0x01, 0x0A,
				0x02, 0x81, 0x81, 0x00,		/* p */
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
					0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
					0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
					0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
					0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
					0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
					0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
					0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
					0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
					0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
					0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
					0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
					0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
					0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0x02, 0x01,					/* g */
					0x02,
				0x02, 0x81, 0x80,			/* q */
					0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					0xE4, 0x87, 0xED, 0x51, 0x10, 0xB4, 0x61, 0x1A,
					0x62, 0x63, 0x31, 0x45, 0xC0, 0x6E, 0x0E, 0x68,
					0x94, 0x81, 0x27, 0x04, 0x45, 0x33, 0xE6, 0x3A,
					0x01, 0x05, 0xDF, 0x53, 0x1D, 0x89, 0xCD, 0x91,
					0x28, 0xA5, 0x04, 0x3C, 0xC7, 0x1A, 0x02, 0x6E,
					0xF7, 0xCA, 0x8C, 0xD9, 0xE6, 0x9D, 0x21, 0x8D,
					0x98, 0x15, 0x85, 0x36, 0xF9, 0x2F, 0x8A, 0x1B,
					0xA7, 0xF0, 0x9A, 0xB6, 0xB6, 0xA8, 0xE1, 0x22,
					0xF2, 0x42, 0xDA, 0xBB, 0x31, 0x2F, 0x3F, 0x63,
					0x7A, 0x26, 0x21, 0x74, 0xD3, 0x1B, 0xF6, 0xB5,
					0x85, 0xFF, 0xAE, 0x5B, 0x7A, 0x03, 0x5B, 0xF6,
					0xF7, 0x1C, 0x35, 0xFD, 0xAD, 0x44, 0xCF, 0xD2,
					0xD7, 0x4F, 0x92, 0x08, 0xBE, 0x25, 0x8F, 0xF3,
					0x24, 0x94, 0x33, 0x28, 0xF6, 0x73, 0x29, 0xC0,
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x03, 0x04, 0x00,
			0x02, 0x01, 0x00				/* y */
	};

#endif /* TEST_DH */

/****************************************************************************
*																			*
*								Key Load Routines							*
*																			*
****************************************************************************/

/* Set the label for a device object */

static BOOLEAN setLabel( const CRYPT_CONTEXT cryptContext, const C_STR label )
	{
	if( cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL,
								 label, paramStrlen( label ) ) == CRYPT_ERROR_DUPLICATE )
		{
		printf( "A key object with the label '%s' already exists inside the\n"
				"device.  To perform this test, you need to delete the "
				"existing object so\nthat cryptlib can create a new one.\n",
				label );
		return( FALSE );
		}

	return( TRUE );
	}

/* Load DH, RSA, DSA, and Elgamal PKC encrytion contexts */

#ifdef TEST_DH

typedef struct {
	void *data;							/* Data */
	int length;							/* Length */
	} xRESOURCE_DATA;

#define xsetMessageData( msgDataPtr, dataPtr, dataLength ) \
	{ \
	( msgDataPtr )->data = ( dataPtr ); \
	( msgDataPtr )->length = ( dataLength ); \
	}

BOOLEAN loadDHKey( const CRYPT_DEVICE cryptDevice,
				   CRYPT_CONTEXT *cryptContext )
	{
	const BOOLEAN isDevice = ( cryptDevice != CRYPT_UNUSED ) ? TRUE : FALSE;
	int status;

	if( isDevice )
		status = cryptDeviceCreateContext( cryptDevice, cryptContext,
										   CRYPT_ALGO_DH );
	else
		status = cryptCreateContext( cryptContext, CRYPT_UNUSED,
									 CRYPT_ALGO_DH );
	if( cryptStatusError( status ) )
		{
		printf( "crypt%sCreateContext() failed with error code %d.\n",
				isDevice ? "Device" : "", status );
		return( status );
		}
	if( !setLabel( *cryptContext, "DH key" ) )
		{
		cryptDestroyContext( *cryptContext );
		return( status );
		}
	if( cryptStatusOK( status ) )
		{
#if 1	/* Undefine to test DH keygen */
		status = cryptGenerateKey( *cryptContext );
#else
		xRESOURCE_DATA msgData;

		xsetMessageData( &msgData, ( void * ) dh1024SPKI,
						 sizeof( dh1024SPKI ) );
  #if 0
		status = krnlSendMessage( *cryptContext, IMESSAGE_SETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEY_SPKI );
  #else
		status = cryptDeviceQueryCapability( *cryptContext, 1000,
									( CRYPT_QUERY_INFO * ) &msgData );
  #endif /* 0 */
#endif /* 0 */
		}
	if( cryptStatusError( status ) )
		{
		printf( "DH key load failed, status = %d, line %d.\n", status,
				__LINE__ );
		cryptDestroyContext( *cryptContext );
		return( FALSE );
		}
	return( TRUE );
	}
#endif /* TEST_DH */

static int loadRSAPublicKey( const CRYPT_DEVICE cryptDevice,
							 CRYPT_CONTEXT *cryptContext,
							 const C_STR cryptContextLabel,
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
						   const C_STR cryptContextLabel,
						   const C_STR decryptContextLabel )
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
						   const C_STR signContextLabel,
						   const C_STR sigCheckContextLabel )
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
