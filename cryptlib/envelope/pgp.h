/****************************************************************************
*																			*
*							PGP Definitions Header File						*
*						Copyright Peter Gutmann 1996-2003					*
*																			*
****************************************************************************/

#ifndef _PGP_DEFINED

#define _PGP_DEFINED

#ifndef _STREAM_DEFINED
  #if defined( INC_ALL )
	#include "stream.h"
  #elif defined INC_CHILD
	#include "../misc/stream.h"
  #else
	#include "misc/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */

/* PGP packet types, encoded into the CTB */

#define PGP_PACKET_PKE			1	/* PKC-encrypted session key */
#define PGP_PACKET_SIGNATURE	2	/* Signature */
#define PGP_PACKET_SKE			3	/* Secret-key-encrypted session key */
#define PGP_PACKET_SIGNATURE_ONEPASS 4	/* One-pass signature */
#define PGP_PACKET_SECKEY	5		/* Secret key */
#define PGP_PACKET_PUBKEY	6		/* Public key */
#define PGP_PACKET_SECKEY_SUB 7		/* Secret key subkey */
#define PGP_PACKET_COPR		8		/* Compressed data */
#define PGP_PACKET_ENCR		9		/* Encrypted data */
#define PGP_PACKET_MARKER	10		/* Obsolete marker packet */
#define PGP_PACKET_DATA		11		/* Raw data */
#define PGP_PACKET_TRUST	12		/* Trust information */
#define PGP_PACKET_USERID	13		/* Userid */
#define PGP_PACKET_PUBKEY_SUB 14	/* Public key subkey */
#define PGP_PACKET_USERATTR	17		/* User attributes */
#define PGP_PACKET_ENCR_MDC	18		/* Encrypted data with MDC */
#define PGP_PACKET_MDC		19		/* MDC */

/* PGP signature subpacket types */

#define PGP_SUBPACKET_TIME	2		/* Signing time */
#define PGP_SUBPACKET_KEYID	16		/* Key ID */
#define PGP_SUBPACKET_TYPEANDVALUE 20	/* Type-and-value pairs */
#define PGP_SUBPACKET_LAST	29		/* Last valid subpacket type */

/* A special-case packet type that denotes a signature that follows on from 
   a one-pass signature packet.  When generating a signature of this type PGP
   splits the information in the normal signature packet across the one-pass
   signature packet and the signature packet itself, so we have to read the 
   data on two parts, with half the information in the one-pass packet and 
   the other half in the signature packet */

#define PGP_PACKET_SIGNATURE_SPECIAL	1002

/* PGP CTB information.  All CTBs have the MSB set, and OpenPGP CTBs have the
   next-to-MSB set.  We also have a special-case CTB which is used for
   indefinite-length compressed data */

#define PGP_CTB				0x80	/* PGP 2.x CTB template */
#define PGP_CTB_OPENPGP		0xC0	/* OpenPGP CTB template */
#define PGP_CTB_COMPRESSED	0xA3	/* Compressed indef-length data */

/* A macro to extract the packet type from the full CTB */

#define getCTB( ctb )		( ( ( ctb & PGP_CTB_OPENPGP ) == PGP_CTB_OPENPGP ) ? \
							  ( ctb & 0x3F ) : ( ( ctb >> 2 ) & 0x0F ) )

/* A macro to check whether a packet is a private packet type */

#define isPrivatePacket( type ) \
							( ( type ) >= 60 && ( type ) <= 63 )

/* Version information */

#define PGP_VERSION_2		2		/* Version number byte for PGP 2.0 */
#define PGP_VERSION_3		3		/* Version number byte for legal-kludged PGP 2.0 */
#define PGP_VERSION_OPENPGP	4		/* Version number for OpenPGP */

/* Public-key algorithms */

#define PGP_ALGO_RSA		1		/* RSA algorithm */
#define PGP_ALGO_RSA_ENCRYPT 2		/* RSA encrypt-only */
#define PGP_ALGO_RSA_SIGN	3		/* RSA sign-only */
#define PGP_ALGO_ELGAMAL	16		/* ElGamal algorithm */
#define PGP_ALGO_DSA		17		/* DSA signature algorithm */

/* Conventional encryption algorithms */

#define PGP_ALGO_NONE		0		/* No CKE algorithm */
#define PGP_ALGO_IDEA		1		/* IDEA cipher */
#define PGP_ALGO_3DES		2		/* Triple DES */
#define PGP_ALGO_CAST5		3		/* CAST-128 */
#define PGP_ALGO_BLOWFISH	4		/* Blowfish */
#define PGP_ALGO_SAFERSK	5		/* Safer-SK */
#define PGP_ALGO_RESERVED1	6		/* Reserved/never used */
#define PGP_ALGO_AES_128	7		/* AES with 128-bit key */
#define PGP_ALGO_AES_192	8		/* AES with 192-bit key */
#define PGP_ALGO_AES_256	9		/* AES with 256-bit key */
#define PGP_ALGO_TWOFISH	10		/* Twofish */

/* Hash algorithms */

#define PGP_ALGO_MD5		1		/* MD5 */
#define PGP_ALGO_SHA		2		/* SHA-1 */
#define PGP_ALGO_RIPEMD160	3		/* RIPEMD-160 */
#define PGP_ALGO_RESERVED2	4		/* Reserved/never used */
#define PGP_ALGO_MD2		5		/* MD2 */
#define PGP_ALGO_RESERVED3	6		/* Reserved/never used (Tiger/192) */
#define PGP_ALGO_RESERVED4	7		/* Reserved/never used (Haval) */
#define PGP_ALGO_SHA2_256	8		/* SHA-2 256bit */
#define PGP_ALGO_SHA2_384	9		/* SHA-2 384bit */
#define PGP_ALGO_SHA2_512	10		/* SHA-2 512bit */

/* Compression algorithms */

#define PGP_ALGO_ZIP		1		/* ZIP compression */
#define PGP_ALGO_ZLIB		2		/* zlib compression */

/* S2K specifier */

#define PGP_S2K				0xFF	/* Standard S2K */
#define PGP_S2K_HASHED		0xFE	/* S2K with hashed key */

/* Signed data types */

#define PGP_SIG_DATA		0x00	/* Binary data */
#define PGP_SIG_TEXT		0x01	/* Canonicalised text data */
#define	PGP_SIG_CERT0		0x10	/* Key certificate, unknown assurance */
#define	PGP_SIG_CERT1		0x11	/* Key certificate, no assurance */
#define	PGP_SIG_CERT2		0x12	/* Key certificate, casual assurance */
#define	PGP_SIG_CERT3		0x13	/* Key certificate, strong assurance */
#define PGP_SIG_KRL			0x20	/* Key revocation */
#define PGP_SIG_CRL			0x30	/* Certificate revocation */
#define	PGP_SIG_TS			0x40	/* Timestamp signature */

/* The maximum size of an MPI (4096 bits) */

#define PGP_MAX_MPISIZE		512

/* The maximum size of a PGP user ID.  Note that this is larger than the
   cryptlib-wide maximum user ID size */

#define PGP_MAX_USERIDSIZE	256

/* The size of the IV used for PGP's weird CFB mode */

#define PGP_IVSIZE			8

/* The size of the salt used for password hashing and the number of 
   setup "iterations".  This isn't a true iteration count but the number of 
   salt+password bytes hashed, and in fact it isn't even that but the
   actual count scaled by dividing it by 64, which is how PGP encodes the
   count in the data packet */

#define PGP_SALTSIZE		8
#define PGP_ITERATIONS		1024

/* Various PGP packet header sizes, used to estimate how much data we still 
   need to process */

#define PGP_MIN_HEADER_SIZE	2		/* CTB + length */
#define PGP_MAX_HEADER_SIZE	6		/* CTB + 0xFF + 4-byte length */
#define PGP_DATA_HEADER		"b\x00\x00\x00\x00\x00"
#define PGP_DATA_HEADER_SIZE ( 1 + 1 + 4 )
#define PGP_MDC_PACKET_SIZE	( 1 + 1 + 20 )	/* Size of MDC packet */

/* Since PGP only provides a subset of cryptlib's algorithm types and uses
   different identifiers, we have to both check that there's a mapping
   possible and map from one to the other.  When going from PGP -> cryptlib
   we specify both the algorithm ID and the algorithm class we expect to 
   find it in to allow type checking */

typedef enum {
	PGP_ALGOCLASS_NONE,		/* No algorithm class */
	PGP_ALGOCLASS_CRYPT,	/* Conventional encryption algorithms */
	PGP_ALGOCLASS_PWCRYPT,	/* Password-based encryption algorithms */
	PGP_ALGOCLASS_PKCCRYPT,	/* PKC algorithms */
	PGP_ALGOCLASS_SIGN,		/* Signature algorithms */
	PGP_ALGOCLASS_HASH,		/* Hash algorithms */
	PGP_ALGOCLASS_LAST		/* Last possible algorithm class */
	} PGP_ALGOCLASS_TYPE;

CRYPT_ALGO_TYPE pgpToCryptlibAlgo( const int pgpAlgo, 
								   const PGP_ALGOCLASS_TYPE pgpAlgoClass );
int cryptlibToPgpAlgo( const CRYPT_ALGO_TYPE cryptlibAlgo );

/* Prototypes for functions in pgp_misc.c */

int pgpPasswordToKey( CRYPT_CONTEXT cryptContext, const char *password,
					  const int passwordLength, 
					  const CRYPT_ALGO_TYPE hashAlgo, const BYTE *salt, 
					  const int iterations );
int pgpProcessIV( const CRYPT_CONTEXT iCryptContext, BYTE *ivInfo,
				  const int ivSize, const BOOLEAN isEncrypt, 
				  const BOOLEAN resyncIV );
int pgpReadMPI( STREAM *stream, BYTE *data );
int pgpWriteMPI( STREAM *stream, const BYTE *data, const int length );
#define sizeofMPI( length )		( ( length ) + 2 )

#endif /* _PGP_DEFINED */
