/****************************************************************************
*																			*
*				ASN.1 Supplementary Constants and Structures				*
*						Copyright Peter Gutmann 1992-2003					*
*																			*
****************************************************************************/

#ifndef _ASN1OID_DEFINED

#define _ASN1OID_DEFINED

#ifndef _STREAM_DEFINED
  #if defined( INC_ALL ) ||  defined( INC_CHILD )
	#include "stream.h"
  #else
	#include "misc/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */

/* The cryptlib (strictly speaking DDS) OID arc is as follows:

	1 3 6 1 4 1 3029 = dds
					 1 = algorithm
					   1 = symmetric encryption
						 1 = blowfishECB
						 2 = blowfishCBC
						 3 = blowfishCFB
						 4 = blowfishOFB
					   2 = public-key encryption
						 1 = elgamal
						   1 = elgamalWithSHA-1
						   2 = elgamalWithRIPEMD-160
					   3 = hash
					 2 = mechanism
					 3 = attribute
					   1 = PKIX fixes
						 1 = cryptlibPresenceCheck
						 2 = pkiBoot
						 (3 unused)
						 4 = cRLExtReason
						 5 = keyFeatures
					 4 = content-type
					   1 = cryptlib
						 1 = cryptlibConfigData
						 2 = cryptlibUserIndex 
						 3 = cryptlibUserInfo
						 4 = cryptlibRtcsRequest
						 5 = cryptlibRtcsResponse
						 5 = cryptlibRtcsResponseExt
					 x58 x59 x5A x5A x59 = XYZZY cert policy */

/* A macro to make make declaring OIDs simpler */

#define MKOID( value )	( ( BYTE * ) value )

/* Attribute OIDs */

#define OID_CRYPTLIB_PRESENCECHECK	MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x03\x01\x01" )
#define OID_ESS_CERTID			MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x0C" )
#define OID_TSP_TSTOKEN			MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x0E" )
#define OID_PKCS9_FRIENDLYNAME	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x14" )
#define OID_PKCS9_LOCALKEYID	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x15" )
#define OID_PKCS9_X509CERTIFICATE MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x09\x16\x01" )

/* The PKCS #9 OID for cert extensions in a certification request, from the
   CMMF draft.  Naturally MS had to define their own incompatible OID for
   this, so we check for this as well */

#define OID_PKCS9_EXTREQ		MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x0E" )
#define OID_MS_EXTREQ			MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x0E" )

/* Content-type OIDs */

#define OID_CMS_DATA			MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x01" )
#define OID_CMS_SIGNEDDATA		MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02" )
#define OID_CMS_ENVELOPEDDATA	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x03" )
#define OID_CMS_DIGESTEDDATA	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x05" )
#define OID_CMS_ENCRYPTEDDATA	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x06" )
#define OID_CMS_AUTHDATA		MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x02" )
#define OID_CMS_TSTOKEN			MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x04" )
#define OID_CMS_COMPRESSEDDATA	MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x09" )
#define OID_CRYPTLIB_CONTENTTYPE MKOID( "\x06\x09\x2B\x06\x01\x04\x01\x97\x55\x04\x01" )
#define OID_CRYPTLIB_CONFIGDATA	MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x01" )
#define OID_CRYPTLIB_USERINDEX	MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x02" )
#define OID_CRYPTLIB_USERINFO	MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x03" )
#define OID_CRYPTLIB_RTCSREQ	MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x04" )
#define OID_CRYPTLIB_RTCSRESP	MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x05" )
#define OID_CRYPTLIB_RTCSRESP_EXT	MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x06" )
#define OID_MS_SPCINDIRECTDATACONTEXT MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x04" )
#define OID_NS_CERTSEQ			MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x02\x05" )
#define OID_OCSP_RESPONSE_OCSP MKOID( "\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x01" )
#define OID_PKIBOOT				MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x03\x01\x02" )
#define OID_PKCS12_SHROUDEDKEYBAG MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x0A\x01\x02" )
#define OID_PKCS12_CERTBAG		MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x0A\x01\x03" )
#define OID_PKCS15_CONTENTTYPE	MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0F\x03\x01" )

/* Misc OIDs */

#define OID_CRYPTLIB_XYZZYCERT	MKOID( "\x06\x0C\x2B\x06\x01\x04\x01\x97\x55\x58\x59\x5A\x5A\x59" )
#define OID_PKCS12_PBEWITHSHAAND3KEYTRIPLEDESCBC MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x01\x03" )
#define OID_PKCS12_PBEWITHSHAAND2KEYTRIPLEDESCBC MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x01\x04" )

/* AlgorithmIdentifiers that are used in various places.  The Fortezza key
   wrap one is keyExchangeAlgorithm { fortezzaWrap80Algorithm } */

#define ALGOID_CMS_ZLIB			MKOID( "\x30\x0F" \
									   "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x03\x08" \
									   "\x05\x00" )
#define ALGOID_FORTEZZA_KEYWRAP	MKOID( "\x30\x18" \
									   "\x06\x09\x60\x86\x48\x01\x65\x02\x01\x01\x16" \
									   "\x30\x0B" \
									   "\x06\x09\x60\x86\x48\x01\x65\x02\x01\x01\x17" )

/* The structure which is used to look up OIDs when reading a CMS header.  We
   step through an array of these checking each OID in turn, when we find a
   match we return the selection value */

typedef struct {
	const BYTE *oid;		/* OID */
	const int minVersion;	/* Minimum version number for content type */
	const int maxVersion;	/* Maximum version number for content type */
	const int selection;	/* Value to return for this OID */
	} OID_SELECTION;

/* When reading/writing an AlgorithmIdentifier there are all sorts of 
   variations.  Setting the algoID-only flag will only read or write the
   basic algorithm information, by default the algorithm and all parameter
   information are written */

#define ALGOID_FLAG_NONE		0x00	/* No special handling */
#define ALGOID_FLAG_ALGOID_ONLY	0x01	/* Only write basic AlgorithmID */

/* AlgorithmIdentifier routines */

BOOLEAN checkAlgoID( const CRYPT_ALGO_TYPE algorithm, 
					 const CRYPT_MODE_TYPE mode );
int sizeofAlgoID( const CRYPT_ALGO_TYPE algorithm );
int sizeofAlgoIDex( const CRYPT_ALGO_TYPE algorithm, 
					const CRYPT_ALGO_TYPE subAlgorithm, 
					const int extraLength );
int writeAlgoID( STREAM *stream, const CRYPT_ALGO_TYPE algorithm );
int writeAlgoIDex( STREAM *stream, const CRYPT_ALGO_TYPE algorithm,
				   const CRYPT_ALGO_TYPE subAlgorithm, const int extraLength );
int readAlgoID( STREAM *stream, CRYPT_ALGO_TYPE *cryptAlgo );
int readAlgoIDex( STREAM *stream, CRYPT_ALGO_TYPE *cryptAlgo,
				  CRYPT_ALGO_TYPE *cryptSubAlgo, int *extraLength );

/* Alternative versions that read/write various algorithm ID types (algo and 
   mode only or full details depending on the option parameter) from encryption 
   contexts */

int sizeofContextAlgoID( const CRYPT_CONTEXT iCryptContext,
						 const CRYPT_ALGO_TYPE subAlgorithm,
						 const int flags );
int readContextAlgoID( STREAM *stream, CRYPT_CONTEXT *iCryptContext,
					   QUERY_INFO *queryInfo, const int tag );
int writeContextAlgoID( STREAM *stream, const CRYPT_CONTEXT iCryptContext,
						const CRYPT_ALGO_TYPE subAlgorithm, 
						const int flags );

/* Read/write general-purpose OIDs */

int readOID( STREAM *stream, const BYTE *oid );
int readOIDSelection( STREAM *stream, const OID_SELECTION *oidSelection, 
					  int *selection );

/* Read/write a message digest */

int readMessageDigest( STREAM *stream, CRYPT_ALGO_TYPE *hashAlgo, 
					   void *hash, int *hashSize );
int writeMessageDigest( STREAM *stream, const CRYPT_ALGO_TYPE hashAlgo, 
						const void *hash, const int hashSize );
#define sizeofMessageDigest( hashAlgo, hashSize ) \
		( int ) sizeofObject( sizeofAlgoID( hashAlgo ) + \
							  sizeofObject( hashSize ) )

/* Read/write CMS headers */

int readCMSheader( STREAM *stream, const OID_SELECTION *oidSelection,
				   long *dataSize, const BOOLEAN isInnerHeader );
int writeCMSheader( STREAM *stream, const BYTE *oid, const long dataSize,
					const BOOLEAN isInnerHeader );
int sizeofCMSencrHeader( const BYTE *contentOID, const long dataSize,
						 const CRYPT_CONTEXT iCryptContext );
int readCMSencrHeader( STREAM *stream, const OID_SELECTION *oidSelection,
					   CRYPT_CONTEXT *iCryptContext, QUERY_INFO *queryInfo );
int writeCMSencrHeader( STREAM *stream, const BYTE *contentOID,
						const long dataSize,
						const CRYPT_CONTEXT iCryptContext );

#endif /* _ASN1OID_DEFINED */
