/****************************************************************************
*																			*
*					  ASN.1 Data Object Management Routines					*
*						Copyright Peter Gutmann 1992-2002					*
*																			*
****************************************************************************/

#ifndef _ASN1OBJS_DEFINED

#define _ASN1OBJS_DEFINED

/* The data formats for key exchange/transport and signature types.  These
   are an extension of the externally-visible cryptlib formats and are needed
   for things like X.509 signatures and various secure session protocols
   which wrap stuff other than straight keys up using a KEK.  Note the non-
   orthogonal handling of reading/writing CMS signatures, this is needed
   because creating a CMS signature involves adding assorted additional data
   like iAndS and signed attributes which present too much information to
   pass into a basic writeSignature() call */

typedef enum {
	KEYEX_NONE,			/* No recipient type */
	KEYEX_CMS,			/* iAndS + algoID + OCTET STRING */
	KEYEX_CRYPTLIB,		/* keyID + algoID + OCTET STRING */
	KEYEX_PGP,			/* PGP keyID + MPI */
	KEYEX_LAST			/* Last possible recipient type */
	} KEYEX_TYPE;

typedef enum {
	SIGNATURE_NONE,		/* No signature type */
	SIGNATURE_RAW,		/* Raw signature data */
	SIGNATURE_X509,		/* algoID + BIT STRING */
	SIGNATURE_CMS,		/* sigAlgoID + OCTET STRING (write) */
						/* iAndS + hAlgoID + sAlgoID + OCTET STRING (read) */
	SIGNATURE_CRYPTLIB,	/* keyID + hashAlgoID + sigAlgoID + OCTET STRING */
	SIGNATURE_PGP,		/* Signature as PGP MPIs */
	SIGNATURE_SSH,		/* Signature as SSHv2 sig.record */
	SIGNATURE_LAST		/* Last possible signature type */
	} SIGNATURE_TYPE;

/* Signature read/write methods for the different format types */

typedef int ( *READSIG_FUNCTION )( STREAM *stream, QUERY_INFO *queryInfo );
typedef int ( *WRITESIG_FUNCTION )( STREAM *stream, 
									const CRYPT_CONTEXT iSignContext,
									const CRYPT_ALGO_TYPE hashAlgo, 
									const CRYPT_ALGO_TYPE signAlgo, 
									const BYTE *signature, 
									const int signatureLength );

extern const READSIG_FUNCTION sigReadTable[];
extern const WRITESIG_FUNCTION sigWriteTable[];

/* Key exchange read/write methods for the different format types */

typedef int ( *READKEYTRANS_FUNCTION )( STREAM *stream, QUERY_INFO *queryInfo );
typedef int ( *WRITEKEYTRANS_FUNCTION )( STREAM *stream, 
										 const CRYPT_CONTEXT iCryptContext,
										 const BYTE *buffer, const int length,
										 const void *auxInfo, 
										 const int auxInfoLength );
typedef int ( *READKEK_FUNCTION )( STREAM *stream, QUERY_INFO *queryInfo );
typedef int ( *WRITEKEK_FUNCTION )( STREAM *stream, 
									const CRYPT_CONTEXT iCryptContext,
									const BYTE *buffer, const int length );

extern const READKEYTRANS_FUNCTION keytransReadTable[];
extern const WRITEKEYTRANS_FUNCTION keytransWriteTable[];
extern const READKEK_FUNCTION kekReadTable[];
extern const WRITEKEK_FUNCTION kekWriteTable[];

/* Get information on exported key or signature data */

int queryAsn1Object( STREAM *stream, QUERY_INFO *queryInfo );
int queryPgpObject( STREAM *stream, QUERY_INFO *queryInfo );

#endif /* _ASN1OBJS_DEFINED */
