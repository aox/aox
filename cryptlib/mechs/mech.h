/****************************************************************************
*																			*
*					  Signature/Keyex Mechanism Header File					*
*						Copyright Peter Gutmann 1992-2006					*
*																			*
****************************************************************************/

#ifndef _MECHANISM_DEFINED

#define _MECHANISM_DEFINED

#ifndef _STREAM_DEFINED
  #if defined( INC_ALL )
	#include "stream.h"
  #else
	#include "io/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */

/****************************************************************************
*																			*
*							ASN.1 Constants and Macros						*
*																			*
****************************************************************************/

/* CMS version numbers for various objects.  They're monotonically increasing
   because it was thought that this was enough to distinguish the record
   types (see the note about CMS misdesign above).  This was eventually fixed
   but the odd version numbers remain, except for PWRI which was done right */

enum { KEYTRANS_VERSION, SIGNATURE_VERSION, KEYTRANS_EX_VERSION,
	   SIGNATURE_EX_VERSION, KEK_VERSION, PWRI_VERSION = 0 };

/* Context-specific tags for the RecipientInfo record.  KeyTrans has no tag
   (actually it has an implied 0 tag because of CMS misdesign, so the other
   tags start at 1).  To allow for addition of new RI types we permit (but
   ignore) objects tagged up to CTAG_RI_MAX */

enum { CTAG_RI_KEYAGREE = 1, CTAG_RI_KEKRI, CTAG_RI_PWRI, CTAG_RI_MAX = 9 };

/****************************************************************************
*																			*
*							Mechanism Function Prototypes					*
*																			*
****************************************************************************/

/* The data formats for key exchange/transport and signature types.  These
   are an extension of the externally-visible cryptlib formats and are needed
   for things like X.509 signatures and various secure session protocols
   that wrap stuff other than straight keys up using a KEK.  Note the non-
   orthogonal handling of reading/writing CMS signatures, this is needed
   because creating a CMS signature involves adding assorted additional data
   like iAndS and signed attributes that present too much information to
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
	SIGNATURE_RAW,		/* BIT STRING */
	SIGNATURE_X509,		/* algoID + BIT STRING */
	SIGNATURE_CMS,		/* sigAlgoID + OCTET STRING (write) */
						/* iAndS + hAlgoID + sAlgoID + OCTET STRING (read) */
	SIGNATURE_CRYPTLIB,	/* keyID + hashAlgoID + sigAlgoID + OCTET STRING */
	SIGNATURE_PGP,		/* PGP MPIs */
	SIGNATURE_SSH,		/* SSHv2 sig.record */
	SIGNATURE_SSL,		/* Raw signature data (no encapsulation) */
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

READSIG_FUNCTION getReadSigFunction( const SIGNATURE_TYPE sigType );
WRITESIG_FUNCTION getWriteSigFunction( const SIGNATURE_TYPE sigType );

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

READKEYTRANS_FUNCTION getReadKeytransFunction( const KEYEX_TYPE keyexType );
WRITEKEYTRANS_FUNCTION getWriteKeytransFunction( const KEYEX_TYPE keyexType );
READKEK_FUNCTION getReadKekFunction( const KEYEX_TYPE keyexType );
WRITEKEK_FUNCTION getWriteKekFunction( const KEYEX_TYPE keyexType );

/* Prototypes for keyex functions in keyex_int.c */

int exportConventionalKey( void *encryptedKey, int *encryptedKeyLength,
						   const int encryptedKeyMaxLength,
						   const CRYPT_CONTEXT iSessionKeyContext,
						   const CRYPT_CONTEXT iExportContext,
						   const KEYEX_TYPE keyexType );
int exportPublicKey( void *encryptedKey, int *encryptedKeyLength,
					 const int encryptedKeyMaxLength,
					 const CRYPT_CONTEXT iSessionKeyContext,
					 const CRYPT_CONTEXT iExportContext,
					 const void *auxInfo, const int auxInfoLength,
					 const KEYEX_TYPE keyexType );
int exportKeyAgreeKey( void *encryptedKey, int *encryptedKeyLength,
					   const int encryptedKeyMaxLength,
					   const CRYPT_CONTEXT iSessionKeyContext,
					   const CRYPT_CONTEXT iExportContext,
					   const CRYPT_CONTEXT iAuxContext,
					   const void *auxInfo, const int auxInfoLength );
int importConventionalKey( const void *encryptedKey, 
						   const int encryptedKeyLength,
						   const CRYPT_CONTEXT iSessionKeyContext,
						   const CRYPT_CONTEXT iImportContext,
						   const KEYEX_TYPE keyexType );
int importPublicKey( const void *encryptedKey, const int encryptedKeyLength,
					 const CRYPT_CONTEXT iSessionKeyContext,
					 const CRYPT_CONTEXT iImportContext,
					 CRYPT_CONTEXT *iReturnedContext, 
					 const KEYEX_TYPE keyexType );
int importKeyAgreeKey( const void *encryptedKey, const int encryptedKeyLength,
					   const CRYPT_CONTEXT iSessionKeyContext,
					   const CRYPT_CONTEXT iImportContext );

/* Prototypes for signature functions in sign_cms.c */

int createSignatureCMS( void *signature, int *signatureLength,
						const int sigMaxLength, 
						const CRYPT_CONTEXT signContext,
						const CRYPT_CONTEXT iHashContext,
						const CRYPT_CERTIFICATE extraData,
						const CRYPT_SESSION iTspSession,
						const CRYPT_FORMAT_TYPE formatType );
int checkSignatureCMS( const void *signature, const int signatureLength,
					   const CRYPT_CONTEXT sigCheckContext,
					   const CRYPT_CONTEXT iHashContext,
					   CRYPT_CERTIFICATE *iExtraData,
					   const CRYPT_HANDLE iSigCheckKey );

/* Prototypes for signature functions in sign_pgp.c */

int createSignaturePGP( void *signature, int *signatureLength,
						const int sigMaxLength,
						const CRYPT_CONTEXT iSignContext,
						const CRYPT_CONTEXT iHashContext );
int checkSignaturePGP( const void *signature, const int signatureLength,
					   const CRYPT_CONTEXT sigCheckContext,
					   const CRYPT_CONTEXT iHashContext );

/* Prototypes for common low-level signature functions in sign_int.c */

int createSignature( void *signature, int *signatureLength, 
					 const int sigMaxLength, 
					 const CRYPT_CONTEXT iSignContext,
					 const CRYPT_CONTEXT iHashContext,
					 const CRYPT_CONTEXT iHashContext2,
					 const SIGNATURE_TYPE signatureType );
int checkSignature( const void *signature, const int signatureLength,
					const CRYPT_CONTEXT iSigCheckContext,
					const CRYPT_CONTEXT iHashContext,
					const CRYPT_CONTEXT iHashContext2,
					const SIGNATURE_TYPE signatureType );

/* Prototypes for functions in sign_rw.c */

int readOnepassSigPacket( STREAM *stream, QUERY_INFO *queryInfo );

/* Prototypes for functions in obj_qry.c */

int getPacketInfo( STREAM *stream, QUERY_INFO *queryInfo );

#endif /* _MECHANISM_DEFINED */
