/****************************************************************************
*																			*
*						PKCS #15 Definitions Header File					*
*						Copyright Peter Gutmann 1996-2002					*
*																			*
****************************************************************************/

#ifndef _PKCS15_DEFINED

#define _PKCS15_DEFINED

/* A PKCS #15 file can contain multiple key and cert objects, before we do
   anything with the file we scan it and build an in-memory index of what's
   present.  When we perform an update we just flush the in-memory
   information to disk.

   Each file can contain information for multiple personalities (although
   it's extremely unlikely to contain more than one or two), we allow a
   maximum of MAX_PKCS15_OBJECTS per file in order to discourage them from
   being used as general-purpose public-key keysets, which they're not 
   supposed to be.  A setting of 32 objects consumes ~4K of memory 
   (32 x ~128), so we choose that as the limit */

#ifdef CONFIG_CONSERVE_MEMORY
  #define MAX_PKCS15_OBJECTS	8
#else
  #define MAX_PKCS15_OBJECTS	32
#endif /* CONFIG_CONSERVE_MEMORY */

/* Usually a PKCS #15 personality consists of a collection of related PKCS
   #15 objects (typically a public and private key and a cert), but sometimes
   we have personalities which consist only of a cert and little other
   information (for example a trusted CA root cert, which contains no user-
   supplied information such as a label).  The following types of personality
   are handled for PKCS #15 files */

typedef enum {
	PKCS15_SUBTYPE_NONE,			/* Non-personality */
	PKCS15_SUBTYPE_NORMAL,			/* Standard personality, keys+optional cert */
	PKCS15_SUBTYPE_CERT,			/* Standalone cert */
	PKCS15_SUBTYPE_SECRETKEY,		/* Secret key */
	PKCS15_SUBTYPE_DATA,			/* Pre-encoded cryptlib-specific data */
	PKCS15_SUBTYPE_LAST
	} PKCS15_SUBTYPE;

/* The following structure contains the the information for one personality,
   which covers one or more of a private key, public key, and cert */

typedef struct {
	/* General information on the personality: The subtype, a local unique
	   identifier which is easier to manage than the iD, the PKCS #15
	   object label, and the PKCS #15 object ID and key ID (which is usually
	   the same as the object ID) */
	PKCS15_SUBTYPE type;			/* Personality subtype */
	int index;						/* Unique value for this personality */
	char label[ CRYPT_MAX_TEXTSIZE ];/* PKCS #15 object label */
	int labelLength;
	BYTE iD[ CRYPT_MAX_HASHSIZE ], keyID[ CRYPT_MAX_HASHSIZE ];
	int iDlength, keyIDlength;		/* PKCS #15 object ID and key ID */

	/* Certificate-related ID information: Hash of the issuer name, subject
	   name, and issuerAndSerialNumber, and PGP key IDs */
	BYTE iAndSID[ KEYID_SIZE ], subjectNameID[ KEYID_SIZE ];
	BYTE issuerNameID[ KEYID_SIZE ];
	BYTE pgp2KeyID[ PGP_KEYID_SIZE ], openPGPKeyID[ PGP_KEYID_SIZE ];
	int iAndSIDlength, subjectNameIDlength, issuerNameIDlength;
	int pgp2KeyIDlength, openPGPKeyIDlength;

	/* Key/cert object data */
	void *pubKeyData, *privKeyData, *certData;	/* Encoded object data */
	int pubKeyDataSize, privKeyDataSize, certDataSize;
	int pubKeyOffset, privKeyOffset, certOffset;
									/* Offset of payload in data */
	int pubKeyUsage, privKeyUsage;	/* Permitted usage for the key */
	int trustedUsage;				/* Usage which key is trusted for */
	BOOLEAN implicitTrust;			/* Whether cert is implicitly trusted */
	time_t validFrom, validTo;		/* Key/cert validity information */

	/* Data object data */
	CRYPT_ATTRIBUTE_TYPE dataType;	/* Type of the encoded object data */
	void *dataData;					/* Encoded object data */
	int dataDataSize, dataOffset;
	} PKCS15_INFO;

/* The types of object we can find in a PKCS #15 file.  These are also used
   as context-specific object tags */

typedef enum { PKCS15_OBJECT_PRIVKEY, PKCS15_OBJECT_PUBKEY,
			   PKCS15_OBJECT_TRUSTEDPUBKEY, PKCS15_OBJECT_SECRETKEY,
			   PKCS15_OBJECT_CERT, PKCS15_OBJECT_TRUSTEDCERT,
			   PKCS15_OBJECT_USEFULCERT, PKCS15_OBJECT_DATA,
			   PKCS15_OBJECT_AUTH, PKCS15_OBJECT_LAST } PKCS15_OBJECT_TYPE;

/* The types of key identifiers we can find attached to an object */

enum { PKCS15_KEYID_NONE, PKCS15_KEYID_ISSUERANDSERIALNUMBER,
	   PKCS15_KEYID_SUBJECTKEYIDENTIFIER, PKCS15_KEYID_ISSUERANDSERIALNUMBERHASH,
	   PKCS15_KEYID_SUBJECTKEYHASH, PKCS15_KEYID_ISSUERKEYHASH,
	   PKCS15_KEYID_ISSUERNAMEHASH, PKCS15_KEYID_SUBJECTNAMEHASH,
	   PKCS15_KEYID_PGP2, PKCS15_KEYID_OPENPGP };

/* PKCS #15 key usage flags, a complex mixture of PKCS #11 and some bits of
   X.509 */

#define PKCS15_USAGE_ENCRYPT		0x0001
#define PKCS15_USAGE_DECRYPT		0x0002
#define PKCS15_USAGE_SIGN			0x0004
#define PKCS15_USAGE_SIGNRECOVER	0x0008
#define PKCS15_USAGE_WRAP			0x0010
#define PKCS15_USAGE_UNWRAP			0x0020
#define PKCS15_USAGE_VERIFY			0x0040
#define PKCS15_USAGE_VERIFYRECOVER	0x0080
#define PKCS15_USAGE_DERIVE			0x0100
#define PKCS15_USAGE_NONREPUDIATION	0x0200

/* PKCS #15 flags that can't be set for public keys.  We use this as a mask
   to derive public-key flags from private key ones */

#define PUBKEY_USAGE_MASK	~( PKCS15_USAGE_DECRYPT | PKCS15_USAGE_SIGN | \
							   PKCS15_USAGE_SIGNRECOVER | PKCS15_USAGE_UNWRAP )

/* PKCS #15 usage types for encryption and signature keys.  We use these when
   looking specifically for signing or encryption keys */

#define ENCR_USAGE_MASK		( PKCS15_USAGE_ENCRYPT | PKCS15_USAGE_DECRYPT | \
							  PKCS15_USAGE_WRAP | PKCS15_USAGE_UNWRAP )
#define SIGN_USAGE_MASK		( PKCS15_USAGE_SIGN | PKCS15_USAGE_SIGNRECOVER | \
							  PKCS15_USAGE_VERIFY | PKCS15_USAGE_VERIFYRECOVER | \
							  PKCS15_USAGE_NONREPUDIATION )

/* The access flags for various types of key objects.  For a public key we
   set 'extractable', for a private key we set 'sensitive',
   'alwaysSensitive', and 'neverExtractable' */

#define KEYATTR_ACCESS_PUBLIC	0x02	/* 00010b */
#define KEYATTR_ACCESS_PRIVATE	0x0D	/* 01101b */

/* Since PKCS #15 uses more key ID types than are used by the rest of 
   cryptlib, we extend the standard range with PKCS15-only types */

#define CRYPT_KEYIDEX_ID				CRYPT_KEYID_LAST
#define CRYPT_KEYIDEX_SUBJECTNAMEID		( CRYPT_KEYID_LAST + 1 )

/* Context-specific tags for the PublicKeyInfo record */

enum { CTAG_PK_CERTIFICATE, CTAG_PK_CERTCHAIN };

/* Context-specific tags for the PKCS #15 object record */

enum { CTAG_OB_SUBCLASSATTR, CTAG_OB_TYPEATTR };

/* Context-specific tags for the PKCS #15 object value record */

enum { CTAG_OV_DIRECT, CTAG_OV_DUMMY, CTAG_OV_DIRECTPROTECTED };

/* Context-specific tags for the PKCS #15 class attributes record */

enum { CTAG_KA_VALIDTO };
enum { CTAG_CA_DUMMY, CTAG_CA_TRUSTED_USAGE, CTAG_CA_IDENTIFIERS,
	   CTAG_CA_TRUSTED_IMPLICIT, CTAG_CA_VALIDTO };

/* Context-specific tags for the PKCS #15 data objects record */

enum { CTAG_DO_EXTERNALDO, CTAG_DO_OIDDO };

/* Utility functions */

void pkcs15freeEntry( PKCS15_INFO *pkcs15info );
PKCS15_INFO *findEntry( const PKCS15_INFO *pkcs15info,
						const CRYPT_KEYID_TYPE keyIDtype,
						const void *keyID, const int keyIDlength,
						const int requestedUsage );
int getValidityInfo( PKCS15_INFO *pkcs15info,
					 const CRYPT_HANDLE cryptHandle );

/* Get-data functions */

int readKeyset( STREAM *stream, PKCS15_INFO *pkcs15info, const long endPos );
void initPKCS15read( KEYSET_INFO *keysetInfo );

/* Set-data functions */

void initPKCS15write( KEYSET_INFO *keysetInfo );

#endif /* _PKCS15_DEFINED */
