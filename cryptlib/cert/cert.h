/****************************************************************************
*																			*
*				Certificate Management Structures and Prototypes 			*
*						Copyright Peter Gutmann 1996-2004					*
*																			*
****************************************************************************/

#ifndef _CERT_DEFINED

#define _CERT_DEFINED

#include <time.h>
#ifndef _STREAM_DEFINED
  #if defined( INC_ALL )
	#include "stream.h"
  #elif defined( INC_CHILD )
	#include "../io/stream.h"
  #else
	#include "io/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */

/* The minimum size of an attribute, SEQUENCE (2), OID (5),
   OCTET STRING (2+3 for payload).  This is the amount of slop to allow when
   reading attributes.  Some software gets the length encoding wrong by a few
   bytes, if what's left at the end of an encoded object is >= this value
   then we look for attributes */

#define MIN_ATTRIBUTE_SIZE		12

/* The maximum size of a PKCS #7 certificate chain */

#define MAX_CHAINLENGTH			16

/* The default size of the serial number, size of the built-in serial number 
   buffer (anything larger than this uses a dynamically-allocated buffer) 
   and the maximum size in bytes of a serial number (for example in a 
   certificate or CRL).  Technically values of any size are allowed, but 
   anything larger than this is probably an error */

#define DEFAULT_SERIALNO_SIZE	8
#define SERIALNO_BUFSIZE		32
#define MAX_SERIALNO_SIZE		256

/* The size of the PKI user binary authenticator information before 
   checksumming and encoding, and the size of the encrypted user info: 
   sizeofObject( 2 * sizeofObject( PKIUSER_AUTHENTICATOR_SIZE ) ) + PKCS #5 
   padding = 2 + ( 2 + 12 + 2 + 12 ) = 30 + 2 = 32.  This works for both 64- 
   and 128-bit block ciphers */

#define PKIUSER_AUTHENTICATOR_SIZE		12
#define PKIUSER_ENCR_AUTHENTICATOR_SIZE	32

/* Attribute information flags.  These are:

	FLAG_INVALID: Used to catch accidental use of a boolean value for the 
			flag (an early version of the code used a simple boolean 
			isCritical in place of the current multi-purpose flags).
	FLAG_CRITICAL: The extension containing the field is marked criticial.
	FLAG_LOCKED: The attribute can't be deleted once set, needed to handle
			fields that are added internally by cryptlib that shouldn't be
			deleted by users once set.
	FLAG_BLOB: Disables all type-checking on the field, needed to handle 
			some certs that have invalid field encodings.
	FLAG_BLOB_PAYLOAD: Disables type checking on the field payload, for 
			example checking that the chars in the string are valid for the 
			given ASN.1 string type.
	FLAG_MULTIVALUED: Multiple instantiations of this field are allowed.
	FLAG_DEFAULTVALUE: The field has a value which is equal to the default 
			for this field, so it doesn't get encoded.  This flag is set 
			during the encoding pre-processing pass.
	FLAG_IGNORED: The field is recognised but was ignored at this compliance 
			level.  This prevents the cert from being rejected if the field 
			is marked critical */

#define ATTR_FLAG_NONE			0x00	/* No flag */
#define ATTR_FLAG_INVALID		0x01	/* To catch use of TRUE */
#define ATTR_FLAG_CRITICAL		0x02	/* Critical cert extension */
#define ATTR_FLAG_LOCKED		0x04	/* Field can't be modified */
#define ATTR_FLAG_BLOB			0x08	/* Non-type-checked blob data */
#define ATTR_FLAG_BLOB_PAYLOAD	0x10	/* Payload is non-type-checked blob data */
#define ATTR_FLAG_MULTIVALUED	0x20	/* Multiple instances allowed */
#define ATTR_FLAG_DEFAULTVALUE	0x40	/* Field has default value */
#define ATTR_FLAG_IGNORED		0x80	/* Attribute ignored at this compl.level */

/* Certificate information flags.  These are:

	FLAG_SELFSIGNED: Indicates that the certificate is self-signed.
	FLAG_SIGCHECKED: Caches the check of the cert signature.  This is done 
			because it's only necessary to perform this once when the cert 
			is checked for the first time.  Checking of cert fields that 
			aren't affected by the issuer cert is also cached, but this is 
			handled by the compliance-level check value rather than a simple 
			boolean flag since a cert can be checked at various levels of 
			standards-compliance.
	FLAG_DATAONLY: Indicates a pure data object with no attached context.  
	FLAG_CRLENTRY: The CRL object contains the data from a single CRL entry 
			rather than being a complete CRL.
	FLAG_CERTCOLLECTION: Indicates that a cert chain object contains only an 
			unordered collection of (non-duplicate) certs rather than a true 
			cert chain.  Note that this is a pure container object for which
			only the cert chain member contains certs, the base cert object
			doesn't correspond to an actual cert.
	FLAG_PATHKLUDGE: Indicates that although the cert appears to be a self-
			signed (CA root) cert, it's actually a PKIX path kludge cert 
			that's used to tie a re-issued CA cert (with a new CA key) to 
			existing issued certs signed with the old CA key.  This kludge 
			requires that issuer DN == subject DN, which denotes a CA root 
			cert under normal circumstances */

#define CERT_FLAG_NONE			0x00	/* No flag */
#define CERT_FLAG_SELFSIGNED	0x01	/* Certificate is self-signed */
#define CERT_FLAG_SIGCHECKED	0x02	/* Signature has been checked */
#define CERT_FLAG_DATAONLY		0x04	/* Cert is data-only (no context) */
#define CERT_FLAG_CRLENTRY		0x08	/* CRL is a standalone single entry */
#define CERT_FLAG_CERTCOLLECTION 0x10	/* Cert chain is unordered collection */
#define CERT_FLAG_PATHKLUDGE	0x20	/* Cert is a PKIX path kludge */

/* When creating RTCS responses from a request, there are several subtypes 
   that we can use based on a format specifier in the request.  When we turn 
   the request into a response we check the format specifiers and record the 
   response format as being one of the following */

typedef enum { 
	RTCSRESPONSE_TYPE_NONE,				/* No response type */
	RTCSRESPONSE_TYPE_BASIC,			/* Basic response */
	RTCSRESPONSE_TYPE_EXTENDED,			/* Extended response */
	RTCSRESPONSE_TYPE_LAST				/* Last valid response type */
	} RTCSRESPONSE_TYPE;

/* Set the error locus and type.  This is used for cert checking functions 
   that need to return extended error information but can't modify the cert.
   info, so that setErrorInfo() can't be used */

#define setErrorValues( locus, type ) \
		*errorLocus = ( locus ); *errorType = ( type )

/* The are several types of attributes that can be used depending on the
   object that they're associated with.  The following values are used to 
   select the type of attribute that we want to work with */

typedef enum { 
	ATTRIBUTE_CERTIFICATE,				/* Certificate attribute */
	ATTRIBUTE_CMS,						/* CMS / S/MIME attribute */
	ATTRIBUTE_LAST						/* Last valid attribute type */
	} ATTRIBUTE_TYPE;

/* When checking policy constraints there are several different types of
   checking that we can apply, depending on the presence of other 
   constraints in the issuing certificate(s) and the level of checking that 
   we're performing.  Policies can be optional, required, or a specific-
   policy check that disallows the wildcard anyPolicy as a matching policy */

typedef enum {							/* Issuer		Subject		*/
	POLICY_NONE,						/*	 -			 -			*/
	POLICY_NONE_SPECIFIC,				/*	 -,  !any	 -,  !any	*/
	POLICY_SUBJECT,						/*	 -			yes			*/
	POLICY_SUBJECT_SPECIFIC,			/*	 -			yes, !any	*/
	POLICY_BOTH,						/*	yes			yes			*/
	POLICY_BOTH_SPECIFIC,				/*	yes, !any	yes, !any	*/
	POLICY_LAST							/* Last valid policy type */
	} POLICY_TYPE;

/****************************************************************************
*																			*
*							Certificate Element Tags						*
*																			*
****************************************************************************/

/* Context-specific tags for certificates */

enum { CTAG_CE_VERSION, CTAG_CE_ISSUERUNIQUEID, CTAG_CE_SUBJECTUNIQUEID,
	   CTAG_CE_EXTENSIONS };

/* Context-specific tags for attribute certificates */

enum { CTAG_AC_BASECERTIFICATEID, CTAG_AC_ENTITYNAME,
	   CTAG_AC_OBJECTDIGESTINFO };

/* Context-specific tags for certification requests */

enum { CTAG_CR_ATTRIBUTES };

/* Context-specific tags for CRLs */

enum { CTAG_CL_EXTENSIONS };

/* Context-specific tags for CRMF certification requests */

enum { CTAG_CF_VERSION, CTAG_CF_SERIALNUMBER, CTAG_CF_SIGNINGALG, 
	   CTAG_CF_ISSUER, CTAG_CF_VALIDITY, CTAG_CF_SUBJECT, CTAG_CF_PUBLICKEY,
	   CTAG_CF_ISSUERUID, CTAG_CF_SUBJECTUID, CTAG_CF_EXTENSIONS };

/* Context-specific tags for RTCS responses */

enum { CTAG_RP_EXTENSIONS };

/* Context-specific tags for OCSP requests */

enum { CTAG_OR_VERSION, CTAG_OR_DUMMY, CTAG_OR_EXTENSIONS };

/* Context-specific tags for OCSP responses */

enum { CTAG_OP_VERSION, CTAG_OP_EXTENSIONS };

/* Context-specific tags for CMS attributes */

enum { CTAG_SI_AUTHENTICATEDATTRIBUTES };

/****************************************************************************
*																			*
*							Certificate Data Structures						*
*																			*
****************************************************************************/

/* The structure to hold a field of a certificate attribute */

typedef struct AL {
	/* Identification and encoding information for this attribute field or
	   attribute.  This consists of the field ID for the attribute as a
	   whole, for the attribute field (that is, a field of an attribute, not
	   an attribute field) and for the subfield of the attribute field in the
	   case of composite fields like GeneralNames, a pointer to the sync
	   point used when encoding the attribute, and the encoded size of this
	   field.  If it's a special-case attribute field, the attributeID and
	   fieldID are set to special values decoded by the isXXX() macros
	   further down.  The subFieldID is only set if the fieldID is for a
	   GeneralName field.

	   Although the field type information is contained in the
	   attributeInfoPtr, it's sometimes needed before this has been set up
	   to handle special formatting requirements, for example to enable
	   special-case handling for a DN attribute field or to specify that an
	   OID needs to be decoded into its string representation before being
	   returned to the caller.  Because of this we store the field type here
	   to allow for this special processing */
	CRYPT_ATTRIBUTE_TYPE attributeID;/* Attribute ID */
	CRYPT_ATTRIBUTE_TYPE fieldID;	/* Attribute field ID */
	CRYPT_ATTRIBUTE_TYPE subFieldID;	/* Attribute subfield ID */
	void *attributeInfoPtr;			/* Pointer to encoding sync point */
	int encodedSize;				/* Encoded size of this field */
	int fieldType;					/* Attribute field type */
	int flags;						/* Flags for this field */

	/* Sometimes a field is part of a constructed object, or even a nested
	   series of constructed objects (these are always SEQUENCEs).  Since
	   this is purely an encoding issue, there are no attribute list entries 
	   for the SEQUENCE fields, so when we perform the first pass over the
	   attribute list prior to encoding we remember the lengths of the
	   SEQUENCEs for later use.  Since we can have nested SEQUENCEs
	   containing a given field, we store the lengths and pointers to the
	   table entries used to encode them in a fifo, with the innermost one
	   first and successive outer ones following it */
	int sizeFifo[ 10 ];				/* Encoded size of SEQUENCE containing
									   this field, if present */
	void *encodingFifo[ 10 ];		/* Encoding table entry used to encode
									   this SEQUENCE */
	int fifoEnd;					/* End of list of SEQUENCE sizes */
	int fifoPos;					/* Current position in list */

	/* The data payload for this attribute field or attribute.  If it's 
	   numeric data such as a simple boolean, bitstring, or small integer, 
	   we store it in the intValue member.  If it's an OID or some form of 
	   string we store it in the variable-length buffer */
	long intValue;					/* Integer value for simple types */
	void *value;					/* Attribute value */
	int valueLength;				/* Attribute value length */

	/* The OID, for blob-type attributes */
	BYTE *oid;						/* Attribute OID */

	/* The next and previous list element in the linked list of elements */
	struct AL *next, *prev;

	/* Variable-length storage for the attribute data */
	DECLARE_VARSTRUCT_VARS;
	} ATTRIBUTE_LIST;

/* The structure to hold information on the current selection of attribute/
   GeneralName/DN data used when adding/reading/deleting cert components.  
   The usage of this information is too complex to explain here, see the
   comments at the start of comp_get.c for more information */

typedef struct {
	void **dnPtr;						/* Pointer to current DN */
	CRYPT_ATTRIBUTE_TYPE generalName;	/* Selected GN */
	BOOLEAN dnInExtension;				/* Whether DN is in extension */
	BOOLEAN updateCursor;				/* Whether to upate attr.cursor */
	} SELECTION_INFO;

#define initSelectionInfo( certInfoPtr ) \
	memset( &( certInfoPtr )->currentSelection, 0, sizeof( SELECTION_INFO ) ); \
	( certInfoPtr )->currentSelection.dnPtr = &( ( certInfoPtr )->subjectName ); \
	( certInfoPtr )->currentSelection.generalName = CRYPT_CERTINFO_SUBJECTALTNAME;

/* Sometimes we need to manipulate an internal component which is addressed
   indirectly as a side-effect of some other processing operation.  We can't
   change the selection information for the cert object since this will affect 
   any future operations that the user performs, so we provide the following 
   macros to save and restore the selection state around these operations */

typedef struct {
	int savedChainPos;					/* Current cert.chain position */
	SELECTION_INFO savedSelectionInfo;	/* Current DN/GN selection info */
	ATTRIBUTE_LIST *savedAttributeCursor;	/* Atribute cursor pos.*/
	} SELECTION_STATE;

#define saveSelectionState( savedState, certInfoPtr ) \
	{ \
	if( ( certInfoPtr )->type == CRYPT_CERTTYPE_CERTCHAIN ) \
		( savedState ).savedChainPos = ( certInfoPtr )->cCertCert->chainPos; \
	( savedState ).savedSelectionInfo = ( certInfoPtr )->currentSelection; \
	( savedState ).savedAttributeCursor = ( certInfoPtr )->attributeCursor; \
	}

#define restoreSelectionState( savedState, certInfoPtr ) \
	{ \
	if( ( certInfoPtr )->type == CRYPT_CERTTYPE_CERTCHAIN ) \
		( certInfoPtr )->cCertCert->chainPos = ( savedState ).savedChainPos; \
	( certInfoPtr )->currentSelection = ( savedState ).savedSelectionInfo; \
	( certInfoPtr )->attributeCursor = ( savedState ).savedAttributeCursor; \
	}

/* The structure to hold a validity information entry */

typedef struct VI {
	/* Certificate ID information */
	BYTE data[ KEYID_SIZE ];
	int dCheck;						/* Data checksum for quick match */

	/* Validity information */
	BOOLEAN status;					/* Valid/not valid */
	int extStatus;					/* Extended validity status */
	time_t invalidityTime;			/* Cert invalidity time */

	/* Per-entry attributes.  These are a rather ugly special case for the
	   user because, unlike the attributes for all other cert objects where
	   cryptlib can provide the illusion of a flat type<->value mapping,
	   there can be multiple sets of identical per-entry attributes present
	   if there are multiple RTCS entries present */
	ATTRIBUTE_LIST *attributes;		/* RTCS entry attributes */
	int attributeSize;				/* Encoded size of attributes */

	/* The next element in the linked list of elements */
	struct VI *next;
	} VALIDITY_INFO;

/* The structure to hold a revocation information entry, either a CRL entry
   or OCSP request/response information */

typedef struct RI {
	/* Certificate ID information, either a serial number (for CRLs) or a
	   cert hash or issuerID (for OCSP requests/responses).  In addition
	   this could also be a pre-encoded OCSP v1 certID, which is treated as
	   an opaque blob of type CRYPT_ATTRIBUTE_NONE since it can't be used in 
	   any useful way.  Usually the information fits in the data value, if 
	   it's longer than that (which can only occur with enormous serial 
	   numbers) it's held in the dynamically-allocated dataPtr value */
	CRYPT_ATTRIBUTE_TYPE type;		/* ID type */
	BYTE data[ 128 ], *dataPtr;
	int dataLength;					/* ID information */
	int dCheck;						/* Data checksum for quick match */

	/* Revocation information */
	int status;						/* OCSP revocation status */
	time_t revocationTime;			/* Cert revocation time */

	/* Per-entry attributes.  These are a rather ugly special case for the
	   user because, unlike the attributes for all other cert objects where
	   cryptlib can provide the illusion of a flat type<->value mapping,
	   there can be multiple sets of identical per-entry attributes present
	   if there are multiple CRL/OCSP entries present */
	ATTRIBUTE_LIST *attributes;		/* CRL/OCSP entry attributes */
	int attributeSize;				/* Encoded size of attributes */

	/* The next element in the linked list of elements */
	struct RI *next;
	} REVOCATION_INFO;

/* The internal fields in a cert that hold subtype-specific data for the 
   various cert object types */

typedef struct {
	/* The cert serial number.  This is stored in the buffer if it fits (it 
	   almost always does), otherwise in a dynamically-allocated buffer */
	BYTE serialNumberBuffer[ SERIALNO_BUFSIZE ];
	void *serialNumber;
	int serialNumberLength;			/* Certificate serial number */

	/* The highest compliance level at which a certificate has been checked.
	   We have to record this high water-mark level because increasing the 
	   compliance level may invalidate an earlier check performed at a lower 
	   level */
	int maxCheckLevel;

	/* The allowed usage for a certificate can be further controlled by the 
	   user.  The trustedUsage value is a mask which is applied to the key 
	   usage extension to further constrain usage, alongside this there is 
	   an additional implicit trustImplicit value that acts a boolean flag 
	   that indicates whether the user implicitly trusts this certificate 
	   (without requiring further checking upstream).  This value isn't 
	   stored with the cert since it's a property of any instantiation of 
	   the cert rather than just the current one, so when the user queries 
	   it it's obtained dynamically from the trust manager */
	int trustedUsage;

	/* Cert chains are a special variant of standard certs, being complex 
	   container objects that contain further certificates leading up to a 
	   CA root cert.  The reason why they're combined with standard certs
	   is because when we're building a chain from a cert collection or
	   assembling it from a cert source we can't tell at the time of cert 
	   creation which cert will be the leaf cert, so that any cert 
	   potentially has to be able to act as the chain container (another way 
	   of looking at this is that all standard certs are a special case of a 
	   chain with a length of one).
	   
	   A possible alternative to this way of handling chains is to make the
	   chain object a pure container object used only to hold pointers to 
	   the actual certs, but this requires an extra level of indirection 
	   every time a cert chain object is used, since in virtually all cases
	   what'll be used is the leaf cert with which the chain-as-standard-
	   cert model is the default cert but with the chain-as-container model
	   requires an extra object dereference to obtain.
	   
	   In theory we should use a linked list to store chains, but since the 
	   longest chain ever seen in the wild has a length of 4, using a fixed 
	   maximum length seveal times this size shouldn't be a problem.  The 
	   certs in the chain are ordered from the parent of the leaf cert up to 
	   the root cert, with the leaf cert corresponding to the [-1]th entry 
	   in the list.  We also maintain a current position in the cert chain
	   that denotes the cert in the chain that will be accessed by the
	   component-manipulation functions.  This is set to CRYPT_ERROR if the
	   current cert is the leaf cert */
	CRYPT_CERTIFICATE chain[ MAX_CHAINLENGTH ];
	int chainEnd;					/* Length of cert chain */
	int chainPos;					/* Currently selected cert in chain */

	/* The hash algorithm used to sign the certificate.  Although a part of
	   the signature, a second copy of the algorithm ID is embedded inside 
	   the signed certificate data because of a theoretical attack that 
	   doesn't actually work with any standard signature padding 
	   technique */
	CRYPT_ALGO_TYPE hashAlgo;

	/* The (deprecated) X.509v2 unique ID */
	void *issuerUniqueID, *subjectUniqueID;
	int issuerUniqueIDlength, subjectUniqueIDlength;
	} CERT_CERT_INFO;

typedef struct {
	/* The cert serial number, used when requesting a revocation by 
	   issuerAndSerialNumber.  This is stored in the buffer if it fits (it 
	   almost always does), otherwise in a dynamically-allocated buffer */
	BYTE serialNumberBuffer[ SERIALNO_BUFSIZE ];
	void *serialNumber;
	int serialNumberLength;			/* Certificate serial number */

	/* The cert ID of the PKI user or cert that authorised this request.
	   This is from an external source, supplied when the request is 
	   used as part of the CMP protocol */
	BYTE authCertID[ KEYID_SIZE ];
	} CERT_REQ_INFO;

typedef struct {
	/* The list of revocations for a CRL or a list of OCSP request or response 
	   entries, and a pointer to the revocation/request/response which is 
	   currently being accessed */
	REVOCATION_INFO *revocations;	/* List of revocations */
	REVOCATION_INFO *currentRevocation;	/* Currently selected revocation */

	/* The default revocation time for a CRL, used for if no explicit time 
	   is set for a revocation */
	time_t revocationTime;			/* Default cert revocation time */

	/* The URL for the OCSP responder */
	char *responderUrl;
	int responderUrlSize;			/* OCSP responder URL */

	/* The hash algorithm used to sign the certificate.  Although a part of
	   the signature, a second copy of the algorithm ID is embedded inside 
	   the signed certificate data because of a theoretical attack that 
	   doesn't actually work with any standard signature padding 
	   technique */
	CRYPT_ALGO_TYPE hashAlgo;

	/* Signed OCSP requests can include varying levels of detail in the 
	   signature.  The following value determines how much information is
	   included in the signature */
	CRYPT_SIGNATURELEVEL_TYPE signatureLevel;
	} CERT_REV_INFO;

typedef struct {
	/* A list of RTCS request or response entries, and a pointer to the 
	   request/response which is currently being accessed */
	VALIDITY_INFO *validityInfo;	/* List of validity info */
	VALIDITY_INFO *currentValidity;	/* Currently selected validity info */

	/* The URL for the RTCS responder */
	char *responderUrl;				/* RTCS responder URL */
	int responderUrlSize;

	/* Since RTCS allows for a variety of response types, we include an 
	   indication of the request/response format */
	RTCSRESPONSE_TYPE responseType;	/* Request/response format */
	} CERT_VAL_INFO;

typedef struct {
	/* The authenticator used for authenticating certificate issue and 
	   revocation requests */
	BYTE pkiIssuePW[ 16 ], pkiRevPW[ 16 ];
	} CERT_PKIUSER_INFO;

/* Defines to make access to the union fields less messy */

#define cCertCert		certInfo.certInfo
#define cCertReq		certInfo.reqInfo
#define cCertRev		certInfo.revInfo
#define cCertVal		certInfo.valInfo
#define cCertUser		certInfo.pkiUserInfo

/* The structure that stores information on a certificate object */

typedef struct {
	/* General certificate information */
	CRYPT_CERTTYPE_TYPE type;		/* Certificate type */
	int flags;						/* Certificate flags */
	int version;					/* Cert object version */

	/* Cert type-specific information */
	union {
		CERT_CERT_INFO *certInfo;
		CERT_REQ_INFO *reqInfo;
		CERT_REV_INFO *revInfo;
		CERT_VAL_INFO *valInfo;
		CERT_PKIUSER_INFO *pkiUserInfo;
		} certInfo;

	/* The encoded certificate object.  We save this when we import it
	   because there are many different interpretations of how a cert should
	   be encoded and if we parse and re-encode the cert object, the
	   signature check would fail */
	void *certificate;
	int certificateSize;

	/* The public key associated with this certificate.  When the cert is in
	   the low (unsigned state), this consists of the encoded public-key data
	   and associated attributes.  When the cert is in the high (signed)
	   state, either by being imported from an external source or by being
	   signed by cryptlib, this consists of a public-key context.  In 
	   addition some certificates are imported as data-only certificates, 
	   denoted by CERT_FLAG_DATAONLY being set.  These constitute a 
	   container object that contain no public-key context, and are used for 
	   cert chains (when read from a trusted source) and to store cert 
	   information associated with a private-key context.  Since it's not 
	   known during the import stage whether a cert in a chain will be a 
	   data-only or standard cert (it's not known which cert is the leaf 
	   cert until the entire chain has been processed), cert chains from a 
	   trusted source are imported as data-only certs and then the leaf 
	   has its context instantiated */
	CRYPT_CONTEXT iPubkeyContext;	/* Public-key context */
	CRYPT_ALGO_TYPE publicKeyAlgo;	/* Key algorithm */
	int publicKeyFeatures;			/* Key features */
	void *publicKeyInfo;			/* Encoded key information */
	int publicKeyInfoSize;
	BYTE publicKeyID[ KEYID_SIZE ];	/* Key ID */

	/* General certificate object information */
	void *issuerName;				/* Issuer name */
	void *subjectName;				/* Subject name */
	time_t startTime;				/* Validity start or update time */
	time_t endTime;					/* Validity end or next update time */

	/* In theory we can just copy the subject DN of a CA cert into the issuer
	   DN of a subject cert, however due to broken implementations this will
	   break chaining if we correct any problems in the DN.  Because of this
	   we need to preserve a copy of the cert's subject DN so that we can 
	   write it as a blob to the issuer DN field of any certs it signs.  We 
	   also need to remember the encoded issuer DN so that we can chain 
	   upwards.  The following fields identify the size and location of the 
	   encoded DNs inside the encoded certificate object */
	void *subjectDNptr, *issuerDNptr;	/* Pointer to encoded DN blobs */
	int subjectDNsize, issuerDNsize;	/* Size of encoded DN blobs */

	/* For some objects the public key and/or subject DN and/or issuer DN are 
	   copied in from an external source before the object is signed so we 
	   can't just point the issuerDNptr at the encoded object, we have to 
	   allocate a separate data area to copy the DN into.  This is used in 
	   cases where we don't copy in a full subject/issuerName but only use 
	   an encoded DN blob for the reasons described above */
	void *publicKeyData, *subjectDNdata, *issuerDNdata;

	/* The certificate hash/fingerprint/oobCertID/thumbprint/whatever.  This 
	   is used so frequently that it's cached here for future re-use */
	BYTE certHash[ KEYID_SIZE ];	/* Cached cert hash */
	BOOLEAN certHashSet;			/* Whether hash has been set */

	/* Certificate object attributes and a cursor into the attribute list.  
	   This can be moved by the user on a per-attribute, per-field, and per-
	   component basis */
	ATTRIBUTE_LIST *attributes, *attributeCursor;

	/* The currently selected GeneralName and DN.  A cert can contain 
	   multiple GeneralNames and DNs that can be selected by their field types, 
	   after which adding DN components will affected the selected DN.  This 
	   value contains the currently selected GeneralName and DN info */
	SELECTION_INFO currentSelection;

	/* Save area for the currently selected GeneralName and DN, and position
	   in the cert chain.  The current values are saved to this area when the
	   object receives a lock object message, and restored when the object
	   receives the corresponding unlock message.  This guarantees that any
	   changes made during processing while the cert is locked don't get 
	   reflected back to external users */
	SELECTION_STATE selectionState;

	/* Error information */
	CRYPT_ATTRIBUTE_TYPE errorLocus;/* Error locus */
	CRYPT_ERRTYPE_TYPE errorType;	/* Error type */

	/* The object's handle and the handle of the user who owns this object.
	   The former is used when sending messages to the object when only the 
	   xxx_INFO is available, the latter is used to avoid having to fetch the
	   same information from the system object table */
	CRYPT_HANDLE objectHandle;
	CRYPT_USER ownerHandle;

	/* Variable-length storage for the type-specific data */
	DECLARE_VARSTRUCT_VARS;
	} CERT_INFO;

/* Cert read/write methods for the different format types */

typedef struct {
	const CRYPT_CERTTYPE_TYPE type;
	int ( *readFunction )( STREAM *stream, CERT_INFO *certInfoPtr );
	} CERTREAD_INFO;

typedef struct {
	const CRYPT_CERTTYPE_TYPE type;
	int ( *writeFunction )( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
							const CERT_INFO *issuerCertInfoPtr,
							const CRYPT_CONTEXT iIssuerCryptContext );
	} CERTWRITE_INFO;

extern const CERTREAD_INFO certReadTable[];
extern const CERTWRITE_INFO certWriteTable[];

/****************************************************************************
*																			*
*							Attribute Selection Macros						*
*																			*
****************************************************************************/

/* Determine whether an attribute list item is a dummy entry that denotes
   that this field isn't present in the list but has a default value, that 
   this field isn't present in the list but represents an entire 
   (constructed) attribute, or that it contains a single blob-type 
   attribute */

#define DEFAULTFIELD_VALUE		{ 0, CRYPT_ERROR, 0 }
#define COMPLETEATTRIBUTE_VALUE	{ CRYPT_ERROR, 0, 0 }

#define isDefaultFieldValue( attributeListPtr ) \
		( ( attributeListPtr )->fieldID == CRYPT_ERROR && \
		  ( attributeListPtr )->attributeID == 0 )
#define isCompleteAttribute( attributeListPtr ) \
		( ( attributeListPtr )->fieldID == 0 && \
		  ( attributeListPtr )->attributeID == CRYPT_ERROR )
#define isBlobAttribute( attributeListPtr ) \
		( ( attributeListPtr )->fieldID == 0 && \
		  ( attributeListPtr )->attributeID == 0 )

/* Determine whether a component which is being added to a cert is a special-
   case DN selection component that selects the current DN without changing
   the cert itself, a GeneralName selection component, an attribute cursor
   movement component, or a general control information component */

#define isDNSelectionComponent( certInfoType ) \
	( ( certInfoType ) == CRYPT_CERTINFO_ISSUERNAME || \
	  ( certInfoType ) == CRYPT_CERTINFO_SUBJECTNAME || \
	  ( certInfoType ) == CRYPT_CERTINFO_DIRECTORYNAME )

#define isGeneralNameSelectionComponent( certInfoType ) \
	( ( certInfoType ) == CRYPT_CERTINFO_AUTHORITYINFO_RTCS || \
	  ( certInfoType ) == CRYPT_CERTINFO_AUTHORITYINFO_OCSP || \
	  ( certInfoType ) == CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS || \
	  ( certInfoType ) == CRYPT_CERTINFO_SUBJECTINFO_CAREPOSITORY || \
	  ( certInfoType ) == CRYPT_CERTINFO_SUBJECTINFO_TIMESTAMPING || \
	  ( certInfoType ) == CRYPT_CERTINFO_SIGG_PROCURE_SIGNINGFOR || \
	  ( certInfoType ) == CRYPT_CERTINFO_SUBJECTALTNAME || \
	  ( certInfoType ) == CRYPT_CERTINFO_ISSUERALTNAME || \
	  ( certInfoType ) == CRYPT_CERTINFO_ISSUINGDIST_FULLNAME || \
	  ( certInfoType ) == CRYPT_CERTINFO_CERTIFICATEISSUER || \
	  ( certInfoType ) == CRYPT_CERTINFO_PERMITTEDSUBTREES || \
	  ( certInfoType ) == CRYPT_CERTINFO_EXCLUDEDSUBTREES || \
	  ( certInfoType ) == CRYPT_CERTINFO_CRLDIST_FULLNAME || \
	  ( certInfoType ) == CRYPT_CERTINFO_CRLDIST_CRLISSUER || \
	  ( certInfoType ) == CRYPT_CERTINFO_AUTHORITY_CERTISSUER || \
	  ( certInfoType ) == CRYPT_CERTINFO_FRESHESTCRL_FULLNAME || \
	  ( certInfoType ) == CRYPT_CERTINFO_FRESHESTCRL_CRLISSUER || \
	  ( certInfoType ) == CRYPT_CERTINFO_CMS_RECEIPT_TO || \
	  ( certInfoType ) == CRYPT_CERTINFO_CMS_MLEXP_INSTEADOF || \
	  ( certInfoType ) == CRYPT_CERTINFO_CMS_MLEXP_INADDITIONTO )

#define isCursorComponent( certInfoType ) \
	( ( certInfoType ) == CRYPT_CERTINFO_CURRENT_CERTIFICATE || \
	  ( certInfoType ) == CRYPT_ATTRIBUTE_CURRENT_GROUP || \
	  ( certInfoType ) == CRYPT_ATTRIBUTE_CURRENT || \
	  ( certInfoType ) == CRYPT_ATTRIBUTE_CURRENT_INSTANCE )

#define isControlComponent( certInfoType ) \
	( ( certInfoType ) == CRYPT_CERTINFO_TRUSTED_USAGE || \
	  ( certInfoType ) == CRYPT_CERTINFO_TRUSTED_IMPLICIT )

/* Determine whether a component which is being added is a DN or GeneralName
   component */

#define isDNComponent( certInfoType ) \
	( ( certInfoType ) >= CRYPT_CERTINFO_FIRST_DN && \
	  ( certInfoType ) <= CRYPT_CERTINFO_LAST_DN )

#define isGeneralNameComponent( certInfoType ) \
	( ( certInfoType ) >= CRYPT_CERTINFO_FIRST_GENERALNAME && \
	  ( certInfoType ) <= CRYPT_CERTINFO_LAST_GENERALNAME )

/* Determine whether a component which is being added is pseudo-information
   that corresponds to certificate control information rather than a normal
   cert attribute */

#define isPseudoInformation( certInfoType ) \
	( ( certInfoType ) >= CRYPT_CERTINFO_FIRST_PSEUDOINFO && \
	  ( certInfoType ) <= CRYPT_CERTINFO_LAST_PSEUDOINFO )

/* Determine whether a component which is being added to a validity/
   revocation check request/response is a standard attribute or a per-entry 
   attribute */

#define isRevocationEntryComponent( certInfoType ) \
	( ( certInfoType ) == CRYPT_CERTINFO_CRLREASON || \
	  ( certInfoType ) == CRYPT_CERTINFO_HOLDINSTRUCTIONCODE || \
	  ( certInfoType ) == CRYPT_CERTINFO_INVALIDITYDATE )

/* Check whether an entry in an attribute list is valid.  This checks not
   only the pointer value but also whether it has a non-zero attribute
   ID, denoting a non blob-type attribute */

#define isValidAttributeField( attributePtr ) \
		( ( attributePtr ) != NULL && ( attributePtr )->attributeID > 0 )

/****************************************************************************
*																			*
*							String-Handling Functions						*
*																			*
****************************************************************************/

/* Copy a string to/from an ASN.1 string type */

int getAsn1StringInfo( const void *string, const int stringLen,
					   int *stringType, int *asn1StringType, 
					   int *asn1StringLen );
int copyToAsn1String( void *dest, int *destLen, const int maxLen,
					  const void *source, const int sourceLen, 
					  const int stringType );
int copyFromAsn1String( void *dest, int *destLen, const int maxLen, 
						const void *source, const int sourceLen, 
						const int stringTag );

/* Check that a text string contains valid characters for its string type.
   This is used in non-DN strings where we can't avoid the problem by varying 
   the string type based on the characters being used */

BOOLEAN checkTextStringData( const char *string, const int stringLength,
							 const BOOLEAN isPrintableString );

/****************************************************************************
*																			*
*							DN Manipulation Functions						*
*																			*
****************************************************************************/

/* Selection options when working with DNs/GeneralNames in extensions.  These 
   are used internally when handling user get/set/delete DN/GeneralName 
   requests */

typedef enum {
	MAY_BE_ABSENT,		/* Component may be absent */
	MUST_BE_PRESENT,	/* Component must be present */
	CREATE_IF_ABSENT,	/* Create component if absent */
	SELECTION_OPTION_LAST	/* Last valid selection option type */
	} SELECTION_OPTION;

/* DN manipulation routines */

int insertDNComponent( void **dnListHead,
					   const CRYPT_ATTRIBUTE_TYPE componentType,
					   const void *value, const int valueLength,
					   CRYPT_ERRTYPE_TYPE *errorType );
int deleteDNComponent( void **dnListHead, const CRYPT_ATTRIBUTE_TYPE type, 
					   const void *value, const int valueLength );
int getDNComponentValue( const void *dnListHead, 
						 const CRYPT_ATTRIBUTE_TYPE type,
						 void *value, int *length, const int maxLength );
void deleteDN( void **dnListHead );

/* Copy and compare a DN */

int copyDN( void **dnDest, const void *dnSrc );
BOOLEAN compareDN( const void *dnComponentListHead1,
				   const void *dnComponentListHead2,
				   const BOOLEAN dn1substring );

/* Read/write a DN */

int checkDN( const void *dnComponentListHead,
			 const BOOLEAN checkCN, const BOOLEAN checkC,
			 CRYPT_ATTRIBUTE_TYPE *errorLocus, 
			 CRYPT_ERRTYPE_TYPE *errorType );
int sizeofDN( void *dnComponentListHead );
int readDN( STREAM *stream, void **dnComponentListHead );
int writeDN( STREAM *stream, const void *dnComponentListHead,
			 const int tag );
int readDNstring( const char *string, const int stringLength,
				  void **dnComponentListHead );
int writeDNstring( STREAM *stream, const void *dnComponentListHead );

/****************************************************************************
*																			*
*						Attribute Manipulation Functions					*
*																			*
****************************************************************************/

/* Find information on an attribute */

ATTRIBUTE_LIST *findAttributeByOID( const ATTRIBUTE_LIST *attributeListPtr,
									const BYTE *oid );
ATTRIBUTE_LIST *findAttribute( const ATTRIBUTE_LIST *attributeListPtr,
							   const CRYPT_ATTRIBUTE_TYPE attributeID,
							   const BOOLEAN isFieldID );
ATTRIBUTE_LIST *findAttributeField( const ATTRIBUTE_LIST *attributeListPtr,
									const CRYPT_ATTRIBUTE_TYPE fieldID,
									const CRYPT_ATTRIBUTE_TYPE subFieldID );
ATTRIBUTE_LIST *findAttributeFieldEx( const ATTRIBUTE_LIST *attributeListPtr,
									  const CRYPT_ATTRIBUTE_TYPE fieldID );
ATTRIBUTE_LIST *findNextFieldInstance( const ATTRIBUTE_LIST *attributeListPtr );
int getDefaultFieldValue( const CRYPT_ATTRIBUTE_TYPE fieldID );
BOOLEAN checkAttributePresent( const ATTRIBUTE_LIST *attributeListPtr,
							   const CRYPT_ATTRIBUTE_TYPE fieldID );

/* Move the current attribute cursor */

ATTRIBUTE_LIST *moveAttributeCursor( const ATTRIBUTE_LIST *currentCursor,
									 const CRYPT_ATTRIBUTE_TYPE certInfoType, 
									 const int position );

/* Add/delete attributes/attribute fields */

int addAttribute( const ATTRIBUTE_TYPE attributeType,
				  ATTRIBUTE_LIST **listHeadPtr, const BYTE *oid,
				  const BOOLEAN critical, const void *data,
				  const int dataLength, const int flags );
int addAttributeField( ATTRIBUTE_LIST **attributeListPtr,
					   const CRYPT_ATTRIBUTE_TYPE fieldID,
					   const CRYPT_ATTRIBUTE_TYPE subFieldID,
					   const void *data, const int dataLength,
					   const int flags, CRYPT_ATTRIBUTE_TYPE *errorLocus, 
					   CRYPT_ERRTYPE_TYPE *errorType );
int deleteAttributeField( ATTRIBUTE_LIST **attributeListPtr,
						  ATTRIBUTE_LIST **listCursorPtr,
						  ATTRIBUTE_LIST *listItem,
						  const void *dnDataPtr );
int deleteAttribute( ATTRIBUTE_LIST **attributeListPtr,
					 ATTRIBUTE_LIST **listCursorPtr,
					 ATTRIBUTE_LIST *listItem,
					 const void *dnDataPtr );
void deleteAttributes( ATTRIBUTE_LIST **attributeListPtr );
int copyAttributes( ATTRIBUTE_LIST **destListHeadPtr,
					ATTRIBUTE_LIST *srcListPtr,
					CRYPT_ATTRIBUTE_TYPE *errorLocus, 
					CRYPT_ERRTYPE_TYPE *errorType );
int copyIssuerAttributes( ATTRIBUTE_LIST **destListHeadPtr,
						  const ATTRIBUTE_LIST *srcListPtr,
						  const CRYPT_CERTTYPE_TYPE type,
						  CRYPT_ATTRIBUTE_TYPE *errorLocus, 
						  CRYPT_ERRTYPE_TYPE *errorType );
int copyOCSPRequestAttributes( ATTRIBUTE_LIST **destListHeadPtr,
							   const ATTRIBUTE_LIST *srcListPtr );
int copyRevocationAttributes( ATTRIBUTE_LIST **destListHeadPtr,
							  const ATTRIBUTE_LIST *srcListPtr );

/* Read/write a collection of attributes */

int checkAttributes( const ATTRIBUTE_TYPE attributeType,
					 const ATTRIBUTE_LIST *listHeadPtr,
					 CRYPT_ATTRIBUTE_TYPE *errorLocus, 
					 CRYPT_ERRTYPE_TYPE *errorType );
int sizeofAttributes( const ATTRIBUTE_LIST *attributeListPtr );
int writeAttributes( STREAM *stream, ATTRIBUTE_LIST *attributeListPtr,
					 const CRYPT_CERTTYPE_TYPE type,
					 const int attributeSize );
int readAttributes( STREAM *stream, ATTRIBUTE_LIST **attributeListPtrPtr,
					const CRYPT_CERTTYPE_TYPE type, const int attributeSize,
					CRYPT_ATTRIBUTE_TYPE *errorLocus, 
					CRYPT_ERRTYPE_TYPE *errorType );

/****************************************************************************
*																			*
*			Validity/Revocation Information Manipulation Functions			*
*																			*
****************************************************************************/

/* Read/write validity/revocation information */

int sizeofCRLentry( REVOCATION_INFO *crlEntry );
int readCRLentry( STREAM *stream, REVOCATION_INFO **listHeadPtr,
				  CRYPT_ATTRIBUTE_TYPE *errorLocus, 
				  CRYPT_ERRTYPE_TYPE *errorType );
int writeCRLentry( STREAM *stream, const REVOCATION_INFO *crlEntry );
int sizeofOcspRequestEntry( REVOCATION_INFO *ocspEntry );
int readOcspRequestEntry( STREAM *stream, REVOCATION_INFO **listHeadPtr,
						  CERT_INFO *certInfoPtr );
int writeOcspRequestEntry( STREAM *stream, const REVOCATION_INFO *ocspEntry );
int sizeofOcspResponseEntry( REVOCATION_INFO *ocspEntry );
int readOcspResponseEntry( STREAM *stream, REVOCATION_INFO **listHeadPtr,
						   CERT_INFO *certInfoPtr );
int writeOcspResponseEntry( STREAM *stream, const REVOCATION_INFO *ocspEntry,
							const time_t entryTime );
int sizeofRtcsRequestEntry( VALIDITY_INFO *rtcsEntry );
int readRtcsRequestEntry( STREAM *stream, VALIDITY_INFO **listHeadPtr,
						  CERT_INFO *certInfoPtr );
int writeRtcsRequestEntry( STREAM *stream, const VALIDITY_INFO *rtcsEntry );
int sizeofRtcsResponseEntry( VALIDITY_INFO *rtcsEntry, 
							 const BOOLEAN isFullResponse );
int readRtcsResponseEntry( STREAM *stream, VALIDITY_INFO **listHeadPtr,
						   CERT_INFO *certInfoPtr, 
						   const BOOLEAN isFullResponse );
int writeRtcsResponseEntry( STREAM *stream, const VALIDITY_INFO *rtcsEntry,
							const BOOLEAN isFullResponse );

/* Add/delete a validity/revocation entry */

int addValidityEntry( VALIDITY_INFO **listHeadPtr, 
					  VALIDITY_INFO **newEntryPosition,
					  const void *value, const int valueLength );
int addRevocationEntry( REVOCATION_INFO **listHeadPtr, 
						REVOCATION_INFO **newEntryPosition,
						const CRYPT_KEYID_TYPE valueType,
						const void *value, const int valueLength,
						const BOOLEAN noCheck );
void deleteValidityEntries( VALIDITY_INFO **listHeadPtr );
void deleteRevocationEntries( REVOCATION_INFO **listHeadPtr );

/* Copy a set of validity/revocation entries */

int copyValidityEntries( VALIDITY_INFO **destListHeadPtr,
						 const VALIDITY_INFO *srcListPtr );
int copyRevocationEntries( REVOCATION_INFO **destListHeadPtr,
						   const REVOCATION_INFO *srcListPtr );

/* Determine whether a cert has been revoked by this CRL/OCSP response */

int checkRevocation( const CERT_INFO *certInfoPtr, CERT_INFO *revocationInfoPtr );

/****************************************************************************
*																			*
*							Certificate Checking Functions					*
*																			*
****************************************************************************/

/* Check a certificate object */

int checkCert( CERT_INFO *subjectCertInfoPtr,
			   const CERT_INFO *issuerCertInfoPtr,
			   const BOOLEAN shortCircuitCheck,
			   CRYPT_ATTRIBUTE_TYPE *errorLocus, 
			   CRYPT_ERRTYPE_TYPE *errorType );
int checkCertChain( CERT_INFO *certInfoPtr );

/* Check that a public-key certificate/key is valid for a particular 
   purpose */

#define CHECKKEY_FLAG_NONE			0x01	/* No specific checks */
#define CHECKKEY_FLAG_CA			0x02	/* Must be CA key */
#define CHECKKEY_FLAG_PRIVATEKEY	0x04	/* Check priv.key constraints */

int getKeyUsageFromExtKeyUsage( const CERT_INFO *certInfoPtr,
								CRYPT_ATTRIBUTE_TYPE *errorLocus, 
								CRYPT_ERRTYPE_TYPE *errorType );
int checkKeyUsage( const CERT_INFO *certInfoPtr,
				   const int flags, const int specificUsage, 
				   const int complianceLevel, 
				   CRYPT_ATTRIBUTE_TYPE *errorLocus, 
				   CRYPT_ERRTYPE_TYPE *errorType );

/* Check cert constraints */

int checkNameConstraints( const CERT_INFO *subjectCertInfoPtr,
						  const ATTRIBUTE_LIST *issuerAttributes,
						  const BOOLEAN matchValue,
						  CRYPT_ATTRIBUTE_TYPE *errorLocus, 
						  CRYPT_ERRTYPE_TYPE *errorType );
int checkPolicyConstraints( const CERT_INFO *subjectCertInfoPtr,
							const ATTRIBUTE_LIST *issuerAttributes,
							const POLICY_TYPE policyType,
							CRYPT_ATTRIBUTE_TYPE *errorLocus, 
							CRYPT_ERRTYPE_TYPE *errorType );
int checkPathConstraints( const CERT_INFO *subjectCertInfoPtr,
						  const ATTRIBUTE_LIST *issuerAttributes,
						  const int complianceLevel,
						  CRYPT_ATTRIBUTE_TYPE *errorLocus, 
						  CRYPT_ERRTYPE_TYPE *errorType );

/* Sign/sig check a certificate */

int signCert( CERT_INFO *certInfoPtr, const CRYPT_CONTEXT signContext );
int checkCertValidity( CERT_INFO *certInfoPtr, const CRYPT_HANDLE sigCheckKey );

/****************************************************************************
*																			*
*							Certificate Chain Functions						*
*																			*
****************************************************************************/

/* Read/write/copy a certificate chain */

int readCertChain( STREAM *stream, CRYPT_CERTIFICATE *iCryptCert,
				   const CRYPT_USER cryptOwner,
				   const CRYPT_CERTTYPE_TYPE type,
				   const CRYPT_KEYID_TYPE keyIDtype,
				   const void *keyID, const int keyIDlength,
				   const BOOLEAN dataOnlyCert );
int writeCertChain( STREAM *stream, const CERT_INFO *certInfoPtr );
int copyCertChain( CERT_INFO *certInfoPtr, const CRYPT_HANDLE certChain,
				   const BOOLEAN isCertCollection );

/* Read/write cert collections in assorted formats */

int sizeofCertCollection( const CERT_INFO *certInfoPtr,
						  const CRYPT_CERTFORMAT_TYPE certFormatType );
int writeCertCollection( STREAM *stream, const CERT_INFO *certInfoPtr,
						 const CRYPT_CERTFORMAT_TYPE certFormatType );

/* Assemble a cert chain from certs read from an object */

int assembleCertChain( CRYPT_CERTIFICATE *iCertificate,
					   const CRYPT_HANDLE iCertSource, 
					   const CRYPT_KEYID_TYPE keyIDtype,
					   const void *keyID, const int keyIDlength,
					   const int options );

/****************************************************************************
*																			*
*								Certificate Functions						*
*																			*
****************************************************************************/

/* Create a certificate object ready for further initialisation */

int createCertificateInfo( CERT_INFO **certInfoPtrPtr, 
						   const CRYPT_USER cryptOwner,
						   const CRYPT_CERTTYPE_TYPE certType );

/* Add/get/delete a certificate component */

int addCertComponent( CERT_INFO *certInfoPtr,
					  const CRYPT_ATTRIBUTE_TYPE certInfoType,
					  const void *certInfo, const int certInfoLength );
int getCertComponent( CERT_INFO *certInfoPtr,
					  const CRYPT_ATTRIBUTE_TYPE certInfoType,
					  void *certInfo, int *certInfoLength );
int deleteCertComponent( CERT_INFO *certInfoPtr,
						 const CRYPT_ATTRIBUTE_TYPE certInfoType );

/* Import/export a certificate */

int importCert( const void *certObject, const int certObjectLength,
				CRYPT_CERTIFICATE *certificate,
				const CRYPT_USER cryptOwner,
				const CRYPT_KEYID_TYPE keyIDtype,
				const void *keyID, const int keyIDlength,
				const CERTFORMAT_TYPE formatType );
int exportCert( void *certObject, int *certObjectLength,
				const CRYPT_CERTFORMAT_TYPE certFormatType,
				const CERT_INFO *certInfoPtr, const int maxLength );

/* Oddball routines: work with a certificate's serial number */

int setSerialNumber( CERT_INFO *certInfoPtr, const void *serialNumber, 
					 const int serialNumberLength );
int compareSerialNumber( const void *canonSerialNumber, 
						 const int canonSerialNumberLength,
						 const void *serialNumber, 
						 const int serialNumberLength );

#endif /* _CERT_DEFINED */
