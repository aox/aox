/****************************************************************************
*																			*
*				Certificate Management Structures and Prototypes 			*
*						Copyright Peter Gutmann 1996-2003					*
*																			*
****************************************************************************/

#ifndef _CERT_DEFINED

#define _CERT_DEFINED

#include <time.h>
#ifndef _STREAM_DEFINED
  #if defined( INC_ALL )
	#include "stream.h"
  #elif defined( INC_CHILD )
	#include "../misc/stream.h"
  #else
	#include "misc/stream.h"
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

/* The size of the built-in serial number buffer (anything larger than this
   uses a dynamically-allocated buffer) and the maximum size in bytes of a 
   serial number (for example in a certificate or CRL).  Technically values 
   of any size are allowed, but anything larger than this is probably an 
   error */

#define SERIALNO_BUFSIZE		32
#define MAX_SERIALNO_SIZE		256

/* The size of the PKI user binary authenticator information before 
   checksumming and encoding, and the size of the encrypted user info: 
   sizeofObject( 2 * sizeofObject( PKIUSER_AUTHENTICATOR_SIZE ) ) + PKCS #5 
   padding = 2 + ( 2 + 12 + 2 + 12 ) = 30 + 2 = 32.  This works for both 64- 
   and 128-bit block ciphers */

#define PKIUSER_AUTHENTICATOR_SIZE		12
#define PKIUSER_ENCR_AUTHENTICATOR_SIZE	32

/* Attribute information flags.  The invalid flag is used to catch accidental
   use of a boolean value for the flag, the critical flag is used to indicate 
   that the extension is marked criticial, the blob flag is used to disable 
   all type-checking on the field (needed to handle some certs that have 
   invalid field encodings), the blob-data flag is used to disable type
   checking on the field payload (for example that the string data is valid 
   for the string type), the multivalued flag is used to indicate that 
   multiple instantiations of this field are valid, and the default value 
   flag indicates that the field has a value which is equal to the default 
   for this field, so it doesn't get encoded (this flags is set during the
   encoding preprocessing pass) */

#define ATTR_FLAG_NONE			0x00	/* No flag */
#define ATTR_FLAG_INVALID		0x01	/* To catch use of TRUE */
#define ATTR_FLAG_CRITICAL		0x02	/* Critical cert extension */
#define ATTR_FLAG_LOCKED		0x04	/* Field can't be modified */
#define ATTR_FLAG_BLOB			0x08	/* Non-type-checked blob data */
#define ATTR_FLAG_BLOB_PAYLOAD	0x10	/* Payload is non-type-checked blob data */
#define ATTR_FLAG_MULTIVALUED	0x20	/* Multiple instances allowed */
#define ATTR_FLAG_DEFAULTVALUE	0x40	/* Field has default value */

/* Certificate information flags.  The sigChecked flags is used to cache 
   the check of the cert signature since it's only necessary to perform this 
   once when the cert is imported or checked for the first time.  Checking of
   cert fields that aren't affected by the issuer cert is also cached, but
   this is handled by the compliance-level check value rather than a simple
   boolean flag since a cert can be checked at various levels of standards-
   compliance.  The data-only flag indicates a pure data object with no 
   attached context.  The CRL-entry flag is used to indicate that the CRL 
   object contains the data from a single CRL entry rather than being a 
   complete CRL.  The cert-collection flag indicates that a cert chain object 
   contains only an unordered collection of (non-duplicate) certs rather than 
   a true cert chain */

#define CERT_FLAG_NONE			0x00	/* No flag */
#define CERT_FLAG_SELFSIGNED	0x01	/* Certificate is self-signed */
#define CERT_FLAG_SIGCHECKED	0x02	/* Signature has been checked */
#define CERT_FLAG_DATAONLY		0x04	/* Cert is data-only (no context) */
#define CERT_FLAG_CRLENTRY		0x08	/* CRL is a standalone single entry */
#define CERT_FLAG_CERTCOLLECTION 0x10	/* Cert chain is unordered collection */

/* When creating RTCS and OCSP responses from a request, there are several 
   subtypes that we can use based on a format specifier in the request.  When 
   we turn the request into a response we check the format specifiers and 
   record the response format as being one of the following */

typedef enum { 
	RTCSRESPONSE_TYPE_NONE,				/* No response type */
	RTCSRESPONSE_TYPE_BASIC,			/* Basic response */
	RTCSRESPONSE_TYPE_EXTENDED,			/* Extended response */
	RTCSRESPONSE_TYPE_LAST				/* Last valid response type */
	} RTCSRESPONSE_TYPE;

typedef enum { 
	OCSPRESPONSE_TYPE_NONE,				/* No response type */
	OCSPRESPONSE_TYPE_OCSP,				/* OCSP standard response */
	OCSPRESPONSE_TYPE_LAST				/* Last valid response type */
	} OCSPRESPONSE_TYPE;

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

enum { CTAG_SI_AUTHENTICATEDATTRIBUTES	};

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
	   case of composite fields like GeneralName's, a pointer to the sync
	   point used when encoding the attribute, and the encoded size of this
	   field.  If it's a special-case attribute field, the attributeID and
	   fieldID are set to special values decoded by the isXXX() macros
	   further down.  The subFieldID is only set if the fieldID is for a
	   GeneralName field

	   Although the field type information is contained in the
	   attributeInfoPtr, it's sometimes needed before this has been set up
	   to handle special formatting requirements (for example to enable
	   special-case handling for a DN attribute field or to specify that an
	   OID needs to be decoded into its string representation before being
	   returned to the caller).  Because of this we store the field type here
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
	   this purely an encoding issue, there are no attribute list entries for
	   the SEQUENCE fields, so when we perform the first pass over the
	   attribute list prior to encoding we remember the lengths of the
	   SEQUENCES for later use.  Since we can have nested SEQUENCEs
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
   comments at the start of certcomp.c for more information */

typedef struct {
	void **dnPtr;						/* Pointer to current DN */
	CRYPT_ATTRIBUTE_TYPE generalName;	/* Selected GN */
	BOOLEAN dnInExtension;				/* Whether DN is in extension */
	BOOLEAN updateCursor;				/* Whether to upate attr.cursor */
	} SELECTION_INFO;

#define initSelectionInfo( certInfoPtr ) \
	( certInfoPtr )->currentSelection.dnPtr = &( ( certInfoPtr )->subjectName ); \
	( certInfoPtr )->currentSelection.generalName = CRYPT_CERTINFO_SUBJECTALTNAME;

/* The structure to hold the current volatile state of a certificate object:
   which certificate in a chain is selected, and which GeneralName/DN/
   attribute is selected */

typedef struct {
	int savedCertChainPos;			/* Current cert.chain position */
	SELECTION_INFO savedSelectionInfo;	/* Current DN/GN selection info */
	ATTRIBUTE_LIST *savedAttributeCursor;	/* Atribute cursor pos.*/
	} SELECTION_STATE;

/* The structure to hold a validity information entry */

typedef struct VI {
	/* Certificate ID information */
	BYTE data[ KEYID_SIZE ];
	int dCheck;						/* Data checksum */

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

/* The structure to hold a revocation information entry (either a CRL entry
   or OCSP request/response information) */

typedef struct RI {
	/* Certificate ID information, either a serial number (for CRLs) or a
	   cert hash or issuerID (for OCSP requests/responses).  In addition
	   this could also be a pre-encoded OCSP v1 certID, which is treated as
	   an opaque blob of type CRYPT_ATTRIBUTE_NONE (it can't be used in any
	   useful way).  Usually the information fits in the data value, if it's 
	   longer than that (which can only occur with enormous serial numbers)
	   it's held in the dynamically-allocated dataPtr value */
	CRYPT_ATTRIBUTE_TYPE type;		/* ID type */
	BYTE data[ 128 ], *dataPtr;
	int dataLength;					/* ID information */
	int dCheck;						/* Data checksum */

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

/* The structure that stores information on a certificate object */

typedef struct {
	/* General certificate information */
	CRYPT_CERTTYPE_TYPE type;		/* Certificate type */
	int flags;						/* Certificate flags */
	int version;					/* Cert object version */

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
	   denoted by the CERT_FLAG_DATAONLY being set.  These constitute a 
	   container object that contain no public-key context, and are used for 
	   cert chains (when read from atrusted source) and to store cert 
	   information associated with a private-key context.  Since it's not 
	   known during the import stage whether a cert in a chain will be a 
	   data-only or standard cert (it's not known until the entire chain has 
	   been processed which cert is the leaf cert), cert chains from a 
	   trusted source are imported as data-only certs and then the leaf 
	   has its context instantiated */
	CRYPT_CONTEXT iPubkeyContext;	/* Public-key context */
	CRYPT_ALGO_TYPE publicKeyAlgo;	/* Key algorithm */
	int publicKeyFeatures;			/* Key features */
	void *publicKeyInfo;			/* Encoded key information */
	int publicKeyInfoSize;
	BYTE publicKeyID[ KEYID_SIZE ];	/* Key ID */

	/* General certificate object information */
	BYTE serialNumberBuffer[ SERIALNO_BUFSIZE ];
	void *serialNumber;
	int serialNumberLength;			/* Certificate serial number */
	time_t startTime;				/* Validity start or update time */
	time_t endTime;					/* Validity end or next update time */
	void *issuerUniqueID, *subjectUniqueID;
	int issuerUniqueIDlength, subjectUniqueIDlength;
									/* Certificate serial number */
	/* Name fields */
	void *issuerName;				/* Issuer name */
	void *subjectName;				/* Subject name */

	/* In theory we can just copy the subject DN of a CA cert into the issuer
	   DN of a subject cert, however due to broken implementations this will
	   break chaining if we correct any problems in the DN.  Because of this
	   we need to preserve a copy of the cert's subject DN so we can write it
	   as a blob to the issuer DN field of any certs it signs.  We also need
	   to remember the encoded issuer DN so we can chain upwards.

	   The following fields identify the size and location of the encoded DNs
	   inside the encoded certificate object */
	void *subjectDNptr, *issuerDNptr;	/* Pointer to encoded DN blobs */
	int subjectDNsize, issuerDNsize;	/* Size of encoded DN blobs */

	/* For some objects the public key and/or subject DN and/or issuer DN are 
	   copied in from an external source before the object is signed so we 
	   can't just point the issuerDNptr at the encoded object, we have to 
	   allocate a separate data area to copy the DN into.  This is used in 
	   cases where we don't copy in a full subhect/issuerName but only use 
	   an encoded DN blob for the reasons described above */
	void *publicKeyData, *subjectDNdata, *issuerDNdata;

	/* For chaining we may also need to use key identifiers, unfortunately
	   this rarely works as intended because most certs don't contain key
	   identifiers or contain them in some peculiar form that isn't useful
	   or in an incorrect form.  This isn't helped by the fact that the
	   subject and authority key identifiers have different forms and can't
	   be compared by matching the encoded blobs.  For this reason we only
	   try to chain on key identifiers if chaining on names fails */
	void *subjectKeyIDptr, *issuerKeyIDptr;	/* Pointer to encoded key ID blobs */
	int subjectKeyIDsize, issuerKeyIDsize;	/* Size of encoded key ID blobs */

	/* The certificate hash/fingerprint/oobCertID/thumbprint/whatever.  This 
	   is used so frequently that it's cached here for future re-use */
	BYTE certHash[ KEYID_SIZE ];	/* Cached cert hash */
	BOOLEAN certHashSet;			/* Whether hash has been set */

	/* Some signed objects can include varying levels of detail in the
	   signature.  The following value determines how much information is
	   included in the signature */
	CRYPT_SIGNATURELEVEL_TYPE signatureLevel;

	/* The highest compliance level at which a certificate has been checked.
	   We have to record this because increasing the compliance level may
	   invalidate an earlier check performed at a lower level */
	int maxCheckLevel;

	/* Certificate-specific information. The allowed usage for a certificate 
	   can be further controlled by the user.  The trustedUsage value is a 
	   mask which is applied to the key usage extension to further constrain 
	   usage, alongside this there is an additional implicit trustImplicit 
	   value that acts a boolean flag that indicates whether the user 
	   implicitly trusts this certificate (without requiring further checking 
	   upstream).  This value isn't stored with the cert since it's a 
	   property of any instantiation of the cert rather than just the 
	   current one, so when the user queries it it's obtained dynamically 
	   from the trust manager */
	int trustedUsage;

	/* Cert-chain specific information.  These are complex container objects 
	   that contain further certificates leading up to a CA root cert.  In 
	   theory we should use a linked list to store chains, but since the 
	   longest chain ever seen in the wild has a length of 4, using a fixed 
	   maximum length seveal times this size shouldn't be a problem.

	   The certs in the chain are ordered from the parent of the leaf cert up
	   to the root cert, with the leaf cert corresponding to the [-1]th entry
	   in the list.  We also maintain a current position in the cert chain
	   that denotes the cert in the chain that will be accessed by the
	   component-manipulation functions.  This is set to CRYPT_ERROR if the
	   current cert is the leaf cert */
	CRYPT_CERTIFICATE certChain[ MAX_CHAINLENGTH ];
	int certChainEnd;				/* Length of cert chain */
	int certChainPos;				/* Currently selected cert in chain */

	/* CRL/RTCS/OCSP-specific information.  The list of revocations for a 
	   CRL or a list of RTCS/OCSP request entries or responses, and a 
	   pointer to the revocation/request/response which is currently being 
	   accessed.  In addition for a CRL we store the default revocation time 
	   which is used for revocations if no explicit time is set for them, and 
	   for RTCS/OCSP we store the URL for the responder.  Finally, since OCSP 
	   allows for a variety of response types, we include a flag indicating 
	   whether we should use the extended rather than basic response format */
	VALIDITY_INFO *validityInfo;	/* List of validity info */
	VALIDITY_INFO *currentValidity;	/* Currently selected validity info */
	REVOCATION_INFO *revocations;	/* List of revocations */
	REVOCATION_INFO *currentRevocation;	/* Currently selected revocation */
	time_t revocationTime;			/* Default cert revocation time */
	char *responderUrl;
	int responderUrlSize;			/* RTCS/OCSP responder URL */
	OCSPRESPONSE_TYPE responseType;	/* OCSP response format */

	/* PKI user-specific information.  The authenticator used for 
	   authenticating certificate issue and revocation requests */
	BYTE pkiIssuePW[ 16 ], pkiRevPW[ 16 ];

	/* Cert request-specific information.  The cert ID of the PKI user or 
	   cert that authorised this request (supplied externally when the 
	   request is received) */
	BYTE authCertID[ KEYID_SIZE ];

	/* Certificate object attributes are stored in two ways, as the native
	   field types for the attributes we recognise (or at least for the ones
	   we care about), and as a list of encoded blobs for the rest */
	ATTRIBUTE_LIST *attributes;		/* Certificate object attributes */

	/* The cursor into the attribute list.  This can be moved by the user on
	   a per-attribute, per-field, and per-component basis.  We also remember
	   whether there's been an attempt to set the attribute cursor so that
	   we can differentiate between the case where the cursor is NULL because
	   no attempt was made to set it, or because there are no attributes
	   present */
	ATTRIBUTE_LIST *attributeCursor;

	/* The currently selected GeneralName and DN and DN pointer.  A cert can
	   contain multiple GeneralNames and DNs that can be selected by their
	   field types, after which adding DN components will affected the
	   selected DN.  This value contains the currently selected GeneralName
	   and DN, and a pointer to the DN data if it exists (when creating a new
	   DN, the pointer will be null after it's selected since it won't be
	   instantiated until data is added to it in later calls) */
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

/* Determine whether an attribute list item is a dummy entry that denotes
   either that this field isn't present in the list but has a default value
   or that this field isn't present in the list but represents an entire
   (constructed) attribute, or whether it contains a single blob-type
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
   movement component, or a general control information component.  We also
   define an alternate form for the GeneralName components to allow them to
   be used in a switch() statement */

#define isDNSelectionComponent( certInfoType ) \
	( ( certInfoType ) == CRYPT_CERTINFO_ISSUERNAME || \
	  ( certInfoType ) == CRYPT_CERTINFO_SUBJECTNAME || \
	  ( certInfoType ) == CRYPT_CERTINFO_DIRECTORYNAME )

#define isGeneralNameSelectionComponent( certInfoType ) \
	( ( certInfoType ) == CRYPT_CERTINFO_AUTHORITYINFO_RTCS || \
	  ( certInfoType ) == CRYPT_CERTINFO_AUTHORITYINFO_OCSP || \
	  ( certInfoType ) == CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS || \
	  ( certInfoType ) == CRYPT_CERTINFO_AUTHORITYINFO_TIMESTAMPING || \
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
	  ( certInfoType ) == CRYPT_CERTINFO_CURRENT_EXTENSION || \
	  ( certInfoType ) == CRYPT_CERTINFO_CURRENT_FIELD || \
	  ( certInfoType ) == CRYPT_CERTINFO_CURRENT_COMPONENT )

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

/* Determine whether a component which is being added to a CRL or OCSP 
   request/response is a standard attribute or a per-entry attribute */

#define isRevocationEntryComponent( certInfoType ) \
	( ( certInfoType ) == CRYPT_CERTINFO_CRLREASON || \
	  ( certInfoType ) == CRYPT_CERTINFO_HOLDINSTRUCTIONCODE || \
	  ( certInfoType ) == CRYPT_CERTINFO_INVALIDITYDATE )

/* Sometimes we need to manipulate an internal component which is addressed
   indirectly as a side-effect of some other processing operation.  We can't
   change the selection information since this will affect any future
   operations the user performs, so we provide the following macros to save
   and restore the selection state around these operations */

#define saveSelectionState( savedState, certInfoPtr ) \
	{ \
	( savedState ).savedCertChainPos = ( certInfoPtr )->certChainPos; \
	( savedState ).savedSelectionInfo = ( certInfoPtr )->currentSelection; \
	( savedState ).savedAttributeCursor = ( certInfoPtr )->attributeCursor; \
	}

#define restoreSelectionState( savedState, certInfoPtr ) \
	{ \
	( certInfoPtr )->certChainPos = ( savedState ).savedCertChainPos; \
	( certInfoPtr )->currentSelection = ( savedState ).savedSelectionInfo; \
	( certInfoPtr )->attributeCursor = ( savedState ).savedAttributeCursor; \
	}

/* Set the error locus and type.  This is used for checking functions that
   need to return extended error information but can't modify the cert.info 
   (so that setErrorInfo() can't be used) but */

#define setErrorValues( locus, type ) \
		*errorLocus = ( locus ); *errorType = ( type )

/* Selection options when working with DNs/GeneralNames in extensions.  These 
   are used internally when handling user get/set/delete DN/GeneralName 
   requests */

typedef enum {
	MAY_BE_ABSENT,		/* Component may be absent */
	MUST_BE_PRESENT,	/* Component must be present */
	CREATE_IF_ABSENT	/* Create component if absent */
	} SELECTION_OPTION;

/* The are several types of attributes that can be used depending on the
   object they're associated with.  The following values are used to select
   the type of attribute we want to work with */

typedef enum { ATTRIBUTE_CERTIFICATE, ATTRIBUTE_CMS } ATTRIBUTE_TYPE;

/****************************************************************************
*																			*
*							String-Handling Functions						*
*																			*
****************************************************************************/

/* Copy a string to/from an ASN.1 string type */

int copyToAsn1String( void *dest, int *destLen, const int maxLen,
					  const void *source, const int sourceLen );
int copyFromAsn1String( void *dest, int *destLen, const int maxLen, 
						const void *source, const int sourceLen, 
						const int stringTag );

/* Check that a text string contains valid characters for its string type.
   This is used in non-DN strings where we can't vary the string type based 
   on the characters being used */

BOOLEAN checkTextStringData( const char *string, const int stringLength,
							 const BOOLEAN isPrintableString );

/****************************************************************************
*																			*
*							DN Manipulation Functions						*
*																			*
****************************************************************************/

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
int getDefaultFieldValue( const CRYPT_ATTRIBUTE_TYPE fieldID );
BOOLEAN checkAttributePresent( const ATTRIBUTE_LIST *attributeListPtr,
							   const CRYPT_ATTRIBUTE_TYPE fieldID );

/* Move the current attribute cursor */

int moveAttributeCursor( ATTRIBUTE_LIST **currentCursor,
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
						  CRYPT_ATTRIBUTE_TYPE *errorLocus, 
						  CRYPT_ERRTYPE_TYPE *errorType,
						  const CRYPT_CERTTYPE_TYPE type );
int copyRequestAttributes( ATTRIBUTE_LIST **destListHeadPtr,
						   const ATTRIBUTE_LIST *srcListPtr,
						   CRYPT_ATTRIBUTE_TYPE *errorLocus, 
						   CRYPT_ERRTYPE_TYPE *errorType );
int copyRevocationAttributes( ATTRIBUTE_LIST **destListHeadPtr,
							  const ATTRIBUTE_LIST *srcListPtr,
							  CRYPT_ATTRIBUTE_TYPE *errorLocus, 
							  CRYPT_ERRTYPE_TYPE *errorType );

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

/* Read/write revocation information */

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

/* Copy a set of revocation entries */

int copyValidityEntries( VALIDITY_INFO **destListHeadPtr,
						 const VALIDITY_INFO *srcListPtr,
						 CRYPT_ATTRIBUTE_TYPE *errorLocus, 
						 CRYPT_ERRTYPE_TYPE *errorType );
int copyRevocationEntries( REVOCATION_INFO **destListHeadPtr,
						   const REVOCATION_INFO *srcListPtr,
						   CRYPT_ATTRIBUTE_TYPE *errorLocus, 
						   CRYPT_ERRTYPE_TYPE *errorType );

/* Determine whether a cert has been revoked by this CRL/OCSP response */

int checkRevocation( const CERT_INFO *certInfoPtr, CERT_INFO *revocationInfoPtr );

/****************************************************************************
*																			*
*								Certificate Functions						*
*																			*
****************************************************************************/

/* Create a locked certificate information object ready for further 
   initialisation */

int createCertificateInfo( CERT_INFO **certInfoPtrPtr, 
						   const CRYPT_USER cryptOwner,
						   const CRYPT_CERTTYPE_TYPE certType );

/* Read and write complex certificate objects */

int readCertChain( STREAM *stream, CRYPT_CERTIFICATE *iCryptCert,
				   const CRYPT_USER cryptOwner,
				   const CRYPT_CERTTYPE_TYPE type,
				   const CRYPT_KEYID_TYPE keyIDtype,
				   const void *keyID, const int keyIDlength,
				   const BOOLEAN dataOnlyCert );
int writeCertChain( STREAM *stream, const CERT_INFO *certInfoPtr );

/* Check a certificate object */

int checkCert( CERT_INFO *subjectCertInfoPtr,
			   const CERT_INFO *issuerCertInfoPtr,
			   const BOOLEAN shortCircuitCheck,
			   CRYPT_ATTRIBUTE_TYPE *errorLocus, 
			   CRYPT_ERRTYPE_TYPE *errorType );
int checkCertChain( CERT_INFO *certInfoPtr );

/* Check that a key cert is valid for a particular purpose */

int getKeyUsageFromExtKeyUsage( const CERT_INFO *certInfoPtr,
								CRYPT_ATTRIBUTE_TYPE *errorLocus, 
								CRYPT_ERRTYPE_TYPE *errorType );
int checkCertUsage( const CERT_INFO *certInfoPtr, const int keyUsage,
					const MESSAGE_CHECK_TYPE exactUsage,
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
							CRYPT_ATTRIBUTE_TYPE *errorLocus, 
							CRYPT_ERRTYPE_TYPE *errorType );

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

/* Sign/sig check a certificate */

int signCert( CERT_INFO *certInfoPtr, const CRYPT_CONTEXT signContext );
int checkCertValidity( CERT_INFO *certInfoPtr, const CRYPT_HANDLE sigCheckKey );

/* Read/write a SET OF/SEQUENCE OF Certificate */

int sizeofCertSet( const CERT_INFO *certInfoPtr );
int writeCertSet( STREAM *stream, const CERT_INFO *certInfoPtr );
int writeCertSequence( STREAM *stream, const CERT_INFO *certInfoPtr );

/* Oddball routines: set a certificate's serial number, copy a cert chain, 
   assemble a cert chain from certs read from an object */

int setSerialNumber( CERT_INFO *certInfoPtr, const void *serialNumber, 
					 const int serialNumberLength );
int copyCertChain( CERT_INFO *certInfoPtr, const CRYPT_HANDLE certChain,
				   const BOOLEAN isCertCollection );
int assembleCertChain( CRYPT_CERTIFICATE *iCertificate,
					   const CRYPT_HANDLE iCertSource, 
					   const CRYPT_KEYID_TYPE keyIDtype,
					   const void *keyID, const int keyIDlength,
					   const int options );

#endif /* _CERT_DEFINED */
