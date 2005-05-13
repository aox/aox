/****************************************************************************
*																			*
*					  cryptlib Kernel Interface Header File 				*
*						Copyright Peter Gutmann 1992-2004					*
*																			*
****************************************************************************/

#ifndef _CRYPTKRN_DEFINED

#define _CRYPTKRN_DEFINED

/* Macros to handle code correctness checking of critical sections of the
   code such as the kernel and CSPRNG (sed quis custodiet ipsos custodes?).
   By default these are mapped directly to C assertions, but they can be
   remapped for use by an external verifier if USE_EXTERNAL_CHECKER is
   defined (typically this means turning them into no-ops for ADL) */

#if !defined( USE_EXTERNAL_CHECKER ) && !defined( NDEBUG )

/* Value of a variable at the start of block scope, used for postcondition
   predicates.  The pointer is declared as BYTE * rather than the more
   general void * in order to allow range comparisons, and a BYTE * rather
   than char * because of compilers that complain about comparisons between
   signed and unsigned pointer types.  Note that these declarations must be
   the last in any set of variable declarations since the release build
   expands them to nothing, leaving only the terminating semicolon on the
   line, which must follow all other declarations */

#define ORIGINAL_VALUE( x )			orig_##x
#define ORIGINAL_INT( x )			const int orig_##x = ( int ) x
#define ORIGINAL_PTR( x )			const BYTE *orig_##x = ( const BYTE * ) x

/* Sometimes we can't use the preprocessor tricks above because the value
   being saved isn't a primitive type or the variable value isn't available
   at the start of the block, in which case we have to use the somewhat less
   transaparent macros below */

#define ORIGINAL_INT_VAR( x, y )	const int orig_##x = ( y )
#define DECLARE_ORIGINAL_INT( x )	int orig_##x
#define STORE_ORIGINAL_INT( x, y )	orig_##x = ( y )

/* Sometimes we need to declare temporary intermediate variables to avoid
   having to cram a dozen lines of expression into a single assertion, the
   following define allows this */

#define TEMP_INT( x )		int x
#define TEMP_VAR( x )		x

/* Preconditions, invariants, postconditions */

#define PRE( x )			assert( x )
#define INV( x )			assert( x )
#define POST( x )			assert( x )

/* Universal qualifiers: for_all, there_exists */

#define FORALL( iter, start, end, condition ) \
		{ \
		int iter; \
		\
		for( iter = ( start ); iter < ( end ); iter++ ) \
			assert( condition ); \
		}

#define EXISTS( iter, start, end, condition ) \
		{ \
		int iter; \
		\
		for( iter = ( start ); iter < ( end ); iter++ ) \
			if( condition ) \
				break; \
		assert( iter < ( end ) ); \
		}
#else

/* Non-debug version, no-op out the various checks */

#define ORIGINAL_VALUE( a )
#define ORIGINAL_INT( a )
#define ORIGINAL_PTR( a )
#define ORIGINAL_INT_VAR( a, b )
#define DECLARE_ORIGINAL_INT( x )
#define STORE_ORIGINAL_INT( x, y )
#define TEMP_INT( a )
#define TEMP_VAR( a )
#define PRE( x )
#define INV( x )
#define POST( x )
#define FORALL( a, b, c, d )
#define EXISTS( a, b, c, d )

#endif /* USE_EXTERNAL_CHECKER || NDEBUG */

/****************************************************************************
*																			*
*							Object Message Types							*
*																			*
****************************************************************************/

/* The object types.  Sometimes several object types can be packed into
   a single object-type variable (for example an indication than both a
   context and a cert are valid at this location), to ensure that the data
   type is wide enough to contain it we use a range-extension to force it
   to 32 bits */

typedef enum {
	OBJECT_TYPE_NONE,				/* No object type */
	OBJECT_TYPE_CONTEXT,			/* Context */
	OBJECT_TYPE_KEYSET,				/* Keyset */
	OBJECT_TYPE_ENVELOPE,			/* Envelope */
	OBJECT_TYPE_CERTIFICATE,		/* Certificate */
	OBJECT_TYPE_DEVICE,				/* Crypto device */
	OBJECT_TYPE_SESSION,			/* Secure session */
	OBJECT_TYPE_USER,				/* User object */
	OBJECT_TYPE_LAST,				/* Last object type */
	OBJECT_RANGEEXTEND = 0x0FFFFFFL	/* Range extension */
	} OBJECT_TYPE;

/* Object subtypes.  The subtype names aren't needed by the kernel (it just
   treats the values as an anonymous bitfield during an ACL check) but they
   are used in the ACL definitions and by the code that calls
   krnlCreateObject(), so they need to be defined here.

   Because there are so many object subtypes we have to split them across
   two 32-bit bitfields in order to permit a simple bitwise AND check, if we
   ordered them by the more obvious major and minor type (that is, object
   type and subtype) this wouldn't be necessary but it would increase the
   size of the compiled ACL table (from 2 * 32 bits to NO_OBJECT_TYPES *
   32 bits) and would make automated consistency checking difficult since
   it's no longer possible to spot a case where a subtype bit for object A
   has inadvertently been set for object B.

   To resolve this, we divide the subtype bit field into two smaller bit
   fields (classes) with the high two bits designating which class the
   subtype is in (actually we use the bits one below the high bit since
   this may be interpreted as a sign bit by some preprocessors even if it's
   declared as a xxxxUL, so in the following discussion we're talking about
   logical rather than physical high bits).  Class A is always 01xxx...,
   class B is always 10xxx...  If we get an entry that has 11xxx... we know
   that the ACL entry is inconsistent.  This isn't pretty, but it's the
   least ugly way to do it that still allows the ACL table to be built
   using the preprocessor.

   Note that the device and keyset values must be in the same class, since
   they're interchangeable for many message types and this simplifies some
   of the MKACL() macros that only need to initialise one class type */

#define SUBTYPE_CLASS_MASK			0x60000000L
#define SUBTYPE_CLASS_A				0x20000000L
#define SUBTYPE_CLASS_B				0x40000000L

#define SUBTYPE_CTX_CONV			0x20000001L
#define SUBTYPE_CTX_PKC				0x20000002L
#define SUBTYPE_CTX_HASH			0x20000004L
#define SUBTYPE_CTX_MAC				0x20000008L

#define SUBTYPE_CERT_CERT			0x20000010L
#define SUBTYPE_CERT_CERTREQ		0x20000020L
#define SUBTYPE_CERT_REQ_CERT		0x20000040L
#define SUBTYPE_CERT_REQ_REV		0x20000080L
#define SUBTYPE_CERT_CERTCHAIN		0x20000100L
#define SUBTYPE_CERT_ATTRCERT		0x20000200L
#define SUBTYPE_CERT_CRL			0x20000400L
#define SUBTYPE_CERT_CMSATTR		0x20000800L
#define SUBTYPE_CERT_RTCS_REQ		0x20001000L
#define SUBTYPE_CERT_RTCS_RESP		0x20002000L
#define SUBTYPE_CERT_OCSP_REQ		0x20004000L
#define SUBTYPE_CERT_OCSP_RESP		0x20008000L
#define SUBTYPE_CERT_PKIUSER		0x20010000L

#define SUBTYPE_KEYSET_FILE			0x20020000L
#define SUBTYPE_KEYSET_FILE_PARTIAL	0x20040000L
#define SUBTYPE_KEYSET_DBMS			0x20080000L
#define SUBTYPE_KEYSET_DBMS_STORE	0x20100000L
#define SUBTYPE_KEYSET_HTTP			0x20200000L
#define SUBTYPE_KEYSET_LDAP			0x20400000L

#define SUBTYPE_DEV_SYSTEM			0x20800000L
#define SUBTYPE_DEV_FORTEZZA		0x21000000L
#define SUBTYPE_DEV_PKCS11			0x22000000L
#define SUBTYPE_DEV_CRYPTOAPI		0x24000000L

#define SUBTYPE_ENV_ENV				0x40000001L
#define SUBTYPE_ENV_ENV_PGP			0x40000002L
#define SUBTYPE_ENV_DEENV			0x40000004L

#define SUBTYPE_SESSION_SSH			0x40000008L
#define SUBTYPE_SESSION_SSH_SVR		0x40000010L
#define SUBTYPE_SESSION_SSL			0x40000020L
#define SUBTYPE_SESSION_SSL_SVR		0x40000040L
#define SUBTYPE_SESSION_RTCS		0x40000080L
#define SUBTYPE_SESSION_RTCS_SVR	0x40000100L
#define SUBTYPE_SESSION_OCSP		0x40000200L
#define SUBTYPE_SESSION_OCSP_SVR	0x40000400L
#define SUBTYPE_SESSION_TSP			0x40000800L
#define SUBTYPE_SESSION_TSP_SVR		0x40001000L
#define SUBTYPE_SESSION_CMP			0x40002000L
#define SUBTYPE_SESSION_CMP_SVR		0x40004000L
#define SUBTYPE_SESSION_SCEP		0x40008000L
#define SUBTYPE_SESSION_SCEP_SVR	0x40010000L
#define SUBTYPE_SESSION_CERT_SVR	0x40020000L

#define SUBTYPE_USER_SO				0x40040000L
#define SUBTYPE_USER_NORMAL			0x40080000L
#define SUBTYPE_USER_CA				0x40100000L

/* Message flags.  Normally messages can only be sent to external objects,
   however we can also explicitly send them to internal objects which means
   that we use the internal rather than external access ACL.  This can only
   be done from inside cryptlib, for example when an object sends a message
   to a subordinate object */

#define MESSAGE_FLAG_INTERNAL		0x100
#define MKINTERNAL( message )		( message | MESSAGE_FLAG_INTERNAL )

/* A mask to extract the basic message type */

#define MESSAGE_MASK				0xFF

/* The message types that can be sent to an object via krnlSendMessage().
   By default messages can only be sent to externally visible objects, there
   are also internal versions that can be sent to all objects.  The object
   messages have the following arguments:

	Type								DataPtr			Value
	---------------------------			-------			-----
	MESSAGE_DESTROY						NULL			0
	MESSAGE_INC/DECREFCOUNT				NULL			0
	MESSAGE_GETDEPENDENT				&objectHandle	objectType
	MESSAGE_SETDEPENDENT				&objectHandle	incRefCount
	MESSAGE_CLONE						NULL			cloneContext
	MESSAGE_GET/SETATTRIBUTE			&value			attributeType
	MESSAGE_DELETEATTRIBUTE				NULL			attributeType
	MESSAGE_COMPARE						&value			compareType
	MESSAGE_CHECK						NULL			requestedUse

	MESSAGE_CHANGENOTIFY				&value			attributeType

	MESSAGE_CTX_ENC/DEC/SIG/SIGCHK/HASH	&value			valueLength
	MESSAGE_CTX_GENKEY					NULL			isAsync
	MESSAGE_CTX_GENIV					NULL			0

	MESSAGE_CRT_SIGN,					NULL			sigKey
	MESSAGE_CRT_SIGCHECK,				NULL			verifyObject
	MESSAGE_CRT_EXPORT,					&value			formatType

	MESSAGE_DEV_QUERYCAPABILITY			&queryInfo		algorithm
	MESSAGE_DEV_EXP/IMP/SIG/SIGCHK/DER	&mechanismInfo	mechanismType
	MESSAGE_DEV_CREATEOBJECT			&createInfo		objectType
	MESSAGE_DEV_CREATEOBJECT_INDIRECT	&createInfo		objectType

	MESSAGE_ENV_PUSH/POPDATA			&value			0

	MESSAGE_KEY_GET/SET/DELETEKEY		&keymgmtInfo	itemType
	MESSAGE_KEY_GETFIRST/NEXTCERT		&keymgmtInfo	itemType
	MESSAGE_KEY_CERTMGMT				&certMgmtInfo	action */

typedef enum {
	MESSAGE_NONE,				/* No message */

	/* Control messages to externally visible objects (the internal versions
	   are defined further down).  These messages are handled directly by
	   the kernel and don't affect the object itself except for
	   MESSAGE_DESTROY which is generated by the kernel in response to the
	   final MESSAGE_DECREFCOUNT sent to an object.  These are forwarded out
	   to the object to get it to clean up its state before the kernel
	   destroys it */
	MESSAGE_DESTROY,			/* Destroy the object */
	MESSAGE_INCREFCOUNT,		/* Increment object ref.count */
	MESSAGE_DECREFCOUNT,		/* Decrement object ref.count */
	MESSAGE_GETDEPENDENT,		/* Get dependent object */
	MESSAGE_SETDEPENDENT,		/* Set dependent object (e.g.ctx->dev) */
	MESSAGE_CLONE,				/* Clone the object */

	/* Attribute messages.  The reason for the numeric vs.non-numeric
	   attribute messages is that for improved error checking the data types
	   that these work with are explicitly specified by the user based on
	   which function they call to get/set them rather than being implicitly
	   specified by the attribute ID.  Because of the explicit typing, the
	   handlers have to be able to check to make sure that the actual type
	   matches what the user specified, so we need one message type for
	   numeric attributes and one for string attributes */
	MESSAGE_GETATTRIBUTE,		/* Get numeric object attribute */
	MESSAGE_GETATTRIBUTE_S,		/* Get string object attribute */
	MESSAGE_SETATTRIBUTE,		/* Set numeric object attribute */
	MESSAGE_SETATTRIBUTE_S,		/* Set string object attribute */
	MESSAGE_DELETEATTRIBUTE,	/* Delete object attribute */

	/* General messages.  The check message is used for informational
	   purposes only so that problems (e.g. an attempt to use a public key
	   where a private key is required) can be reported to the user
	   immediately as a function parameter error rather than appearing much
	   later as an object use permission error when the kernel blocks the
	   access.  Final access checking is always still done at the kernel
	   level to avoid the confused deputy problem */
	MESSAGE_COMPARE,			/* Compare objs. or obj.properties */
	MESSAGE_CHECK,				/* Check object info */

	/* Messages sent from the kernel to object message handlers.  These never
	   originate from outside the kernel but are generated in response to
	   other messages to notify an object of a change in its state */
	MESSAGE_CHANGENOTIFY,		/* Notification of obj.status chge.*/

	/* Object-type-specific messages */
	MESSAGE_CTX_ENCRYPT,		/* Context: Action = encrypt */
	MESSAGE_CTX_DECRYPT,		/* Context: Action = decrypt */
	MESSAGE_CTX_SIGN,			/* Context: Action = sign */
	MESSAGE_CTX_SIGCHECK,		/* Context: Action = sigcheck */
	MESSAGE_CTX_HASH,			/* Context: Action = hash */
	MESSAGE_CTX_GENKEY,			/* Context: Generate a key */
	MESSAGE_CTX_GENIV,			/* Context: Generate an IV */
	MESSAGE_CRT_SIGN,			/* Cert: Action = sign cert */
	MESSAGE_CRT_SIGCHECK,		/* Cert: Action = check/verify cert */
	MESSAGE_CRT_EXPORT,			/* Cert: Export encoded cert data */
	MESSAGE_DEV_QUERYCAPABILITY,/* Device: Query capability */
	MESSAGE_DEV_EXPORT,			/* Device: Action = export key */
	MESSAGE_DEV_IMPORT,			/* Device: Action = import key */
	MESSAGE_DEV_SIGN,			/* Device: Action = sign */
	MESSAGE_DEV_SIGCHECK,		/* Device: Action = sig.check */
	MESSAGE_DEV_DERIVE,			/* Device: Action = derive key */
	MESSAGE_DEV_CREATEOBJECT,	/* Device: Create object */
	MESSAGE_DEV_CREATEOBJECT_INDIRECT,	/* Device: Create obj.from data */
	MESSAGE_ENV_PUSHDATA,		/* Envelope: Push data */
	MESSAGE_ENV_POPDATA,		/* Envelope: Pop data */
	MESSAGE_KEY_GETKEY,			/* Keyset: Instantiate ctx/cert */
	MESSAGE_KEY_SETKEY,			/* Keyset: Add ctx/cert */
	MESSAGE_KEY_DELETEKEY,		/* Keyset: Delete key/cert */
	MESSAGE_KEY_GETFIRSTCERT,	/* Keyset: Get first cert in sequence */
	MESSAGE_KEY_GETNEXTCERT,	/* Keyset: Get next cert in sequence */
	MESSAGE_KEY_CERTMGMT,		/* Keyset: Cert management */
	MESSAGE_LAST,				/* Last valid message type */

	/* Internal-object versions of the above messages */
	IMESSAGE_DESTROY = MKINTERNAL( MESSAGE_DESTROY ),
	IMESSAGE_INCREFCOUNT = MKINTERNAL( MESSAGE_INCREFCOUNT ),
	IMESSAGE_DECREFCOUNT = MKINTERNAL( MESSAGE_DECREFCOUNT ),
	IMESSAGE_GETDEPENDENT = MKINTERNAL( MESSAGE_GETDEPENDENT ),
	IMESSAGE_SETDEPENDENT = MKINTERNAL( MESSAGE_SETDEPENDENT ),
	IMESSAGE_CLONE = MKINTERNAL( MESSAGE_CLONE ),

	IMESSAGE_GETATTRIBUTE = MKINTERNAL( MESSAGE_GETATTRIBUTE ),
	IMESSAGE_GETATTRIBUTE_S = MKINTERNAL( MESSAGE_GETATTRIBUTE_S ),
	IMESSAGE_SETATTRIBUTE = MKINTERNAL( MESSAGE_SETATTRIBUTE ),
	IMESSAGE_SETATTRIBUTE_S = MKINTERNAL( MESSAGE_SETATTRIBUTE_S ),
	IMESSAGE_DELETEATTRIBUTE = MKINTERNAL( MESSAGE_DELETEATTRIBUTE ),

	IMESSAGE_COMPARE = MKINTERNAL( MESSAGE_COMPARE ),
	IMESSAGE_CHECK = MKINTERNAL( MESSAGE_CHECK ),

	IMESSAGE_CHANGENOTIFY = MKINTERNAL( MESSAGE_CHANGENOTIFY ),

	IMESSAGE_CTX_ENCRYPT = MKINTERNAL( MESSAGE_CTX_ENCRYPT ),
	IMESSAGE_CTX_DECRYPT = MKINTERNAL( MESSAGE_CTX_DECRYPT ),
	IMESSAGE_CTX_SIGN = MKINTERNAL( MESSAGE_CTX_SIGN ),
	IMESSAGE_CTX_SIGCHECK = MKINTERNAL( MESSAGE_CTX_SIGCHECK ),
	IMESSAGE_CTX_HASH = MKINTERNAL( MESSAGE_CTX_HASH ),
	IMESSAGE_CTX_GENKEY = MKINTERNAL( MESSAGE_CTX_GENKEY ),
	IMESSAGE_CTX_GENIV = MKINTERNAL( MESSAGE_CTX_GENIV ),
	IMESSAGE_CRT_SIGN = MKINTERNAL( MESSAGE_CRT_SIGN ),
	IMESSAGE_CRT_SIGCHECK = MKINTERNAL( MESSAGE_CRT_SIGCHECK ),
	IMESSAGE_CRT_EXPORT = MKINTERNAL( MESSAGE_CRT_EXPORT ),
	IMESSAGE_DEV_QUERYCAPABILITY = MKINTERNAL( MESSAGE_DEV_QUERYCAPABILITY ),
	IMESSAGE_DEV_EXPORT = MKINTERNAL( MESSAGE_DEV_EXPORT ),
	IMESSAGE_DEV_IMPORT = MKINTERNAL( MESSAGE_DEV_IMPORT ),
	IMESSAGE_DEV_SIGN = MKINTERNAL( MESSAGE_DEV_SIGN ),
	IMESSAGE_DEV_SIGCHECK = MKINTERNAL( MESSAGE_DEV_SIGCHECK ),
	IMESSAGE_DEV_DERIVE = MKINTERNAL( MESSAGE_DEV_DERIVE ),
	IMESSAGE_DEV_CREATEOBJECT = MKINTERNAL( MESSAGE_DEV_CREATEOBJECT ),
	IMESSAGE_DEV_CREATEOBJECT_INDIRECT = MKINTERNAL( MESSAGE_DEV_CREATEOBJECT_INDIRECT ),
	IMESSAGE_ENV_PUSHDATA = MKINTERNAL( MESSAGE_ENV_PUSHDATA ),
	IMESSAGE_ENV_POPDATA = MKINTERNAL( MESSAGE_ENV_POPDATA ),
	IMESSAGE_KEY_GETKEY = MKINTERNAL( MESSAGE_KEY_GETKEY ),
	IMESSAGE_KEY_SETKEY = MKINTERNAL( MESSAGE_KEY_SETKEY ),
	IMESSAGE_KEY_DELETEKEY = MKINTERNAL( MESSAGE_KEY_DELETEKEY ),
	IMESSAGE_KEY_GETFIRSTCERT = MKINTERNAL( MESSAGE_KEY_GETFIRSTCERT ),
	IMESSAGE_KEY_GETNEXTCERT = MKINTERNAL( MESSAGE_KEY_GETNEXTCERT ),
	IMESSAGE_KEY_CERTMGMT = MKINTERNAL( MESSAGE_KEY_CERTMGMT ),
	IMESSAGE_LAST = MKINTERNAL( MESSAGE_LAST )
	} MESSAGE_TYPE;

/* The properties that MESSAGE_COMPARE can compare */

typedef enum {
	MESSAGE_COMPARE_NONE,			/* No comparison */
	MESSAGE_COMPARE_HASH,			/* Compare hash value */
	MESSAGE_COMPARE_KEYID,			/* Compare key IDs */
	MESSAGE_COMPARE_KEYID_PGP,		/* Compare PGP key IDs */
	MESSAGE_COMPARE_KEYID_OPENPGP,	/* Compare OpenPGP key IDs */
	MESSAGE_COMPARE_SUBJECT,		/* Compare subject */
	MESSAGE_COMPARE_ISSUERANDSERIALNUMBER,	/* Compare iAndS */
	MESSAGE_COMPARE_FINGERPRINT,	/* Compare cert.fingerprint */
	MESSAGE_COMPARE_CERTOBJ,		/* Compare cert objects */
	MESSAGE_COMPARE_LAST			/* Last possible compare type */
	} MESSAGE_COMPARE_TYPE;

/* The checks that MESSAGE_CHECK performs.  There are a number of variations
   of the checking we can perform, either the object is initialised in a
   state to perform the required action (meaning that it has to be in the
   high state), the object is ready to be initialised for the required
   action, for example an encryption context about to have a key loaded for
   encryption (meaning that it has to be in the low state), or the check is
   on a passive container object that constrains another object (for example
   a cert being attached to a context) for which the state isn't important
   in this instance.  Usually we check to make sure that the cert is in the
   high state, but when a cert is being created/imported it may not be in
   the high state yet at the time the check is being carried out */

typedef enum {
	/* Standard checks, for which the object must be initialised in a state
	   to perform this operation */
	MESSAGE_CHECK_NONE,				/* No check */
	MESSAGE_CHECK_PKC,				/* Public or private key context */
	MESSAGE_CHECK_PKC_PRIVATE,		/* Private key context */
	MESSAGE_CHECK_PKC_ENCRYPT,		/* Public encryption context */
	MESSAGE_CHECK_PKC_DECRYPT,		/* Private decryption context */
	MESSAGE_CHECK_PKC_SIGCHECK,		/* Public signature check context */
	MESSAGE_CHECK_PKC_SIGN,			/* Private signature context */
	MESSAGE_CHECK_PKC_KA_EXPORT,	/* Key agreement - export context */
	MESSAGE_CHECK_PKC_KA_IMPORT,	/* Key agreement - import context */
	MESSAGE_CHECK_CRYPT,			/* Conventional encryption context */
	MESSAGE_CHECK_HASH,				/* Hash context */
	MESSAGE_CHECK_MAC,				/* MAC context */

	/* Checks that an object is ready to be initialised to perform this
	   operation */
	MESSAGE_CHECK_CRYPT_READY,		/* Ready for conv.encr. init */
	MESSAGE_CHECK_MAC_READY,		/* Ready for MAC init */
	MESSAGE_CHECK_KEYGEN_READY,		/* Ready for key generation */

	/* Checks on purely passive container objects that constrain action
	   objects */
	MESSAGE_CHECK_PKC_ENCRYPT_AVAIL,/* Encryption available */
	MESSAGE_CHECK_PKC_DECRYPT_AVAIL,/* Decryption available */
	MESSAGE_CHECK_PKC_SIGCHECK_AVAIL,	/* Signature check available */
	MESSAGE_CHECK_PKC_SIGN_AVAIL,	/* Signature available */
	MESSAGE_CHECK_PKC_KA_EXPORT_AVAIL,	/* Key agreement - export available */
	MESSAGE_CHECK_PKC_KA_IMPORT_AVAIL,	/* Key agreement - import available */

	/* Misc.checks for meta-capabilities not directly connected with object
	   actions */
	MESSAGE_CHECK_CA,				/* Cert signing capability */
	MESSAGE_CHECK_LAST				/* Last possible check type */
	} MESSAGE_CHECK_TYPE;

/* The notifications that a MESSAGE_CHANGENOTIFY can deliver */

typedef enum {
	MESSAGE_CHANGENOTIFY_NONE,		/* No notification */
	MESSAGE_CHANGENOTIFY_STATUS,	/* Object status change */
	MESSAGE_CHANGENOTIFY_STATE,		/* Object should save/rest.int.state */
	MESSAGE_CHANGENOTIFY_OBJHANDLE,	/* Object cloned, handle changed */
	MESSAGE_CHANGENOTIFY_OWNERHANDLE,	/* Object cloned, owner handle changed */
	MESSAGE_CHANGENOTIFY_LAST		/* Last possible notification type */
	} MESSAGE_CHANGENOTIFY_TYPE;

/* Symbolic defines for the MESSAGE_SETDEPENDENT message */

#define SETDEP_OPTION_INCREF	TRUE	/* Increment dep.objs reference count */
#define SETDEP_OPTION_NOINCREF	FALSE	/* Don't inc.dep.objs reference count */

/* When getting/setting string data that consists of (value, length) pairs,
   we pass a pointer to a value-and-length structure rather than a pointer to
   the data itself */

typedef struct {
	void *data;							/* Data */
	int length;							/* Length */
	} RESOURCE_DATA;

#define setMessageData( msgDataPtr, dataPtr, dataLength ) \
	{ \
	( msgDataPtr )->data = ( dataPtr ); \
	( msgDataPtr )->length = ( dataLength ); \
	}

/* Some messages communicate standard data values that are used again and
   again, so we predefine values for these that can be used globally */

#define MESSAGE_VALUE_TRUE			( ( void * ) &messageValueTrue )
#define MESSAGE_VALUE_FALSE			( ( void * ) &messageValueFalse )
#define MESSAGE_VALUE_OK			( ( void * ) &messageValueCryptOK )
#define MESSAGE_VALUE_ERROR			( ( void * ) &messageValueCryptError )
#define MESSAGE_VALUE_UNUSED		( ( void * ) &messageValueCryptUnused )
#define MESSAGE_VALUE_DEFAULT		( ( void * ) &messageValueCryptUseDefault )
#define MESSAGE_VALUE_CURSORFIRST	( ( void * ) &messageValueCursorFirst )
#define MESSAGE_VALUE_CURSORNEXT	( ( void * ) &messageValueCursorNext )
#define MESSAGE_VALUE_CURSORPREVIOUS ( ( void * ) &messageValueCursorPrevious )
#define MESSAGE_VALUE_CURSORLAST	( ( void * ) &messageValueCursorLast )

extern const int messageValueTrue, messageValueFalse;
extern const int messageValueCryptOK, messageValueCryptError;
extern const int messageValueCryptUnused, messageValueCryptUseDefault;
extern const int messageValueCursorFirst, messageValueCursorNext;
extern const int messageValueCursorPrevious, messageValueCursorLast;

/* Check for membership within an attribute class */

#define isAttribute( attribute ) \
	( ( attribute ) > CRYPT_ATTRIBUTE_NONE && \
	  ( attribute ) < CRYPT_ATTRIBUTE_LAST )
#define isInternalAttribute( attribute ) \
	( ( attribute ) > CRYPT_IATTRIBUTE_FIRST && \
	  ( attribute ) < CRYPT_IATTRIBUTE_LAST )

/* Check whether a message is in a given message class, used in object
   message handlers */

#define isAttributeMessage( message ) \
	( ( message ) >= MESSAGE_GETATTRIBUTE && \
	  ( message ) <= MESSAGE_DELETEATTRIBUTE )
#define isActionMessage( message ) \
	( ( message ) >= MESSAGE_CTX_ENCRYPT && \
	  ( message ) <= MESSAGE_CTX_HASH )
#define isMechanismActionMessage( message ) \
	( ( message ) >= MESSAGE_DEV_EXPORT && \
	  ( message ) <= MESSAGE_DEV_DERIVE )

/* The following handles correspond to built-in fixed object types that are
   available throughout the architecture.  Currently there are two objects,
   an internal system object that encapsulates the built-in RNG and the
   built-in mechanism types (if this ever becomes a bottleneck the two can be
   separated into different objects) and a default user object which is used
   when there are no explicit user objects being employed */

#define SYSTEM_OBJECT_HANDLE	0	/* Internal system object */
#define DEFAULTUSER_OBJECT_HANDLE 1	/* Default user object */

#define NO_SYSTEM_OBJECTS		2	/* Total number of system objects */

/* We limit the maximum number of objects to a sensible value to prevent
   deliberate/accidental DoS attacks.  The following represents about 32MB
   of object data, which should be a good indication that there are more
   objects present than there should be */

#define MAX_OBJECTS				16384

/****************************************************************************
*																			*
*							Action Message Types							*
*																			*
****************************************************************************/

/* Action messages come in two types, direct action messages and mechanism-
   action messages.  Action messages apply directly to action objects (for
   example transform a block of data) while mechanism-action messages apply
   to device objects and involve extra formatting above and beyond the direct
   action (for example perform PKCS #1 padding and then transform a block of
   data).

   Each object that processes direct action messages can can have a range of
   permission settings that control how action messages sent to it are
   handled.  The most common case is that the action isn't available for
   this object, ACTION_PERM_NOTAVAIL.  This is an all-zero permission, so
   the default is deny-all unless the action is explicitly permitted.  The
   other permissions are ACTION_PERM_NONE, which means that the action is in
   theory available but has been turned off, ACTION_PERM_NONE_EXTERNAL,
   which means that the action is only valid if the message is coming from
   inside cryptlib, and ACTION_PERM_ALL, which means that the action is
   available for anyone.  In order to set all permissions to a certain value
   (e.g. NONE_EXTERNAL), we define overall values xxx_ALL that (in
   combination with the kernel-enforced ratchet) can be used to set all
   settings to (at most) the given value.

   The order of the action bits is:

	  hash   sign  encr
		|	  |		|
	xx xx xx xx xx xx
	 |	   |	 |
	kgen sigch  decr

    x. .x|x. .x|x. .x	Hex digits

   Common settings are 0xCFF (new PKC, all operations), 0x0F (key-loaded
   conv., all operations), and 0xAA (key-loaded PKC, internal-only
   operations).

   The kernel enforces a ratchet for these setting that only allows them to
   be set to a more restrictive value than their existing one.  If a setting
   starts out as not available on object creation, it can never be enabled.
   If a setting starts as 'none-external', it can only be set to a straight
   'none', but never to 'all' */

#define ACTION_PERM_NOTAVAIL		0x00
#define ACTION_PERM_NONE			0x01
#define ACTION_PERM_NONE_EXTERNAL	0x02
#define ACTION_PERM_ALL				0x03

#define ACTION_PERM_NONE_ALL			0x000
#define ACTION_PERM_NONE_EXTERNAL_ALL	0xAAA

#define ACTION_PERM_BASE	MESSAGE_CTX_ENCRYPT
#define ACTION_PERM_MASK	0x03
#define ACTION_PERM_BITS	2
#define ACTION_PERM_COUNT	( MESSAGE_CTX_GENKEY - \
							  MESSAGE_CTX_ENCRYPT + 1 )
#define ACTION_PERM_LAST	\
		( 1 << ( ( ( ACTION_PERM_COUNT ) * ACTION_PERM_BITS ) + 1 ) )
#define ACTION_PERM_SHIFT( action ) \
		( ( ( action ) - ACTION_PERM_BASE ) * ACTION_PERM_BITS )
#define MK_ACTION_PERM( action, perm ) \
		( ( perm ) << ACTION_PERM_SHIFT( action ) )
#define MK_ACTION_PERM_NONE_EXTERNAL( action ) \
		( ( action ) & ACTION_PERM_NONE_EXTERNAL_ALL )

/* The mechanism types.  The distinction between the PKCS #1 and raw PKCS #1
   mechanisms is somewhat artificial in that they do the same thing, however
   it's easier for the kernel to perform security checks on parameters if
   the two are distinct */

typedef enum {
	MECHANISM_NONE,				/* No mechanism */
	MECHANISM_ENC_PKCS1,		/* PKCS #1 encrypt */
	MECHANISM_ENC_PKCS1_PGP,	/* PKCS #1 using PGP formatting */
	MECHANISM_ENC_PKCS1_RAW,	/* PKCS #1 returning uninterpreted data */
	MECHANISM_ENC_CMS,			/* CMS key wrap */
	MECHANISM_ENC_KEA,			/* KEA key agreement */
	MECHANISM_SIG_PKCS1,		/* PKCS #1 sign */
	MECHANISM_SIG_SSL,			/* SSL sign with dual hashes */
	MECHANISM_DERIVE_PKCS5,		/* PKCS #5 derive */
	MECHANISM_DERIVE_PKCS12,	/* PKCS #12 derive */
	MECHANISM_DERIVE_SSL,		/* SSL derive */
	MECHANISM_DERIVE_TLS,		/* TLS derive */
	MECHANISM_DERIVE_CMP,		/* CMP/Entrust derive */
	MECHANISM_DERIVE_PGP,		/* OpenPGP S2K derive */
	MECHANISM_PRIVATEKEYWRAP,	/* Private key wrap */
	MECHANISM_PRIVATEKEYWRAP_PKCS8,	/* PKCS #8 private key wrap */
	MECHANISM_PRIVATEKEYWRAP_PGP,	/* PGP private key wrap */
	MECHANISM_PRIVATEKEYWRAP_OPENPGP,/* OpenPGP private key wrap */
	MECHANISM_LAST				/* Last valid mechanism type */
	} MECHANISM_TYPE;

/* A structure to hold information needed by the key export/import mechanism.
   The key can be passed as raw key data or as a context if tied to hardware
   that doesn't allow keying material outside the hardware's security
   perimeter:

	PKCS #1,	wrappedData = wrapped key
	PKCS #1 PGP	keyData = -
				keyContext = context containing key
				wrapContext = wrap/unwrap PKC context
				auxContext = CRYPT_UNUSED
	PKCS #1	raw	wrappedData = wrapped raw data
				keyData = raw data
				keyContext = CRYPT_UNUSED
				wrapContext = wrap/unwrap PKC context
				auxContext = CRYPT_UNUSED
	CMS			wrappedData = wrapped key
				keyData = -
				keyContext = context containing key
				wrapContext = wrap/unwrap conventional context
				auxContext = CRYPT_UNUSED
	KEA			wrappedData = len + TEK( MEK ), len + UKM
				keyData = -
				keyContext = MEK
				wrapContext = recipient KEA public key
				auxContext = originator KEA private key
	Private		wrappedData = padded encrypted private key components
	key wrap	keyData = -
				keyContext = context containing private key
				wrapContext = wrap/unwrap conventional context
				auxContext = CRYPT_UNUSED */

typedef struct {
	void *wrappedData;			/* Wrapped key */
	int wrappedDataLength;
	void *keyData;				/* Raw key */
	int keyDataLength;
	CRYPT_HANDLE keyContext;	/* Context containing raw key */
	CRYPT_HANDLE wrapContext;	/* Wrap/unwrap context */
	CRYPT_HANDLE auxContext;	/* Auxiliary context */
	} MECHANISM_WRAP_INFO;

/* A structure to hold information needed by the sign/sig check mechanism:

	PKCS #1		signature = signature
				hashContext = hash to sign
				signContext = signing key

	SSL			signature = signature
				hashContext, hashContext2 = dual hashes to sign
				signContext = signing key */

typedef struct {
	void *signature;			/* Signature */
	int signatureLength;
	CRYPT_CONTEXT hashContext;	/* Hash context */
	CRYPT_CONTEXT hashContext2;	/* Secondary hash context */
	CRYPT_HANDLE signContext;	/* Signing context */
	} MECHANISM_SIGN_INFO;

/* A structure to hold information needed by the key derive mechanism:

	PKCS #5,	dataOut = key data
	CMP, PGP	dataIn = password
				hashAlgo = hash algorithm
				salt = salt
				iterations = iteration count
	SSL/TLS		dataOut = key data/master secret
				dataIn = master secret/premaster secret
				hashAlgo = CRYPT_USE_DEFAULT
				salt = client || server random/server || client random
				iterations = CRYPT_UNUSED */

typedef struct {
	void *dataOut;				/* Output keying information */
	int dataOutLength;
	const void *dataIn;			/* Input keying information */
	int dataInLength;
	CRYPT_ALGO_TYPE hashAlgo;	/* Hash algorithm */
	const void *salt;			/* Salt/randomiser */
	int saltLength;
	int iterations;				/* Iterations of derivation function */
	} MECHANISM_DERIVE_INFO;

/* Macros to make it easier to work with the mechanism info types.  The
   shortened name forms in the macro args are necessary to avoid clashes with
   the struct members.  The long lines are necessary because older Borland
   compilers can't handle line breaks at this point in a macro definition */

#define clearMechanismInfo( mechanismInfo ) \
		memset( mechanismInfo, 0, sizeof( *mechanismInfo ) )

#define setMechanismWrapInfo( mechanismInfo, wrapped, wrappedLen, key, keyLen, keyCtx, wrapCtx, auxCtx ) \
		{ \
		( mechanismInfo )->wrappedData = ( wrapped ); \
		( mechanismInfo )->wrappedDataLength = ( wrappedLen ); \
		( mechanismInfo )->keyData = ( key ); \
		( mechanismInfo )->keyDataLength = ( keyLen ); \
		( mechanismInfo )->keyContext = ( keyCtx ); \
		( mechanismInfo )->wrapContext = ( wrapCtx ); \
		( mechanismInfo )->auxContext = ( auxCtx ); \
		}

#define setMechanismSignInfo( mechanismInfo, sig, sigLen, hashCtx, hashCtx2, signCtx ) \
		{ \
		( mechanismInfo )->signature = ( sig ); \
		( mechanismInfo )->signatureLength = ( sigLen ); \
		( mechanismInfo )->hashContext = ( hashCtx ); \
		( mechanismInfo )->hashContext2 = ( hashCtx2 ); \
		( mechanismInfo )->signContext = ( signCtx ); \
		}

#define setMechanismDeriveInfo( mechanismInfo, out, outLen, in, inLen, hAlgo, slt, sltLen, iters ) \
		{ \
		( mechanismInfo )->dataOut = ( out ); \
		( mechanismInfo )->dataOutLength = ( outLen ); \
		( mechanismInfo )->dataIn = ( in ); \
		( mechanismInfo )->dataInLength = ( inLen ); \
		( mechanismInfo )->hashAlgo = ( hAlgo ); \
		( mechanismInfo )->salt = ( slt ); \
		( mechanismInfo )->saltLength = ( sltLen ); \
		( mechanismInfo )->iterations = ( iters ); \
		}

/****************************************************************************
*																			*
*								Misc Message Types							*
*																			*
****************************************************************************/

/* Beside the general value+length and mechanism messages, we also have a
   number of special-purposes messages that require their own parameter
   data structures.  These are:

   Create object messages, used to create objects via a device, either
   directly or indirectly by instantiating the object from encoded data (for
   example a certificate object from a certificate).  Usually the device is
   the system object, but it can also be used to create contexts in hardware
   devices.  In addition to the creation parameters we also pass in the
   owner's user object to be stored with the object data for use when
   needed */

typedef struct {
	CRYPT_HANDLE cryptHandle;	/* Handle to created object */
	CRYPT_USER cryptOwner;		/* New object's owner */
	int arg1, arg2;				/* Integer args */
	const void *strArg1, *strArg2;	/* String args */
	int strArgLen1, strArgLen2;
	} MESSAGE_CREATEOBJECT_INFO;

#define setMessageCreateObjectInfo( createObjectInfo, a1 ) \
		{ \
		memset( createObjectInfo, 0, sizeof( MESSAGE_CREATEOBJECT_INFO ) ); \
		( createObjectInfo )->cryptHandle = CRYPT_ERROR; \
		( createObjectInfo )->cryptOwner = CRYPT_ERROR; \
		( createObjectInfo )->arg1 = ( a1 ); \
		}

#define setMessageCreateObjectIndirectInfo( createObjectInfo, data, dataLen, type ) \
		{ \
		memset( createObjectInfo, 0, sizeof( MESSAGE_CREATEOBJECT_INFO ) ); \
		( createObjectInfo )->cryptHandle = CRYPT_ERROR; \
		( createObjectInfo )->cryptOwner = CRYPT_ERROR; \
		( createObjectInfo )->strArg1 = ( data ); \
		( createObjectInfo )->strArgLen1 = ( dataLen ); \
		( createObjectInfo )->arg1 = ( type ); \
		}

/* Key management messages, used to set, get and delete keys.  The item type,
   keyIDtype, keyID, and keyIDlength are mandatory, the aux.info depends on
   the type of message (optional password for private key get/set, state
   information for get next cert, null otherwise), and the flags are
   generally only required where the keyset can hold multiple types of keys
   (for example a crypto device acting as a keyset, or a PKCS #15 token).

   An itemType of KEYMGMT_ITEM_PUBLICKEY is somewhat more general than its
   name implies in that keysets/devices that store private key information
   alongside public-key data may delete both types of items if asked to
   delete a KEYMGMT_ITEM_PUBLICKEY since the two items are (implicitly)
   connected.

   In addition to the flags that are used to handle various special-case
   read accesses, we can also specify a usage preference (e.g.
   confidentiality vs.signature) for cases where we may have multiple keys
   with the same keyID that differ only in required usage */

typedef enum {
	KEYMGMT_ITEM_NONE,			/* No item type */
	KEYMGMT_ITEM_PUBLICKEY,		/* Access public key */
	KEYMGMT_ITEM_PRIVATEKEY,	/* Access private key */
	KEYMGMT_ITEM_SECRETKEY,		/* Access secret key */
	KEYMGMT_ITEM_REQUEST,		/* Access cert request */
	KEYMGMT_ITEM_PKIUSER,		/* Access PKI user info */
	KEYMGMT_ITEM_REVOCATIONINFO,/* Access revocation info/CRL */
	KEYMGMT_ITEM_DATA,			/* Other data (for PKCS #15 tokens) */
	KEYMGMT_ITEM_LAST			/* Last item type */
	} KEYMGMT_ITEM_TYPE;

#define KEYMGMT_FLAG_NONE			0x0000	/* No flag */
#define KEYMGMT_FLAG_CHECK_ONLY		0x0001	/* Perform existence check only */
#define KEYMGMT_FLAG_LABEL_ONLY		0x0002	/* Get key label only */
#define KEYMGMT_FLAG_UPDATE			0x0004	/* Update existing (allow dups) */
#define KEYMGMT_FLAG_DATAONLY_CERT	0x0008	/* Create data-only certs */
#define KEYMGMT_FLAG_USAGE_CRYPT	0x0010	/* Prefer encryption key */
#define KEYMGMT_FLAG_USAGE_SIGN		0x0020	/* Prefer signature key */
#define KEYMGMT_FLAG_GETISSUER		0x0040	/* Get issuing PKI user for cert */
#define KEYMGMT_FLAG_LAST			0x0080	/* Last valid flag */

#define KEYMGMT_MASK_USAGEOPTIONS	( KEYMGMT_FLAG_USAGE_CRYPT | \
									  KEYMGMT_FLAG_USAGE_SIGN )
#define KEYMGMT_MASK_CERTOPTIONS	( KEYMGMT_FLAG_DATAONLY_CERT | \
									  KEYMGMT_FLAG_USAGE_CRYPT | \
									  KEYMGMT_FLAG_USAGE_SIGN )
typedef struct {
	CRYPT_HANDLE cryptHandle;	/* Returned key */
	CRYPT_KEYID_TYPE keyIDtype;	/* Key ID type */
	const void *keyID;			/* Key ID */
	int keyIDlength;
	void *auxInfo;				/* Aux.info (e.g.password for private key) */
	int auxInfoLength;
	int flags;					/* Access options */
	} MESSAGE_KEYMGMT_INFO;

#define setMessageKeymgmtInfo( keymgmtInfo, idType, id, idLength, aux, auxLen, keyFlags ) \
		{ \
		( keymgmtInfo )->cryptHandle = CRYPT_ERROR; \
		( keymgmtInfo )->keyIDtype = ( idType ); \
		( keymgmtInfo )->keyID = ( id ); \
		( keymgmtInfo )->keyIDlength = ( idLength ); \
		( keymgmtInfo )->auxInfo = ( aux ); \
		( keymgmtInfo )->auxInfoLength = ( auxLen ); \
		( keymgmtInfo )->flags = ( keyFlags ); \
		}

/* Cert management messages used to handle CA operations.  All fields are
   mandatory, however the cryptCert and request fields may be set to
   CRYPT_UNUSED to indicate 'don't care' conditions */

typedef struct {
	CRYPT_CERTIFICATE cryptCert;	/* Returned cert */
	CRYPT_CONTEXT caKey;			/* CA key to sign item */
	CRYPT_CERTIFICATE request;		/* Request for operation */
	} MESSAGE_CERTMGMT_INFO;

#define setMessageCertMgmtInfo( certMgmtInfo, mgmtCaKey, mgmtRequest ) \
		{ \
		( certMgmtInfo )->cryptCert = CRYPT_ERROR; \
		( certMgmtInfo )->caKey = ( mgmtCaKey ); \
		( certMgmtInfo )->request = ( mgmtRequest ); \
		}

/****************************************************************************
*																			*
*							Object Management Functions						*
*																			*
****************************************************************************/

/* Prototype for an object's message-handling function */

typedef int ( *MESSAGE_FUNCTION )( const void *objectInfoPtr,
								   const MESSAGE_TYPE message,
								   void *messageDataPtr,
								   const int messageValue );

/* Object management functions.  A dummy object is one that exists but
   doesn't have the capabilities of the actual object, for example an
   encryption context that just maps to underlying crypto hardware.  This
   doesn't affect krnlCreateObject(), but is used by the object-type-specific
   routines that decorate the results of krnlCreateObject() with object-
   specific extras */

#define CREATEOBJECT_FLAG_NONE		0x00	/* No create-object flags */
#define CREATEOBJECT_FLAG_SECUREMALLOC \
									0x01	/* Use krnlMemAlloc() to alloc.*/
#define CREATEOBJECT_FLAG_DUMMY		0x02	/* Dummy obj.used as placeholder */

int krnlCreateObject( void **objectDataPtr, const int objectDataSize,
					  const OBJECT_TYPE type, const int subType,
					  const int createObjectFlags, const CRYPT_USER owner,
					  const int actionFlags,
					  MESSAGE_FUNCTION messageFunction );
int krnlSendMessage( const int objectHandle, const MESSAGE_TYPE message,
					 void *messageDataPtr, const int messageValue );

/* Since some messages contain no data but act only as notifiers, we define
   the following macro to make using them less messy */

#define krnlSendNotifier( handle, message ) \
		krnlSendMessage( handle, message, NULL, 0 )

/* In some rare cases we have to access an object directly without sending
   it a message.  This happens either with certs where we're already
   processing a message for one cert and need to access internal data in
   another cert, when we're working with a crypto device tied to a context
   where we need access to both context and device internals at the same
   time, or when we're updating config data in a user object.  This type of
   access is handled by the following function, which also explicitly
   disallows any access types apart from the three described here */

int krnlAcquireObject( const int objectHandle, const OBJECT_TYPE type,
					   void **objectPtr, const int errorCode );
int krnlReleaseObject( const int objectHandle );

/* In even rarer cases, we have to allow a second thread access to an object
   when another thread has it locked.  This only occurs in one case, when a
   background polling thread is adding entropy to the system device.  The way
   this works is that the calling thread hands ownership over to the polling
   thread and suspends itself until the polling thread completes.  When the
   polling thread has completed, it terminates, whereupon ownership passes
   back to the original thread.  The value passed to the release call is
   actually a thread ID, but since this isn't visible outside the kernel we
   just us a generic int */

int krnlRelinquishSystemObject( const int /* THREAD_HANDLE */ objectOwnerThread );
int krnlReacquireSystemObject( void );

/* Semaphores and mutexes */

typedef enum {
	SEMAPHORE_NONE,					/* No semaphore */
	SEMAPHORE_DRIVERBIND,			/* Async driver bind */
	SEMAPHORE_LAST					/* Last semaphore */
	} SEMAPHORE_TYPE;

typedef enum {
	MUTEX_NONE,						/* No mutex */
	MUTEX_SESSIONCACHE,				/* SSL/TLS session cache */
	MUTEX_SOCKETPOOL,				/* Network socket pool */
	MUTEX_RANDOMPOLLING,			/* Randomness polling */
	MUTEX_LAST						/* Last mutex */
	} MUTEX_TYPE;

/* Execute a function in a background thread.  This takes a pointer to the
   function to execute in the background thread, a set of parameters to pass
   to the function, and an optional semaphore ID to set once the thread is
   started.  A function is run via a background thread as follows:

	void threadFunction( const THREAD_FUNCTION_PARAMS *threadParams )
		{
		}

	initThreadParams( &threadParams, ptrParam, intParam );
	krnlDispatchThread( threadFunction, &threadParams, SEMAPHORE_ID );

   Note that the parameters must be held in static storage because the
   caller's stack frame may have long since disappeared before the thread
   gets to access them.  To emphasise this, we define the storage specifier
   STATIC_THREADPARAM_STORAGE for when we declare the variables */

struct TF;

typedef void ( *THREAD_FUNCTION )( const struct TF *threadParams );

typedef struct TF {
	THREAD_FUNCTION threadFunction;	/* Function to call from thread */
	void *ptrParam;					/* Thread function parameters */
	int intParam;
	SEMAPHORE_TYPE semaphore;		/* Optional semaphore to set */
	long syncHandle;				/* Handle to use for thread sync */
	} THREAD_FUNCTION_PARAMS;

#define STATIC_THREADPARAM_STORAGE	static

#define initThreadParams( threadParams, pParam, iParam ) \
		memset( ( threadParams ), 0, sizeof( THREAD_FUNCTION_PARAMS ) ); \
		( threadParams )->ptrParam = ( void * )( pParam ); \
		( threadParams )->intParam = ( iParam );

int krnlDispatchThread( THREAD_FUNCTION threadFunction,
						THREAD_FUNCTION_PARAMS *threadParams,
						const SEMAPHORE_TYPE semaphore );

/* Wait on a semaphore, enter and exit a mutex */

void krnlWaitSemaphore( const SEMAPHORE_TYPE semaphore );
void krnlEnterMutex( const MUTEX_TYPE mutex );
void krnlExitMutex( const MUTEX_TYPE mutex );

/* Secure memory handling functions */

int krnlMemalloc( void **pointer, int size );
void krnlMemfree( void **pointer );
int krnlMemsize( const void *pointer );

#ifdef NEED_ENUMFIX
  #undef OBJECT_TYPE_LAST
  #undef MESSAGE_COMPARE_LAST
  #undef MESSAGE_CHECK_LAST
  #undef MESSAGE_CHANGENOTIFY_LAST
  #undef MECHANISM_LAST
  #undef KEYMGMT_ITEM_LAST
  #undef SEMAPHORE_LAST
  #undef MUTEX_LAST
#endif /* NEED_ENUMFIX */
#endif /* _CRYPTKRN_DEFINED */
