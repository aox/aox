/****************************************************************************
*																			*
*						cryptlib Internal API Header File 					*
*						Copyright Peter Gutmann 1992-2006					*
*																			*
****************************************************************************/

#ifndef _INTAPI_DEFINED

#define _INTAPI_DEFINED

/* Internal forms of various external functions.  These work with internal
   resources that are marked as being inaccessible to the corresponding
   external functions, and don't perform all the checking that their
   external equivalents perform, since the parameters have already been
   checked by cryptlib */

int iCryptCreateSignatureEx( void *signature, int *signatureLength,
							 const int sigMaxLength,
							 const CRYPT_FORMAT_TYPE formatType,
							 const CRYPT_CONTEXT iSignContext,
							 const CRYPT_CONTEXT iHashContext,
							 const CRYPT_CERTIFICATE iExtraData,
							 const CRYPT_SESSION iTspSession );
int iCryptCheckSignatureEx( const void *signature, const int signatureLength,
							const CRYPT_FORMAT_TYPE formatType,
							const CRYPT_HANDLE iSigCheckKey,
							const CRYPT_CONTEXT iHashContext,
							CRYPT_HANDLE *extraData );
int iCryptImportKeyEx( const void *encryptedKey, const int encryptedKeyLength,
					   const CRYPT_FORMAT_TYPE formatType,
					   const CRYPT_CONTEXT iImportKey,
					   const CRYPT_CONTEXT iSessionKeyContext,
					   CRYPT_CONTEXT *iReturnedContext );
int iCryptExportKeyEx( void *encryptedKey, int *encryptedKeyLength,
					   const int encryptedKeyMaxLength,
					   const CRYPT_FORMAT_TYPE formatType,
					   const CRYPT_CONTEXT iSessionKeyContext,
					   const CRYPT_CONTEXT iExportKey );

/* Copy a string attribute to external storage, with various range checks
   to follow the cryptlib external API semantics.  We also have a second
   function that's used internally for data-copying */

int attributeCopy( MESSAGE_DATA *msgData, const void *attribute,
				   const int attributeLength );
int dataCopy( void *dest, const int destMaxLength, int *destLength,
			  const void *source, const int sourceLength );

/* Check whether a password is valid or not.  Currently this just checks that
   it contains at least one character, but stronger checking can be
   substituted if required */

#ifdef UNICODE_CHARS
  #define isBadPassword( password ) \
		  ( !isReadPtr( password, sizeof( wchar_t ) ) || \
		    ( wcslen( password ) < 1 ) )
#else
  #define isBadPassword( password ) \
		  ( !isReadPtr( password, 1 ) || \
		    ( strlen( password ) < 1 ) )
#endif /* Unicode vs. ASCII environments */

/* Check whether a given algorithm is available for use.  This is performed
   frequently enough that we have a special krnlSendMessage() wrapper
   function for it rather than having to explicitly query the system
   object */

BOOLEAN algoAvailable( const CRYPT_ALGO_TYPE cryptAlgo );

/* For a given algorithm pair, check whether the first is stronger than the
   second */

BOOLEAN isStrongerHash( const CRYPT_ALGO_TYPE algorithm1,
						const CRYPT_ALGO_TYPE algorithm2 );

/* Compare two strings in a case-insensitive manner for those systems that
   don't have this function */

#if defined( __UNIX__ ) && !( defined( __CYGWIN__ ) )
  #if defined( __TANDEM_NSK__ ) || defined( __TANDEM_OSS__ )
	#include <strings.h>
  #endif /* Tandem */
  #define strnicmp	strncasecmp
  #define stricmp	strcasecmp
#elif defined( __WINCE__ )
  #define strnicmp	_strnicmp
  #define stricmp	_stricmp
#elif defined( _MSC_VER ) && ( _MSC_VER >= 1300 )
  /* VC++ 8 and up warn about these being deprecated Posix functions and
     require the ANSI/ISO conformant _strXcmp */
  #define strnicmp	_strnicmp
  #define stricmp	_stricmp
#elif defined __PALMOS__
  /* PalmOS has strcasecmp()/strncasecmp() but these aren't i18n-aware so we
     have to use a system function instead */
  #include <StringMgr.h>

  #define strnicmp	StrNCaselessCompare
  #define stricmp	StrCaselessCompare
#elif defined( __xxxOS___ )
  int strnicmp( const char *src, const char *dest, const int length );
  int stricmp( const char *src, const char *dest );
#endif /* OS-specific case-insensitive string compares */

/* Sanitise a string before passing it back to the user.  This is used to
   clear potential problem characters (for example control characters)
   from strings passed back from untrusted sources */

char *sanitiseString( char *string, const int stringLength );

/* Perform various string-processing operations */

int strFindCh( const char *str, const int strLen, const char findCh );
int strFindStr( const char *str, const int strLen, 
				const char *findStr, const int findStrLen );
int strStripWhitespace( char **newStringPtr, const char *string,
						const int stringLen );

/* Read a line of text from a stream.  The caller passes in a character-read
   function callback that returns the next character from a supplied input
   stream, and readTextLine() uses it to fetch the next line of input up to
   an EOL.  The textDataError flag is set when the returned error code was
   generated by readTextLine() itself, rather than being passed up from the
   character-read function.  This allows the caller to report the errors
   differently, for example a data-formatting error vs. a network I/O error */

typedef int ( *READCHARFUNCTION )( void *streamPtr );

int readTextLine( READCHARFUNCTION readCharFunction, void *streamPtr,
				  char *buffer, const int maxSize, BOOLEAN *textDataError );

/* Get system-specific hardware capabilities */

#define SYSCAP_FLAG_NONE	0x00	/* No special HW capabilities */
#define SYSCAP_FLAG_RDTSC	0x01	/* x86 RDTSC instruction support */
#define SYSCAP_FLAG_XSTORE	0x02	/* VIA XSTORE instruction support */
#define SYSCAP_FLAG_XCRYPT	0x04	/* VIA XCRYPT instruction support */
#define SYSCAP_FLAG_XSHA	0x08	/* VIA XSHA instruction support */
#define SYSCAP_FLAG_MONTMUL	0x10	/* VIA bignum instruction support */

int getSysCaps( void );

/* Windows NT/2000/XP support ACL-based access control mechanisms for system
   objects, so when we create objects such as files and threads we give them
   an ACL that allows only the creator access.  The following functions
   return the security info needed when creating objects */

#ifdef __WINDOWS__
  #ifdef __WIN32__
	void *initACLInfo( const int access );
	void *getACLInfo( void *securityInfoPtr );
	void freeACLInfo( void *securityInfoPtr );
  #else
	#define initACLInfo( x )	NULL
	#define getACLInfo( x )		NULL
	#define freeACLInfo( x )
  #endif /* __WIN32__ */
#endif /* __WINDOWS__ */

/****************************************************************************
*																			*
*							Data Encode/Decode Functions					*
*																			*
****************************************************************************/

/* Special-case certificate functions.  The indirect-import function works
   somewhat like the import cert messages, but reads certs by sending
   get_next_cert messages to the message source and provides extended control
   over the format of the imported object.  The public-key read function
   converts an X.509 SubjectPublicKeyInfo record into a context.  The first
   parameter for this function is actually a STREAM *, but we can't use this
   here since STREAM * hasn't been defined yet.

   Neither of these are strictly speaking certificate functions, but the
   best (meaning least inappropriate) place to put them is with the cert-
   management code */

int iCryptImportCertIndirect( CRYPT_CERTIFICATE *iCertificate,
							  const CRYPT_HANDLE iCertSource,
							  const CRYPT_KEYID_TYPE keyIDtype,
							  const void *keyID, const int keyIDlength,
							  const int options );
int iCryptReadSubjectPublicKey( void *streamPtr, CRYPT_CONTEXT *iCryptContext,
								const BOOLEAN deferredLoad );

/* Get information on encoded object data.  The first parameter for this
   function is actually a STREAM *, but we can't use this here since
   STREAM * hasn't been defined yet */

int queryAsn1Object( void *streamPtr, QUERY_INFO *queryInfo );
int queryPgpObject( void *streamPtr, QUERY_INFO *queryInfo );

/* Export/import data to/from a stream without the overhead of going via a
   dynbuf.  The first parameter for these functions is actually a STREAM *,
   but we can't use this here since STREAM * hasn't been defined yet */

int exportAttributeToStream( void *streamPtr, const CRYPT_HANDLE cryptHandle,
							 const CRYPT_ATTRIBUTE_TYPE attributeType );
int exportVarsizeAttributeToStream( void *streamPtr,
									const CRYPT_HANDLE cryptHandle,
									const CRYPT_ATTRIBUTE_TYPE attributeType,
									const int attributeDataLength );
int exportCertToStream( void *streamPtr,
						const CRYPT_CERTIFICATE cryptCertificate,
						const CRYPT_CERTFORMAT_TYPE certFormatType );
int importCertFromStream( void *streamPtr,
						  CRYPT_CERTIFICATE *cryptCertificate,
						  const CRYPT_CERTTYPE_TYPE certType,
						  const int certDataLength );

/* base64/SMIME-en/decode routines */

int base64checkHeader( const char *data, const int dataLength,
					   int *startPos );
int base64encodeLen( const int dataLength,
					 const CRYPT_CERTTYPE_TYPE certType );
int base64encode( char *dest, const int destMaxLen, const void *src,
				  const int srcLen, const CRYPT_CERTTYPE_TYPE certType );
int base64decodeLen( const char *data, const int dataLength );
int base64decode( void *dest, const int destMaxLen, const char *src,
				  const int srcLen, const CRYPT_CERTFORMAT_TYPE format );

/* User data en/decode routines */

BOOLEAN isPKIUserValue( const char *encVal, const int encValueLength );
int adjustPKIUserValue( BYTE *value, const int noCodeGroups );
int encodePKIUserValue( char *encVal, const int encValMaxLen,
						const BYTE *value, const int noCodeGroups );
int decodePKIUserValue( BYTE *value, const int valueMaxLen,
						const char *encVal, const int encValLength );

/****************************************************************************
*																			*
*							List Manipulation Functions						*
*																			*
****************************************************************************/

/* Insert a new element into singly-linked and doubly-lined lists.  This is
   the sort of thing we'd really need templates for */

#define insertSingleListElement( listHead, insertPoint, newElement ) \
		{ \
		if( *( listHead ) == NULL ) \
			/* It's an empty list, make this the new list */ \
			*( listHead ) = ( newElement ); \
		else \
			if( ( insertPoint ) == NULL ) \
				{ \
				/* We're inserting at the start of the list, make this the \
				   new first element */ \
				( newElement )->next = *( listHead ); \
				*( listHead ) = ( newElement ); \
				} \
			else \
				{ \
				/* Insert the element in the middle or the end of the list */ \
				( newElement )->next = ( insertPoint )->next; \
				( insertPoint )->next = ( newElement ); \
				} \
		}

#define insertDoubleListElements( listHead, insertPoint, newStartElement, newEndElement ) \
		{ \
		if( *( listHead ) == NULL ) \
			/* If it's an empty list, make this the new list */ \
			*( listHead ) = ( newStartElement ); \
		else \
			if( ( insertPoint ) == NULL ) \
				{ \
				/* We're inserting at the start of the list, make this the \
				   new first element */ \
				( newEndElement )->next = *( listHead ); \
				( *( listHead ) )->prev = ( newEndElement ); \
				*( listHead ) = ( newStartElement ); \
				} \
			else \
				{ \
				/* Insert the element in the middle or the end of the list */ \
				( newEndElement )->next = ( insertPoint )->next; \
				\
				/* Update the links for the next and previous elements */ \
				if( ( insertPoint )->next != NULL ) \
					( insertPoint )->next->prev = ( newEndElement ); \
				( insertPoint )->next = ( newStartElement ); \
				( newStartElement )->prev = ( insertPoint ); \
				} \
		}

#define insertDoubleListElement( listHead, insertPoint, newElement ) \
		insertDoubleListElements( listHead, insertPoint, newElement, newElement )

#define deleteSingleListElement( listHead, listPrev, element ) \
		{ \
		if( element == *( listHead ) ) \
			/* Special case for first item */ \
			*( listHead ) = element->next; \
		else \
			/* Delete from middle or end of the list */ \
			listPrev->next = element->next; \
		}

#define deleteDoubleListElement( listHead, element ) \
		{ \
		if( element == *( listHead ) ) \
			{ \
			/* Special case for first item */ \
			*( listHead ) = element->next; \
			if( element->next != NULL ) \
				element->next->prev = NULL; \
			} \
		else \
			{ \
			/* Delete from the middle or the end of the list */ \
			element->prev->next = element->next; \
			if( element->next != NULL ) \
				element->next->prev = element->prev; \
			} \
		}

/****************************************************************************
*																			*
*						Attribute List Manipulation Functions				*
*																			*
****************************************************************************/

/* In order to work with attribute lists of different types, we need a
   means of accessing the type-specific previous and next pointers and the
   attribute ID information.  The following callback function is passed to
   all attribute-list manipulation functions and provides external access
   to the required internal fields */

typedef enum {
	ATTR_NONE,			/* No attribute get type */
	ATTR_CURRENT,		/* Get details for current attribute */
	ATTR_PREV,			/* Get details for previous attribute */
	ATTR_NEXT,			/* Get details for next attribute */
	ATTR_LAST			/* Last valid attribute get type */
	} ATTR_TYPE;

typedef const void * ( *GETATTRFUNCTION )( const void *attributePtr,
										   CRYPT_ATTRIBUTE_TYPE *groupID,
										   CRYPT_ATTRIBUTE_TYPE *attributeID,
										   CRYPT_ATTRIBUTE_TYPE *instanceID,
										   const ATTR_TYPE attrGetType );

void *attributeFindStart( const void *attributePtr,
						  GETATTRFUNCTION getAttrFunction );
void *attributeFindEnd( const void *attributePtr,
						GETATTRFUNCTION getAttrFunction );
void *attributeFind( const void *attributePtr,
					 GETATTRFUNCTION getAttrFunction,
					 const CRYPT_ATTRIBUTE_TYPE attributeID,
					 const CRYPT_ATTRIBUTE_TYPE instanceID );
void *attributeFindNextInstance( const void *attributePtr,
								 GETATTRFUNCTION getAttrFunction );
const void *attributeMoveCursor( const void *currentCursor,
								 GETATTRFUNCTION getAttrFunction,
								 const CRYPT_ATTRIBUTE_TYPE attributeMoveType,
								 const int cursorMoveType );

/****************************************************************************
*																			*
*								Time Functions								*
*																			*
****************************************************************************/

/* In exceptional circumstances an attempt to read the time can fail,
   returning either a garbage value (unsigned time_t) or -1 (signed time_t).
   This can be problematic because many crypto protocols and operations use
   the time at some point.  In order to protect against this, we provide a
   safe time-read function that returns either a sane time value or zero,
   and for situations where the absolute time isn't critical an approximate
   current-time function that returns either a sane time value or an
   approximate value hardcoded in at compile time.  Finally, we provide a
   reliable time function used for operations such as signing certs and
   timestamping that tries to get the time from a hardware time source if
   one is available.

   The following two values define the minimum time value that's regarded as
   being a valid time (we have to allow dates slightly before the current
   time because of things like backdated cert revocations, as a rule of
   thumb we allow a date up to five years in the past) and an approximation
   of the current time, with the constraint that it's not after the current
   date */

#define MIN_TIME_VALUE			( ( 2000 - 1970 ) * 365 * 86400L )
#define CURRENT_TIME_VALUE		( MIN_TIME_VALUE + ( 86400L * 365 * 6 ) )

#include <time.h>

time_t getTime( void );
time_t getApproxTime( void );
time_t getReliableTime( const CRYPT_HANDLE cryptHandle );

/* Hardware timer read routine used for performance evaluation */

long getTickCount( long startTime );

/****************************************************************************
*																			*
*							Checksum/Hash Functions							*
*																			*
****************************************************************************/

/* Hash state information.  We can either call the hash function with
   HASH_ALL to process an entire buffer at a time, or HASH_START/
   HASH_CONTINUE/HASH_END to process it in parts */

typedef enum {
	HASH_START,					/* Begin hashing */
	HASH_CONTINUE,				/* Continue existing hashing */
	HASH_END,					/* Complete existing hashing */
	HASH_ALL,					/* One-step hash operation */
	HASH_LAST					/* Last valid hash option */
	} HASH_STATE;

/* The hash functions are used quite a bit so we provide an internal API for
   them to avoid the overhead of having to set up an encryption context
   every time they're needed.  These take a block of input data and hash it,
   leaving the result in the output buffer.  If the hashState parameter is
   HASH_ALL the hashInfo parameter may be NULL, in which case the function
   will use its own memory for the hashInfo */

#ifdef SYSTEM_64BIT
  /* RIPEMD160: 24 * sizeof( long64 ) + 64 */
  typedef BYTE HASHINFO[ ( 24 * 8 ) + 64 ];
#else
  /* SHA-256: 26 * sizeof( long ).  Note that if SHA-512 is used this
     becomes 26 * sizeof( long long) instead */
  typedef BYTE HASHINFO[ 26 * 4 ];
#endif /* SYSTEM_64BIT */

typedef void ( *HASHFUNCTION )( HASHINFO hashInfo, BYTE *outBuffer,
								const int outBufMaxLength,
								const BYTE *inBuffer, const int inLength,
								const HASH_STATE hashState );

void getHashParameters( const CRYPT_ALGO_TYPE hashAlgorithm,
						HASHFUNCTION *hashFunction, int *hashOutputSize );

/* Sometimes all we need is a quick-reject check, usually performed to
   lighten the load before we do a full hash check.  The following
   function returns an integer checksum that can be used to weed out
   non-matches */

int checksumData( const void *data, const int dataLength );

/****************************************************************************
*																			*
*						Dynamic Memory Management Functions					*
*																			*
****************************************************************************/

/* Dynamic buffer management functions.  When reading variable-length
   attribute data we can usually fit the data in a small, fixed-length
   buffer, but occasionally we have to cope with larger data amounts that
   require a dynamically-allocated buffer.  The following routines manage
   this process, dynamically allocating and freeing a larger buffer if
   required */

#define DYNBUF_SIZE		1024

typedef struct {
	void *data;						/* Pointer to data */
	int length;
	BYTE dataBuffer[ DYNBUF_SIZE + 8 ];	/* Data buf.if size <= DYNBUF_SIZE */
	} DYNBUF;

int dynCreate( DYNBUF *dynBuf, const CRYPT_HANDLE cryptHandle,
			   const CRYPT_ATTRIBUTE_TYPE attributeType );
void dynDestroy( DYNBUF *dynBuf );

#define dynLength( dynBuf )		( dynBuf ).length
#define dynData( dynBuf )		( dynBuf ).data

/* When allocating many little blocks of memory, especially in resource-
   constrained systems, it's better if we pre-allocate a small memory pool
   ourselves and grab chunks of it as required, falling back to dynamically
   allocating memory later on if we exhaust the pool.  To use a custom
   memory pool, the caller declares a state variable of type MEMPOOL_STATE,
   calls initMemPool() to initialise the pool, and then calls getMemPool()
   and freeMemPool() to allocate and free memory blocks.  The state pointer
   is declared as a void * because to the caller it's an opaque memory block
   while to the memPool routines it's structured storage */

typedef BYTE MEMPOOL_STATE[ 32 ];

void initMemPool( void *statePtr, void *memPool, const int memPoolSize );
void *getMemPool( void *statePtr, const int size );
void freeMemPool( void *statePtr, void *memblock );

/* Almost all objects require object-subtype-specific amounts of memory to
   store object information.  In addition some objects such as certificates
   contain arbitrary numbers of arbitrary-sized bits and pieces, most of
   which are quite small.  To avoid having to allocate worst-case sized
   blocks of memory for objects (a problem in embedded environments) or large
   numbers of tiny little blocks of memory for certificate attributes, we use
   variable-length structures in which the payload is stored after the
   structure, with a pointer inside the structure pointing into the payload
   storage.  To make this easier to handle, we use macros to set up and tear
   down the necessary variables */

#define DECLARE_VARSTRUCT_VARS \
		int storageSize; \
		BYTE storage[ 1 ]

#define initVarStruct( structure, structureType, size ) \
		memset( structure, 0, sizeof( structureType ) ); \
		structure->value = structure->storage; \
		structure->storageSize = size

#define copyVarStruct( destStructure, srcStructure, structureType ) \
		memcpy( destStructure, srcStructure, \
				sizeof( structureType ) + srcStructure->storageSize ); \
		destStructure->value = destStructure->storage;

#define endVarStruct( structure, structureType ) \
		zeroise( structure, sizeof( structureType ) + structure->storageSize )

#define sizeofVarStruct( structure, structureType ) \
		( sizeof( structureType ) + structure->storageSize )

/****************************************************************************
*																			*
*								Randomness Functions						*
*																			*
****************************************************************************/

/* In order to make it easier to add lots of arbitrary-sized random data
   values, we make the following functions available to the polling code to
   implement a clustered-write mechanism for small data quantities.  These
   add an integer, long, or (short) string value to a buffer and send it
   through to the system device when the buffer is full.  Using the
   intermediate buffer ensures that we don't have to send a message to the
   device for every bit of data added

   The caller declares a state variable of type RANDOM_STATE, calls
   initRandomData() to initialise it, calls addRandomData() for each
   consecutive piece of data to add to the buffer, and finally calls
   endRandomData() to flush the data through to the system device.  The
   state pointer is declared as a void * because to the caller it's an
   opaque memory block while to the randomData routines it's structured
   storage */

typedef BYTE RANDOM_STATE[ 128 ];

void initRandomData( void *statePtr, void *buffer, const int maxSize );
int addRandomData( void *statePtr, const void *value,
				   const int valueLength );
int addRandomLong( void *statePtr, const long value );
int endRandomData( void *statePtr, const int quality );

/* We also provide an addRandomValue() to make it easier to add function
   return values for getXYZ()-style system calls that return system info as
   their return value, for which we can't pass an address to addRandomData()
   unless we copy it to a temporary var first */

#define addRandomValue( statePtr, value ) \
		addRandomLong( statePtr, ( long ) value )

/****************************************************************************
*																			*
*							Envelope Management Functions					*
*																			*
****************************************************************************/

/* General-purpose enveloping functions, used by various high-level
   protocols */

int envelopeWrap( const void *inData, const int inDataLength, void *outData,
				  int *outDataLength, const int outDataMaxLength,
				  const CRYPT_FORMAT_TYPE formatType,
				  const CRYPT_CONTENT_TYPE contentType,
				  const CRYPT_HANDLE iCryptKey );
int envelopeUnwrap( const void *inData, const int inDataLength,
					void *outData, int *outDataLength,
					const int outDataMaxLength,
					const CRYPT_CONTEXT iDecryptKey );
int envelopeSign( const void *inData, const int inDataLength,
				  void *outData, int *outDataLength,
				  const int outDataMaxLength,
				  const CRYPT_CONTENT_TYPE contentType,
				  const CRYPT_CONTEXT iSigKey,
				  const CRYPT_CERTIFICATE iCmsAttributes );
int envelopeSigCheck( const void *inData, const int inDataLength,
					  void *outData, int *outDataLength,
					  const int outDataMaxLength,
					  const CRYPT_CONTEXT iSigCheckKey,
					  int *sigResult, CRYPT_CERTIFICATE *iSigningCert,
					  CRYPT_CERTIFICATE *iCmsAttributes );

#endif /* _INTAPI_DEFINED */
