/****************************************************************************
*																			*
*							cryptlib Core Routines							*
*						Copyright Peter Gutmann 1992-2003					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"

/* Prototypes for functions in cryptkrn.c */

BOOLEAN beginInitialisation( const BOOLEAN checkState );
void endInitialisation( const BOOLEAN newState );
int initInternalFunctions( void );
void endInternalFunctions( void );
int destroyObjects( void );

/****************************************************************************
*																			*
*							Internal Self-test Routines						*
*																			*
****************************************************************************/

/* Self-test code for several general crypto algorithms that are used 
   internally all over cryptlib: MD5, SHA-1, and 3DES (and by extension 
   DES) */

#define DES_BLOCKSIZE	8
#if defined( INC_ALL )
  #include "des.h"
  #include "testdes.h"
#else
  #include "crypt/des.h"
  #include "crypt/testdes.h"
#endif /* Compiler-specific includes */

static BOOLEAN des3TestLoop( const DES_TEST *testData, int iterations )
	{
	BYTE temp[ DES_BLOCKSIZE ];
	BYTE key1[ DES_SCHEDULE_SZ ], key2[ DES_SCHEDULE_SZ ], key3[ DES_SCHEDULE_SZ ];
	int i;

	for( i = 0; i < iterations; i++ )
		{
		memcpy( temp, testData[ i ].plaintext, DES_BLOCKSIZE );

		des_set_key_unchecked( ( C_Block * ) testData[ i ].key,
							   *( ( Key_schedule * ) key1 ) );
		des_set_key_unchecked( ( C_Block * ) testData[ i ].key,
							   *( ( Key_schedule * ) key2 ) );
		des_set_key_unchecked( ( C_Block * ) testData[ i ].key,
							   *( ( Key_schedule * ) key3 ) );
		des_ecb3_encrypt( ( C_Block * ) temp, ( C_Block * ) temp,
						  *( ( Key_schedule * ) key1 ), 
						  *( ( Key_schedule * ) key2 ), 
						  *( ( Key_schedule * ) key3 ), DES_ENCRYPT );
		if( memcmp( testData[ i ].ciphertext, temp, DES_BLOCKSIZE ) )
			return( FALSE );
		}

	return( TRUE );
	}

static BOOLEAN testGeneralAlgorithms( void )
	{
	static const FAR_BSS struct {
		const char *data;
		const int length;
		const BYTE hashValue[ 16 ];
		} md5Vectors[] = {	/* RFC 1321 MD5 test vectors */
		{ "", 0,
		  { 0xD4, 0x1D, 0x8C, 0xD9, 0x8F, 0x00, 0xB2, 0x04,
			0xE9, 0x80, 0x09, 0x98, 0xEC, 0xF8, 0x42, 0x7E } },
		{ "a", 1,
		  { 0x0C, 0xC1, 0x75, 0xB9, 0xC0, 0xF1, 0xB6, 0xA8,
			0x31, 0xC3, 0x99, 0xE2, 0x69, 0x77, 0x26, 0x61 } },
		{ "abc", 3,
		  { 0x90, 0x01, 0x50, 0x98, 0x3C, 0xD2, 0x4F, 0xB0,
			0xD6, 0x96, 0x3F, 0x7D, 0x28, 0xE1, 0x7F, 0x72 } },
		{ "message digest", 14,
		  { 0xF9, 0x6B, 0x69, 0x7D, 0x7C, 0xB7, 0x93, 0x8D,
			0x52, 0x5A, 0x2F, 0x31, 0xAA, 0xF1, 0x61, 0xD0 } },
		{ "abcdefghijklmnopqrstuvwxyz", 26,
		  { 0xC3, 0xFC, 0xD3, 0xD7, 0x61, 0x92, 0xE4, 0x00,
			0x7D, 0xFB, 0x49, 0x6C, 0xCA, 0x67, 0xE1, 0x3B } },
		{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62,
		  { 0xD1, 0x74, 0xAB, 0x98, 0xD2, 0x77, 0xD9, 0xF5,
			0xA5, 0x61, 0x1C, 0x2C, 0x9F, 0x41, 0x9D, 0x9F } },
		{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80,
		  { 0x57, 0xED, 0xF4, 0xA2, 0x2B, 0xE3, 0xC9, 0x55,
			0xAC, 0x49, 0xDA, 0x2E, 0x21, 0x07, 0xB6, 0x7A } },
		{ NULL, 0, { 0 } }
		};
	static const FAR_BSS struct {
		const char *data;
		const int length;
		const BYTE hashValue[ 20 ];
		} sha1Vectors[] = {	/* FIPS 180-1 SHA-1 test vectors */
		{ "abc", 3,
		  { 0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
			0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C,
			0x9C, 0xD0, 0xD8, 0x9D } },
		{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
		  { 0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E,
			0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5,
			0xE5, 0x46, 0x70, 0xF1 } },
		{ NULL, 0, { 0 } }
		};
	HASHFUNCTION hashFunction;
	BYTE hashValue[ CRYPT_MAX_HASHSIZE ];
	int hashSize, i;

	/* Test the MD5 code against the values given in RFC 1321 */
	getHashParameters( CRYPT_ALGO_MD5, &hashFunction, &hashSize );
	if( hashFunction == NULL || hashSize != 16 )
		return( FALSE );
	for( i = 0; md5Vectors[ i ].data != NULL; i++ )
		{
		hashFunction( NULL, hashValue, ( BYTE * ) md5Vectors[ i ].data,
					  md5Vectors[ i ].length, HASH_ALL );
		if( memcmp( hashValue, md5Vectors[ i ].hashValue, 16 ) )
			return( FALSE );
		}

	/* Test the SHA-1 code against the values given in FIPS 180-1 */
	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
	if( hashFunction == NULL || hashSize != 20 )
		return( FALSE );
	for( i = 0; sha1Vectors[ i ].data != NULL; i++ )
		{
		hashFunction( NULL, hashValue, ( BYTE * ) sha1Vectors[ i ].data,
					  sha1Vectors[ i ].length, HASH_ALL );
		if( memcmp( hashValue, sha1Vectors[ i ].hashValue, 20 ) )
			return( FALSE );
		}

	/* Test the 3DES code against the values given in NIST Special Pub.800-20, 
	   1999, which are actually the same as NBS Special Pub.500-20, 1980 since 
	   they require that K1 = K2 = K3 */
	if( !des3TestLoop( testIP, sizeof( testIP ) / sizeof( DES_TEST ) ) || \
		!des3TestLoop( testVP, sizeof( testVP ) / sizeof( DES_TEST ) ) || \
		!des3TestLoop( testKP, sizeof( testKP ) / sizeof( DES_TEST ) ) || \
		!des3TestLoop( testDP, sizeof( testDP ) / sizeof( DES_TEST ) ) || \
		!des3TestLoop( testSB, sizeof( testSB ) / sizeof( DES_TEST ) ) )
		return( FALSE );

	return( TRUE );
	}

/* Test the kernel mechanisms to make sure that everything's working as 
   expected */

static BOOLEAN testKernelMechanisms( void )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	CRYPT_CONTEXT cryptHandle;
	static const BYTE key[] = { 0x10, 0x46, 0x91, 0x34, 0x89, 0x98, 0x01, 0x31 };
	BYTE buffer[ 128 ];
	time_t timeVal;
	int value, status;

	/* Verify object creation */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_DES );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( FALSE );
	cryptHandle = createInfo.cryptHandle;

	/* Verify inability to access internal object or attribute using 
	   external message */
	if( krnlSendMessage( cryptHandle, MESSAGE_GETATTRIBUTE, &value, 
						 CRYPT_CTXINFO_ALGO ) != CRYPT_ARGERROR_OBJECT || \
		krnlSendMessage( cryptHandle, MESSAGE_GETATTRIBUTE, &value, 
						 CRYPT_IATTRIBUTE_TYPE ) != CRYPT_ARGERROR_VALUE )
		{
		krnlSendNotifier( cryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify ability to perform standard operations, and inability to 
	   perform state=high operation on state=low object */
	setMessageData( &msgData, ( void * ) key, 8 );
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_CTXINFO_IV ) != CRYPT_OK || \
		krnlSendMessage( cryptHandle, IMESSAGE_CTX_ENCRYPT, 
						 buffer, 8 ) != CRYPT_ERROR_NOTINITED )
		{
		krnlSendNotifier( cryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify functioning of kernel range checking, phase 1: Numeric values */
	value = -10;		/* Below (negative) */
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE, &value, 
						 CRYPT_CTXINFO_KEYING_ITERATIONS ) != CRYPT_ARGERROR_NUM1 )
		status = CRYPT_ERROR;
	value = 0;			/* Lower bound fencepost error */
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE, &value, 
						 CRYPT_CTXINFO_KEYING_ITERATIONS ) != CRYPT_ARGERROR_NUM1 )
		status = CRYPT_ERROR;
	value = 1;			/* Lower bound */
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE, &value, 
						 CRYPT_CTXINFO_KEYING_ITERATIONS ) != CRYPT_OK )
		status = CRYPT_ERROR;
	value = 10000;		/* Mid-range */
	krnlSendMessage( cryptHandle, IMESSAGE_DELETEATTRIBUTE, NULL, 
					 CRYPT_CTXINFO_KEYING_ITERATIONS );
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE, &value, 
						 CRYPT_CTXINFO_KEYING_ITERATIONS ) != CRYPT_OK )
		status = CRYPT_ERROR;
	value = 20000;		/* Upper bound */
	krnlSendMessage( cryptHandle, IMESSAGE_DELETEATTRIBUTE, NULL, 
					 CRYPT_CTXINFO_KEYING_ITERATIONS );
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE, &value, 
						 CRYPT_CTXINFO_KEYING_ITERATIONS ) != CRYPT_OK )
		status = CRYPT_ERROR;
	value = 20001;		/* Upper bound fencepost error */
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE, &value, 
						 CRYPT_CTXINFO_KEYING_ITERATIONS ) != CRYPT_ARGERROR_NUM1 )
		status = CRYPT_ERROR;
	value = 32767;		/* High */
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE, &value, 
						 CRYPT_CTXINFO_KEYING_ITERATIONS ) != CRYPT_ARGERROR_NUM1 )
		status = CRYPT_ERROR;
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( cryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify functioning of kernel range checking, phase 2: String values.
	   We have to disable the more outrageous out-of-bounds values in the 
	   debug version since they'll cause the debug kernel to throw an 
	   exception if it sees them */
	status = CRYPT_OK;
	memset( buffer, '*', CRYPT_MAX_HASHSIZE + 1 );
	/* Below (negative) */
#ifdef NDEBUG
	setMessageData( &msgData, buffer, -10 );
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_CTXINFO_KEYING_SALT ) != CRYPT_ARGERROR_NUM1 )
		status = CRYPT_ERROR;
#endif /* NDEBUG */
	/* Lower bound fencepost error */
	setMessageData( &msgData, buffer, 7 );
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_CTXINFO_KEYING_SALT ) != CRYPT_ARGERROR_NUM1 )
		status = CRYPT_ERROR;
	/* Lower bound */
	setMessageData( &msgData, buffer, 8 );
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_CTXINFO_KEYING_SALT ) != CRYPT_OK )
		status = CRYPT_ERROR;
	/* Mid-range */
	setMessageData( &msgData, buffer, CRYPT_MAX_HASHSIZE / 2 );
	krnlSendMessage( cryptHandle, IMESSAGE_DELETEATTRIBUTE, NULL, 
					 CRYPT_CTXINFO_KEYING_SALT );
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_CTXINFO_KEYING_SALT ) != CRYPT_OK )
		status = CRYPT_ERROR;
	/* Upper bound */
	setMessageData( &msgData, buffer, CRYPT_MAX_HASHSIZE );
	krnlSendMessage( cryptHandle, IMESSAGE_DELETEATTRIBUTE, NULL, 
					 CRYPT_CTXINFO_KEYING_SALT );
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_CTXINFO_KEYING_SALT ) != CRYPT_OK )
		status = CRYPT_ERROR;
	/* Upper bound fencepost error */
	setMessageData( &msgData, buffer, CRYPT_MAX_HASHSIZE + 1 );
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_CTXINFO_KEYING_SALT ) != CRYPT_ARGERROR_NUM1 )
		status = CRYPT_ERROR;
	/* High */
#ifdef NDEBUG
	setMessageData( &msgData, buffer, 32767 );
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_CTXINFO_KEYING_SALT ) != CRYPT_ARGERROR_NUM1 )
		status = CRYPT_ERROR;
#endif /* NDEBUG */
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( cryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify ability to transition state=low object to state=high */
	setMessageData( &msgData, ( void * ) key, 8 );
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_CTXINFO_KEY ) != CRYPT_OK )
		{
		krnlSendNotifier( cryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify inability to read write-only object */
	setMessageData( &msgData, NULL, 0 );
	if( krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S, &msgData, 
						 CRYPT_CTXINFO_KEY ) != CRYPT_ERROR_PERMISSION )
		{
		krnlSendNotifier( cryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify inability to perform state=low operations on state=high 
	   object */
	setMessageData( &msgData, ( void * ) key, 8 );
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_CTXINFO_KEY ) != CRYPT_ERROR_PERMISSION || \
		krnlSendMessage( cryptHandle, IMESSAGE_CTX_GENKEY, NULL, 
						 FALSE ) != CRYPT_ERROR_PERMISSION )
		{
		krnlSendNotifier( cryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify inability to perform disallowed action externally but still
	   perform it internally.  Note that the object becomes very briefly
	   visible externally at this point, but there's nothing that can be
	   done with it because of the permission settings */
	value = \
		MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_NONE_EXTERNAL ) | \
		MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_NONE_EXTERNAL );
	krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE, &value,
					 CRYPT_IATTRIBUTE_ACTIONPERMS );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_INTERNAL );
	if( krnlSendMessage( cryptHandle, MESSAGE_CTX_ENCRYPT,
						 buffer, 8 ) != CRYPT_ERROR_PERMISSION || \
		krnlSendMessage( cryptHandle, IMESSAGE_CTX_ENCRYPT,
						 buffer, 8 ) != CRYPT_OK )
		{
		krnlSendNotifier( cryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_INTERNAL );

	/* Verify ability to use object with a finite usage count and inability
	   to exceed the usage count */
	value = 1;
	status = krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE, &value, 
							  CRYPT_PROPERTY_USAGECOUNT );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( cryptHandle, IMESSAGE_CTX_ENCRYPT,
								  buffer, 8 );
	if( cryptStatusError( status ) || \
		krnlSendMessage( cryptHandle, IMESSAGE_CTX_ENCRYPT,
						 buffer, 8 ) != CRYPT_ERROR_PERMISSION )
		{
		krnlSendNotifier( cryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify ability to lock object and inability to change security 
	   parameters once locked */
	value = 5;
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE, &value, 
						 CRYPT_PROPERTY_FORWARDCOUNT ) != CRYPT_OK || \
		krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE, 
						 MESSAGE_VALUE_TRUE, 
						 CRYPT_PROPERTY_HIGHSECURITY ) != CRYPT_OK )
		{
		krnlSendNotifier( cryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}
	if( krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE, &value, 
						 CRYPT_PROPERTY_LOCKED ) != CRYPT_OK || \
		value != TRUE || \
		krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE, &value, 
						 CRYPT_PROPERTY_FORWARDCOUNT ) != CRYPT_ERROR_PERMISSION )
		{
		/* Object should be locked, forwardcount should be inaccessible */
		krnlSendNotifier( cryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}
	value = 1;
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE, &value, 
						 CRYPT_PROPERTY_FORWARDCOUNT ) != CRYPT_ERROR_PERMISSION )
		{
		/* Security parameters shouldn't be writeable */
		krnlSendNotifier( cryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	krnlSendNotifier( cryptHandle, IMESSAGE_DECREFCOUNT );

	/* Create a cert object for the remaining kernel range checks */
	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_CERTIFICATE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( FALSE );
	cryptHandle = createInfo.cryptHandle;

	/* Verify functioning of kernel range checking, phase 3: Boolean values.
	   Any value should be OK, with conversion to TRUE/FALSE */
	value = 0;
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE, &value, 
						 CRYPT_CERTINFO_SELFSIGNED ) != CRYPT_OK )
		status = CRYPT_ERROR;
	if( krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE, &value, 
						 CRYPT_CERTINFO_SELFSIGNED ) != CRYPT_OK || \
		value != FALSE )
		status = CRYPT_ERROR;
	value = 1;
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE, &value, 
						 CRYPT_CERTINFO_SELFSIGNED ) != CRYPT_OK )
		status = CRYPT_ERROR;
	if( krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE, &value, 
						 CRYPT_CERTINFO_SELFSIGNED ) != CRYPT_OK || \
		value != TRUE )
		status = CRYPT_ERROR;
	value = 10000;
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE, &value, 
						 CRYPT_CERTINFO_SELFSIGNED ) != CRYPT_OK )
		status = CRYPT_ERROR;
	if( krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE, &value, 
						 CRYPT_CERTINFO_SELFSIGNED ) != CRYPT_OK || \
		value != TRUE )
		status = CRYPT_ERROR;
	value = -1;
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE, &value, 
						 CRYPT_CERTINFO_SELFSIGNED ) != CRYPT_OK )
		status = CRYPT_ERROR;
	if( krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE, &value, 
						 CRYPT_CERTINFO_SELFSIGNED ) != CRYPT_OK || \
		value != TRUE )
		status = CRYPT_ERROR;
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( cryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify functioning of kernel range checking, phase 4: Time values,
	   Any value above the initial cutoff date should be OK */
	setMessageData( &msgData, &timeVal, sizeof( time_t ) );
	timeVal = -10;					/* Below (negative) */
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_CERTINFO_VALIDFROM ) != CRYPT_ARGERROR_STR1 )
		status = CRYPT_ERROR;
	timeVal = MIN_TIME_VALUE - 1;	/* Lower bound fencepost error */
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_CERTINFO_VALIDFROM ) != CRYPT_ARGERROR_STR1 )
		status = CRYPT_ERROR;
	timeVal = MIN_TIME_VALUE;		/* Lower bound */
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_CERTINFO_VALIDFROM ) != CRYPT_OK )
		status = CRYPT_ERROR;
	timeVal = 0x40000000L;			/* Mid-range */
	krnlSendMessage( cryptHandle, IMESSAGE_DELETEATTRIBUTE, NULL, 
					 CRYPT_CERTINFO_VALIDFROM );
	if( krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_CERTINFO_VALIDFROM ) != CRYPT_OK )
		status = CRYPT_ERROR;
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( cryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	krnlSendNotifier( cryptHandle, IMESSAGE_DECREFCOUNT );
	return( TRUE );
	}

/****************************************************************************
*																			*
*							Startup/Shutdown Routines						*
*																			*
****************************************************************************/

/* The initialisation and shutdown actions performed for various object
   types.  The pre-init actions are used to handle various preparatory
   actions that are required before the actual init can be performed, for
   example to create the system device and user object, which are needed by
   the init routines.  The pre-shutdown actions are used to signal to various
   subsystems that a shutdown is about to occur, for example to allow the
   networking subsystem to gracefully exit from any currently occurring 
   network I/O.

   The order of the init/shutdown actions is:

					Object type		Action
					-----------		------
	Pre-init:		Device			Create system object

	Init:			User			Create default user object
					Keyset			Drivers - keysets
					Device			Drivers - devices
					Session			Drivers - networking

	Pre-shutdown:	Session			Networking - signal socket close
					Device			System object - signal entropy poll end

	Shutdown:		User			Destroy default user object	| Done by
					Device			Destroy system object		| kernel
					Keyset			Drivers - keysets
					Device			Drivers - devices
					Session			Drivers - networking

   The init order is determined by the following dependencies:

	All -> Device (System object handles many message types)
	User -> Cert (Default user object reads trusted certs)

   The shutdown order is determined by the following dependencies:

	Session (Networking needs to shut down to release any objects that are 
			 blocked waiting on network I/O)
	Device (System object needs to shut down ongoing entropy poll)

   After this the shutdown proper can take place.  The shutdown order is
   noncritical, provided the pre-shutdown actions have occurred.

   In theory the user and system objects are destroyed as part of the 
   standard shutdown, however the kernel prevents these objects from ever
   being explicitly destroyed so they're destroyed implicitly by the
   destroyObjects() cleanup call */

int certManagementFunction( const MANAGEMENT_ACTION_TYPE action );
int deviceManagementFunction( const MANAGEMENT_ACTION_TYPE action );
int keysetManagementFunction( const MANAGEMENT_ACTION_TYPE action );
int sessionManagementFunction( const MANAGEMENT_ACTION_TYPE action );
int userManagementFunction( const MANAGEMENT_ACTION_TYPE action );

typedef int ( *MANAGEMENT_FUNCTION )( const MANAGEMENT_ACTION_TYPE action );

static const MANAGEMENT_FUNCTION preInitFunctions[] = {
	deviceManagementFunction, NULL 
	};
static const MANAGEMENT_FUNCTION initFunctions[] = {
	userManagementFunction, NULL 
	};
static const MANAGEMENT_FUNCTION asyncInitFunctions[] = {
  #ifdef USE_KEYSETS
	keysetManagementFunction, 
  #endif /* USE_KEYSETS */
	deviceManagementFunction, 
  #ifdef USE_SESSIONS
	sessionManagementFunction, 
  #endif /* USE_SESSIONS */
	NULL 
	};
static const MANAGEMENT_FUNCTION preShutdownFunctions[] = {
  #ifdef USE_SESSIONS
	sessionManagementFunction, 
  #endif /* USE_SESSIONS */
	deviceManagementFunction, NULL 
	};
static const MANAGEMENT_FUNCTION shutdownFunctions[] = {
	/*userManagementFunction,*/ /*deviceManagementFunction,*/ 
  #ifdef USE_KEYSETS
	keysetManagementFunction, 
  #endif /* USE_KEYSETS */
	deviceManagementFunction, 
  #ifdef USE_SESSIONS
	sessionManagementFunction, 
  #endif /* USE_SESSIONS */
	NULL 
	};

/* Dispatch a set of management actions */

static int dispatchManagementAction( const MANAGEMENT_FUNCTION *mgmtFunctions,
									 const MANAGEMENT_ACTION_TYPE action )
	{
	int i, status = CRYPT_OK;

	for( i = 0; mgmtFunctions[ i ] != NULL; i++ )
		{
		const int localStatus = mgmtFunctions[ i ]( action );
		if( cryptStatusError( localStatus ) && cryptStatusOK( status ) )
			status = localStatus;
		}

	return( status );
	}

/* Under various OSes we bind to a number of drivers at runtime.  We can
   either do this sychronously or asynchronously depending on the setting of 
   a config option.  By default we use the async init since it speeds up the 
   startup.  Synchronisation is achieved by having the open/init functions in 
   the modules that require the drivers call waitSemaphore() on the driver 
   binding semaphore, which blocks until the drivers are bound if an async 
   bind is in progress, or returns immediately if no bind is in progress */

#ifdef USE_THREADS

THREADFUNC_DEFINE( threadedBind, dummy )
	{
	UNUSED( dummy );

	dispatchManagementAction( asyncInitFunctions, MANAGEMENT_ACTION_INIT );
	clearSemaphore( SEMAPHORE_DRIVERBIND );
	THREAD_EXIT();
	}
#endif /* USE_THREADS */

/* Initialise and shut down the system */

#if defined( __WIN32__ ) && defined( STATIC_LIB )
BOOLEAN isWin95;
#endif /* __WIN32__ && STATIC_LIB */

int initCryptlib( void )
	{
	int initLevel = 0, status;

	/* If the Win32 version is being compiled as a static .lib (not
	   recommended) we need to perform initialisation here.  Note that in
	   this form cryptlib is no longer fully thread-safe because we can't
	   guarantee that the thread-locking is automatically set up before
	   anything else */
#if defined( __WIN32__ ) && defined( STATIC_LIB )
	static DWORD dwPlatform = ( DWORD ) CRYPT_ERROR;

	/* Figure out which OS we're running under */
	if( dwPlatform == CRYPT_ERROR )
		{
		OSVERSIONINFO osvi = { sizeof( osvi ) };

		GetVersionEx( &osvi );
		dwPlatform = osvi.dwPlatformId;
		isWin95 = ( dwPlatform == VER_PLATFORM_WIN32_WINDOWS ) ? TRUE : FALSE;

		/* Check for Win32s just in case someone tries to load the DLL under
		   it */
		if( dwPlatform == VER_PLATFORM_WIN32s )
			return( CRYPT_ERROR );
		}
#endif /* __WIN32__ && STATIC_LIB */

	/* If we've already been initialised, don't do anything */
	if( !beginInitialisation( TRUE ) )
		return( CRYPT_OK );

	/* VisualAge C++ doesn't set the TZ correctly */
#if defined( __IBMC__ ) || defined( __IBMCPP__ )
	tzset();
#endif /* VisualAge C++ */

	/* Perform the multi-phase bootstrap */
	status = initInternalFunctions();
	assert( cryptStatusOK( status ) );
	if( cryptStatusOK( status ) )
		{
		initLevel = 1;
		status = dispatchManagementAction( preInitFunctions, 
										   MANAGEMENT_ACTION_PRE_INIT );
		assert( cryptStatusOK( status ) );
		}
	if( cryptStatusOK( status ) )
		{
		initLevel = 2;
		status = dispatchManagementAction( initFunctions, 
										   MANAGEMENT_ACTION_INIT );
		assert( cryptStatusOK( status ) );
		}
	if( cryptStatusOK( status ) )
		{
#ifdef USE_THREADS
		int asyncInit;
#endif /* USE_THREADS */

		initLevel = 3;

		/* Perform the final init phase asynchronously or synchronously 
		   depending on the config option setting.  We always send this 
		   query to the default user object since no other user objects 
		   exist at this time */
#ifdef USE_THREADS
		krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE, 
						 &asyncInit, CRYPT_OPTION_MISC_ASYNCINIT );
		if( asyncInit )
			{
			THREAD_HANDLE thread;
			THREAD_CREATE_VARS;

			/* Fire up the thread.  There's no problem with the thread 
			   exiting before we set the semaphore because it's a one-shot,
			   so if the thread gets there first the attempt to set the
			   semaphore below is ignored */
			status = THREAD_CREATE( threadedBind, NULL, thread );
			if( cryptStatusOK( status ) )
				setSemaphore( SEMAPHORE_DRIVERBIND, thread );
			else
				/* The thread couldn't be started, try again with a 
				   synchronous init */
				asyncInit = FALSE;
			}
		if( !asyncInit )
#endif /* USE_THREADS */
		status = dispatchManagementAction( asyncInitFunctions, 
										   MANAGEMENT_ACTION_INIT );
		assert( cryptStatusOK( status ) );
		}

	/* Everything's set up, verify that the general crypto algorithms and 
	   kernel security mechanisms are working as required */
	if( cryptStatusOK( status ) && \
		( !testGeneralAlgorithms() || !testKernelMechanisms() ) )
		{
		/* We should probably sound klaxons as well at this point */
		assert( NOTREACHED );
		status = CRYPT_ERROR_FAILED;
		}

	/* If anything failed, shut down the internal functions and services
	   before we exit */
	if( !cryptStatusOK( status ) )
		{
		if( initLevel >= 3 )
			{
			/* Shut down any external interfaces after making sure that the
			   initalisation ran to completion */
			waitSemaphore( SEMAPHORE_DRIVERBIND );
			dispatchManagementAction( preShutdownFunctions, 
									  MANAGEMENT_ACTION_PRE_SHUTDOWN );
			dispatchManagementAction( shutdownFunctions, 
									  MANAGEMENT_ACTION_SHUTDOWN );
			}
		if( initLevel >= 2 )
			destroyObjects();
		if( initLevel >= 1 )
			endInternalFunctions();
		endInitialisation( FALSE );
		return( status );
		}

	/* Unlock the initialisation state */
	endInitialisation( TRUE );
	return( CRYPT_OK );
	}

int endCryptlib( void )
	{
	int status;

	/* If we've already been shut down, don't do anything */
	if( !beginInitialisation( FALSE ) )
		return( CRYPT_OK );

	/* Reverse the process carried out in the multi-phase bootstrap */
	waitSemaphore( SEMAPHORE_DRIVERBIND );
	dispatchManagementAction( preShutdownFunctions, 
							  MANAGEMENT_ACTION_PRE_SHUTDOWN );
	status = destroyObjects();
	dispatchManagementAction( shutdownFunctions, 
							  MANAGEMENT_ACTION_SHUTDOWN );
	endInternalFunctions();

	/* Unlock the initialisation state */
	endInitialisation( FALSE );

	/* If the Win32 version is being compiled as a static .lib, we need to
	   perform the cleanup here */
#if defined( __WIN32__ ) && defined( STATIC_LIB )
	/* Delete the initialisation lock in the kernel */
	postShutdown();
#endif /* __WIN32__ && STATIC_LIB */

	return( status );
	}

/****************************************************************************
*																			*
*						Client/Server Interface Routines					*
*																			*
****************************************************************************/

/* If we're running in our own address space (either in another VM or on
   separate hardware), we need to have some sort of client/server mechanism
   to communicate with processes running in the applications address space.
   The following section implements the server-side interface for various
   environments */

#ifdef USE_CLIENT_SERVER

/* Prototypes for functions in cryptapi.c.  Currently this is all done 
   locally (cryptsvr_client calls cryptsvr_server directly), someone else 
   can fight with these daemons... */

#if defined( __UNIX__ )

#include <sys/un.h>

#define DAEMON_NAME			"cryptd"
#define DAEMON_SOCKET_NAME	"/dev/crypt"
#define DAEMON_NO_THREADS	10

/* Per-thread main function */

static MUTEX acceptMutex;			/* Mutex for accept() */
static int sockfd;					/* Socket for accept() */
static BOOLEAN doShutdown = FALSE;	/* Signal for threads to shut down */
static int activeThreads = 0;		/* No.of currently active threads */

THREADFUNC_DEFINE( threadedMain, dummy )
	{
	while( TRUE )
		{
		int connfd;

		/* Some implementations don't handle threads blocking in accept() too
		   well, and in any case managing the thundering herd in user space
		   is a lot more efficient than doing it in the kernel, so we
		   explicitly manage locking ourselves with a mutex.

		   If we've been told to shut down, we don't try the accept() but
		   just drop through to the shutdown check afterwards.  This
		   decrements the activeThreads counter, the last thread out turns
		   off the lights.  The way the shutdown works is that the accept()
		   fails (due to the socket being closed) and the thread falls out of
		   the accept lock/unlock, at which point either it passes into the
		   shutdown lock/unlock and exits or (rarely) it gets preempted and
		   the next thread passes through the accept lock/unlock.  In the
		   most extreme case the accept mutex pileup moves down to the exit
		   mutex, but in either case all threads eventually terminate.  The
		   only time the daemon might shut down improperly is if a thread is
		   in the middle of a long-running keygen and keeps everything else
		   active.  There isn't really any clean way to handle this, and in
		   any case if the system is about to shut down there probably won't
		   be anything left running to pick up the pieces */
		MUTEX_LOCK( &acceptMutex );
		if( !doShutdown )
			connfd = accept( sockfd, NULL, 0 );
		MUTEX_UNLOCK( &acceptMutex );
		if( doShutdown )
			{
			MUTEX_LOCK( &acceptMutex );
			activeThreads--;
			if( !activeThreads )
				cryptEnd();
			MUTEX_UNLOCK( &acceptMutex );
			THREAD_EXIT();
			}

		if( connfd == -1 )
			{
			/* If we got zapped by a signal, continue where we left off */
			if( errno == EINTR )
				continue;

			/* If we got caught by a RST for an established connection before
			   accept() got called, the connection will be aborted, in which
			   case we just continue */
			if( errno == ECONNABORTED )
				continue;

			/* ... */
			}

		/* Get the request type and make sure that it's valid */
		/* ... */

		/* Dispatch the request */
		status = dispatchRequest( request.UserDefined, request.RequestID );

		/* Clean up */
		close( connfd );
		}
	}

/* Set up the daemon and fire up the thread pool */

void sigTermFunction( int dummy )
	{
	/* Signal all active threads to die and close the socket, which forces
	   accept() to fail, guaranteeing that a thread doesn't remain blocked
	   in the call */
	doShutdown = TRUE;
	close( socket );
	}

int main( int argc, char *argv[] )
	{
	THREAD threadPool[ DAEMON_NO_THREADS ];
	const struct rlimit rl = { 0, 0 };
	struct sockaddr_un sockAddr;
	struct timeval tv;
	char *socketName, *errorString = NULL;
	int fd, status;

	/* Start logging our status */
	openlog( DAEMON_NAME, 0, LOG_DAEMON );
	syslog( LOG_INFO, DAEMON_NAME "started" );

	/* Check that everything is OK */
	if( argc > 2 )
		errorString = "usage: " DAEMON_NAME " <server socket pathname>";
	else
		{
		socketName = ( argc == 2 ) ? argv[ 1 ] : DAEMON_SOCKET_NAME;
		if( strlen( socketName > 100 )
			errorString = DAEMON_NAME ": Socket pathname too long";
		else
			if( access( socketName, F_OK )
				errorString = DAEMON_NAME ": Socket already exists";
		}
	if( errorString != NULL )
		{
		syslog( LOG_ERR, errorString );
		closelog();
		exit( EXIT_FAILURE );
		}

	/* Turn ourselves into a daemon by forking a new process and killing its
	   parent.  After this sequence of operations, we're a daemon owned by
	   init */
	if( ( status = fork() ) < 0 )
		{
		syslog( LOG_ERR, "%m" );
		closelog();
		exit( EXIT_FAILURE );
		}
	if( status )
		exit( EXIT_SUCCESS ); /* Exit if we're the parent */

#if 1
	/* Create a new session with ourselves as the session leader and no
	   controlling TTY, ignore SIGHUP, and fork again.  This is necessary
	   because when a session leader without a controlling terminal opens a
	   terminal device, it gets assigned as its controlling TTY.  By forking
	   a second time, we make sure that the child is no longer a session 
	   leader.  The reason we need to ignore SIGHUP is because when the 
	   first-level child (the session leader) exits, the second-level child 
	   (just another process in the session) will be SIGHUP'd */
	setsid();
	signal( SIGHUP, SIG_IGN );
	if( ( status = fork() ) != 0 )
		exit( EXIT_SUCCESS );
#else
	/* Detach ourselves from the controlling TTY to avoid interruptions and
	   move into our own process group to avoid mass murders */
	fd = open( "/dev/tty", O_RDWR );
	ioctl( fd, TIOCNOTTY, 0 );
	close( fd );
	setpgrp( 0, getpid() );
#endif /* 1 */

	/* Close all inherited file descriptors */
	for( fd = getdtablesize() - 1; fd >= 0; fd-- )
		close( fd );

	/* Move to a (safe) standard directory, set our umask to make sure that 
	   our files are kept private (although the cryptlib streams module does 
	   this anyway), and point the stdin, stdout, and stderr streams to the 
	   null device in case library routines try and do any I/O */
	chdir( "/tmp" );
	umask( 0177 );      /* Owner RW access only */
	fd = open( "/dev/null", O_RDWR );   /* stdin = 0 */
	dup( fd );                          /* stdout = 1 */
	dup( fd );                          /* stderr = 2 */

	/* Make sure that we can never dump core (we really, *really* don't want 
	   to do this) */
	setrlimit( RLIMIT_CORE, &rl );

	/* Go catatonic */
	signal( SIG_IGN, SIGHUP );

	/* Create a domain socket and wait for connections */
	memset( sockAddr, 0, sizeof( struct sockaddr_un ) );
	strcpy( sockAddr.sun_path, socketName );
	status = sockfd = socket( AF_LOCAL, SOCK_STREAM, 0 );
	if( status != -1 )
		status = bind( sockfd, ( SA * ) &sockAddr, SUN_LEN( &sockAddr ) );
	if( status != -1 )
		status = listen( sockfd, 5 );
	if( status == -1 )
		{
		syslog( LOG_ERR, "%m" );
		closelog();
		exit( EXIT_FAILURE );
		}

	/* Set the socket timeout to 5 seconds to make sure that we don't block
	   forever if a client hangs */
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	setsockopt( sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv,
				sizeof( struct timeval ) );
	setsockopt( sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv,
				sizeof( struct timeval ) );

	/* Initialise the crypto code */
	status = cryptInit();
	if( cryptStatusError( status ) )
		{
		syslog( LOG_ERR, "Crypto initialisation failed" );
		closelog();
		exit( EXIT_FAILURE );
		}

	/* Make sure that if we get killed by init, we shut down cleanly */
	signal( sigTermFunction, SIGTERM );

	/* Start up the thread pool.  We hold the accept() mutex while we're
	   doing this to ensure that it's an all-or-nothing start, in other
	   words that there are no threads accepting commands while there's
	   still a chance that the init could be aborted */
	MUTEX_INIT( &acceptMutex );
	MUTEX_LOCK( &acceptMutex );
	for( i = 0; i < DAEMON_NO_THREADS; i++ )
		{
		status = THREAD_CREATE( &threadMain, NULL );
		if( THREAD_STATUS( status ) != CRYPT_OK )
			break;
		activeThreads++;
		}
	if( cryptStatusError( status ) )
		{
		/* Signal any threads that got started to terminate immediately */
		doShutdown = TRUE;
		close( socket );
		MUTEX_UNLOCK( &acceptMutex );

		syslog( LOG_ERR, "Thread pool initialisation failed" );
		closelog();
		exit( EXIT_FAILURE );
		}
	MUTEX_UNLOCK( &acceptMutex );

	/* We're ready to talk, make the socket path accessible to others (the
	   umask will have made it inaccessible, which is fine since we don't
	   want anyone poking messages at us while we're initialising) */
	chmod( socketName, 0666 );

	/* Everything is done by the threads, so we just twiddle our thumbs */
	while( TRUE )
		pause();

	/* Clean up */
	MUTEX_DESTROY( &acceptMutex );
	exit( EXIT_SUCCESS );
	}

#elif defined( __WINDOWS__ )

#define SERVICE_NAME			"cryptd"
#define SERVICE_DISPLAY_NAME	"cryptlib Server"
#define SERVICE_PATH			"%SystemRoot%\\System32\\cryptd.exe"

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE hServiceStatus;

/* Service control handler */

void WINAPI Handler( DWORD fdwControl )
	{
	switch( fdwControl )
		{
		case SERVICE_CONTROL_STOP:
			serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
			break;

		case SERVICE_CONTROL_SHUTDOWN:
			break;

		case SERVICE_CONTROL_INTERROGATE:
			; /* Fall through */
		}

	SetServiceStatus( hServiceStatus, &serviceStatus );
	}

/* Service-specific and generic main functions */

void WINAPI ServiceMain( DWORD dwArgc, LPTSTR *lpszArgv )
	{
	static const SERVICE_STATUS serviceStatusTemplate = {
		SERVICE_WIN32_OWN_PROCESS, SERVICE_START_PENDING,
		SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN, 0, 0, 0, 0
		};
	int status;

	/* Register the service control handler and tell the SCM what we're
	   doing */
	if( ( hServiceStatus = RegisterServiceCtrlHandler( SERVICE_NAME,
													   Handler ) ) == 0 )
		return;
	serviceStatus = serviceStatusTemplate;
	SetServiceStatus( hServiceStatus, &serviceStatus );

	/* Initialise cryptlib */
	status = cryptInit();
	if( cryptStatusError( status ) )
		{
		serviceStatus.dwCurrentState = SERVICE_STOPPED;
		serviceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
		serviceStatus.dwServiceSpecificExitCode = status;
		SetServiceStatus( hServiceStatus, &serviceStatus );
		return;
		}
	serviceStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus( hServiceStatus, &serviceStatus );
	}

int main( int argc, char *argv[] )
	{
	static const SERVICE_TABLE_ENTRY serviceTable[] = {
		{ TEXT( SERVICE_NAME ), ServiceMain }, { NULL, NULL } };

	if( argc > 2 )
		{
		puts( "Usage: " SERVICE_NAME " <install> <remove>" );
		exit( EXIT_FAILURE );
		}
	if( argc == 2 )
		{
		/* Handle service installation */
		if( !stricmp( argv[ 1 ], "install" ) )
			{
			SC_HANDLE schSCM, schService;

			/* Try and install the service */
			schSCM = OpenSCManager( NULL, NULL, SC_MANAGER_CREATE_SERVICE );
			if( schSCM == NULL )
				{
				perror( SERVICE_NAME );
				exit( EXIT_FAILURE );
				}
			schService = CreateService( schSCM, TEXT( SERVICE_NAME ),
							TEXT( SERVICE_DISPLAY_NAME ), SERVICE_ALL_ACCESS,
#if 0	/* For debugging we make it demand-start */
							SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
#else
							SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
#endif /* 0 */
							SERVICE_ERROR_NORMAL, SERVICE_PATH, NULL, NULL,
							NULL, NULL, NULL );
			if( schService == NULL )
				{
				CloseServiceHandle( schSCM );
				if( GetLastError() == ERROR_SERVICE_EXISTS )
					puts( "The service is already installed.  To reinstall, "
						  "stop the service with\n'net stop " SERVICE_NAME "', "
						  "remove the current service with\n'" SERVICE_NAME " "
						  "remove', and rerun the install." );
				else
					perror( SERVICE_NAME );
				exit( EXIT_FAILURE );
				}
			CloseServiceHandle( schService );
			CloseServiceHandle( schSCM );

			puts( SERVICE_NAME " service successfully installed." );
			exit( EXIT_SUCCESS );
			}

		/* Handle service removal */
		if( !stricmp( argv[ 1 ], "remove" ) )
			{
			SC_HANDLE schSCM, schService;
			SERVICE_STATUS removeServiceStatus;

			/* Open the service */
			schSCM = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
			if( schSCM == NULL )
				{
				perror( SERVICE_NAME );
				exit( EXIT_FAILURE );
				}
			schService = OpenService( schSCM, SERVICE_NAME, DELETE );
			if( schService == NULL )
				{
				CloseServiceHandle( schSCM );
				perror( SERVICE_NAME );
				exit( EXIT_FAILURE );
				}

			/* If the service is currently running, stop it before we try to
			   remove it.  Note that we use ControlService() to determine its
			   status rather than QueryServiceStatus() since the former
			   returns the actual state while the latter only returns the
			   state last reported to the SCM, which means the service could
			   already be stopped without the SCM realising it (probably one
			   of the reasons why it seems to take ages to stop even the
			   simplest service) */
			ControlService( schService, SERVICE_CONTROL_INTERROGATE,
							&removeServiceStatus );
			if( removeServiceStatus.dwCurrentState != SERVICE_STOPPED )
				{
				int timeout = 30;

				printf( "Stopping " SERVICE_DISPLAY_NAME );
				ControlService( schService, SERVICE_CONTROL_STOP,
								&removeServiceStatus );
				do
					{
					putchar( '.' );
					Sleep( 1000 );
					ControlService( schService, SERVICE_CONTROL_INTERROGATE,
									&removeServiceStatus );
					}
				while( ( removeServiceStatus.dwCurrentState == \
												SERVICE_STOP_PENDING ) && \
					   timeout-- > 0 );
				}
			if( removeServiceStatus.dwCurrentState != SERVICE_STOPPED )
				{
				puts( "Couldn't stop " SERVICE_DISPLAY_NAME "." );
				CloseServiceHandle( schSCM );
				exit( EXIT_FAILURE );
				}

			/* The service is stopped, remove it */
			DeleteService( schService );
			CloseServiceHandle( schService );
			CloseServiceHandle( schSCM );

			puts( SERVICE_NAME " service successfully removed." );
			exit( EXIT_SUCCESS );
			}

		printf( "Unknown argument '%s'.\n", argv[ 1 ] );
		exit( EXIT_FAILURE );
		}

	/* Pass control on to the service's main().  Since this is a
	   SERVICE_WIN32_OWN_PROCESS, we don't have to specify a name for it or
	   worry about much else */
	StartServiceCtrlDispatcher( serviceTable );
	}

#elif defined( __IBM4758__ )

#include <scc_err.h>
#include <scc_int.h>

void main( void )	/* Because the docs say so, that's why */
	{
	const static sccAgentID_t agentID = { "\x06\x00", "cryptlib\x00\x00\x00", 0x21, 0x00, 0x00 };
	sccRequestHeader_t request;
	long status;
	int initStatus;

	/* Register ourselves with the SCC manager */
	status = sccSignOn( ( sccAgentID_t * ) &agentID, NULL );
	if( status != PPDGood )
		exit( status );

	/* If we're running in debug mode, we have to make sure that we don't 
	   start running before the debugger can attach to the process.  The 
	   following infinite loop just yields our timeslice back to the OS, to 
	   move past it set a breakpoint on the i++ and then use 'Jump to 
	   location' to break out of the loop */
#ifdef _DEBUG
	{
	long i = 0, j = 1;

	while( j )
		{
		CPYield();
		i++; if( !i ) j++;	/* Confound the optimiser */
		}
	}
#endif /* _DEBUG */

	/* Initialise cryptlib.  Normally this is done in response to a user
	   request, however we can do it when the device is started so that
	   everything's ready when the user needs it.  In the spirit of FIPS 140,
	   we call cryptInit() rather than plain cryptInit() (this isn't that bad 
	   since many capabilities aren't present, all the slow stuff is being 
	   done in hardware, and the device isn't restarted that often anyway) */
	cryptInit();

	while( TRUE )
		{
		/* Wait for a request from the host system */
		status = sccGetNextHeader( &request, 0, SVCWAITFOREVER );
		if( status != PPDGood )
			break;

		/* Dispatch the message.  This just calls the built-in command
		   dispatcher with the request type (i.e.the cryptlib function being
		   called) and a reference to the data source.  Once the request has
		   been handled, the status value is passed back to the caller */
		status = dispatchRequest( request.UserDefined, request.RequestID );
		sccEndRequest( request.RequestID, 0, NULL, 0, status );
		}

	/* Clean up */
	cryptEnd();
	exit( PPDGood );
	}
#endif /* Client-server server-side code */

#endif /* USE_CLIENT_SERVER */

/****************************************************************************
*																			*
*						OS-Specific Support Routines						*
*																			*
****************************************************************************/

#if defined( __WINDOWS__ ) && !( defined( NT_DRIVER ) || defined( STATIC_LIB ) )

/* WinMain() and WEP() under Win16 are intended for DLL initialisation,
   however it isn't possible to reliably do anything terribly useful in these
   routines.  The reason for this is that the WinMain/WEP functions are
   called by the windows module loader, which has a very limited workspace
   and can cause peculiar behaviour for some functions (allocating/freeing
   memory and loading other modules from these routines is unreliable), the
   order in which WinMain() and WEP() will be called for a set of DLL's is
   unpredictable (sometimes WEP doesn't seem to be called at all), and they
   can't be tracked by a standard debugger.  This is why MS have
   xxxRegisterxxx() and xxxUnregisterxxx() functions in their DLL's.

   Under Win16 on a Win32 system this isn't a problem because the module
   loader has been rewritten to work properly, but it isn't possible to get
   reliable performance under pure Win16, so the DLL entry/exit routines here
   do almost nothing, with the real work being done in cryptInit()/
   cryptEnd() */

#ifdef __WIN16__

HWND hInst;

int CALLBACK LibMain( HINSTANCE hInstance, WORD wDataSeg, WORD wHeapSize, \
					  LPSTR lpszCmdLine )
	{
	/* Remember the proc instance for later */
	hInst = hInstance;

	return( TRUE );
	}

int CALLBACK WEP( int nSystemExit )
	{
	switch( nSystemExit )
		{
		case WEP_SYSTEM_EXIT:
			/* System is shutting down */
			break;

		case WEP_FREE_DLL:
			/* DLL reference count = 0, DLL-only shutdown */
			break;
		}

	return( TRUE );
	}

#else

BOOLEAN isWin95;

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )
	{
	void preInit( void );
	void postShutdown( void );
	static DWORD dwPlatform = ( DWORD ) CRYPT_ERROR;

	UNUSED( hinstDLL );
	UNUSED( lpvReserved );

	switch( fdwReason )
		{
		case DLL_PROCESS_ATTACH:
			/* Figure out which OS we're running under */
			if( dwPlatform == ( DWORD ) CRYPT_ERROR )
				{
				OSVERSIONINFO osvi = { sizeof( osvi ) };

				GetVersionEx( &osvi );
				dwPlatform = osvi.dwPlatformId;
				isWin95 = ( dwPlatform == VER_PLATFORM_WIN32_WINDOWS ) ? \
						  TRUE : FALSE;

				/* Check for Win32s just in case someone tries to load the
				   DLL under it */
				if( dwPlatform == VER_PLATFORM_WIN32s )
					return( FALSE );
				}

			/* Disable thread-attach notifications, which we don't do
			   anything with and therefore don't need */
			 DisableThreadLibraryCalls( hinstDLL );

			/* Set up the initialisation lock in the kernel */
			preInit();
			break;

		case DLL_PROCESS_DETACH:
			/* Delete the initialisation lock in the kernel */
			postShutdown();
			break;

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
			break;
		}

	return( TRUE );
	}

/* Idiot-proofing.  Yes, there really are people who'll try and register a 
   straight DLL */

#define MB_OK				0x00000000L
#define MB_ICONQUESTION		0x00000020L

int WINAPI MessageBoxA( HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, 
						UINT uType );

#pragma comment( linker, "/export:DllRegisterServer=_DllRegisterServer@0,PRIVATE" )

STDAPI DllRegisterServer( void )
	{
	MessageBoxA( NULL, "Why are you trying to register the cryptlib DLL?\n"
				 "It's just a standard Windows DLL, there's nothing\nto be "
				 "registered.", "ESO Error", 
				 MB_ICONQUESTION | MB_OK );
	return( E_NOINTERFACE );
	}
#endif /* Win16 */
#endif /* Windows DLL */
