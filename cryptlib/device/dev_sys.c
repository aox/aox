/****************************************************************************
*																			*
*						cryptlib System Device Routines						*
*						Copyright Peter Gutmann 1995-2003					*
*																			*
****************************************************************************/

/* The random pool handling code in this module and the misc/rnd*.c modules
   represent the cryptlib continuously seeded pseudorandom number generator
   (CSPRNG) as described in my 1998 Usenix Security Symposium paper "The
   generation of practically strong random numbers".

   The CSPRNG code is copyright Peter Gutmann (and various others) 1995-2003
   all rights reserved.  Redistribution of the CSPRNG modules and use in
   source and binary forms, with or without modification, are permitted
   provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice
	  and this permission notice in its entirety.

   2. Redistributions in binary form must reproduce the copyright notice in
	  the documentation and/or other materials provided with the distribution.

   3. A copy of any bugfixes or enhancements made must be provided to the
	  author, <pgut001@cs.auckland.ac.nz> to allow them to be added to the
	  baseline version of the code.

   ALTERNATIVELY, the code may be distributed under the terms of the GNU
   General Public License, version 2 or any later version published by the
   Free Software Foundation, in which case the provisions of the GNU GPL are
   required INSTEAD OF the above restrictions.

   Although not required under the terms of the GPL, it would still be nice
   if you could make any changes available to the author to allow a
   consistent code base to be maintained */

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "des.h"
  #include "capabil.h"
  #include "device.h"
  #include "libs.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../crypt/des.h"
  #include "capabil.h"
  #include "device.h"
  #include "../libs/libs.h"
#else
  #include "crypt.h"
  #include "crypt/des.h"
  #include "device/capabil.h"
  #include "device/device.h"
  #include "libs/libs.h"
#endif /* Compiler-specific includes */

/* Mechanisms supported by the system device.  These are sorted in order of
   frequency of use in order to make lookups a bit faster */

static const FAR_BSS MECHANISM_FUNCTION_INFO mechanismFunctions[] = {
	{ MESSAGE_DEV_EXPORT, MECHANISM_PKCS1, ( MECHANISM_FUNCTION ) exportPKCS1 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PKCS1, ( MECHANISM_FUNCTION ) importPKCS1 },
	{ MESSAGE_DEV_SIGN, MECHANISM_PKCS1, ( MECHANISM_FUNCTION ) signPKCS1 },
	{ MESSAGE_DEV_SIGCHECK, MECHANISM_PKCS1, ( MECHANISM_FUNCTION ) sigcheckPKCS1 },
	{ MESSAGE_DEV_EXPORT, MECHANISM_PKCS1_RAW, ( MECHANISM_FUNCTION ) exportPKCS1 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PKCS1_RAW, ( MECHANISM_FUNCTION ) importPKCS1 },
#ifdef USE_PGP
	{ MESSAGE_DEV_EXPORT, MECHANISM_PKCS1_PGP, ( MECHANISM_FUNCTION ) exportPKCS1PGP },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PKCS1_PGP, ( MECHANISM_FUNCTION ) importPKCS1PGP },
#endif /* USE_PGP */
	{ MESSAGE_DEV_EXPORT, MECHANISM_CMS, ( MECHANISM_FUNCTION ) exportCMS },
	{ MESSAGE_DEV_IMPORT, MECHANISM_CMS, ( MECHANISM_FUNCTION ) importCMS },
	{ MESSAGE_DEV_DERIVE, MECHANISM_PKCS5, ( MECHANISM_FUNCTION ) derivePKCS5 },
#if defined( USE_PGP ) || defined( USE_PGPKEYS )
	{ MESSAGE_DEV_DERIVE, MECHANISM_PGP, ( MECHANISM_FUNCTION ) derivePGP },
#endif /* USE_PGP || USE_PGPKEYS */
#ifdef USE_SSL
	{ MESSAGE_DEV_DERIVE, MECHANISM_SSL, ( MECHANISM_FUNCTION ) deriveSSL },
	{ MESSAGE_DEV_DERIVE, MECHANISM_TLS, ( MECHANISM_FUNCTION ) deriveTLS },
#endif /* USE_SSL */
#ifdef USE_CMP
	{ MESSAGE_DEV_DERIVE, MECHANISM_CMP, ( MECHANISM_FUNCTION ) deriveCMP },
#endif /* USE_CMP */
#ifdef USE_PKCS12
	{ MESSAGE_DEV_DERIVE, MECHANISM_PKCS12, ( MECHANISM_FUNCTION ) derivePKCS12 },
#endif /* USE_PKCS12 */
	{ MESSAGE_DEV_EXPORT, MECHANISM_PRIVATEKEYWRAP, ( MECHANISM_FUNCTION ) exportPrivateKey },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP, ( MECHANISM_FUNCTION ) importPrivateKey },
	{ MESSAGE_DEV_EXPORT, MECHANISM_PRIVATEKEYWRAP_PKCS8, ( MECHANISM_FUNCTION ) exportPrivateKeyPKCS8 },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP_PKCS8, ( MECHANISM_FUNCTION ) importPrivateKeyPKCS8 },
#ifdef USE_PGPKEYS
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP_PGP, ( MECHANISM_FUNCTION ) importPrivateKeyPGP },
	{ MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP_OPENPGP, ( MECHANISM_FUNCTION ) importPrivateKeyOpenPGP },
#endif /* USE_PGPKEYS */
	{ MESSAGE_NONE, MECHANISM_NONE, NULL }
	};

/* Object creation functions supported by the system device.  These are
   sorted in order of frequency of use in order to make lookups a bit
   faster */

int createContext( MESSAGE_CREATEOBJECT_INFO *createInfo,
				   const void *auxDataPtr, const int auxValue );
int createCertificate( MESSAGE_CREATEOBJECT_INFO *createInfo,
					   const void *auxDataPtr, const int auxValue );
int createEnvelope( MESSAGE_CREATEOBJECT_INFO *createInfo,
					const void *auxDataPtr, const int auxValue );
int createSession( MESSAGE_CREATEOBJECT_INFO *createInfo,
				   const void *auxDataPtr, const int auxValue );
int createKeyset( MESSAGE_CREATEOBJECT_INFO *createInfo,
				  const void *auxDataPtr, const int auxValue );
int createDevice( MESSAGE_CREATEOBJECT_INFO *createInfo,
				  const void *auxDataPtr, const int auxValue );
int createUser( MESSAGE_CREATEOBJECT_INFO *createInfo,
				const void *auxDataPtr, const int auxValue );

static const FAR_BSS CREATEOBJECT_FUNCTION_INFO createObjectFunctions[] = {
	{ OBJECT_TYPE_CONTEXT, createContext },
	{ OBJECT_TYPE_CERTIFICATE, createCertificate },
#ifdef USE_ENVELOPES
	{ OBJECT_TYPE_ENVELOPE, createEnvelope },
#endif /* USE_ENVELOPES */
#ifdef USE_SESSIONS
	{ OBJECT_TYPE_SESSION, createSession },
#endif /* USE_SESSIONS */
#ifdef USE_KEYSETS
	{ OBJECT_TYPE_KEYSET, createKeyset },
#endif /* USE_KEYSETS */
	{ OBJECT_TYPE_DEVICE, createDevice },
	{ OBJECT_TYPE_USER, createUser },
	{ OBJECT_TYPE_NONE, NULL }
	};

/****************************************************************************
*																			*
*						Randomness Interface Definitions					*
*																			*
****************************************************************************/

/* If we don't have a defined randomness interface, complain */

#if !( defined( __BEOS__ ) || defined( __IBM4758__ ) || \
	   defined( __MAC__ ) || defined( __MSDOS__ ) || defined( __OS2__ ) || \
	   defined( __TANDEMNSK__ ) || defined( __TANDEMOSS__ ) || \
	   defined( __UNIX__ ) || defined( __VMCMS__ ) || \
	   defined( __WIN16__ ) || defined( __WIN32__ ) )
  #error You need to create OS-specific randomness-gathering functions in misc/rnd<os-name>.c
#endif /* Various OS-specific defines */

/* Some systems systems require special-case initialisation to allow 
   background randomness gathering, where this doesn't apply the routines to 
   do this are nop'd out */

#if defined( __WIN32__ )
  void initRandomPolling( void );
  void endRandomPolling( void );
  void waitforRandomCompletion( const BOOLEAN force );
#elif defined( __UNIX__ ) && !defined( __MVS__ )
  void initRandomPolling( void );
  #define endRandomPolling()
  void waitforRandomCompletion( const BOOLEAN force );
#else
  #define initRandomPolling()
  #define endRandomPolling()
  #define waitforRandomCompletion( dummy )
#endif /* !( __WIN32__ || __UNIX__ ) */

/* On Unix systems the randomness pool may be duplicated at any point if
   the process forks (qualis pater, talis filius), so we need to perform a 
   complex check to make sure that we're running with a unique copy of the 
   pool contents rather than a clone of data held in another process.  The 
   following function checks whether we've forked or not, which is used as a 
   signal to adjust the pool contents */

#if defined( __UNIX__ ) && !defined( __MVS__ )
  BOOLEAN checkForked( void );
#else
  #define checkForked()		FALSE
#endif /* __UNIX__ */

/* Prototypes for functions in the OS-specific randomness polling routines */

void slowPoll( void );
void fastPoll( void );

/* The size in bytes of the randomness pool and the size of the X9.17 
   post-processor generator pool */

#define RANDOMPOOL_SIZE			256
#define X917_POOLSIZE			8

/* The allocated size of the randomness pool, which allows for the overflow
   created by the fact that the hash function blocksize isn't any useful
   multiple of a power of 2 */

#define RANDOMPOOL_ALLOCSIZE	( ( ( RANDOMPOOL_SIZE + 20 - 1 ) / 20 ) * 20 )

/* In order to avoid the pool startup problem (where initial pool data may
   consist of minimally-mixed entropy samples) we require that the pool be
   mixed at least the following number of times before we can draw data from
   it.  This usually happens automatically because a slow poll adds enough
   data to cause many mixing iterations, however if this doesn't happen we
   manually mix it the appropriate number of times to get it up to the
   correct level */

#define RANDOMPOOL_MIXES		10

/* The number of samples of previous output that we keep for the FIPS 140
   continuous tests, and the number of retries we perform if we detect a
   repeat of a previous output */

#define RANDOMPOOL_SAMPLES		16
#define RANDOMPOOL_RETRIES		5

/* The number of times that we cycle the X9.17 generator before we load new 
   key and state variables.  This means that we re-seed for every 
   X917_MAX_BYTES of output produced */

#define X917_MAX_BYTES			8192
#define X917_MAX_CYCLES			( X917_MAX_BYTES / X917_POOLSIZE )

/* The scheduled DES keys for the X9.17 generator */

typedef struct {
	Key_schedule desKey1, desKey2, desKey3;
	} X917_3DES_KEY;

#define DES_KEYSIZE		sizeof( Key_schedule )

/* The size of the X9.17 generator key (112 bits for EDE 3DES) */

#define X917_KEYSIZE	16

/* Random pool information, pagelocked in memory to ensure that it never gets
   swapped to disk.  We keep track of the write position in the pool, which
   tracks where new data is added.  Whenever we add new data the write
   position is updated, once we reach the end of the pool we mix the pool
   and start again at the beginning.  We track the pool status by recording 
   the quality of the pool contents (1-100) and the number of times the pool 
   has been mixed, we can't draw data from the pool unless both of these 
   values have reached an acceptable level.  In addition to the pool state 
   information we keep track of the previous RANDOMPOOL_SAMPLES output 
   samples to check for stuck-at faults or (short) cyles */

typedef struct {
	/* Pool state information */
	BYTE randomPool[ RANDOMPOOL_ALLOCSIZE ];	/* Random byte pool */
	int randomPoolPos;		/* Current write position in the pool */

	/* Pool status information */
	int randomQuality;		/* Level of randomness in the pool */
	int randomPoolMixes;	/* Number of times pool has been mixed */

	/* X9.17 generator state information */
	BYTE x917Pool[ X917_POOLSIZE ];	/* Generator state */
	X917_3DES_KEY x917Key;	/* Scheduled 3DES key */
	BOOLEAN x917Inited;		/* Whether generator has been inited */
	int x917Count;			/* No.of times generator has been cycled */

	/* Information for the FIPS 140 continuous tests */
	unsigned long prevOutput[ RANDOMPOOL_SAMPLES ];
	unsigned long x917PrevOutput[ RANDOMPOOL_SAMPLES ];
	int prevOutputIndex;

	/* Other status information used to check the pool's operation */
	int entropyByteCount;	/* Number of bytes entropy added */
	} RANDOM_INFO;

/****************************************************************************
*																			*
*						Randomness Utility Functions						*
*																			*
****************************************************************************/

/* Convenience functions used by the system-specific randomness-polling
   routines to send data to the system device.  These just accumulate as
   close to bufSize bytes of data as possible in a user-provided buffer and
   then forward them to the device object.  Note that addRandomData() 
   assumes that the quantity of data being added is small (a fixed-size 
   struct or something similar), it shouldn't be used to add large buffers 
   full of data since information at the end of the buffer will be lost (in 
   the debug build this will trigger an exception telling the caller to use 
   a direct krnlSendMessage() instead) */

typedef struct {
	void *buffer;			/* Entropy buffer */
	int bufPos, bufSize;	/* Current buffer pos.and total size */
	int updateStatus;		/* Error status if update failed */
	} RANDOM_STATE_INFO;

void initRandomData( void *statePtr, void *buffer, const int maxSize )
	{
	RANDOM_STATE_INFO *state = ( RANDOM_STATE_INFO * ) statePtr;

	assert( isWritePtr( state, sizeof( RANDOM_STATE_INFO ) ) );
	assert( sizeof( RANDOM_STATE_INFO ) <= sizeof( RANDOM_STATE ) );
	assert( isWritePtr( buffer, maxSize ) );
	assert( maxSize >= 16 );

	memset( state, 0, sizeof( RANDOM_STATE_INFO ) );
	state->buffer = buffer;
	state->bufSize = maxSize;
	}

int addRandomData( void *statePtr, const void *value, 
				   const int valueLength )
	{
	RANDOM_STATE_INFO *state = ( RANDOM_STATE_INFO * ) statePtr;
	RESOURCE_DATA msgData;
	const BYTE *valuePtr = value;
	int length = min( valueLength, state->bufSize - state->bufPos );
	int totalLength = valueLength, status;

	assert( isWritePtr( state, sizeof( RANDOM_STATE_INFO ) ) );
	assert( isReadPtr( value, valueLength ) );
	assert( state->bufPos >= 0 && state->bufPos <= state->bufSize );
	assert( valueLength > 0 && valueLength <= state->bufSize );

	/* Sanity check on inputs (the length check checks both the input data
	   length and that bufSize > bugPos) */
	if( state->bufPos < 0 || length < 0 || state->bufSize < 16 )
		{
		/* Some type of fatal data corruption has occurred */
		state->updateStatus = CRYPT_ERROR_FAILED;
		assert( NOTREACHED );
		return( CRYPT_ERROR_FAILED );
		}

	/* Copy as much of the input as we can into the accumulator */
	if( length > 0 )
		{
		memcpy( ( BYTE * ) state->buffer + state->bufPos, valuePtr, length );
		state->bufPos += length;
		valuePtr += length;
		totalLength -= length;
		}
	assert( totalLength >= 0 );

	/* If everything went into the accumulator, we're done */
	if( state->bufPos < state->bufSize )
		return( CRYPT_OK );

	assert( state->bufPos == state->bufSize );

	/* The accumulator is full, send the data through to the system device */
	setMessageData( &msgData, state->buffer, state->bufPos );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_SETATTRIBUTE_S, 
							  &msgData, CRYPT_IATTRIBUTE_ENTROPY );
	if( cryptStatusError( status ) )
		{
		/* There was a problem moving the data through, make the error status
		   persistent */
		state->updateStatus = status;
		assert( NOTREACHED );
		return( status );
		}
	state->bufPos = 0;

	/* If there's uncopied data left, copy it in now */
	if( totalLength > 0 )
		{
		length = min( totalLength, state->bufSize );
		memcpy( state->buffer, valuePtr, length );
		state->bufPos += length;
		}
	return( CRYPT_OK );
	}

int addRandomLong( void *statePtr, const long value )
	{
	return( addRandomData( statePtr, &value, sizeof( long ) ) );
	}

int endRandomData( void *statePtr, const int quality )
	{
	RANDOM_STATE_INFO *state = ( RANDOM_STATE_INFO * ) statePtr;
	int status = state->updateStatus;

	assert( isWritePtr( state, sizeof( RANDOM_STATE_INFO ) ) );

	/* If there's data still in the accumulator, send it through to the 
	   system device */
	if( state->bufPos > 0 && state->bufPos < state->bufSize && \
		state->bufSize >= 16 )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, state->buffer, state->bufPos );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_ENTROPY );
		if( cryptStatusOK( status ) )
			status = state->updateStatus;
		}
	assert( cryptStatusOK( status ) );

	/* If everything went OK, set the quality estimate for the data that 
	   we've added */
	if( cryptStatusOK( status ) && quality > 0 )
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_SETATTRIBUTE, ( void * ) &quality, 
								  CRYPT_IATTRIBUTE_ENTROPY_QUALITY );

	/* Clear the accumulator and exit */
	zeroise( state->buffer, state->bufSize );
	zeroise( state, sizeof( RANDOM_STATE_INFO ) );
	return( status );
	}

/****************************************************************************
*																			*
*						Random Pool Management Routines						*
*																			*
****************************************************************************/

/* Initialise and shut down a random pool */

static void initRandomPool( RANDOM_INFO *randomInfo )
	{
	memset( randomInfo, 0, sizeof( RANDOM_INFO ) );
	}

static void endRandomPool( RANDOM_INFO *randomInfo )
	{
	memset( randomInfo, 0, sizeof( RANDOM_INFO ) );
	}

/* Stir up the data in the random buffer.  Given a circular buffer of length
   n bytes, a buffer position p, and a hash output size of h bytes, we hash
   bytes from p - h...p - 1 (to provide chaining across previous hashes) and
   p...p + 64 (to have as much surrounding data as possible affect the
   current data).  Then we move on to the next h bytes until all n bytes have
   been mixed */

static void mixRandomPool( RANDOM_INFO *randomInfo )
	{
	HASHFUNCTION hashFunction;
	BYTE dataBuffer[ CRYPT_MAX_HASHSIZE + 64 ];
	int hashSize, hashIndex;
	ORIGINAL_INT_VAR( randomPoolMixes, randomInfo->randomPoolMixes );

	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );

	/* Stir up the entire pool.  We can't check the return value of the 
	   hashing call because there isn't one, however the SHA-1 code has gone
	   through a self-test when the randomness subsystem was inited */
	for( hashIndex = 0; hashIndex < RANDOMPOOL_SIZE; hashIndex += hashSize )
		{
		int dataBufIndex, poolIndex;

		/* Precondition: We're processing hashSize bytes at a time */
		PRE( hashIndex % hashSize == 0 );

		/* If we're at the start of the pool then the first block that we hash 
		   is at the end of the pool, otherwise it's the block immediately
		   preceding the current one */
		poolIndex = hashIndex ? hashIndex - hashSize : \
								RANDOMPOOL_SIZE - hashSize;

		/* Copy hashSize bytes from position p - 19...p - 1 in the circular
		   pool into the hash data buffer.  We do this manually rather than
		   using memcpy() in order for the assertion-based testing to work */
		for( dataBufIndex = 0; dataBufIndex < hashSize; dataBufIndex++ )
			dataBuffer[ dataBufIndex ] = randomInfo->randomPool[ poolIndex++ ];

		/* Postconditions for the chaining data copy: We got h bytes from 
		   within the pool, and before the current pool position */
		POST( dataBufIndex == hashSize );
		POST( poolIndex >= hashSize && poolIndex <= RANDOMPOOL_SIZE );
		POST( !hashIndex || hashIndex == poolIndex );

		/* Copy 64 bytes from position p from the circular pool into the hash
		   data buffer */
		poolIndex = hashIndex;
		while( dataBufIndex < hashSize + 64 )
			dataBuffer[ dataBufIndex++ ] = \
						randomInfo->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ];

		/* Postconditions for the state data copy: We got 64 bytes after the
		   current pool position */
		POST( dataBufIndex == hashSize + 64 );
		POST( poolIndex == hashIndex + 64 );

		/* Hash the data at position p...p + hashSize in the circular pool
		   using the surrounding data extracted previously */
		hashFunction( NULL, randomInfo->randomPool + hashIndex,
					  dataBuffer, dataBufIndex, HASH_ALL );
		}
	zeroise( dataBuffer, sizeof( dataBuffer ) );

	/* Postconditions for the pool mixing: The entire pool was mixed and
	   temporary storage was cleared */
	POST( hashIndex >= RANDOMPOOL_SIZE );
	FORALL( i, 0, sizeof( dataBuffer ), 
			dataBuffer[ i ] == 0 );

	/* Increment the mix count and move the write position back to the start
	   of the pool */
	if( randomInfo->randomPoolMixes < RANDOMPOOL_MIXES )
		randomInfo->randomPoolMixes++;
	randomInfo->randomPoolPos = 0;

	/* Postconditions for the status update: We mixed the pool at least 
	   once, and we're back at the start of the pool */
	POST( randomInfo->randomPoolMixes == RANDOMPOOL_MIXES || \
		  randomInfo->randomPoolMixes == \
							ORIGINAL_VALUE( randomPoolMixes ) + 1 );
	POST( randomInfo->randomPoolPos == 0 );
	}

/****************************************************************************
*																			*
*								ANSI X9.17 Generator						*
*																			*
****************************************************************************/

/* The ANSI X9.17 Annex C generator has a number of problems (besides just
   being slow) including a tiny internal state, use of fixed keys, no
   entropy update, revealing the internal state to an attacker whenever it
   generates output, and a horrible vulnerability to state compromise,
   however for FIPS 140 compliance we need to use an approved generator (even
   though Annex C is informative rather than normative and contains only "an
   example of a pseudorandom key and IV generator" so that it could be argued
   that any generator based on X9.17 3DES is permitted), which is why this
   generator appears here.

   In order to minimise the potential for damage we employ it as a post-
   processor for the pool (since X9.17 produces a 1-1 mapping, it can never
   make the output any worse), using as our timestamp input the main RNG
   output.  This is perfectly valid since X9.17 requires the use of DT, "a
   date/time vector which is updated on each key generation", a requirement
   that is met by the fastPoll() which is performed before the main pool is
   mixed.  The cryptlib representation of the date and time vector is as a
   hash of assorted incidental data and the date and time.

   The fact that 99.9999% of the value of the generator is coming from the,
   uhh, timestamp is as coincidental as the side effect of the engine cooling
   fan in the Brabham ground effect cars */

/* A macro to make what's being done by the generator easier to follow */

#define tdesEncrypt( data, key ) \
		des_ecb3_encrypt( ( C_Block * ) ( data ), ( C_Block * ) ( data ), \
						  ( key )->desKey1, ( key )->desKey2, \
						  ( key )->desKey3, DES_ENCRYPT )

/* Set the X9.17 generator key */

static int setKeyX917( RANDOM_INFO *randomInfo, const BYTE *key, 
					   const BYTE *seed )
	{
	X917_3DES_KEY *des3Key = &randomInfo->x917Key;
	int desStatus;

	/* Make sure that the key and seed aren't taken from the same location */
	assert( memcmp( key, seed, X917_POOLSIZE ) );

	/* Remember that we're about to reset the generator state */
	randomInfo->x917Inited = FALSE;

	/* Schedule the DES keys.  Rather than performing the third key schedule,
	   we just copy the first scheduled key into the third one */
	des_set_odd_parity( ( C_Block * ) key );
	des_set_odd_parity( ( C_Block * ) ( key + bitsToBytes( 64 ) ) );
	desStatus = des_key_sched( ( des_cblock * ) key, des3Key->desKey1 );
	if( desStatus == 0 )
		desStatus = des_key_sched( ( des_cblock * ) ( key + bitsToBytes( 64 ) ),
								   des3Key->desKey2 );
	memcpy( des3Key->desKey3, des3Key->desKey1, DES_KEYSIZE );
	if( desStatus )
		{
		/* There was a problem initialising the keys, don't try and go any
		   further */
		assert( randomInfo->x917Inited == FALSE );
		return( CRYPT_ERROR_RANDOM );
		}

	/* Set up the seed value V(0) */
	memcpy( randomInfo->x917Pool, seed, X917_POOLSIZE );

	/* We've initialised the generator and reset the cryptovariables, we're
	   ready to go */
	randomInfo->x917Inited = TRUE;
	randomInfo->x917Count = 0;

	return( CRYPT_OK );
	}

/* Run the X9.17 generator over a block of data */

static int generateX917( RANDOM_INFO *randomInfo, BYTE *data, 
						 const int length )
	{
	BYTE timeBuffer[ X917_POOLSIZE ], *dataPtr = data;
	int i;

	/* Sanity check to make sure that the generator has been initialised */
	if( !randomInfo->x917Inited )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_RANDOM );
		}

	/* Precondition: We're not asking for more data than the maximum needed
	   in any cryptlib operation (which in this case is the size of a
	   maximum-length PKC key), the generator has been initialised, and the
	   cryptovariables aren't past their use-by date */
	PRE( length >= 1 && length <= CRYPT_MAX_PKCSIZE );
	PRE( randomInfo->x917Inited == TRUE );
	PRE( randomInfo->x917Count >= 0 && \
		 randomInfo->x917Count < X917_MAX_CYCLES );

	/* Process as many blocks of output as needed.  We can't check the 
	   return value of the encryption call because there isn't one, however 
	   the 3DES code has gone through a self-test when the randomness 
	   subsystem was inited */
	for( i = 0; i < length; i += X917_POOLSIZE )
		{
		const int bytesToCopy = min( length - i, X917_POOLSIZE );
		int j;
		ORIGINAL_INT_VAR( x917Count, randomInfo->x917Count );

		/* Precondition: We're processing from 1...X917_POOLSIZE bytes of
		   data */
		PRE( bytesToCopy >= 1 && bytesToCopy <= X917_POOLSIZE );

		/* Copy in as much timestamp (+ other assorted data) as we can from
		   the input */
		memcpy( timeBuffer, dataPtr, bytesToCopy );

		/* Inner precondition: The local buffer contains the input data */
		FORALL( k, 0, bytesToCopy, 
				timeBuffer[ k ] == data[ i + k ] );

		/* out = Enc( Enc( time ) ^ V(n) ); */
		tdesEncrypt( timeBuffer, &randomInfo->x917Key );
		for( j = 0; j < X917_POOLSIZE; j++ )
			randomInfo->x917Pool[ j ] ^= timeBuffer[ j ];
		tdesEncrypt( randomInfo->x917Pool, &randomInfo->x917Key );
		memcpy( dataPtr, randomInfo->x917Pool, bytesToCopy );

		/* Postcondition: The internal state has been copied to the output
		   (ick) */
		FORALL( k, 0, bytesToCopy, \
				data[ i + k ] == randomInfo->x917Pool[ k ] );

		/* V(n+1) = Enc( Enc( time ) ^ out ); */
		for( j = 0; j < X917_POOLSIZE; j++ )
			randomInfo->x917Pool[ j ] ^= timeBuffer[ j ];
		tdesEncrypt( randomInfo->x917Pool, &randomInfo->x917Key );

		/* Move on to the next block */
		dataPtr += bytesToCopy;
		randomInfo->x917Count++;

		/* Postcondition: We've processed one more block of data */
		POST( dataPtr == data + i + bytesToCopy );
		POST( randomInfo->x917Count == ORIGINAL_VALUE( x917Count ) + 1 );
		}

	/* Postcondition: We processed all of the data */
	POST( dataPtr == data + length );

	zeroise( timeBuffer, X917_POOLSIZE );

	/* Postcondition: Nulla vestigia retrorsum */
	FORALL( i, 0, X917_POOLSIZE, 
			timeBuffer[ i ] == 0 );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Randomness Routines								*
*																			*
****************************************************************************/

/* Self-test code for the two crypto algorithms that are used for random 
   number generation.  The self-test of these two algorithms is performed 
   every time the randomness subsystem is initialised.  Note that the same 
   tests have already been performed as part of the startup self-test, but 
   we perform them again here for the benefit of the randomness subsystem,
   which doesn't necessarily trust (or even know about) the startup self-
   test */

#define DES_BLOCKSIZE	X917_POOLSIZE
#if defined( INC_ALL )
  #include "testdes.h"
#elif defined( INC_CHILD )
  #include "../crypt/testdes.h"
#else
  #include "crypt/testdes.h"
#endif /* Compiler-specific includes */

static int des3TestLoop( const DES_TEST *testData, int iterations )
	{
	BYTE temp[ DES_BLOCKSIZE ];
	BYTE key1[ DES_KEYSIZE ], key2[ DES_KEYSIZE ], key3[ DES_KEYSIZE ];
	int i;

	for( i = 0; i < iterations; i++ )
		{
		memcpy( temp, testData[ i ].plaintext, DES_BLOCKSIZE );

		/* Some of the old NBS test vectors have bad key parity values so we
		   explicitly call the key-schedule function that ignores parity 
		   bits */
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
			return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

static int algorithmSelfTest( void )
	{
	static const FAR_BSS struct {
		const char *data;
		const int length;
		const BYTE hashValue[ 20 ];
		} hashData[] = {	/* FIPS 180-1 SHA-1 test vectors */
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

	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );

	/* Test the SHA-1 code against the values given in FIPS 180-1.  We don't
	   perform the final test (using 10MB of data) because this takes too 
	   long to run */
	for( i = 0; hashData[ i ].data != NULL; i++ )
		{
		hashFunction( NULL, hashValue, ( BYTE * ) hashData[ i ].data,
					  hashData[ i ].length, HASH_ALL );
		if( memcmp( hashValue, hashData[ i ].hashValue, hashSize ) )
			return( CRYPT_ERROR_FAILED );
		}

	/* Test the 3DES code against the values given in NIST Special Pub.800-20, 
	   1999, which are actually the same as 500-20, 1980, since they require 
	   that K1 = K2 = K3 */
	if( ( des3TestLoop( testIP, sizeof( testIP ) / sizeof( DES_TEST ) ) != CRYPT_OK ) || \
		( des3TestLoop( testVP, sizeof( testVP ) / sizeof( DES_TEST ) ) != CRYPT_OK ) || \
		( des3TestLoop( testKP, sizeof( testKP ) / sizeof( DES_TEST ) ) != CRYPT_OK ) || \
		( des3TestLoop( testDP, sizeof( testDP ) / sizeof( DES_TEST ) ) != CRYPT_OK ) || \
		( des3TestLoop( testSB, sizeof( testSB ) / sizeof( DES_TEST ) ) != CRYPT_OK ) )
		return( CRYPT_ERROR_FAILED );

	return( CRYPT_OK );
	}

/* Initialise and shut down the randomness subsystem */

static int initRandomInfo( DEVICE_INFO *deviceInfo )
	{
	int status;

	/* Make sure that the crypto we need is functioning as required */
	status = algorithmSelfTest();
	if( cryptStatusError( status ) )
		{
		assert( NOTREACHED );
		return( status );
		}

	/* Allocate and initialise the random pool */
	if( ( status = krnlMemalloc( ( void ** ) &deviceInfo->randomInfo,
								 sizeof( RANDOM_INFO ) ) ) != CRYPT_OK )
		return( status );
	initRandomPool( deviceInfo->randomInfo );

	/* Initialise any helper routines that may be needed */
	initRandomPolling();

	return( CRYPT_OK );
	}

static void endRandomInfo( DEVICE_INFO *deviceInfo )
	{
	/* Make sure that there are no background threads/processes still trying 
	   to send us data */
	waitforRandomCompletion( TRUE );

	/* Call any special-case shutdown functions */
	endRandomPolling();

	/* Shut down the random data pool */
	endRandomPool( deviceInfo->randomInfo );
	krnlMemfree( ( void ** ) &deviceInfo->randomInfo );
	}

/* Get a block of random data from the randomness pool in such a way that
   compromise of the data doesn't compromise the pool, and vice versa.  This
   is done by performing the (one-way) pool mixing operation on the pool, and
   on a transformed version of the pool that becomes the key.  The
   transformed version of the pool from which the key data will be drawn is
   then further processed by running each 64-bit block through the X9.17
   generator.  As an additional precaution the key data is folded in half to
   ensure that not even a hashed or encrypted form of the previous contents
   is available.  No pool data ever leaves the pool.

   This function performs a more paranoid version of the FIPS 140 continuous
   test on both the main pool contents and the X9.17 generator output that
   will detect stuck-at faults and short cycles in the output.  In addition
   the higher-level message handler applies the FIPS 140 statistical tests
   to the output and will retry the fetch if the output fails the tests (this
   is performed at the higher level because it's then applied to all
   randomness sources used by cryptlib, not just the built-in one).

   Since the pool output is folded to mask the output, the output from each
   round of mixing is only half the pool size as defined below */

#define RANDOM_OUTPUTSIZE	( RANDOMPOOL_SIZE / 2 )

static int tryGetRandomOutput( RANDOM_INFO *randomInfo, 
							   RANDOM_INFO *exportedRandomInfo )
	{
	const BYTE *samplePtr = randomInfo->randomPool;
	const BYTE *x917SamplePtr = exportedRandomInfo->randomPool;
	unsigned long sample;
	int i, status;

	/* Precondition: The pool is ready to do.  This check isn't so much to 
	   confirm that this really is the case (it's already been checked 
	   elsewhere) but to ensure that the two pool parameters haven't been
	   reversed.  The use of generic pools for all types of random output is 
	   useful in terms of providing a nice abstraction, but less useful for 
	   type safety */
	PRE( randomInfo->randomQuality >= 100 && \
		 randomInfo->randomPoolMixes >= RANDOMPOOL_MIXES && \
		 randomInfo->x917Inited == TRUE );
	PRE( exportedRandomInfo->randomQuality == 0 && \
		 exportedRandomInfo->randomPoolMixes == 0 && \
		 exportedRandomInfo->x917Inited == FALSE );

	/* Copy the contents of the main pool across to the export pool, 
	   transforming it as we go by flipping all of the bits */
	for( i = 0; i < RANDOMPOOL_ALLOCSIZE; i++ )
		exportedRandomInfo->randomPool[ i ] = randomInfo->randomPool[ i ] ^ 0xFF;

	/* Postcondition for the bit-flipping: The two pools differ, and the 
	   difference is in the flipped bits */
	POST( memcmp( randomInfo->randomPool, exportedRandomInfo->randomPool,
				  RANDOMPOOL_ALLOCSIZE ) );
	FORALL( i, 0, RANDOMPOOL_ALLOCSIZE, \
			randomInfo->randomPool[ i ] == \
							( exportedRandomInfo->randomPool[ i ] ^ 0xFF ) );

	/* Mix the original and export pools so that neither can be recovered 
	   from the other */
	mixRandomPool( randomInfo );
	mixRandomPool( exportedRandomInfo );

	/* Postcondition for the mixing: The two pools differ, and the difference 
	   is more than just the bit flipping (this has a 1e-12 chance of a false 
	   positive and even that's only in the debug version) */
	POST( memcmp( randomInfo->randomPool, exportedRandomInfo->randomPool,
				  RANDOMPOOL_ALLOCSIZE ) );
	POST( randomInfo->randomPool[ 0 ] != \
			  ( exportedRandomInfo->randomPool[ 0 ] ^ 0xFF ) ||
		  randomInfo->randomPool[ 8 ] != \
			  ( exportedRandomInfo->randomPool[ 8 ] ^ 0xFF ) ||
		  randomInfo->randomPool[ 16 ] != \
			  ( exportedRandomInfo->randomPool[ 16 ] ^ 0xFF ) ||
		  randomInfo->randomPool[ 24 ] != \
			  ( exportedRandomInfo->randomPool[ 24 ] ^ 0xFF ) ||
		  randomInfo->randomPool[ 32 ] != \
			  ( exportedRandomInfo->randomPool[ 32 ] ^ 0xFF ) );

	/* Precondition for sampling the output: It's a sample from the start of 
	   the pool */
	PRE( samplePtr == randomInfo->randomPool );
	PRE( x917SamplePtr == exportedRandomInfo->randomPool );

	/* Check for stuck-at faults by comparing a short sample from the current 
	   output with samples from the previous RANDOMPOOL_SAMPLES outputs */
	sample = mgetLong( samplePtr );
	for( i = 0; i < RANDOMPOOL_SAMPLES; i++ )
		if( randomInfo->prevOutput[ i ] == sample )
			/* We're repeating previous output, tell the caller to try 
			   again */
			return( OK_SPECIAL );

	/* Postcondition: There are no values seen during a previous run present 
	   in the output */
	FORALL( i, 0, RANDOMPOOL_SAMPLES, \
			randomInfo->prevOutput[ i ] != sample );

	/* Process the exported pool with the X9.17 generator */
	status = generateX917( randomInfo, exportedRandomInfo->randomPool, 
						   RANDOMPOOL_ALLOCSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Check for stuck-at faults in the X9.17 generator by comparing a short 
	   sample from the current output with samples from the previous 
	   RANDOMPOOL_SAMPLES outputs */
	sample = mgetLong( x917SamplePtr );
	for( i = 0; i < RANDOMPOOL_SAMPLES; i++ )
		if( randomInfo->x917PrevOutput[ i ] == sample )
			/* We're repeating previous output, tell the caller to try 
			   again */
			return( OK_SPECIAL );

	/* Postcondition: There are no values seen during a previous run present 
	   in the output */
	FORALL( i, 0, RANDOMPOOL_SAMPLES, \
			randomInfo->x917PrevOutput[ i ] != sample );

	return( CRYPT_OK );
	}

static int getRandomOutput( RANDOM_INFO *randomInfo, BYTE *buffer, 
							const int length )
	{
	RANDOM_INFO exportedRandomInfo;
	BYTE *samplePtr;
	int noRandomRetries, i, status;

	/* Precondition for output quantity: We're being asked for a valid output 
	   length and we're not trying to use more than half the pool contents */
	PRE( length > 0 && length <= RANDOM_OUTPUTSIZE );
	PRE( length <= RANDOMPOOL_SIZE / 2 );
	PRE( RANDOM_OUTPUTSIZE == RANDOMPOOL_SIZE / 2 );

	/* If the X9.17 generator cryptovariables haven't been initialised yet 
	   or have reached their use-by date, set the generator key and seed from 
	   the pool contents, then mix the pool and crank the generator twice to 
	   obscure the data that was used */
	if( !randomInfo->x917Inited || \
		randomInfo->x917Count >= X917_MAX_CYCLES )
		{
		mixRandomPool( randomInfo );
		status = setKeyX917( randomInfo, randomInfo->randomPool,
							 randomInfo->randomPool + X917_KEYSIZE );
		if( cryptStatusOK( status ) )
			{
			mixRandomPool( randomInfo );
			status = generateX917( randomInfo, randomInfo->randomPool,
								   RANDOMPOOL_ALLOCSIZE );
			}
		if( cryptStatusOK( status ) )
			{
			mixRandomPool( randomInfo );
			generateX917( randomInfo, randomInfo->randomPool,
						  RANDOMPOOL_ALLOCSIZE );
			}
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Precondition for drawing output from the generator: The pool is 
	   sufficiently mixed, there's enough entropy present, and the X9.17 
	   post-processor is ready for use */
	PRE( randomInfo->randomPoolMixes == RANDOMPOOL_MIXES );
	PRE( randomInfo->randomQuality >= 100 );
	PRE( randomInfo->x917Inited );

	/* Initialise the pool to contain the exported random data */
	initRandomPool( &exportedRandomInfo );

	/* Try to obtain random data from the pool */
	for( noRandomRetries = 0; noRandomRetries < RANDOMPOOL_RETRIES;
		 noRandomRetries++ )
		{
		status = tryGetRandomOutput( randomInfo, &exportedRandomInfo );
		if( status != OK_SPECIAL )
			break;
		}

	/* If we ran out of retries so that we're repeating the same output 
	   data or there was an error, fail */
	if( cryptStatusError( status ) )
		{
		endRandomPool( &exportedRandomInfo );

		/* Postcondition: Nulla vestigia retrorsum */
		FORALL( i, 0, RANDOMPOOL_ALLOCSIZE, \
				exportedRandomInfo.randomPool[ i ] == 0 );

		/* We can't trust the pool data any more so we set its quality 
		   estimate to zero.  Ideally we should flash lights and sound 
		   klaxons as well, this is a catastrophic failure */
		randomInfo->randomQuality = 0;
		assert( NOTREACHED );
		return( CRYPT_ERROR_RANDOM );
		}

	/* Postcondition: We produced output without running out of retries */
	POST( noRandomRetries < RANDOMPOOL_RETRIES );

	/* Save a short sample from the current output for future checks */
	PRE( randomInfo->prevOutputIndex >= 0 && \
		 randomInfo->prevOutputIndex < RANDOMPOOL_SAMPLES );
	samplePtr = randomInfo->randomPool;
	randomInfo->prevOutput[ randomInfo->prevOutputIndex ] = mgetLong( samplePtr );
	samplePtr = exportedRandomInfo.randomPool;
	randomInfo->x917PrevOutput[ randomInfo->prevOutputIndex++ ] = mgetLong( samplePtr );
	randomInfo->prevOutputIndex %= RANDOMPOOL_SAMPLES;
	POST( randomInfo->prevOutputIndex >= 0 && \
		  randomInfo->prevOutputIndex < RANDOMPOOL_SAMPLES );

	/* Copy the transformed data to the output buffer, folding it in half as 
	   we go to mask the original content */
	for( i = 0; i < length; i++ )
		buffer[ i ] = exportedRandomInfo.randomPool[ i ] ^ \
					  exportedRandomInfo.randomPool[ RANDOM_OUTPUTSIZE + i ];

	/* Postcondition: We drew at most half of the transformed output from the 
	   export pool */
	POST( i <= RANDOMPOOL_SIZE / 2 );

	/* Clean up */
	endRandomPool( &exportedRandomInfo );

	/* Postcondition: Nulla vestigia retrorsum */
	FORALL( i, 0, RANDOMPOOL_ALLOCSIZE, \
			exportedRandomInfo.randomPool[ i ] == 0 );

	return( CRYPT_OK );
	}

static int getRandomFunction( DEVICE_INFO *deviceInfo, void *buffer,
							  const int length )
	{
	RANDOM_INFO *randomInfo = deviceInfo->randomInfo;
	BYTE *bufPtr = buffer;
	int count;

	/* Clear the return value and make sure that we fail the FIPS 140 tests 
	   on the output if there's a problem */
	zeroise( buffer, length );

	/* Precondition: We're not asking for more data than the maximum needed
	   in any cryptlib operation, which in this case is the size of a
	   maximum-length PKC key */
	PRE( length >= 1 && length <= CRYPT_MAX_PKCSIZE );

	/* Perform a failsafe check to make sure that there's data available.  
	   This should only ever be called once per app because after the first
	   blocking poll the programmer of the calling app will make sure that 
	   there's a slow poll done earlier on */
	if( randomInfo->randomQuality < 100 )
		slowPoll();

	/* Make sure that any background randomness-gathering process has 
	   finished */
	waitforRandomCompletion( FALSE );

	/* If we still can't get any random information, let the user know */
	if( randomInfo->randomQuality < 100 )
		return( CRYPT_ERROR_RANDOM );

	/* If the process has forked, we need to restart the generator output
	   process, but we can't determine this until after we've already
	   produced the output.  If we do need to restart, we do it from this
	   point */
restartPoint:

	/* Prepare to get data from the randomness pool.  Before we do this, we 
	   perform a final quick poll of the system to get any last bit of 
	   entropy, and mix the entire pool.  If the pool hasn't been sufficiently 
	   mixed, we iterate until we've reached the minimum mix count */
	do
		{
		fastPoll();
		mixRandomPool( randomInfo );
		}
	while( randomInfo->randomPoolMixes < RANDOMPOOL_MIXES );

	/* Keep producing RANDOMPOOL_OUTPUTSIZE bytes of output until the request
	   is satisfied */
	for( count = 0; count < length; count += RANDOM_OUTPUTSIZE )
		{
		const int outputBytes = min( length - count, RANDOM_OUTPUTSIZE );
		int status;
		ORIGINAL_PTR( bufPtr );

		/* Precondition for output quantity: Either we're on the last output
		   block or we're producing the maximum-size output quantity, and
		   we're never trying to use more than half the pool contents */
		PRE( length - count < RANDOM_OUTPUTSIZE || \
			 outputBytes == RANDOM_OUTPUTSIZE );
		PRE( outputBytes <= RANDOMPOOL_SIZE / 2 );

		status = getRandomOutput( randomInfo, bufPtr, outputBytes );
		if( cryptStatusError( status ) )
			return( status );
		bufPtr += outputBytes;

		/* Postcondition: We're filling the output buffer and we wrote the
		   output to the correct portion of the output buffer */
		POST( ( bufPtr > ( BYTE * ) buffer ) && \
			  ( bufPtr <= ( BYTE * ) buffer + length ) );
		POST( bufPtr == ORIGINAL_VALUE( bufPtr ) + outputBytes );
		}

	/* Postcondition: We filled the output buffer with the required amount
	   of output */
	POST( bufPtr == ( BYTE * ) buffer + length );

	/* Check whether the process forked while we were generating output.  If
	   it did, force a complete remix of the pool and restart the output
	   generation process (the fast poll will ensure that the pools in the
	   parent and child differ) */
	if( checkForked() )
		{
		randomInfo->randomPoolMixes = 0;
		bufPtr = buffer;
		goto restartPoint;
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Device Init/Shutdown/Device Control Routines			*
*																			*
****************************************************************************/

/* Initialise and shut down the system device */

static int initFunction( DEVICE_INFO *deviceInfo, const char *name,
						 const int nameLength )
	{
	STATIC_FN void initCapabilities( void );
	int status;

	UNUSED( name );

	/* Set up the randomness info */
	status = initRandomInfo( deviceInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Set up the capability information for this device and mark it as
	   active */
	initCapabilities();
	deviceInfo->label = "cryptlib system device";
	deviceInfo->flags = DEVICE_ACTIVE | DEVICE_LOGGEDIN | DEVICE_TIME;
	return( CRYPT_OK );
	}

static void shutdownFunction( DEVICE_INFO *deviceInfo )
	{
	endRandomInfo( deviceInfo );
	}

/* Handle device control functions */

static int controlFunction( DEVICE_INFO *deviceInfo,
							const CRYPT_ATTRIBUTE_TYPE type,
							const void *data, const int dataLength )
	{
	assert( type == CRYPT_IATTRIBUTE_ENTROPY || \
			type == CRYPT_IATTRIBUTE_ENTROPY_QUALITY || \
			type == CRYPT_IATTRIBUTE_RANDOM_NONCE || \
			type == CRYPT_IATTRIBUTE_SELFTEST || \
			type == CRYPT_IATTRIBUTE_TIME );

	/* Handle entropy addition */
	if( type == CRYPT_IATTRIBUTE_ENTROPY )
		{
		RANDOM_INFO *randomInfo = deviceInfo->randomInfo;
		BYTE *bufPtr = ( BYTE * ) data;
		int count = dataLength;
		ORIGINAL_INT_VAR( entropyByteCount, randomInfo->entropyByteCount );
		ORIGINAL_PTR( data );

		/* Precondition: The current entropy byte count has a sensible 
		   value */
		PRE( randomInfo->entropyByteCount >= 0 );

		/* Mix the incoming data into the pool.  This operation is resistant
		   to chosen- and known-input attacks because the pool contents are
		   unknown to an attacker, so XORing in known data won't help them.
		   If an attacker could determine pool contents by observing the
		   generator output (which is defeated by the postprocessing), we'd
		   have to perform an extra input mixing operation to defeat these
		   attacks */
		while( count-- )
			{
			ORIGINAL_INT_VAR( bufVal, *bufPtr );
			DECLARE_ORIGINAL_INT( poolVal );
			DECLARE_ORIGINAL_INT( newPoolVal );
			DECLARE_ORIGINAL_INT( poolPos );

			/* If the pool write position has reached the end of the pool, 
			   mix the pool */
			if( randomInfo->randomPoolPos >= RANDOMPOOL_SIZE )
				mixRandomPool( randomInfo );

			STORE_ORIGINAL_INT( poolVal,
								randomInfo->randomPool[ randomInfo->randomPoolPos ] );
			STORE_ORIGINAL_INT( poolPos, randomInfo->randomPoolPos );

			/* Precondition: We're adding data inside the pool */
			PRE( randomInfo->randomPoolPos >= 0 && \
				 randomInfo->randomPoolPos < RANDOMPOOL_SIZE );

			randomInfo->randomPool[ randomInfo->randomPoolPos++ ] ^= *bufPtr++;

			STORE_ORIGINAL_INT( newPoolVal,
								randomInfo->randomPool[ randomInfo->randomPoolPos - 1 ] );

			/* Postcondition: We've updated the byte at the current pool
			   position, and the value really was XORed into the pool rather
			   than (for example) overwriting it as with PGP/xorbytes or
			   GPG/add_randomness.  Note that in this case we can use a non-
			   XOR operation to check that the XOR succeeded, unlike the pool
			   mixing code which requires an XOR to check the original XOR */
			POST( randomInfo->randomPoolPos == \
				  ORIGINAL_VALUE( poolPos ) + 1 );
			POST( ( ( ORIGINAL_VALUE( newPoolVal ) == \
					  ORIGINAL_VALUE( bufVal ) ) && \
					( ORIGINAL_VALUE( poolVal ) == 0 ) ) || \
				  ( ORIGINAL_VALUE( newPoolVal ) != \
				    ORIGINAL_VALUE( bufVal ) ) );
			}

		/* Remember how many bytes of entropy we added on this update */
		randomInfo->entropyByteCount += dataLength;

		/* Postcondition: We processed all of the data */
		POST( bufPtr == ORIGINAL_VALUE( data ) + dataLength );
		POST( randomInfo->entropyByteCount == \
			  ORIGINAL_VALUE( entropyByteCount ) + dataLength );

		return( CRYPT_OK );
		}
	if( type == CRYPT_IATTRIBUTE_ENTROPY_QUALITY )
		{
		RANDOM_INFO *randomInfo = deviceInfo->randomInfo;

		/* If there's not enough entropy data present to justify the claimed 
		   entropy quality level, signal an error */
		if( randomInfo->entropyByteCount <= 0 || \
			dataLength / 2 > randomInfo->entropyByteCount )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_RANDOM );
			}
		randomInfo->entropyByteCount = 0;

		/* If we haven't reached the minimum quality level for generating
		   keys yet, update the quality level */
		if( randomInfo->randomQuality < 100 )
			randomInfo->randomQuality += dataLength;
		return( CRYPT_OK );
		}

	/* Handle nonces */
	if( type == CRYPT_IATTRIBUTE_RANDOM_NONCE )
		{
		static BOOLEAN nonceDataInitialised = FALSE;
		static BYTE nonceData[ CRYPT_MAX_HASHSIZE + 8 ];
		static HASHFUNCTION hashFunction;
		static int hashSize;
		BYTE *noncePtr = ( BYTE * ) data;
		int nonceLength = dataLength;

		/* Get a random (but not necessarily cryptographically strong random) 
		   nonce.  Some nonces can simply be fresh (for which a monotonically 
		   increasing sequence will do), some should be random (for which a 
		   hash of the sequence is adequate), and some need to be 
		   unpredictable.  In order to avoid problems arising from the
		   inadvertent use of a nonce with the wrong properties, we use 
		   unpredictable nonces in all cases, even where it isn't strictly 
		   necessary.
   
		   This simple generator divides the nonce state up into a public 
		   section of the same size as the hash output, and a private section 
		   which contains 64 bits of data from the crypto RNG which 
		   influences the public section.  The public and private sections 
		   are repeatedly hashed to produce the required amount of output.  
		   Note that this leaks a small amount of information about the 
		   crypto RNG output since an attacker knows that 
		   public_state_n = hash( public_state_n - 1, private_state ), but 
		   this isn't a major weakness.

		   If the nonce generator hasn't been initialised yet, we set up the 
		   hashing and get 64 bits of private nonce state.  What to do if 
		   the attempt to initialise the state fails is somewhat debatable.  
		   Since nonces are only ever used in protocols alongside crypto 
		   keys, and an RNG failure will be detected when the key is 
		   generated, we can generally ignore a failure at this point.
		   However, nonces are sometimes also used in non-crypto contexts 
		   (for example to generate cert serial numbers) where this 
		   detection in the RNG won't happen.  On the other hand we 
		   shouldn't really abort processing just because we can't get some 
		   no-value nonce data, so what we do is retry the fetch of nonce 
		   data (in case the system object was busy and the first attempt 
		   timed out), and if that fails too fall back to the system time.  
		   This is no longer unpredictable, but the only location where 
		   unpredictability matters is when used in combination with crypto 
		   operations, for which the absence of random data will be detected 
		   during key generation */
		if( !nonceDataInitialised )
			{
			RESOURCE_DATA msgData;
			int status;

			getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
			setMessageData( &msgData, nonceData + hashSize, 8 );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
									  IMESSAGE_GETATTRIBUTE_S, &msgData, 
									  CRYPT_IATTRIBUTE_RANDOM );
			if( cryptStatusError( status ) )
				status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
										  IMESSAGE_GETATTRIBUTE_S, &msgData, 
										  CRYPT_IATTRIBUTE_RANDOM );
			if( cryptStatusError( status ) )
				{
				const time_t theTime = getTime();

				memcpy( nonceData + hashSize, &theTime, sizeof( time_t ) );
				}
			nonceDataInitialised = TRUE;
			}

		/* Shuffle the public state and copy it to the output buffer until 
		   it's full */
		while( nonceLength > 0 )
			{
			const int bytesToCopy = min( nonceLength, hashSize );

			/* Hash the state and copy the appropriate amount of data to the 
			   output buffer */
			hashFunction( NULL, nonceData, nonceData, hashSize + 8, 
						  HASH_ALL );
			memcpy( noncePtr, nonceData, bytesToCopy );

			/* Move on to the next block of the output buffer */
			noncePtr += bytesToCopy;
			nonceLength -= bytesToCopy;
			}

		return( CRYPT_OK );
		}

	/* Handle algorithm self-test */
	if( type == CRYPT_IATTRIBUTE_SELFTEST )
		{
		const CAPABILITY_INFO *capabilityInfoPtr = deviceInfo->capabilityInfo;

		while( capabilityInfoPtr != NULL )
			{
			const CRYPT_ALGO_TYPE cryptAlgo = capabilityInfoPtr->cryptAlgo;
			int status;

			assert( capabilityInfoPtr->selfTestFunction != NULL );

			/* Perform the self-test for this algorithm type and skip to the
			   next algorithm */
			status = capabilityInfoPtr->selfTestFunction();
			if( cryptStatusError( status ) )
				return( status );
			while( capabilityInfoPtr != NULL && \
				   capabilityInfoPtr->cryptAlgo == cryptAlgo )
				capabilityInfoPtr = capabilityInfoPtr->next;
			}

		return( CRYPT_OK );
		}

	/* Handle high-reliability time */
	if( type == CRYPT_IATTRIBUTE_TIME )
		{
		time_t *timePtr = ( time_t * ) data;

		*timePtr = getTime();
		return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/****************************************************************************
*																			*
*							Random Pool External Interface					*
*																			*
****************************************************************************/

/* Add random data to the random pool.  This should eventually be replaced 
   by some sort of device control mechanism, the problem with doing this is
   that it's handled by the system device which isn't visible to the user */

C_RET cryptAddRandom( C_IN void C_PTR randomData, C_IN int randomDataLength )
	{
	/* Perform basic error checking */
	if( randomData == NULL )
		{
		if( randomDataLength != CRYPT_RANDOM_FASTPOLL && \
			randomDataLength != CRYPT_RANDOM_SLOWPOLL )
			return( CRYPT_ERROR_PARAM1 );
		}
	else
		{
		if( randomDataLength <= 0 || randomDataLength > MAX_INTLENGTH )
			return( CRYPT_ERROR_PARAM2 );
		if( checkBadPtrRead( randomData, randomDataLength ) )
			return( CRYPT_ERROR_PARAM1 );
		}

	/* If we're adding data to the pool, add it now and exit.  Since the data
	   is of unknown provenance (and empirical evidence indicates that it
	   won't be very random) we give it a weight of zero for estimation 
	   purposes */
	if( randomData != NULL )
		{
		RESOURCE_DATA msgData;

#ifndef NDEBUG	/* For debugging tests only */
if( randomDataLength == 5 && !memcmp( randomData, "xyzzy", 5 ) )
{
BYTE buffer[ 256 ];
int kludge = 100;
#ifndef __MAC__
printf( "Kludging randomness, file " __FILE__ ", line %d.\n", __LINE__ );
#endif /* __MAC__ */
memset( buffer, '*', 256 );
setMessageData( &msgData, buffer, 256 );
krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_SETATTRIBUTE_S, 
				 &msgData, CRYPT_IATTRIBUTE_ENTROPY );
krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_SETATTRIBUTE,
				 &kludge, CRYPT_IATTRIBUTE_ENTROPY_QUALITY );
}
#endif /* NDEBUG */

		setMessageData( &msgData, ( void * ) randomData, randomDataLength );
		return( krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								 IMESSAGE_SETATTRIBUTE_S, &msgData, 
								 CRYPT_IATTRIBUTE_ENTROPY ) );
		}

	/* Perform either a fast or slow poll for random system data */
	if( randomDataLength == CRYPT_RANDOM_FASTPOLL )
		fastPoll();
	else
		slowPoll();

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Device Capability Routines						*
*																			*
****************************************************************************/

/* The cryptlib intrinsic capability list */

static CAPABILITY_INFO FAR_BSS capabilities[] = {
	/* The DES capabilities */
	{ CRYPT_ALGO_DES, bits( 64 ), "DES",
		bits( 40 ), bits( 64 ), bits( 64 ),
		desSelfTest, desGetInfo, NULL, initKeyParams, desInitKey, NULL,
		desEncryptECB, desDecryptECB, desEncryptCBC, desDecryptCBC,
		desEncryptCFB, desDecryptCFB, desEncryptOFB, desDecryptOFB },

	/* The triple DES capabilities.  Unlike the other algorithms, the minimum
	   key size here is 64 + 8 bits (nominally 56 + 1 bits) because using a
	   key any shorter is (a) no better than single DES, and (b) will result
	   in a key load error since the second key will be an all-zero weak
	   key.  We also give the default key size as 192 bits instead of 128 to
	   make sure that anyone using a key of the default size ends up with
	   three-key 3DES rather than two-key 3DES */
	{ CRYPT_ALGO_3DES, bits( 64 ), "3DES",
		bits( 64 + 8 ), bits( 192 ), bits( 192 ),
		des3SelfTest, des3GetInfo, NULL, initKeyParams, des3InitKey, NULL,
		des3EncryptECB, des3DecryptECB, des3EncryptCBC, des3DecryptCBC,
		des3EncryptCFB, des3DecryptCFB, des3EncryptOFB, des3DecryptOFB },

#ifdef USE_IDEA
	/* The IDEA capabilities */
	{ CRYPT_ALGO_IDEA, bits( 64 ), "IDEA",
		bits( 40 ), bits( 128 ), bits( 128 ),
		ideaSelfTest, ideaGetInfo, NULL, initKeyParams, ideaInitKey, NULL,
		ideaEncryptECB, ideaDecryptECB, ideaEncryptCBC, ideaDecryptCBC,
		ideaEncryptCFB, ideaDecryptCFB, ideaEncryptOFB, ideaDecryptOFB },
#endif /* USE_IDEA */

#ifdef USE_CAST
	/* The CAST-128 capabilities */
	{ CRYPT_ALGO_CAST, bits( 64 ), "CAST-128",
		bits( 40 ), bits( 128 ), bits( 128 ),
		castSelfTest, castGetInfo, NULL, initKeyParams, castInitKey, NULL,
		castEncryptECB, castDecryptECB, castEncryptCBC, castDecryptCBC,
		castEncryptCFB, castDecryptCFB, castEncryptOFB, castDecryptOFB },
#endif /* USE_CAST */

#ifdef USE_RC2
	/* The RC2 capabilities */
	{ CRYPT_ALGO_RC2, bits( 64 ), "RC2",
		bits( 40 ), bits( 128 ), bits( 1024 ),
		rc2SelfTest, rc2GetInfo, NULL, initKeyParams, rc2InitKey, NULL,
		rc2EncryptECB, rc2DecryptECB, rc2EncryptCBC, rc2DecryptCBC,
		rc2EncryptCFB, rc2DecryptCFB, rc2EncryptOFB, rc2DecryptOFB },
#endif /* USE_RC2 */

#ifdef USE_RC4
	/* The RC4 capabilities */
	{ CRYPT_ALGO_RC4, bits( 8 ), "RC4",
		bits( 40 ), bits( 128 ), 256,
		rc4SelfTest, rc4GetInfo, NULL, initKeyParams, rc4InitKey, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, rc4Encrypt, rc4Encrypt },
#endif /* USE_RC4 */

#ifdef USE_RC5
	/* The RC5 capabilities */
	{ CRYPT_ALGO_RC5, bits( 64 ), "RC5",
		bits( 40 ), bits( 128 ), bits( 832 ),
		rc5SelfTest, rc5GetInfo, NULL, initKeyParams, rc5InitKey, NULL,
		rc5EncryptECB, rc5DecryptECB, rc5EncryptCBC, rc5DecryptCBC,
		rc5EncryptCFB, rc5DecryptCFB, rc5EncryptOFB, rc5DecryptOFB },
#endif /* USE_RC5 */

	/* The AES capabilities */
	{ CRYPT_ALGO_AES, bits( 128 ), "AES",
		bits( 128 ), bits( 128 ), bits( 256 ),
		aesSelfTest, aesGetInfo, NULL, initKeyParams, aesInitKey, NULL,
		aesEncryptECB, aesDecryptECB, aesEncryptCBC, aesDecryptCBC,
		aesEncryptCFB, aesDecryptCFB, aesEncryptOFB, aesDecryptOFB },

	/* The Blowfish capabilities */
	{ CRYPT_ALGO_BLOWFISH, bits( 64 ), "Blowfish",
		bits( 40 ), bits( 128 ), bits( 448 ),
		blowfishSelfTest, blowfishGetInfo, NULL, initKeyParams, blowfishInitKey, NULL,
		blowfishEncryptECB, blowfishDecryptECB, blowfishEncryptCBC, blowfishDecryptCBC,
		blowfishEncryptCFB, blowfishDecryptCFB, blowfishEncryptOFB, blowfishDecryptOFB },

#ifdef USE_SKIPJACK
	/* The Skipjack capabilities */
	{ CRYPT_ALGO_SKIPJACK, bits( 64 ), "Skipjack",
		bits( 80 ), bits( 80 ), bits( 80 ),
		skipjackSelfTest, skipjackGetInfo, NULL, initKeyParams, skipjackInitKey, NULL,
		skipjackEncryptECB, skipjackDecryptECB, skipjackEncryptCBC, skipjackDecryptCBC,
		skipjackEncryptCFB, skipjackDecryptCFB, skipjackEncryptOFB, skipjackDecryptOFB },
#endif /* USE_SKIPJACK */

#ifdef USE_MD2
	/* The MD2 capabilities */
	{ CRYPT_ALGO_MD2, bits( 128 ), "MD2",
		bits( 0 ), bits( 0 ), bits( 0 ),
		md2SelfTest, md2GetInfo, NULL, NULL, NULL, NULL, md2Hash, md2Hash },
#endif /* USE_MD2 */

#ifdef USE_MD4
	/* The MD4 capabilities */
	{ CRYPT_ALGO_MD4, bits( 128 ), "MD4",
		bits( 0 ), bits( 0 ), bits( 0 ),
		md4SelfTest, md4GetInfo, NULL, NULL, NULL, NULL, md4Hash, md4Hash },
#endif /* USE_MD4 */

	/* The MD5 capabilities */
	{ CRYPT_ALGO_MD5, bits( 128 ), "MD5",
		bits( 0 ), bits( 0 ), bits( 0 ),
		md5SelfTest, md5GetInfo, NULL, NULL, NULL, NULL, md5Hash, md5Hash },

	/* The SHA1 capabilities */
	{ CRYPT_ALGO_SHA, bits( 160 ), "SHA",
		bits( 0 ), bits( 0 ), bits( 0 ),
		shaSelfTest, shaGetInfo, NULL, NULL, NULL, NULL, shaHash, shaHash },

#ifdef USE_RIPEMD160
	/* The RIPEMD-160 capabilities */
	{ CRYPT_ALGO_RIPEMD160, bits( 160 ), "RIPEMD-160",
		bits( 0 ), bits( 0 ), bits( 0 ),
		ripemd160SelfTest, ripemd160GetInfo, NULL, NULL, NULL, NULL,
		ripemd160Hash, ripemd160Hash },
#endif /* USE_RIPEMD160 */

#ifdef USE_SHA2
	/* The SHA2 capabilities */
	{ CRYPT_ALGO_SHA2, bits( 256 ), "SHA2",
		bits( 0 ), bits( 0 ), bits( 0 ),
		sha2SelfTest, sha2GetInfo, NULL, NULL, NULL, NULL, sha2Hash, sha2Hash },
#endif /* USE_SHA2 */

#ifdef USE_HMAC_MD5
	/* The HMAC-MD5 capabilities */
	{ CRYPT_ALGO_HMAC_MD5, bits( 128 ), "HMAC-MD5",
		bits( 40 ), bits( 128 ), CRYPT_MAX_KEYSIZE,
		hmacMD5SelfTest, hmacMD5GetInfo, NULL, NULL, hmacMD5InitKey,
		NULL, hmacMD5Hash, hmacMD5Hash },
#endif /* USE_HMAC_MD5 */

	/* The HMAC-SHA capabilities */
	{ CRYPT_ALGO_HMAC_SHA, bits( 160 ), "HMAC-SHA",
		bits( 40 ), bits( 128 ), CRYPT_MAX_KEYSIZE,
		hmacSHASelfTest, hmacSHAGetInfo, NULL, NULL, hmacSHAInitKey,
		NULL, hmacSHAHash, hmacSHAHash },

#ifdef USE_HMAC_RIPEMD160
	/* The HMAC-RIPEMD160 capabilities */
	{ CRYPT_ALGO_HMAC_RIPEMD160, bits( 160 ), "HMAC-RIPEMD160",
		bits( 40 ), bits( 128 ), CRYPT_MAX_KEYSIZE,
		hmacRIPEMD160SelfTest, hmacRIPEMD160GetInfo, NULL, NULL, hmacRIPEMD160InitKey,
		NULL, hmacRIPEMD160Hash, hmacRIPEMD160Hash },
#endif /* USE_HMAC_RIPEMD160 */

	/* The Diffie-Hellman capabilities */
	{ CRYPT_ALGO_DH, bits( 0 ), "Diffie-Hellman",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE,
		dhSelfTest, getInfo, NULL, NULL, dhInitKey, dhGenerateKey,
		dhEncrypt, dhDecrypt },

	/* The RSA capabilities */
	{ CRYPT_ALGO_RSA, bits( 0 ), "RSA",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE,
		rsaSelfTest, getInfo, NULL, NULL, rsaInitKey, rsaGenerateKey,
		rsaEncrypt, rsaDecrypt, NULL, NULL, NULL, NULL, NULL, NULL,
		rsaDecrypt, rsaEncrypt },

	/* The DSA capabilities */
	{ CRYPT_ALGO_DSA, bits( 0 ), "DSA",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE,
		dsaSelfTest, getInfo, NULL, NULL, dsaInitKey, dsaGenerateKey,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		dsaSign, dsaSigCheck },

#ifdef USE_ELGAMAL
	/* The ElGamal capabilities */
	{ CRYPT_ALGO_ELGAMAL, bits( 0 ), "Elgamal",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE,
		elgamalSelfTest, getInfo, NULL, NULL, elgamalInitKey, elgamalGenerateKey,
		elgamalEncrypt, elgamalDecrypt, NULL, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL },
#endif /* USE_ELGAMAL */

	/* Vendors may want to use their own algorithms which aren't part of the
	   general cryptlib suite.  The following provides the ability to include
	   vendor-specific algorithm capabilities defined in the file
	   vendalgo.c */
#ifdef USE_VENDOR_ALGOS
	#include "vendalgo.c"
#endif /* USE_VENDOR_ALGOS */

	/* The end-of-list marker.  This value isn't linked into the
	   capabilities list when we call initCapabilities() */
	{ CRYPT_ALGO_NONE }
	};

/* Initialise the capability info */

static void initCapabilities( void )
	{
	CAPABILITY_INFO *prevCapabilityInfoPtr = NULL;
	int i;

	/* Perform a consistency check on the encryption mode values, which
	   are used to index a table of per-mode function pointers */
	assert( CRYPT_MODE_CBC == CRYPT_MODE_ECB + 1 && \
			CRYPT_MODE_CFB == CRYPT_MODE_CBC + 1 && \
			CRYPT_MODE_OFB == CRYPT_MODE_CFB + 1 && \
			CRYPT_MODE_LAST == CRYPT_MODE_OFB + 1 );

	for( i = 0; capabilities[ i ].cryptAlgo != CRYPT_ALGO_NONE; i++ )
		{
		assert( capabilityInfoOK( &capabilities[ i ], FALSE ) );
		if( prevCapabilityInfoPtr != NULL )
			prevCapabilityInfoPtr->next = &capabilities[ i ];
		prevCapabilityInfoPtr = &capabilities[ i ];
		}
	}

/****************************************************************************
*																			*
*						 	Device Access Routines							*
*																			*
****************************************************************************/

/* Set up the function pointers to the device methods */

int setDeviceSystem( DEVICE_INFO *deviceInfo )
	{
	deviceInfo->initFunction = initFunction;
	deviceInfo->shutdownFunction = shutdownFunction;
	deviceInfo->controlFunction = controlFunction;
	deviceInfo->getRandomFunction = getRandomFunction;
	deviceInfo->capabilityInfo = capabilities;
	deviceInfo->createObjectFunctions = createObjectFunctions;
	deviceInfo->mechanismFunctions = mechanismFunctions;

	return( CRYPT_OK );
	}
