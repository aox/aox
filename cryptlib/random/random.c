/****************************************************************************
*																			*
*					cryptlib Randomness Management Routines					*
*						Copyright Peter Gutmann 1995-2004					*
*																			*
****************************************************************************/

/* The random pool handling code in this module and the other modules in the
   /random subdirectory represent the cryptlib continuously seeded
   pseudorandom number generator (CSPRNG) as described in my 1998 Usenix
   Security Symposium paper "The generation of practically strong random
   numbers".

   The CSPRNG code is copyright Peter Gutmann (and various others) 1995-2004
   all rights reserved.  Redistribution of the CSPRNG modules and use in
   source and binary forms, with or without modification, are permitted
   provided that the following BSD-style license conditions are met:

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
  #ifdef CONFIG_RANDSEED
	#include "stream.h"
  #endif /* CONFIG_RANDSEED */
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../crypt/des.h"
  #ifdef CONFIG_RANDSEED
	#include "../misc/stream.h"
  #endif /* CONFIG_RANDSEED */
#else
  #include "crypt.h"
  #include "crypt/des.h"
  #ifdef CONFIG_RANDSEED
	#include "misc/stream.h"
  #endif /* CONFIG_RANDSEED */
#endif /* Compiler-specific includes */

/* The maximum amount of random data needed by any cryptlib operation, 
   equivalent to the size of a maximum-length PKC key.  However this isn't 
   the absolute length because when generating the k value for DLP 
   operations we get n + m bits and then reduce via one of the DLP 
   parameters to get the value within range.  If we just got n bits, this 
   would introduce a bias into the top bit, see the DLP code for more 
   details.  Because of this we allow a length slightly larger than the 
   maximum PKC key size */

#define MAX_RANDOM_BYTES	( CRYPT_MAX_PKCSIZE + 8 )

/* If we don't have a defined randomness interface, complain */

#if !( defined( __BEOS__ ) || defined( __IBM4758__ ) || \
	   defined( __MAC__ ) || defined( __MSDOS__ ) || defined( __MVS__ ) || \
	   defined( __OS2__ ) || defined( __PALMOS__ ) || \
	   defined( __TANDEM_NSK__ ) || defined( __TANDEM_OSS__ ) || \
	   defined( __UNIX__ ) || defined( __VMCMS__ ) || \
	   defined( __WIN16__ ) || defined( __WIN32__ ) || \
	   defined( __WINCE__ ) )
  #error You need to create OS-specific randomness-gathering functions in random/<os-name>.c
#endif /* Various OS-specific defines */

/* If we're using stored seed data, make sure that the seed update count and 
   quality settings are in order */

#ifdef CONFIG_RANDSEED
  #if CONFIG_RANDSEED < 0
	#error CONFIG_RANDSEED must be >= 0
  #endif /* CONFIG_RANDSEED < 0 */
  #ifndef CONFIG_RANDSEED_QUALITY
	/* If the user hasn't provided a quality estimate, default to 80 */
	#define CONFIG_RANDSEED_QUALITY		80
  #endif /* !CONFIG_RANDSEED_QUALITY */
  #if ( CONFIG_RANDSEED_QUALITY < 10 ) || ( CONFIG_RANDSEED_QUALITY > 100 )
	#error CONFIG_RANDSEED_QUALITY must be between 10 and 100
  #endif /* CONFIG_RANDSEED_QUALITY check */
#endif /* CONFIG_RANDSEED */

/* Some systems systems require special-case initialisation to allow
   background randomness gathering, where this doesn't apply the routines to
   do this are nop'd out */

#if defined( __WIN32__ ) || defined( __WINCE__ )
  void initRandomPolling( void );
  void endRandomPolling( void );
  void waitforRandomCompletion( const BOOLEAN force );
#elif defined( __UNIX__ ) && \
	  !( defined( __MVS__ ) || defined( __TANDEM_NSK__ ) || \
		 defined( __TANDEM_OSS__ ) )
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

#if defined( __UNIX__ ) && \
	!( defined( __MVS__ ) || defined( __TANDEM_NSK__ ) || \
	   defined( __TANDEM_OSS__ ) )
  BOOLEAN checkForked( void );
#else
  #define checkForked()		FALSE
#endif /* __UNIX__ */

/* Prototypes for functions in the OS-specific randomness polling routines */

void slowPoll( void );
void fastPoll( void );

/****************************************************************************
*																			*
*						Randomness Interface Definitions					*
*																			*
****************************************************************************/

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
   continuous tests, and the number of retries that we perform if we detect 
   a repeat of a previous output */

#define RANDOMPOOL_SAMPLES		16
#define RANDOMPOOL_RETRIES		5

/* The number of times that we cycle the X9.17 generator before we load new
   key and state variables.  This means that we re-seed for every
   X917_MAX_BYTES of output produced */

#define X917_MAX_BYTES			4096
#define X917_MAX_CYCLES			( X917_MAX_BYTES / X917_POOLSIZE )

/* The scheduled DES keys for the X9.17 generator */

typedef struct {
	Key_schedule desKey1, desKey2, desKey3;
	} X917_3DES_KEY;

#define DES_KEYSIZE		sizeof( Key_schedule )

/* The size of the X9.17 generator key (112 bits for EDE 3DES) */

#define X917_KEYSIZE	16

/* Random pool information.  We keep track of the write position in the 
   pool, which tracks where new data is added.  Whenever we add new data the 
   write position is updated, once we reach the end of the pool we mix the 
   pool and start again at the beginning.  We track the pool status by 
   recording the quality of the pool contents (1-100) and the number of 
   times the pool has been mixed, we can't draw data from the pool unless 
   both of these values have reached an acceptable level.  In addition to 
   the pool state information we keep track of the previous 
   RANDOMPOOL_SAMPLES output samples to check for stuck-at faults or (short) 
   cyles */

typedef struct {
	/* Pool state information */
	BYTE randomPool[ RANDOMPOOL_ALLOCSIZE ];	/* Random byte pool */
	int randomPoolPos;		/* Current write position in the pool */

	/* Pool status information */
	int randomQuality;		/* Level of randomness in the pool */
	int randomPoolMixes;	/* Number of times pool has been mixed */

	/* X9.17 generator state information */
	BYTE x917Pool[ X917_POOLSIZE ];	/* Generator state */
	BYTE x917DT[ X917_POOLSIZE ];	/* Date/time vector */
	X917_3DES_KEY x917Key;	/* Scheduled 3DES key */
	BOOLEAN x917Inited;		/* Whether generator has been inited */
	int x917Count;			/* No.of times generator has been cycled */
	BOOLEAN x917x931;		/* X9.17 vs. X9.31 operation (see code comments */

	/* Information for the FIPS 140 continuous tests */
	unsigned long prevOutput[ RANDOMPOOL_SAMPLES ];
	unsigned long x917PrevOutput[ RANDOMPOOL_SAMPLES ];
	int prevOutputIndex;

	/* Other status information used to check the pool's operation */
	int entropyByteCount;	/* Number of bytes entropy added */

	/* Random seed data information if seeding is done from a stored seed */
#ifdef CONFIG_RANDSEED
	BOOLEAN seedProcessed;	/* Whether stored seed has been processed */
	int seedSize;			/* Size of stored seed data */
	int seedUpdateCount;	/* When to update stored seed data */
#endif /* CONFIG_RANDSEED */
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
	   length and that bufSize > bufPos) */
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
		   persistent.  Normally this is a should-never-occur error, however 
		   if cryptlib has been shut down from another thread the kernel 
		   will fail all non shutdown-related calls with a permission error.  
		   To avoid false alarms, we mask out failures due to permission 
		   errors */
		state->updateStatus = status;
		assert( ( status == CRYPT_ERROR_PERMISSION ) || NOTREACHED );
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
	   system device.  A failure at this point is a should-never-occur 
	   error, however if cryptlib has been shut down from another thread 
	   the kernel will fail all non shutdown-related calls with a permission 
	   error.  To avoid false alarms, we mask out failures due to permission 
	   errors */
	if( state->bufPos > 0 && state->bufPos <= state->bufSize && \
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
	assert( cryptStatusOK( status ) || ( status == CRYPT_ERROR_PERMISSION ) );

	/* If everything went OK, set the quality estimate for the data that
	   we've added */
	if( cryptStatusOK( status ) && quality > 0 )
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_SETATTRIBUTE, ( void * ) &quality,
								  CRYPT_IATTRIBUTE_ENTROPY_QUALITY );
	assert( cryptStatusOK( status ) || ( status == CRYPT_ERROR_PERMISSION ) );

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

/* Initialise and shut down the random pool */

static void initRandomPool( RANDOM_INFO *randomInfo )
	{
	memset( randomInfo, 0, sizeof( RANDOM_INFO ) );
	}

static void endRandomPool( RANDOM_INFO *randomInfo )
	{
	zeroise( randomInfo, sizeof( RANDOM_INFO ) );
	}

/* Stir up the data in the random pool.  Given a circular buffer of length n 
   bytes, a buffer position p, and a hash output size of h bytes, we hash
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
		poolIndex = ( hashIndex > 0 ) ? hashIndex - hashSize : \
										RANDOMPOOL_SIZE - hashSize;

		/* Copy hashSize bytes from position p - 19...p - 1 in the circular
		   pool into the hash data buffer.  We do this manually rather than
		   using memcpy() in order for the assertion-based testing (which
		   checks the source and desitnation index values) to work */
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
   generates output, and a horrible vulnerability to state compromise.  For 
   FIPS 140 compliance however we need to use an approved generator (even
   though Annex C is informative rather than normative and contains only "an
   example of a pseudorandom key and IV generator" so that it could be argued
   that any generator based on X9.17 3DES is permitted), which is why this
   generator appears here.

   In order to minimise the potential for damage we employ it as a post-
   processor for the pool (since X9.17 produces a 1-1 mapping, it can never
   make the output any worse), using as our timestamp input the main RNG
   output.  This is perfectly valid since X9.17 requires the use of DT, "a
   date/time vector which is updated on each key generation", a requirement
   which is met by the fastPoll() which is performed before the main pool is
   mixed.  The cryptlib representation of the date and time vector is as a
   hash of assorted incidental data and the date and time.  The fact that 
   99.9999% of the value of the generator is coming from the, uhh, timestamp 
   is as coincidental as the side effect of the engine cooling fan in the 
   Brabham ground effect cars.
   
   Some eval labs may not like this use of DT, in which case it's also 
   possible to inject the extra seed material into the generator by using 
   the X9.31 interpretation of X9.17, which makes the V value an externally-
   modifiable value.  In this interpretation the generator design has 
   degenerated to little more than a 3DES encryption of V, which can hardly 
   have been the intent of the X9.17 designers.  In other words the X9.17 
   operation:

	out = Enc( Enc( in ) ^ V(n) );
	V(n+1) = Enc( Enc( in ) ^ out );

   degenerates to:

	out = Enc( Enc( DT ) ^ in );

   since V is overwritten on each iteration.  If the eval lab requires this 
   interpretation rather than the more sensible DT one then this can be
   enabled by clearing the seedViaDT flag in setKeyX917((), although we 
   don't do it by default since it's so far removed from the real X9.17 
   generator */

/* A macro to make what's being done by the generator easier to follow */

#define tdesEncrypt( data, key ) \
		des_ecb3_encrypt( ( C_Block * ) ( data ), ( C_Block * ) ( data ), \
						  ( key )->desKey1, ( key )->desKey2, \
						  ( key )->desKey3, DES_ENCRYPT )

/* Set the X9.17 generator key */

static int setKeyX917( RANDOM_INFO *randomInfo, const BYTE *key,
					   const BYTE *state, const BYTE *dateTime )
	{
	X917_3DES_KEY *des3Key = &randomInfo->x917Key;
	int desStatus;

	/* Make sure that the key and seed aren't being taken from the same 
	   location */
	assert( memcmp( key, state, X917_POOLSIZE ) );

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

	/* Set up the generator state value V(0) and DT if we're using the X9.31
	   interpretation */
	memcpy( randomInfo->x917Pool, state, X917_POOLSIZE );
	if( dateTime != NULL )
		{
		memcpy( randomInfo->x917DT, dateTime, X917_POOLSIZE );
		randomInfo->x917x931 = TRUE;
		}

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
	BYTE encTime[ X917_POOLSIZE ], *dataPtr = data;
	int dataBlockPos;

	/* Sanity check to make sure that the generator has been initialised */
	if( !randomInfo->x917Inited )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_RANDOM );
		}

	/* Precondition: We're not asking for more data than the maximum that
	   should be needed, the generator has been initialised, and the
	   cryptovariables aren't past their use-by date */
	PRE( length >= 1 && length <= MAX_RANDOM_BYTES );
	PRE( randomInfo->x917Inited == TRUE );
	PRE( randomInfo->x917Count >= 0 && \
		 randomInfo->x917Count < X917_MAX_CYCLES );

	/* Process as many blocks of output as needed.  We can't check the
	   return value of the encryption call because there isn't one, however
	   the 3DES code has gone through a self-test when the randomness
	   subsystem was inited.  This can run the generator for slightly more
	   than X917_MAX_CYCLES if we're already close to the limit before we
	   start, but this isn't a big problem, it's only an approximate reset-
	   count measure anyway */
	for( dataBlockPos = 0; dataBlockPos < length; 
		 dataBlockPos += X917_POOLSIZE )
		{
		const int bytesToCopy = min( length - dataBlockPos, X917_POOLSIZE );
		int i;
		ORIGINAL_INT_VAR( x917Count, randomInfo->x917Count );

		/* Precondition: We're processing from 1...X917_POOLSIZE bytes of
		   data */
		PRE( bytesToCopy >= 1 && bytesToCopy <= X917_POOLSIZE );

		/* Set the seed from the user-supplied data.  This varies depending
		   on whether we're using the X9.17 or X9.31 interpretation of
		   seeding */
		if( randomInfo->x917x931 )
			{
			/* It's the X9.31 interpretation, there's no further user seed 
			   input apart from the V and DT that we set initially */
			memcpy( encTime, randomInfo->x917DT, X917_POOLSIZE );
			}
		else
			{
			/* It's the X9.17 seed-via-DT interpretation, the user input is
			   DT.  Copy in as much timestamp (+ other assorted data) as we 
			   can into the DT value */
			memcpy( encTime, dataPtr, bytesToCopy );

			/* Inner precondition: The DT buffer contains the input data */
			FORALL( k, 0, bytesToCopy,
					encTime[ k ] == data[ dataBlockPos + k ] );
			}

		/* out = Enc( Enc( DT ) ^ V(n) ); */
		tdesEncrypt( encTime, &randomInfo->x917Key );
		for( i = 0; i < X917_POOLSIZE; i++ )
			randomInfo->x917Pool[ i ] ^= encTime[ i ];
		tdesEncrypt( randomInfo->x917Pool, &randomInfo->x917Key );
		memcpy( dataPtr, randomInfo->x917Pool, bytesToCopy );

		/* Postcondition: The internal state has been copied to the output
		   (ick) */
		FORALL( k, 0, bytesToCopy, \
				data[ dataBlockPos + k ] == randomInfo->x917Pool[ k ] );

		/* V(n+1) = Enc( Enc( DT ) ^ out ); */
		for( i = 0; i < X917_POOLSIZE; i++ )
			randomInfo->x917Pool[ i ] ^= encTime[ i ];
		tdesEncrypt( randomInfo->x917Pool, &randomInfo->x917Key );

		/* If we're using the X9.31 interpretation, update DT to meet the 
		   monotonically increasing time value requirement.  Although the 
		   spec doesn't explicitly state this, the published test vectors
		   increment the rightmost byte, so the value is treated as big-
		   endian */
		if( randomInfo->x917x931 )
			{
			ORIGINAL_INT_VAR( lsb1, randomInfo->x917DT[ X917_POOLSIZE - 1 ] );
			ORIGINAL_INT_VAR( lsb2, randomInfo->x917DT[ X917_POOLSIZE - 2 ] );
			ORIGINAL_INT_VAR( lsb3, randomInfo->x917DT[ X917_POOLSIZE - 3 ] );

#if 1
			for( i = X917_POOLSIZE - 1; i >= 0; i-- )
				{
				randomInfo->x917DT[ i ]++;
				if( randomInfo->x917DT[ i ] != 0 )
					break;
				i = i;
				}
#else
			for( i = 0; i < X917_POOLSIZE; i++ )
				{
				randomInfo->x917DT[ i ]++;
				if( randomInfo->x917DT[ i ] != 0 )
					break;
				i = i;
				}
#endif

			/* Postcondition: The value has been incremented by one */
			POST( ( randomInfo->x917DT[ X917_POOLSIZE - 1 ] == \
					ORIGINAL_VALUE( lsb1 ) + 1 ) || \
				  ( randomInfo->x917DT[ X917_POOLSIZE - 1 ] == 0 && \
					randomInfo->x917DT[ X917_POOLSIZE - 2 ] == \
					ORIGINAL_VALUE( lsb2 ) + 1 ) || \
				  ( randomInfo->x917DT[ X917_POOLSIZE - 1 ] == 0 && \
					randomInfo->x917DT[ X917_POOLSIZE - 2 ] == 0 && \
					randomInfo->x917DT[ X917_POOLSIZE - 3 ] == \
					ORIGINAL_VALUE( lsb3 ) + 1 ) );
			}

		/* Move on to the next block */
		dataPtr += bytesToCopy;
		randomInfo->x917Count++;

		/* Postcondition: We've processed one more block of data */
		POST( dataPtr == data + dataBlockPos + bytesToCopy );
		POST( randomInfo->x917Count == ORIGINAL_VALUE( x917Count ) + 1 );
		}

	/* Postcondition: We processed all of the data */
	POST( dataPtr == data + length );

	zeroise( encTime, X917_POOLSIZE );

	/* Postcondition: Nulla vestigia retrorsum */
	FORALL( i, 0, X917_POOLSIZE,
			encTime[ i ] == 0 );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Add Random (Entropy) Data						*
*																			*
****************************************************************************/

/* Add new entropy data and an entropy quality estimate to the random pool */

int addEntropyData( RANDOM_INFO *randomInfo, const void *buffer, 
					const int length )
	{
	const BYTE *bufPtr = ( BYTE * ) buffer;
	int count = length;
	ORIGINAL_INT_VAR( entropyByteCount, randomInfo->entropyByteCount );
	ORIGINAL_PTR( buffer );

	/* Preconditions: The input data is valid and the current entropy byte 
	   count has a sensible value */
	PRE( isWritePtr( randomInfo, sizeof( RANDOM_INFO ) ) );
	PRE( length > 0 && isReadPtr( buffer, length ) );
	PRE( randomInfo->randomPoolPos >= 0 && \
		 randomInfo->randomPoolPos <= RANDOMPOOL_SIZE );
	PRE( randomInfo->entropyByteCount >= 0 );

	/* Mix the incoming data into the pool.  This operation is resistant to 
	   chosen- and known-input attacks because the pool contents are unknown 
	   to an attacker, so XORing in known data won't help them.  If an 
	   attacker could determine pool contents by observing the generator 
	   output (which is defeated by the postprocessing), we'd have to 
	   perform an extra input mixing operation to defeat these attacks */
	while( count-- > 0 )
		{
		ORIGINAL_INT_VAR( bufVal, *bufPtr );
		DECLARE_ORIGINAL_INT( poolVal );
		DECLARE_ORIGINAL_INT( newPoolVal );
		DECLARE_ORIGINAL_INT( poolPos );

		/* If the pool write position has reached the end of the pool, mix 
		   the pool */
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
		   GPG/add_randomness.  Note that in this case we can use a non-XOR 
		   operation to check that the XOR succeeded, unlike the pool mixing 
		   code which requires an XOR to check the original XOR */
		POST( randomInfo->randomPoolPos == \
			  ORIGINAL_VALUE( poolPos ) + 1 );
		POST( ( ( ORIGINAL_VALUE( newPoolVal ) == \
				  ORIGINAL_VALUE( bufVal ) ) && \
				( ORIGINAL_VALUE( poolVal ) == 0 ) ) || \
			  ( ORIGINAL_VALUE( newPoolVal ) != \
			    ORIGINAL_VALUE( bufVal ) ) );
		}

	/* Remember how many bytes of entropy we added on this update */
	randomInfo->entropyByteCount += length;

	/* Postcondition: We processed all of the data */
	POST( bufPtr == ORIGINAL_VALUE( buffer ) + length );
	POST( randomInfo->entropyByteCount == \
		  ORIGINAL_VALUE( entropyByteCount ) + length );

	return( CRYPT_OK );
	}

int addEntropyQuality( RANDOM_INFO *randomInfo, const int quality )
	{
	/* Preconditions: The input data is valid */
	PRE( isWritePtr( randomInfo, sizeof( RANDOM_INFO ) ) );
	PRE( randomInfo->randomQuality >= 0 && \
		 randomInfo->randomQuality < 1000 );

	/* If there's not enough entropy data present to justify the claimed 
	   entropy quality level, signal an error.  We do however retain the
	   existing entropy byte count for use the next time an entropy quality
	   estimate is added, since it's still contributing to the total 
	   entropy quality */
	if( randomInfo->entropyByteCount <= 0 || \
		quality / 2 > randomInfo->entropyByteCount )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_RANDOM );
		}
	randomInfo->entropyByteCount = 0;

	/* If we haven't reached the minimum quality level for generating keys 
	   yet, update the quality level */
	if( randomInfo->randomQuality < 100 )
		randomInfo->randomQuality += quality;
	return( CRYPT_OK );
	}

#ifdef CONFIG_RANDSEED

/* Add entropy data from a stored seed value */

static void addStoredSeedData( RANDOM_INFO *randomInfo )
	{
	STREAM stream;
	BYTE streamBuffer[ STREAM_BUFSIZE ], seedBuffer[ 1024 ];
	char seedFilePath[ MAX_PATH_LENGTH + 128 ];	/* Protection for Windows */
	int poolCount = RANDOMPOOL_SIZE, length, status;

	/* Try and access the stored seed data */
	fileBuildCryptlibPath( seedFilePath, NULL, BUILDPATH_RNDSEEDFILE );
	status = sFileOpen( &stream, seedFilePath, FILE_READ );
	if( cryptStatusError( status ) )
		{
		/* The seed data isn't present, don't try and access it again */
		randomInfo->seedProcessed = TRUE;
		assert( NOTREACHED );
		return;
		}

	/* Read up to 1K of data from the stored seed */
	sioctl( &stream, STREAM_IOCTL_IOBUFFER, streamBuffer, STREAM_BUFSIZE );
	sioctl( &stream, STREAM_IOCTL_PARTIALREAD, NULL, 0 );
	status = length = sread( &stream, seedBuffer, 1024 );
	sFileClose( &stream );
	zeroise( streamBuffer, STREAM_BUFSIZE );
	if( cryptStatusError( status ) || length <= 0 )
		{
		/* The seed data is present but we can't read it, don't try and 
		   access it again */
		randomInfo->seedProcessed = TRUE;
		assert( NOTREACHED );
		return;
		}
	randomInfo->seedSize = length;

	/* Precondition: We got at least some non-zero data */
	EXISTS( i, 0, length, 
			seedBuffer[ i ] != 0 );

	/* Add the seed data to the entropy pool.  Both because the entropy-
	   management code gets suspicious about very small amounts of data with
	   claimed high entropy and because it's a good idea to start with all
	   of the pool set to the seed data (rather than most of it set at zero 
	   if the seed data is short), we add the seed data repeatedly until 
	   we've filled the pool */
	while( poolCount > 0 )
		{
		status = addEntropyData( randomInfo, seedBuffer, length );
		assert( cryptStatusOK( status ) );
		poolCount -= length;
		}

	/* If there were at least 128 bits of entropy present in the seed, set 
	   the entropy quality to the user-provided value */
	if( length >= 16 )
		{
		status = addEntropyQuality( randomInfo, CONFIG_RANDSEED_QUALITY );
		assert( cryptStatusOK( status ) );
		}
	
	zeroise( seedBuffer, 1024 );

	/* Postcondition: Nulla vestigia retrorsum */
	FORALL( i, 0, 1024, 
			seedBuffer[ i ] == 0 );
	}
#endif /* CONFIG_RANDSEED */

/****************************************************************************
*																			*
*								Get Random Data								*
*																			*
****************************************************************************/

/* Get a block of random data from the randomness pool in such a way that
   compromise of the data doesn't compromise the pool, and vice versa.  This
   is done by performing the (one-way) pool mixing operation on the pool and
   on a transformed version of the pool that becomes the key.  The
   transformed version of the pool from which the key data will be drawn is
   then further processed by running each 64-bit block through the X9.17
   generator.  As an additional precaution the key data is folded in half to
   ensure that not even a hashed or encrypted form of the previous contents
   is available.  No pool data ever leaves the pool.

   This function performs a more paranoid version of the FIPS 140 continuous
   tests on both the main pool contents and the X9.17 generator output to
   detect stuck-at faults and short cycles in the output.  In addition the 
   higher-level message handler applies the FIPS 140 statistical tests to 
   the output and will retry the fetch if the output fails the tests.  This 
   additional step is performed at a higher level because it's then applied 
   to all randomness sources used by cryptlib, not just the built-in one.

   Since the pool output is folded to mask the output, the output from each
   round of mixing is only half the pool size, as defined below */

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
							 randomInfo->randomPool + X917_KEYSIZE, NULL );
		if( cryptStatusOK( status ) )
			{
			mixRandomPool( randomInfo );
			status = generateX917( randomInfo, randomInfo->randomPool,
								   RANDOMPOOL_ALLOCSIZE );
			}
		if( cryptStatusOK( status ) )
			{
			mixRandomPool( randomInfo );
			status = generateX917( randomInfo, randomInfo->randomPool,
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

		/* We can't trust the pool data any more so we set its content
		   value to zero.  Ideally we should flash lights and sound
		   klaxons as well, this is a catastrophic failure */
		randomInfo->randomQuality = randomInfo->randomPoolMixes = 0;
		randomInfo->x917Inited = FALSE;
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

int getRandomData( RANDOM_INFO *randomInfo, void *buffer, const int length )
	{
	BYTE *bufPtr = buffer;
	int count;

	/* Preconditions: The input data is valid */
	PRE( isWritePtr( randomInfo, sizeof( RANDOM_INFO ) ) );
	PRE( length > 0 && isReadPtr( buffer, length ) );

	/* Clear the return value and by extension make sure that we fail the 
	   FIPS 140 tests on the output if there's a problem */
	zeroise( buffer, length );

	/* Precondition: We're not asking for more data than the maximum that
	   should be needed */
	PRE( length >= 1 && length <= MAX_RANDOM_BYTES );

	/* If we're using a stored random seed, add it to the entropy pool if
	   necessary.  Note that we do this here rather than when we initialise
	   the randomness subsystem both because at that point the stream
	   subsystem may not be ready for use yet and because there may be a
	   requirement to periodically re-read the seed data if it's changed
	   by another process/task */
#ifdef CONFIG_RANDSEED
	if( !randomInfo->seedProcessed )
		addStoredSeedData( randomInfo );
#endif /* CONFIG_RANDSEED */

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
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* X9.17/X9.31 generator test vectors.  The values used are from the NIST
   publication "The Random Number Generator Validation System (RNGVS)", the
   commented-out ones are from test data used by an eval lab */

typedef struct {
	const BYTE key[ X917_KEYSIZE + X917_KEYSIZE ];
	const BYTE DT[ X917_POOLSIZE ], V[ X917_POOLSIZE ];
	const BYTE R[ X917_POOLSIZE ];
	} X917_TESTDATA;

static const X917_TESTDATA x917MCTdata = {	/* Monte Carlo Test (MCT) */
#if 0	/* NIST vectors, possibly wrong */
	/* Key1 = 75C71AE5A11A232C
	   Key2 = 40256DCD94F767B0
	   DT = C89A1D888ED12F3C
	   V = D5538F9CF450F53C
	   R = 77C695C33E51C8C0 */
	"\x75\xC7\x1A\xE5\xA1\x1A\x23\x2C\x40\x25\x6D\xCD\x94\xF7\x67\xB0",
	"\xC8\x9A\x1D\x88\x8E\xD1\x2F\x3C",
	"\xD5\x53\x8F\x9C\xF4\x50\xF5\x3C", 
	"\x77\xC6\x95\xC3\x3E\x51\xC8\xC0"
#else	/* InfoGuard vectors, OK */
	/* Key1 = 625BB5131A45F492
	   Key2 = 70971C9E0D4C9792
	   DT = 5F328264B787B098
	   V = A24F6E0EE43204CD
	   R = C7AC1E8F100CC30A */
	"\x62\x5B\xB5\x13\x1A\x45\xF4\x92\x70\x97\x1C\x9E\x0D\x4C\x97\x92",
	"\x5F\x32\x82\x64\xB7\x87\xB0\x98",
	"\xA2\x4F\x6E\x0E\xE4\x32\x04\xCD", 
	"\xC7\xAC\x1E\x8F\x10\x0C\xC3\x0A"
#endif /* 0 */
	};

static const X917_TESTDATA x917VSTdata[] = {	/* Variable Seed Test (VST) */
	/* Count = 0
	   Key1 = 75C71AE5A11A232C
	   Key2 = 40256DCD94F767B0
	   DT = C89A1D888ED12F3C
	   V = 8000000000000000
	   R = 944DC7210D6D7FD7 */
	{ "\x75\xC7\x1A\xE5\xA1\x1A\x23\x2C\x40\x25\x6D\xCD\x94\xF7\x67\xB0",
	  "\xC8\x9A\x1D\x88\x8E\xD1\x2F\x3C",
	  "\x80\x00\x00\x00\x00\x00\x00\x00",
	  "\x94\x4D\xC7\x21\x0D\x6D\x7F\xD7" },
	/* Count = 1
	   Key1 = 75C71AE5A11A232C
	   Key2 = 40256DCD94F767B0
	   DT = C89A1D888ED12F3D
	   V = C000000000000000
	   R = AF1A648591BB7C2C */
	{ "\x75\xC7\x1A\xE5\xA1\x1A\x23\x2C\x40\x25\x6D\xCD\x94\xF7\x67\xB0",
	  "\xC8\x9A\x1D\x88\x8E\xD1\x2F\x3D",
	  "\xC0\x00\x00\x00\x00\x00\x00\x00",
	  "\xAF\x1A\x64\x85\x91\xBB\x7C\x2C" },
	/* Count = 2
	   Key1 = 75C71AE5A11A232C
	   Key2 = 40256DCD94F767B0
	   DT = C89A1D888ED12F3E
	   V = E000000000000000
	   R = 221839B07451E423 */
	{ "\x75\xC7\x1A\xE5\xA1\x1A\x23\x2C\x40\x25\x6D\xCD\x94\xF7\x67\xB0",
	  "\xC8\x9A\x1D\x88\x8E\xD1\x2F\x3E",
	  "\xE0\x00\x00\x00\x00\x00\x00\x00",
	  "\x22\x18\x39\xB0\x74\x51\xE4\x23" },
	/* Count = 3
	   Key1 = 75C71AE5A11A232C
	   Key2 = 40256DCD94F767B0
	   DT = C89A1D888ED12F3F
	   V = F000000000000000
	   R = EBA9271E04043712 */
	{ "\x75\xC7\x1A\xE5\xA1\x1A\x23\x2C\x40\x25\x6D\xCD\x94\xF7\x67\xB0",
	  "\xC8\x9A\x1D\x88\x8E\xD1\x2F\x3F",
	  "\xF0\x00\x00\x00\x00\x00\x00\x00",
	  "\xEB\xA9\x27\x1E\x04\x04\x37\x12" },
	/* Count = 4
	   Key1 = 75C71AE5A11A232C
	   Key2 = 40256DCD94F767B0
	   DT = C89A1D888ED12F40
	   V = F800000000000000
	   R = 02433C9417A3326F */
	{ "\x75\xC7\x1A\xE5\xA1\x1A\x23\x2C\x40\x25\x6D\xCD\x94\xF7\x67\xB0",
	  "\xC8\x9A\x1D\x88\x8E\xD1\x2F\x40",
	  "\xF8\x00\x00\x00\x00\x00\x00\x00",
	  "\x02\x43\x3C\x94\x17\xA3\x32\x6F" },
#if 0
	/* Count = 0
	   Key1 = 3164916EA2C87AAE
	   Key2 = 2ABC323EFB9802E3
	   DT = 65B9108277AC0582
	   V = 8000000000000000
	   R = D8015B966ADE69BA */
	{ "\x31\x64\x91\x6E\xA2\xC8\x7A\xAE\x2A\xBC\x32\x3E\xFB\x98\x02\xE3",
	  "\x65\xB9\x10\x82\x77\xAC\x05\x82",
	  "\x80\x00\x00\x00\x00\x00\x00\x00",
	  "\xD8\x01\x5B\x96\x6A\xDE\x69\xBA" },
	/* Count = 1
	   Key1 = 3164916EA2C87AAE
	   Key2 = 2ABC323EFB9802E3
	   DT = 65B9108277AC0583
	   V = C000000000000000
	   R = E737E18734365F43 */
	{ "\x31\x64\x91\x6E\xA2\xC8\x7A\xAE\x2A\xBC\x32\x3E\xFB\x98\x02\xE3",
	  "\x65\xB9\x10\x82\x77\xAC\x05\x83",
	  "\xC0\x00\x00\x00\x00\x00\x00\x00",
	  "\xE7\x37\xE1\x87\x34\x36\x5F\x43" },
	/* Count = 2
	   Key1 = 3164916EA2C87AAE
	   Key2 = 2ABC323EFB9802E3
	   DT = 65B9108277AC0584
	   V = E000000000000000
	   R = CA8F00C1DF28FCFF */
	{ "\x31\x64\x91\x6E\xA2\xC8\x7A\xAE\x2A\xBC\x32\x3E\xFB\x98\x02\xE3",
	  "\x65\xB9\x10\x82\x77\xAC\x05\x84",
	  "\xE0\x00\x00\x00\x00\x00\x00\x00",
	  "\xCA\x8F\x00\xC1\xDF\x28\xFC\xFF" },
	/* Count = 3
	   Key1 = 3164916EA2C87AAE
	   Key2 = 2ABC323EFB9802E3
	   DT = 65B9108277AC0585
	   V = F000000000000000
	   R = 9FF307027622FA2A */
	{ "\x31\x64\x91\x6E\xA2\xC8\x7A\xAE\x2A\xBC\x32\x3E\xFB\x98\x02\xE3",
	  "\x65\xB9\x10\x82\x77\xAC\x05\x85",
	  "\xF0\x00\x00\x00\x00\x00\x00\x00",
	  "\x9F\xF3\x07\x02\x76\x22\xFA\x2A" },
	/* Count = 4
	   Key1 = 3164916EA2C87AAE
	   Key2 = 2ABC323EFB9802E3
	   DT = 65B9108277AC0586
	   V = F800000000000000
	   R = 0A4BB2E54842648E */
	{ "\x31\x64\x91\x6E\xA2\xC8\x7A\xAE\x2A\xBC\x32\x3E\xFB\x98\x02\xE3",
	  "\x65\xB9\x10\x82\x77\xAC\x05\x86",
	  "\xF8\x00\x00\x00\x00\x00\x00\x00",
	  "\x0A\x4B\xB2\xE5\x48\x42\x64\x8E" },
	/* Count = 5
	   Key1 = 3164916EA2C87AAE
	   Key2 = 2ABC323EFB9802E3
	   DT = 65B9108277AC0587
	   V = FC00000000000000
	   R = FFAD84A57EE0DE37 */
	{ "\x31\x64\x91\x6E\xA2\xC8\x7A\xAE\x2A\xBC\x32\x3E\xFB\x98\x02\xE3",
	  "\x65\xB9\x10\x82\x77\xAC\x05\x87",
	  "\xFC\x00\x00\x00\x00\x00\x00\x00",
	  "\xFF\xAD\x84\xA5\x7E\xE0\xDE\x37" },
	/* Count = 6
	   Key1 = 3164916EA2C87AAE
	   Key2 = 2ABC323EFB9802E3
	   DT = 65B9108277AC0588
	   V = FE00000000000000
	   R = 0CF064313A7889FD */
	{ "\x31\x64\x91\x6E\xA2\xC8\x7A\xAE\x2A\xBC\x32\x3E\xFB\x98\x02\xE3",
	  "\x65\xB9\x10\x82\x77\xAC\x05\x88",
	  "\xFE\x00\x00\x00\x00\x00\x00\x00",
	  "\x0C\xF0\x64\x31\x3A\x78\x89\xFD" },
	/* Count = 7
	   Key1 = 3164916EA2C87AAE
	   Key2 = 2ABC323EFB9802E3
	   DT = 65B9108277AC0589
	   V = FF00000000000000
	   R = 97B6854447D95A01 */
	{ "\x31\x64\x91\x6E\xA2\xC8\x7A\xAE\x2A\xBC\x32\x3E\xFB\x98\x02\xE3",
	  "\x65\xB9\x10\x82\x77\xAC\x05\x89",
	  "\xFF\x00\x00\x00\x00\x00\x00\x00",
	  "\x97\xB6\x85\x44\x47\xD9\x5A\x01" },
#endif /* 0 */
	{ 0 }
	};


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

int initRandomInfo( void **randomInfoPtrPtr )
	{
	RANDOM_INFO randomInfo;
	BYTE keyBuffer[ X917_KEYSIZE + X917_KEYSIZE ];
	BYTE buffer[ 16 ];
	int i, isX931, status;

	/* Make sure that the crypto that we need is functioning as required */
	status = algorithmSelfTest();
	if( cryptStatusError( status ) )
		{
		assert( NOTREACHED );
		return( status );
		}

	/* The underlying crypto is OK, check that the cryptlib PRNG is working 
	   correctly */
	initRandomPool( &randomInfo );
	mixRandomPool( &randomInfo );
	if( memcmp( randomInfo.randomPool, 
				"\xF6\x8F\x30\xEE\x52\x13\x3E\x40\x06\x06\xA6\xBE\x91\xD2\xD9\x82", 16 ) )
		status = CRYPT_ERROR_FAILED;
	if( cryptStatusOK( status ) )
		{
		mixRandomPool( &randomInfo );
		if( memcmp( randomInfo.randomPool, 
					"\xAE\x94\x3B\xF2\x86\x5F\xCF\x76\x36\x2B\x80\xD5\x73\x86\x9B\x69", 16 ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		{
		mixRandomPool( &randomInfo );
		if( memcmp( randomInfo.randomPool, 
					"\xBC\x2D\xC1\x03\x8C\x78\x6D\x04\xA8\xBD\xD5\x51\x80\xCA\x42\xF4", 16 ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusError( status ) )
		{
		endRandomPool( &randomInfo );
		assert( NOTREACHED );
		return( CRYPT_ERROR_FAILED );
		}

	/* Check that the ANSI X9.17 PRNG is working correctly */
	memset( buffer, 0, 16 );
	status = setKeyX917( &randomInfo, randomInfo.randomPool, 
						 randomInfo.randomPool + X917_KEYSIZE, NULL );
	if( cryptStatusOK( status ) )
		status = generateX917( &randomInfo, buffer, X917_POOLSIZE );
	if( cryptStatusOK( status ) && \
		memcmp( buffer, "\xF0\x8D\xD4\xDE\xFA\x2C\x80\x11", X917_POOLSIZE ) )
		status = CRYPT_ERROR_FAILED;
	if( cryptStatusOK( status ) )
		status = generateX917( &randomInfo, buffer, X917_POOLSIZE );
	if( cryptStatusOK( status ) && \
		memcmp( buffer, "\xA0\xA9\x4E\xEC\xCD\xD9\x28\x7F", X917_POOLSIZE ) )
		status = CRYPT_ERROR_FAILED;
	if( cryptStatusOK( status ) )
		status = generateX917( &randomInfo, buffer, X917_POOLSIZE );
	if( cryptStatusOK( status ) && \
		memcmp( buffer, "\x70\x82\x64\xED\x83\x88\x40\xE4", X917_POOLSIZE ) )
		status = CRYPT_ERROR_FAILED;
	if( cryptStatusError( status ) )
		{
		endRandomPool( &randomInfo );
		assert( NOTREACHED );
		return( CRYPT_ERROR_FAILED );
		}

	/* The underlying PRNGs are OK, check the overall random number 
	   generation system.  Since we started with an all-zero seed, we have 
	   to fake the entropy-quality values for the artificial test pool */
	randomInfo.randomQuality = 100;
	randomInfo.randomPoolMixes = RANDOMPOOL_MIXES;
	status = getRandomOutput( &randomInfo, buffer, 16 );
	if( cryptStatusOK( status ) && \
		memcmp( buffer, "\x6B\x59\x1D\xCD\xE1\xB3\xA8\x50\x32\x84\x8C\x8D\x93\xB0\x74\xD7", 16 ) )
		status = CRYPT_ERROR_FAILED;
	if( cryptStatusError( status ) )
		{
		endRandomPool( &randomInfo );
		assert( NOTREACHED );
		return( CRYPT_ERROR_FAILED );
		}
	endRandomPool( &randomInfo );

	/* Check the ANSI X9.17 PRNG again, this time using X9.31 test vectors.
	   Specifically, these aren't test vectors from X9.31 but vectors used
	   to certify an X9.17 generator when run in X9.31 mode (we actually run
	   the test twice, once in X9.17 seed-via-DT mode and once in X9.31 seed-
	   via-V mode).  We have to do this after the above test since they're 
	   run as a unit from the lowest-level cryptlib and ANSI PRNGs to the 
	   overall random number generation system, inserting this test in the 
	   middle would upset the final result values */
	initRandomPool( &randomInfo );
	memcpy( keyBuffer, x917MCTdata.key, X917_KEYSIZE + X917_KEYSIZE );
	status = setKeyX917( &randomInfo, keyBuffer, x917MCTdata.V, 
						 x917MCTdata.DT );
	if( cryptStatusOK( status ) )
		{
		for( i = 0; cryptStatusOK( status ) && i < 10000; i++ )
			{
			randomInfo.x917Count = 0;
			status = generateX917( &randomInfo, buffer, X917_POOLSIZE );
			}
		}
	if( cryptStatusOK( status ) && \
		memcmp( buffer, x917MCTdata.R, X917_POOLSIZE ) )
		status = CRYPT_ERROR_FAILED;
	if( cryptStatusError( status ) )
		{
		endRandomPool( &randomInfo );
		assert( NOTREACHED );
		return( CRYPT_ERROR_FAILED );
		}
	endRandomPool( &randomInfo );
	for( isX931 = FALSE; isX931 <= TRUE; isX931++ )
		{
		/* Run through the tests twice, once using the X9.17 interpreation,
		   a second time using the X9.31 interpretation */
		for( i = 0; memcmp( x917VSTdata[ i ].key, "\x00\x00\x00\x00", 4 ); 
			 i++ )
			{
			initRandomPool( &randomInfo );
			memcpy( keyBuffer, x917VSTdata[ i ].key, 
					X917_KEYSIZE + X917_KEYSIZE );
			memcpy( buffer, x917VSTdata[ i ].DT, X917_POOLSIZE );
			status = setKeyX917( &randomInfo, keyBuffer, x917VSTdata[ i ].V, 
								 isX931 ? x917VSTdata[ i ].DT : NULL );
			if( cryptStatusOK( status ) )
				status = generateX917( &randomInfo, buffer, X917_POOLSIZE );
			if( cryptStatusOK( status ) && \
				memcmp( buffer, x917VSTdata[ i ].R, X917_POOLSIZE ) )
				status = CRYPT_ERROR_FAILED;
			if( cryptStatusError( status ) )
				{
				endRandomPool( &randomInfo );
				assert( NOTREACHED );
				return( CRYPT_ERROR_FAILED );
				}
			endRandomPool( &randomInfo );
			}
		}

	/* Allocate and initialise the random pool */
	if( ( status = krnlMemalloc( randomInfoPtrPtr, \
								 sizeof( RANDOM_INFO ) ) ) != CRYPT_OK )
		return( status );
	initRandomPool( *randomInfoPtrPtr );

	/* Initialise any helper routines that may be needed */
	initRandomPolling();

	return( CRYPT_OK );
	}

void endRandomInfo( void **randomInfoPtrPtr )
	{
	/* Make sure that there are no background threads/processes still trying
	   to send us data */
	waitforRandomCompletion( TRUE );

	/* Call any special-case shutdown functions */
	endRandomPolling();

	/* Shut down the random data pool */
	endRandomPool( *randomInfoPtrPtr );
	krnlMemfree( randomInfoPtrPtr );
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
		if( !isReadPtr( randomData, randomDataLength ) )
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
