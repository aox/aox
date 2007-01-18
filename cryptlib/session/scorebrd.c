/****************************************************************************
*																			*
*							cryptlib Session Scoreboard						*
*						Copyright Peter Gutmann 1998-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "session.h"
  #include "ssl.h"
#else
  #include "crypt.h"
  #include "session/session.h"
  #include "session/ssl.h"
#endif /* Compiler-specific includes */

#ifdef USE_SSL

/* Scoreboard data and index information */

typedef BYTE SCOREBOARD_DATA[ SSL_SECRET_SIZE ];
typedef struct {
	/* Identification information: The checksum and hash of the session ID */
	int checkValue;
	BYTE hashValue[ 20 ];

	/* Misc info */
	time_t timeStamp;		/* Time entry was added to the scoreboard */
	int uniqueID;			/* Unique ID for this entry */
	BOOLEAN fixedEntry;		/* Whether entry was added manually */
	} SCOREBOARD_INDEX;

/* A template used to initialise scoreboard entries */

static const SCOREBOARD_INDEX SCOREBOARD_INDEX_TEMPLATE = \
								{ 0, { 0 }, 0, 0, 0 };

/* The maximum amount of time that an entry is retained in the scoreboard */

#define SCOREBOARD_TIMEOUT		3600

/* The action to perform on the scoreboard */

typedef enum { 
	SCOREBOARD_ACTION_NONE,		/* No scoreboard action */
	SCOREBOARD_ACTION_PRESENCECHECK,/* Check for an entry presence */
	SCOREBOARD_ACTION_LOOKUP,	/* Look up a scoreboard entry */
	SCOREBOARD_ACTION_ADD,		/* Add a scoreboard entry */
	SCOREBOARD_ACTION_LAST		/* Last possible scoreboard action */
	} SCOREBOARD_ACTION;

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Hash data */

static void hashData( BYTE *hash, const int hashMaxLength, 
					  const void *data, const int dataLength )
	{
	static HASHFUNCTION hashFunction = NULL;

	/* Get the hash algorithm information if necessary */
	if( hashFunction == NULL )
		getHashParameters( CRYPT_ALGO_SHA, &hashFunction, NULL );

	/* Hash the data */
	hashFunction( NULL, hash, hashMaxLength, ( BYTE * ) data, dataLength, 
				  HASH_ALL );
	}

/* Handle the scoreboard.  This function currently uses a straightforward
   linear search with entries clustered towards the start of the scoreboard.
   Although this may seem somewhat suboptimal, since cryptlib isn't a high-
   performance server the scoreboard will rarely contain more than a handful 
   of entries (if any).  In any case a quick scan through a small number of
   integers is probably still faster than the complex in-memory database
   lookup schemes used by many servers, and is also required to handle things
   like scoreboard LRU management */

static int handleScoreboard( SCOREBOARD_INFO *scoreboardInfo,
							 const void *sessionID, const int sessionIDlength, 
							 void *masterKey, const BOOLEAN isFixedEntry,
							 const SCOREBOARD_ACTION action )
	{
	SCOREBOARD_INDEX *scoreboardIndex = scoreboardInfo->index;
	SCOREBOARD_DATA *scoreboardData = scoreboardInfo->data;
	BYTE hashValue[ 20 + 8 ];
	BOOLEAN dataHashed = FALSE;
	const time_t currentTime = getTime();
	time_t oldestTime = currentTime;
	const int checkValue = checksumData( sessionID, sessionIDlength );
	int nextFreeEntry = CRYPT_ERROR, lastUsedEntry = 0, oldestEntry = 0;
	int position, uniqueID = 0, i, status;

	assert( isReadPtr( sessionID, sessionIDlength ) && sessionIDlength >= 8 );
	assert( ( action == SCOREBOARD_ACTION_PRESENCECHECK && masterKey == NULL ) || \
			( action == SCOREBOARD_ACTION_LOOKUP && masterKey != NULL ) || \
			( action == SCOREBOARD_ACTION_ADD && masterKey != NULL ) );
	assert( isWritePtr( scoreboardIndex,
						scoreboardInfo->size * sizeof( SCOREBOARD_INDEX ) ) );
	assert( isWritePtr( scoreboardData,
						scoreboardInfo->size * sizeof( SCOREBOARD_DATA ) ) );

	/* If there's something wrong with the time, we can't perform (time-
	   based) scoreboard management */
	if( currentTime <= MIN_TIME_VALUE )
		return( 0 );

	status = krnlEnterMutex( MUTEX_SCOREBOARD );
	if( cryptStatusError( status ) )
		return( status );

	for( i = 0; i < scoreboardInfo->lastEntry && \
				i < FAILSAFE_ITERATIONS_MAX; i++ )
		{
		SCOREBOARD_INDEX *scorebordIndexEntry = &scoreboardIndex[ i ];

		/* If this entry has expired, delete it */
		if( scorebordIndexEntry->timeStamp + SCOREBOARD_TIMEOUT < currentTime )
			{
			scoreboardIndex[ i ] = SCOREBOARD_INDEX_TEMPLATE;
			zeroise( scoreboardData[ i ], sizeof( SCOREBOARD_DATA ) );
			}

		/* Check for a free entry and the oldest non-free entry.  We could
		   perform an early-out once we find a free entry, but this would
		   prevent any following expired entries from being deleted */
		if( scorebordIndexEntry->timeStamp <= 0 )
			{
			/* We've found a free entry, remember it for future use if
			   required and continue */
			if( nextFreeEntry == CRYPT_ERROR )
				nextFreeEntry = i;
			continue;
			}
		lastUsedEntry = i;
		if( scorebordIndexEntry->timeStamp < oldestTime )
			{
			/* We've found an older entry than the current oldest entry,
			   remember it */
			oldestTime = scorebordIndexEntry->timeStamp;
			oldestEntry = i;
			}

		/* Perform a quick check using a checksum of the name to weed out
		   most entries */
		if( scorebordIndexEntry->checkValue == checkValue )
			{
			if( !dataHashed )
				{
				hashData( hashValue, 20, sessionID, sessionIDlength );
				dataHashed = TRUE;
				}
			if( !memcmp( scorebordIndexEntry->hashValue, hashValue, 20 ) )
				{
				uniqueID = scorebordIndexEntry->uniqueID;

				/* We've found a matching entry in the scoreboard, if we're
				   looking for an existing entry return its data */
				if( action == SCOREBOARD_ACTION_LOOKUP )
					{
					memcpy( masterKey, scoreboardData[ i ], SSL_SECRET_SIZE );
					scorebordIndexEntry->timeStamp = currentTime;
					}

				krnlExitMutex( MUTEX_SCOREBOARD );
				return( uniqueID );
				}
			}
		}
	if( i >= FAILSAFE_ITERATIONS_MAX )
		retIntError();

	/* If the total number of entries has shrunk due to old entries expiring,
	   reduce the overall scoreboard-used size */
	if( lastUsedEntry + 1 < scoreboardInfo->lastEntry )
		scoreboardInfo->lastEntry = lastUsedEntry + 1;

	/* No match found, if we're adding a new entry, add it at the
	   appropriate location */
	if( action == SCOREBOARD_ACTION_ADD )
		{
		if( !dataHashed )
			hashData( hashValue, 20, sessionID, sessionIDlength );
		position = ( nextFreeEntry > 0 ) ? nextFreeEntry : \
				   ( scoreboardInfo->lastEntry >= scoreboardInfo->size ) ? \
				   oldestEntry : scoreboardInfo->lastEntry++;
		assert( position >= 0 && position < scoreboardInfo->size );
		scoreboardIndex[ position ].checkValue = checkValue;
		memcpy( scoreboardIndex[ position ].hashValue, hashValue, 20 );
		scoreboardIndex[ position ].timeStamp = currentTime;
		scoreboardIndex[ position ].uniqueID = uniqueID = \
											scoreboardInfo->uniqueID++;
		memcpy( scoreboardData[ position ], masterKey, SSL_SECRET_SIZE );
		}

	krnlExitMutex( MUTEX_SCOREBOARD );
	return( uniqueID );
	}

/****************************************************************************
*																			*
*							Scoreboard Access Functions						*
*																			*
****************************************************************************/

/* Add and delete entries to/from the scoreboard.  These are just wrappers
   for the local scoreboard-access function, for use by external code */

int findScoreboardEntry( SCOREBOARD_INFO *scoreboardInfo,
						 const void *sessionID, const int sessionIDlength,
						 void *masterSecret, int *masterSecretLength )
	{
	int resumedSessionID;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtr( sessionID, sessionIDlength ) );
	assert( isWritePtr( masterSecret, sizeof( void * ) ) );
	assert( isWritePtr( masterSecretLength, sizeof( int ) ) );

	resumedSessionID = handleScoreboard( scoreboardInfo, 
								sessionID, sessionIDlength, masterSecret, 
								FALSE, SCOREBOARD_ACTION_LOOKUP );
	*masterSecretLength = ( resumedSessionID != 0 ) ? SSL_SECRET_SIZE : 0;
	return( resumedSessionID );
	}

int findScoreboardEntryID( SCOREBOARD_INFO *scoreboardInfo,
						   const void *sessionID, const int sessionIDlength )
	{
	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtr( sessionID, sessionIDlength ) );

	return( handleScoreboard( scoreboardInfo, sessionID, sessionIDlength, 
							  NULL, FALSE, SCOREBOARD_ACTION_PRESENCECHECK ) );
	}

int addScoreboardEntry( SCOREBOARD_INFO *scoreboardInfo,
						const void *sessionID, const int sessionIDlength, 
						const void *masterSecret, 
						const int masterSecretLength, 
						const BOOLEAN isFixedEntry )
	{
	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtr( sessionID, sessionIDlength ) );
	assert( isReadPtr( masterSecret, masterSecretLength ) && \
			masterSecretLength == SSL_SECRET_SIZE );

	/* If we're not doing resumes (or the ID is suspiciously short), don't
	   try and update the scoreboard */
	if( sessionIDlength < 8 )
		return( 0 );

	/* Add the entry to the scoreboard */
	return( handleScoreboard( scoreboardInfo, sessionID, sessionIDlength,
							  ( void * ) masterSecret, isFixedEntry,
							  SCOREBOARD_ACTION_ADD ) );
	}

void deleteScoreboardEntry( SCOREBOARD_INFO *scoreboardInfo, 
							const int uniqueID )
	{
	SCOREBOARD_INDEX *scoreboardIndex = scoreboardInfo->index;
	SCOREBOARD_DATA *scoreboardData = scoreboardInfo->data;
	int i, status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( uniqueID > 0 );

	status = krnlEnterMutex( MUTEX_SCOREBOARD );
	if( cryptStatusError( status ) )
		return;

	/* Search the scoreboard for the entry with the given ID */
	for( i = 0; i < scoreboardInfo->lastEntry && \
				i < FAILSAFE_ITERATIONS_MAX; i++ )
		{
		SCOREBOARD_INDEX *scorebordIndexEntry = &scoreboardIndex[ i ];

		/* If we've found the entry that we're after, clear it and exit */
		if( scorebordIndexEntry->uniqueID == uniqueID )
			{
			scoreboardIndex[ i ] = SCOREBOARD_INDEX_TEMPLATE;
			zeroise( scoreboardData[ i ], sizeof( SCOREBOARD_DATA ) );
			break;
			}
		}
	if( i >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Void();

	krnlExitMutex( MUTEX_SCOREBOARD );
	}

/****************************************************************************
*																			*
*							Scoreboard Init/Shutdown						*
*																			*
****************************************************************************/

/* Initialise and shut down the scoreboard */

int initScoreboard( SCOREBOARD_INFO *scoreboardInfo, 
					const int scoreboardSize )
	{
	SCOREBOARD_INDEX *scoreboardIndex;
	int i, status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( scoreboardSize > 16 && scoreboardSize <= 8192 );

	/* Initialise the scoreboard */
	memset( scoreboardInfo, 0, sizeof( SCOREBOARD_INFO ) );
	scoreboardInfo->uniqueID = 1;
	scoreboardInfo->size = scoreboardSize;

	krnlEnterMutex( MUTEX_SCOREBOARD );

	/* Initialise the scoreboard */
	if( ( scoreboardInfo->index = clAlloc( "initScoreboard", \
				scoreboardSize * sizeof( SCOREBOARD_INDEX ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	status = krnlMemalloc( &scoreboardInfo->data, \
						   scoreboardSize * sizeof( SCOREBOARD_DATA ) );
	if( cryptStatusError( status ) )
		{
		clFree( "initScoreboard", scoreboardInfo->index );
		memset( scoreboardInfo, 0, sizeof( SCOREBOARD_INFO ) );
		return( status );
		}
	scoreboardIndex = scoreboardInfo->index;
	for( i = 0; i < scoreboardSize; i++ )
		scoreboardIndex[ i ] = SCOREBOARD_INDEX_TEMPLATE;
	memset( scoreboardInfo->data, 0, scoreboardSize * \
									 sizeof( SCOREBOARD_DATA ) );
	scoreboardInfo->lastEntry = 0;
	scoreboardInfo->uniqueID = 1;

	krnlExitMutex( MUTEX_SCOREBOARD );
	return( CRYPT_OK );
	}

void endScoreboard( SCOREBOARD_INFO *scoreboardInfo )
	{
	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );

	krnlEnterMutex( MUTEX_SCOREBOARD );

	/* Clear and free the scoreboard */
	krnlMemfree( ( void ** ) &scoreboardInfo->data );
	zeroise( scoreboardInfo->index, \
			 scoreboardInfo->size * sizeof( SCOREBOARD_INDEX ) );
	clFree( "endScoreboard", scoreboardInfo->index );
	memset( scoreboardInfo, 0, sizeof( SCOREBOARD_INFO ) );

	krnlExitMutex( MUTEX_SCOREBOARD );
	}
#endif /* USE_SSL */
