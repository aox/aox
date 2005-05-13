/****************************************************************************
*																			*
*								cryptlib Test Code							*
*						Copyright Peter Gutmann 1995-2004					*
*																			*
****************************************************************************/

#ifdef _MSC_VER
  #include "../cryptlib.h"
  #include "test.h"
#else
  #include "cryptlib.h"
  #include "test/test.h"
#endif /* Braindamaged VC++ include handling */

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII. */
  #pragma convlit( suspend )
#endif /* EBCDIC systems */

/* Define the following to perform a smoke test on the cryptlib kernel.
   This includes:

	Stress test: Create 10K objects and read/write some attributes
	Data processing test: Encrypt/hash/MAC a buffer in a variable number
		of variable-size blocks, then decrypt/hash/MAC with different
		blocks and make sure the results match.
	Kernel check test: Run through every possible object type and attribute
		making sure we don't trigger any assertions.
	Threading stress test: DES-encrypt 100 data blocks in threads.
	Threading continuous test: Envelope data in threads until interrupted.

   Note that these are exhaustive tests that check large numbers of objects
   or parameter types and combinations so they can take some time to run to
   completion */

/* #define SMOKE_TEST */

/****************************************************************************
*																			*
*									Stress Test								*
*																			*
****************************************************************************/

#ifdef SMOKE_TEST

#define NO_OBJECTS	10000		/* Can't exceed MAX_OBJECTS in cryptkrn.h */

static void testStressObjects( void )
	{
	CRYPT_HANDLE *handleArray = malloc( NO_OBJECTS * sizeof( CRYPT_HANDLE ) );
	BYTE hash[ CRYPT_MAX_HASHSIZE ];
	int i, length, status;

	printf( "Running object stress test." );
	assert( handleArray  != NULL );
	for( i = 0; i < NO_OBJECTS; i++ )
		{
		status = cryptCreateContext( &handleArray[ i ], CRYPT_UNUSED,
									 CRYPT_ALGO_SHA );
		if( cryptStatusError( status ) )
			printf( "cryptEncrypt() failed at %d with status %d.\n", i,
					status );
		}
	printf( "." );
	for( i = 0; i < NO_OBJECTS; i++ )
		{
		status = cryptEncrypt( handleArray[ i ], "12345678", 8 );
		if( cryptStatusError( status ) )
			printf( "cryptEncrypt() failed at %d with status %d.\n", i, status );
		}
	printf( "." );
	for( i = 0; i < NO_OBJECTS; i++ )
		{
		status = cryptEncrypt( handleArray[ i ], "", 0 );
		if( cryptStatusError( status ) )
			printf( "cryptEncrypt() failed at %d with status %d.\n", i,
					status );
		}
	printf( "." );
	for( i = 0; i < NO_OBJECTS; i++ )
		{
		status = cryptGetAttributeString( handleArray[ i ],
								CRYPT_CTXINFO_HASHVALUE, hash, &length );
		if( cryptStatusError( status ) )
			printf( "cryptEncrypt() failed at %d with status %d.\n", i,
					status );
		}
	printf( "." );
	for( i = 0; i < NO_OBJECTS; i++ )
		{
		status = cryptDestroyContext( handleArray[ i ] );
		if( cryptStatusError( status ) )
			printf( "cryptEncrypt() failed at %d with status %d.\n", i,
					status );
		}
	free( handleArray );
	puts( "." );
	}

/****************************************************************************
*																			*
*								Data Processing Test						*
*																			*
****************************************************************************/

/* Data processing test */

#define DATABUFFER_SIZE		2048
#define MAX_BLOCKS			16

#define roundUp( size, roundSize ) \
	( ( ( size ) + ( ( roundSize ) - 1 ) ) & ~( ( roundSize ) - 1 ) )

#ifdef __WINDOWS__
  typedef int ( __stdcall *CRYPT_FUNCTION )( const CRYPT_CONTEXT cryptContext,
											 void *data, const int length );
#else
  typedef int ( *CRYPT_FUNCTION )( const CRYPT_CONTEXT cryptContext,
								   void *data, const int length );
#endif /* __WINDOWS__ */

static int processData( const CRYPT_CONTEXT cryptContext, BYTE *buffer,
						const int noBlocks, const int blockSize,
						CRYPT_FUNCTION cryptFunction )
	{
	int offset = 0, i, status;

	/* Encrypt the data in variable-length blocks.  The technique for
	   selecting lengths isn't perfect since it tends to put large blocks
	   at the start and small ones at the end, but it's good enough for
	   general testing */
	for( i = 0; i < noBlocks - 1; i++ )
		{
		int noBytes = rand() % ( DATABUFFER_SIZE - offset - \
								 ( blockSize * ( noBlocks - i  ) ) );
		if( !noBytes )
			noBytes = 1;
		if( blockSize > 1 )
			noBytes = roundUp( noBytes, blockSize );
		status = cryptFunction( cryptContext, buffer + offset, noBytes );
		if( cryptStatusError( status ) )
			return( status );
		offset += noBytes;
		}
	status = cryptFunction( cryptContext, buffer + offset,
							DATABUFFER_SIZE - offset );
	if( cryptStatusOK( status ) )
		status = cryptFunction( cryptContext, "", 0 );
	return( status );
	}

static int testProcessing( const CRYPT_ALGO_TYPE cryptAlgo,
						   const CRYPT_MODE_TYPE cryptMode,
						   const CRYPT_QUERY_INFO cryptQueryInfo )
	{
	BYTE buffer1[ DATABUFFER_SIZE ], buffer2[ DATABUFFER_SIZE ];
	BYTE hash1[ CRYPT_MAX_HASHSIZE ], hash2[ CRYPT_MAX_HASHSIZE ];
	const int blockSize = ( cryptMode == CRYPT_MODE_ECB || \
							cryptMode == CRYPT_MODE_CBC ) ? \
						  cryptQueryInfo.blockSize : 1;
	int length1, length2, i;

	/* Initialise the buffers with a known data pattern */
	memset( buffer1, '*', DATABUFFER_SIZE );
	memcpy( buffer1, "12345678", 8 );
	memcpy( buffer2, buffer1, DATABUFFER_SIZE );

	/* Process the data using various block sizes */
	printf( "Testing algorithm %d, mode %d, for %d-byte buffer with\n  block "
			"count ", cryptAlgo, ( cryptMode == CRYPT_UNUSED ) ? 0 : cryptMode,
			DATABUFFER_SIZE );
	for( i = 1; i <= MAX_BLOCKS; i++ )
		{
		CRYPT_CONTEXT cryptContext;
		int status;

		memcpy( buffer1, buffer2, DATABUFFER_SIZE );
		printf( "%d%s ", i, ( i == MAX_BLOCKS ) ? "." : "," );

		/* Encrypt the data with random block sizes */
		status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, cryptAlgo );
		if( cryptStatusError( status ) )
			return( status );
		if( cryptMode != CRYPT_UNUSED )
			{
			status = cryptSetAttribute( cryptContext, CRYPT_CTXINFO_MODE,
										cryptMode );
			if( cryptStatusError( status ) )
				return( status );
			if( cryptMode != CRYPT_MODE_ECB && cryptAlgo != CRYPT_ALGO_RC4 )
				{
				status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_IV,
								"1234567887654321", cryptQueryInfo.blockSize );
				if( cryptStatusError( status ) )
					return( status );
				}
			}
		if( cryptQueryInfo.keySize )
			{
			status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEY,
								"12345678876543211234567887654321",
								cryptQueryInfo.keySize );
			if( cryptStatusError( status ) )
				return( status );
			}
		status = processData( cryptContext, buffer1, i, blockSize,
							  cryptEncrypt );
		if( cryptStatusError( status ) )
			return( status );
		if( cryptAlgo >= CRYPT_ALGO_FIRST_HASH )
			{
			status = cryptGetAttributeString( cryptContext,
								CRYPT_CTXINFO_HASHVALUE, hash1, &length1 );
			if( cryptStatusError( status ) )
				return( status );
			}
		status = cryptDestroyContext( cryptContext );
		if( cryptStatusError( status ) )
			return( status );

		/* Decrypt the data again with random block sizes */
		status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, cryptAlgo );
		if( cryptStatusError( status ) )
			return( status );
		if( cryptMode != CRYPT_UNUSED )
			{
			status = cryptSetAttribute( cryptContext, CRYPT_CTXINFO_MODE,
										cryptMode );
			if( cryptStatusError( status ) )
				return( status );
			if( cryptMode != CRYPT_MODE_ECB && cryptAlgo != CRYPT_ALGO_RC4 )
				{
				status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_IV,
								"1234567887654321", cryptQueryInfo.blockSize );
				if( cryptStatusError( status ) )
					return( status );
				}
			}
		if( cryptQueryInfo.keySize )
			{
			status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEY,
								"12345678876543211234567887654321",
								cryptQueryInfo.keySize );
			if( cryptStatusError( status ) )
				return( status );
			}
		status = processData( cryptContext, buffer1, i, blockSize,
							  cryptDecrypt );
		if( cryptStatusError( status ) )
			return( status );
		if( cryptAlgo >= CRYPT_ALGO_FIRST_HASH )
			{
			status = cryptGetAttributeString( cryptContext,
								CRYPT_CTXINFO_HASHVALUE, hash2, &length2 );
			if( cryptStatusError( status ) )
				return( status );
			}
		status = cryptDestroyContext( cryptContext );
		if( cryptStatusError( status ) )
			return( status );

		/* Make sure the values match */
		if( cryptAlgo >= CRYPT_ALGO_FIRST_HASH )
			{
			if( ( length1 != length2 ) || memcmp( hash1, hash2, length1 ) )
				{
				puts( "Error: Hash value of identical buffers differs." );
				return( -1234 );
				}
			}
		else
			if( memcmp( buffer1, buffer2, DATABUFFER_SIZE ) )
				{
				printf( "Decrypted data != encrypted data for algorithm %d.\n",
						cryptAlgo );
				return( -1234 );
				}
		}
	printf( "\n" );

	return( CRYPT_OK );
	}

static void testDataProcessing( void )
	{
	CRYPT_QUERY_INFO cryptQueryInfo;
	CRYPT_ALGO_TYPE cryptAlgo;
	int errorCount = 0, status;

	for( cryptAlgo = CRYPT_ALGO_FIRST_CONVENTIONAL;
		 cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo,
												 &cryptQueryInfo ) ) )
			{
			if( cryptAlgo != CRYPT_ALGO_RC4 )
				{
				status = testProcessing( cryptAlgo, CRYPT_MODE_ECB,
										 cryptQueryInfo );
				if( cryptStatusError( status ) )
					{
					printf( "\nAlgorithm %d ECB mode processing failed with "
							"status %d.\n", cryptAlgo, status );
					errorCount++;
					}
				status = testProcessing( cryptAlgo, CRYPT_MODE_CBC,
										 cryptQueryInfo );
				if( cryptStatusError( status ) )
					{
					printf( "\nAlgorithm %d CBC mode processing failed with "
							"status %d.\n", cryptAlgo, status );
					errorCount++;
					}
				status = testProcessing( cryptAlgo, CRYPT_MODE_CFB,
										 cryptQueryInfo );
				if( cryptStatusError( status ) )
					{
					printf( "\nAlgorithm %d CFB mode processing failed with "
							"status %d.\n", cryptAlgo, status );
					errorCount++;
					}
				}
			status = testProcessing( cryptAlgo, CRYPT_MODE_OFB,
									 cryptQueryInfo );
			if( cryptStatusError( status ) )
				{
				printf( "\nAlgorithm %d OFB mode processing failed with "
						"status %d.\n", cryptAlgo, status );
				errorCount++;
				}
			}
	for( cryptAlgo = CRYPT_ALGO_FIRST_HASH;
		 cryptAlgo <= CRYPT_ALGO_LAST_HASH; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, &cryptQueryInfo ) ) )
			{
			status = testProcessing( cryptAlgo, CRYPT_UNUSED,
									 cryptQueryInfo );
			if( cryptStatusError( status ) )
				{
				printf( "\nAlgorithm %d processing failed with status %d.\n",
						cryptAlgo, status );
				errorCount++;
				}
			}
	for( cryptAlgo = CRYPT_ALGO_FIRST_MAC;
		 cryptAlgo <= CRYPT_ALGO_LAST_MAC; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, &cryptQueryInfo ) ) )
			{
			status = testProcessing( cryptAlgo, CRYPT_UNUSED,
									 cryptQueryInfo );
			if( cryptStatusError( status ) )
				{
				printf( "\nAlgorithm %d processing failed with status %d.\n",
						cryptAlgo, status );
				errorCount++;
				}
			}
	if( errorCount )
		printf( "%d errors detected.\n", errorCount );
	}

/****************************************************************************
*																			*
*								Kernel Check Test							*
*																			*
****************************************************************************/

/* Kernel check test */

static void smokeTestAttributes( const CRYPT_HANDLE cryptHandle )
	{
	int attribute;

	printf( "." );
	for( attribute = CRYPT_ATTRIBUTE_NONE; attribute < 8000; attribute++ )
		{
		char buffer[ 1024 ];
		int value;

		cryptGetAttribute( cryptHandle, attribute, &value );
		cryptGetAttributeString( cryptHandle, attribute, buffer, &value );
		}
	cryptDestroyObject( cryptHandle );
	}

static void testKernelChecks( void )
	{
	CRYPT_HANDLE cryptHandle;
	int subType;

	printf( "Running kernel smoke test:\n  Contexts" );
	for( subType = 0; subType < 500; subType++ )
		if( cryptStatusOK( cryptCreateContext( &cryptHandle, CRYPT_UNUSED,
											   subType ) ) )
			smokeTestAttributes( cryptHandle );
	printf( "\n  Certs" );
	for( subType = 0; subType < 500; subType++ )
		if( cryptStatusOK( cryptCreateCert( &cryptHandle, CRYPT_UNUSED,
											subType ) ) )
			smokeTestAttributes( cryptHandle );
	printf( "\n  Envelopes" );
	for( subType = 0; subType < 500; subType++ )
		if( cryptStatusOK( cryptCreateEnvelope( &cryptHandle, CRYPT_UNUSED,
												subType ) ) )
			smokeTestAttributes( cryptHandle );
	printf( "\n  Sessions" );
	for( subType = 0; subType < 500; subType++ )
		if( cryptStatusOK( cryptCreateSession( &cryptHandle, CRYPT_UNUSED,
											   subType ) ) )
			smokeTestAttributes( cryptHandle );
	printf( "\n" );
	}

/****************************************************************************
*																			*
*							Threading Stress Test							*
*																			*
****************************************************************************/

/* Multi-threaded processing stress test.  In order to add a little
   nondeterminism on single-threaded machines, we need to add some sleep()
   calls between crypto operations.  Even this isn't perfect, there's no
   real way to guarantee that they aren't simply executed in round-robin
   fashion with only one thread in the kernel at a time without modifying
   the kernel to provide diagnostic info */

#ifdef WINDOWS_THREADS

#define NO_THREADS	45

static void randSleep( void )
	{
	Sleep( ( rand() % 150 ) + 1 );
	}

unsigned __stdcall processDataThread( void *arg )
	{
	CRYPT_CONTEXT cryptContext;
	BYTE buffer[ 1024 ];
	int threadNo = ( int ) arg;
	int status;

	randSleep();
	memset( buffer, '*', 1024 );
	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED,
								 CRYPT_ALGO_3DES );
	if( cryptStatusOK( status ) )
		{
		randSleep();
		status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEY,
										  "123456781234567812345678", 24 );
		}
	if( cryptStatusOK( status ) )
		{
		randSleep();
		status = cryptEncrypt( cryptContext, buffer, 1024 );
		}
	if( cryptStatusOK( status ) )
		{
		randSleep();
		status = cryptEncrypt( cryptContext, buffer, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		randSleep();
		status = cryptDestroyContext( cryptContext );
		}
	if( cryptStatusError( status ) )
		printf( "\nEncryption failed with status %d.\n", status );
	else
		printf( "%d ", threadNo );

	_endthreadex( 0 );
	return( 0 );
	}

static void testStressThreads( void )
	{
	HANDLE hThreadArray[ NO_THREADS ];
	int i;

	/* Start the threads */
	for( i = 0; i < NO_THREADS; i++ )
		{
		unsigned threadID;

		hThreadArray[ i ] = ( HANDLE ) \
			_beginthreadex( NULL, 0, &processDataThread, ( void * ) i, 0,
							&threadID );
		if( hThreadArray[ i ] == 0 )
			printf( "Thread %d couldn't be created.\n", i );
		}
	printf( "Threads completed: " );

	/* Wait for all the threads to complete */
	if( WaitForMultipleObjects( NO_THREADS, hThreadArray, TRUE,
								15000 ) == WAIT_TIMEOUT )
		puts( "\nNot all threads completed in 15s." );
	else
		puts( "." );
	for( i = 0; i < NO_THREADS; i++ )
		CloseHandle( hThreadArray[ i ] );
	}
#endif /* WINDOWS_THREADS */

#if defined( UNIX_THREADS ) || defined( WINDOWS_THREADS )

#ifdef UNIX_THREADS
  void *envelopeDataThread( void *arg )
#else
  unsigned __stdcall envelopeDataThread( void *arg )
#endif /* Different threading models */
	{
	static const char *envData = "qwertyuiopasdfghjklzxcvbnm";
	BYTE fileBuffer[ BUFFER_SIZE ];
	const unsigned uThread = ( unsigned ) arg;
	const time_t startTime = time( NULL );
	int count, status;

	printf( "Thread %d started.\n", uThread );
	fflush( stdout );

	filenameFromTemplate( fileBuffer, CERT_FILE_TEMPLATE, 13 );

	for( count = 0; count < 150; count++ )
		{
		CRYPT_ENVELOPE cryptEnvelope;
		CRYPT_CERTIFICATE cryptCert;
		BYTE envBuffer[ BUFFER_SIZE ];
		int bytesCopied;

		/* Create the cert and envelope and add the cert to the envelope */
		status = importCertFile( &cryptCert, fileBuffer );
		if( cryptStatusOK( status ) )
			status = cryptCreateEnvelope( &cryptEnvelope, CRYPT_UNUSED,
										  CRYPT_FORMAT_CRYPTLIB );
		if( cryptStatusOK( status ) )
			status = cryptSetAttribute( cryptEnvelope,
										CRYPT_ENVINFO_PUBLICKEY, cryptCert );
		if( cryptStatusError( status ) )
			break;

		/* Envelope data and destroy the envelope */
		status = cryptPushData( cryptEnvelope, envData, strlen( envData ),
								&bytesCopied );
		if( cryptStatusOK( status ) )
			status = cryptPushData( cryptEnvelope, NULL, 0, NULL );
		if( cryptStatusOK( status ) )
			status = cryptPopData( cryptEnvelope, envBuffer, BUFFER_SIZE,
									&bytesCopied );
		if( cryptStatusOK( status ) )
			status = cryptDestroyEnvelope( cryptEnvelope );
		if( cryptStatusError( status ) )
			break;
		printf( "%c", uThread + '0' );
		}

	printf( "Thread %u exited after %d seconds.\n", uThread,
			time( NULL ) - startTime );
	fflush( stdout );
#ifdef UNIX_THREADS
	pthread_exit( NULL );
#else
	_endthreadex( 0 );
#endif /* Different threading models */
	return( 0 );
	}

static void testContinuousThreads( void )
	{
	unsigned threadID1, threadID2;
#ifdef UNIX_THREADS
	pthread_t thread1, thread2;
#else
	HANDLE hThread1, hThread2;
#endif /* Different threading models */

	cryptAddRandom( "xyzzy", 5 );
#ifdef UNIX_THREADS
	pthread_create( &thread1, NULL, envelopeDataThread, ( void * ) 1 );
	pthread_create( &thread2, NULL, envelopeDataThread, ( void * ) 2 );
#else
	hThread1 = ( HANDLE ) _beginthreadex( NULL, 0, envelopeDataThread,
										  ( void * ) 1, 0, &threadID1 );
	hThread2 = ( HANDLE ) _beginthreadex( NULL, 0, envelopeDataThread,
										  ( void * ) 2, 0, &threadID2 );
#endif /* Different threading models */
	delayThread( 30 );
	printf( "Hit a key..." );
	fflush( stdout );
	getchar();
	cryptEnd();
	exit( EXIT_SUCCESS );
	}
#endif /* UNIX_THREADS || WINDOWS_THREADS */

/****************************************************************************
*																			*
*									Test Interface							*
*																			*
****************************************************************************/

void smokeTest( void )
	{
	testDataProcessing();
	testKernelChecks();
	testStressObjects();
#if defined( UNIX_THREADS ) || defined( WINDOWS_THREADS )
	testStressThreads();
#endif /* UNIX_THREADS || WINDOWS_THREADS */
	}
#endif /* SMOKE_TEST */
