/****************************************************************************
*																			*
*						cryptlib Enveloping Test Routines					*
*						Copyright Peter Gutmann 1996-2005					*
*																			*
****************************************************************************/

#include <limits.h>		/* To determine max.buffer size we can encrypt */
#ifdef _MSC_VER
  #include "../cryptlib.h"
  #include "test.h"
#else
  #include "cryptlib.h"
  #include "test/test.h"
#endif /* Braindamaged MSC include handling */

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII. */
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */

/* Test data to use for the self-test.  The PGP test data is slightly 
   different since it's not possible to include a null character in data
   generated via the command-line versions of PGP.  On EBCDIC systems we
   have to hardcode in the character codes since the pre-generated data
   came from an ASCII system */

#if defined( __MVS__ ) || defined( __VMCMS__ )
  #define ENVELOPE_TESTDATA		( ( BYTE * ) "\x53\x6F\x6D\x65\x20\x74\x65\x73\x74\x20\x64\x61\x74\x61" )
  #define ENVELOPE_PGP_TESTDATA	( ( BYTE * ) "\x53\x6F\x6D\x65\x20\x74\x65\x73\x74\x20\x64\x61\x74\x61\x2E" )
  #define ENVELOPE_COMPRESSEDDATA	"\x2F\x2A\x20\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20\x6C\x6F\x77\x65\x73\x74\x2D"
#else
  #define ENVELOPE_TESTDATA		( ( BYTE * ) "Some test data" )
  #define ENVELOPE_PGP_TESTDATA	( ( BYTE * ) "Some test data." )
  #define ENVELOPE_COMPRESSEDDATA	"/* This is a lowest-"
#endif /* EBCDIC systems */
#define ENVELOPE_TESTDATA_SIZE			15
#define ENVELOPE_COMPRESSEDDATA_SIZE	20

/* To convert a CMS blob into an S/MIME message, base64 encode it and add 
   the following header:

	To: <address>
	Subject: S/MIME test
	From: <address>
	MIME-Version: 1.0
	Content-Type: application/x-pkcs7-mime;smime-type=signed-data;name="smime.p7m"
	Content-Disposition: attachment;filename="smime.p7m"
	Content-Transfer-Encoding: base64

	<base64-encoded data>

   To allow the inner message to be processed by a mailer, the contents will 
   themselves have to be MIME-formatted: 

	MIME-Version: 1.0
	Content-Type: text/plain;charset="us-ascii"
	Content-Transfer-Encoding: 7bit

	<text> */

/* External flags which indicate that the key read/update routines worked OK.
   This is set by earlier self-test code, if it isn't set some of the tests
   are disabled */

extern int keyReadOK, doubleCertOK;

/****************************************************************************
*																			*
*								Utility Routines 							*
*																			*
****************************************************************************/

/* The general-purpose buffer used for enveloping.  We use a fixed buffer
   if possible to save having to add huge amounts of allocation/deallocation
   code */

BYTE FAR_BSS globalBuffer[ BUFFER_SIZE ];

/* Determine the size of a file.  If there's a problem, we return the
   default buffer size, which will cause a failure further up the chain
   where the error can be reported better */

static int getFileSize( const char *fileName )
	{
	FILE *filePtr;
	long size;

	if( ( filePtr = fopen( fileName, "rb" ) ) == NULL )
		return( BUFFER_SIZE );
	fseek( filePtr, 0L, SEEK_END );
	size = ftell( filePtr );
	fclose( filePtr );
	if( size > INT_MAX )
		return( BUFFER_SIZE );

	return( ( int ) size );
	}

/* Read test data from a file */

static int readFileData( const char *fileName, const char *description,
						 BYTE *buffer, const int bufSize )
	{
	FILE *filePtr;
	int count;

	if( ( filePtr = fopen( fileName, "rb" ) ) == NULL )
		{
		printf( "Couldn't find %s file, skipping test of data import...\n",
				description );
		return( 0 );
		}
	printf( "Testing %s import...\n", description );
	count = fread( buffer, 1, bufSize, filePtr );
	fclose( filePtr );
	if( count == bufSize )
		{
		puts( "The data buffer size is too small for the data.  To fix this, "
			  "either increase\nthe BUFFER_SIZE value in " __FILE__ " and "
			  "recompile the code, or use the\ntest code with dynamically-"
			  "allocated buffers." );
		return( 0 );		/* Skip this test and continue */
		}
	if( count < 16 )
		{
		printf( "Read failed, only read %d bytes.\n", count );
		return( 0 );		/* Skip this test and continue */
		}
	printf( "%s has size %d bytes.\n", description, count );
	return( count );
	}

/* Common routines to create an envelope, add enveloping information, push
   data, pop data, and destroy an envelope */

static int createEnvelope( CRYPT_ENVELOPE *envelope,
						   const CRYPT_FORMAT_TYPE formatType )
	{
	int status;

	/* Create the envelope */
	status = cryptCreateEnvelope( envelope, CRYPT_UNUSED, formatType );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateEnvelope() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

static int createDeenvelope( CRYPT_ENVELOPE *envelope )
	{
	int status;

	/* Create the envelope */
	status = cryptCreateEnvelope( envelope, CRYPT_UNUSED, CRYPT_FORMAT_AUTO );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateDeevelope() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

static int addEnvInfoString( const CRYPT_ENVELOPE envelope,
							 const CRYPT_ATTRIBUTE_TYPE type,
							 const void *envInfo, const int envInfoLen )
	{
	int status;

	status = cryptSetAttributeString( envelope, type, envInfo, envInfoLen );
	if( cryptStatusError( status ) )
		{
		printf( "cryptSetAttributeString() failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

static int addEnvInfoNumeric( const CRYPT_ENVELOPE envelope,
							  const CRYPT_ATTRIBUTE_TYPE type,
							  const int envInfo )
	{
	int status;

	status = cryptSetAttribute( envelope, type, envInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptSetAttribute() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

static int pushData( const CRYPT_ENVELOPE envelope, const BYTE *buffer,
					 const int length, const void *stringEnvInfo,
					 const int numericEnvInfo )
	{
	BOOLEAN isRestartable = FALSE;
	int status, bytesIn;

	/* Push in the data */
	status = cryptPushData( envelope, buffer, length, &bytesIn );
	if( status == CRYPT_ENVELOPE_RESOURCE )
		{
		int cryptEnvInfo;

		/* Add the appropriate enveloping information we need to continue */
		status = cryptSetAttribute( envelope, CRYPT_ATTRIBUTE_CURRENT_GROUP,
									CRYPT_CURSOR_FIRST );
		if( cryptStatusError( status ) )
			{
			printf( "Attempt to move cursor to start of list failed with "
					"error code %d, line %d.\n", status, __LINE__ );
			return( status );
			}
		do
			{
			C_CHR label[ CRYPT_MAX_TEXTSIZE + 1 ];
			int labelLength;

			status = cryptGetAttribute( envelope, CRYPT_ATTRIBUTE_CURRENT, 
										&cryptEnvInfo );
			if( cryptStatusError( status ) )
				{
				printf( "Attempt to read current group failed with error "
						"code %d, line %d.\n", status, __LINE__ );
				return( status );
				}

			switch( cryptEnvInfo )
				{
				case CRYPT_ATTRIBUTE_NONE:
					/* The required information was supplied via other means
					   (in practice this means there's a crypto device
					   available and that was used for the decrypt), there's
					   nothing left to do */
					puts( "(Decryption key was recovered using crypto device "
						  "or non-password-protected\n private key)." );
					break;

				case CRYPT_ENVINFO_PRIVATEKEY:
					/* If there's no decryptoin password present, the 
					   private key must be passed in directly */
					if( stringEnvInfo == NULL )
						{
						status = cryptSetAttribute( envelope, 
													CRYPT_ENVINFO_PRIVATEKEY, 
													numericEnvInfo );
						if( cryptStatusError( status ) )
							{
							printf( "Attempt to add private key failed with "
									"error code %d, line %d.\n", status, 
									__LINE__ );
							return( status );
							}
						isRestartable = TRUE;
						break;
						}

					/* A private-key keyset is present in the envelope, we 
					   need a password to decrypt the key */
					status = cryptGetAttributeString( envelope,
									CRYPT_ENVINFO_PRIVATEKEY_LABEL,
									label, &labelLength );
					if( cryptStatusError( status ) )
						{
						printf( "Private key label read failed with error "
								"code %d, line %d.\n", status, __LINE__ );
						return( status );
						}
#ifdef UNICODE_STRINGS
					label[ labelLength / sizeof( wchar_t ) ] = '\0';
					printf( "Need password to decrypt private key '%S'.\n",
							label );
#else
					label[ labelLength ] = '\0';
					printf( "Need password to decrypt private key '%s'.\n",
							label );
#endif /* UNICODE_STRINGS */
					if( !addEnvInfoString( envelope, CRYPT_ENVINFO_PASSWORD,
								stringEnvInfo, paramStrlen( stringEnvInfo ) ) )
						return( SENTINEL );
					isRestartable = TRUE;
					break;

				case CRYPT_ENVINFO_PASSWORD:
					puts( "Need user password." );
					if( !addEnvInfoString( envelope, CRYPT_ENVINFO_PASSWORD,
								stringEnvInfo, paramStrlen( stringEnvInfo ) ) )
						return( SENTINEL );
					isRestartable = TRUE;
					break;

				case CRYPT_ENVINFO_SESSIONKEY:
					puts( "Need session key." );
					if( !addEnvInfoNumeric( envelope, CRYPT_ENVINFO_SESSIONKEY,
											numericEnvInfo ) )
						return( SENTINEL );
					isRestartable = TRUE;
					break;

				case CRYPT_ENVINFO_KEY:
					puts( "Need conventional encryption key." );
					if( !addEnvInfoNumeric( envelope, CRYPT_ENVINFO_KEY,
											numericEnvInfo ) )
						return( SENTINEL );
					isRestartable = TRUE;
					break;

				case CRYPT_ENVINFO_SIGNATURE:
					/* If we've processed the entire data block in one go,
					   we may end up with only signature information
					   available, in which case we defer processing them
					   until after we've finished with the deenveloped data */
					break;

				default:
					printf( "Need unknown enveloping information type %d.\n",
							cryptEnvInfo );
					return( SENTINEL );
				}
			}
		while( cryptSetAttribute( envelope, CRYPT_ATTRIBUTE_CURRENT_GROUP, 
								  CRYPT_CURSOR_NEXT ) == CRYPT_OK );

		/* If we're using some form of encrypted enveloping, report the
		   algorithm and keysize used */
		if( cryptEnvInfo == CRYPT_ATTRIBUTE_NONE || \
			cryptEnvInfo == CRYPT_ENVINFO_PRIVATEKEY || \
			cryptEnvInfo == CRYPT_ENVINFO_PASSWORD )
			{
			int cryptAlgo, keySize;

			status = cryptGetAttribute( envelope, CRYPT_CTXINFO_ALGO,
										&cryptAlgo );
			if( cryptStatusOK( status ) )
				status = cryptGetAttribute( envelope, CRYPT_CTXINFO_KEYSIZE,
											&keySize );
			if( cryptStatusError( status ) )
				{
				printf( "Couldn't query encryption algorithm and keysize "
						"used in envelope, status %d, line %d.\n", status,
						__LINE__ );
				return( status );
				}
			printf( "Data is protected using algorithm %d with %d bit key.\n",
					cryptAlgo, keySize * 8 );
			}

		/* If we only got some of the data in due to the envelope stopping to
		   ask us for a decryption resource, push in the rest */
		if( bytesIn < length && isRestartable )
			{
			const int initialBytesIn = bytesIn;

			status = cryptPushData( envelope, buffer + initialBytesIn, 
									length - initialBytesIn, &bytesIn );
			if( cryptStatusError( status ) )
				{
				printf( "cryptPushData() for remaining data failed with "
						"error code %d, line %d.\n", status, __LINE__ );
				return( status );
				}
			bytesIn += initialBytesIn;
			}
		}
	else
		if( cryptStatusError( status ) )
			{
			printf( "cryptPushData() failed with error code %d, line %d.\n",
					status, __LINE__ );
			printErrorAttributeInfo( envelope );
			return( status );
			}
	if( bytesIn != length )
		{
		printf( "cryptPushData() only copied %d of %d bytes, line %d.\n",
				bytesIn, length, __LINE__ );
		return( SENTINEL );
		}

	/* Flush the data */
	status = cryptFlushData( envelope );
	if( cryptStatusError( status ) && status != CRYPT_ERROR_COMPLETE )
		{
		printf( "cryptFlushData() failed with error code %d, line %d.\n", 
				status, __LINE__ );
		printErrorAttributeInfo( envelope );
		return( status );
		}

	return( bytesIn );
	}

static int popData( CRYPT_ENVELOPE envelope, BYTE *buffer, int bufferSize )
	{
	int status, bytesOut;

	status = cryptPopData( envelope, buffer, bufferSize, &bytesOut );
	if( cryptStatusError( status ) )
		{
		printf( "cryptPopData() failed with error code %d, line %d.\n",
				status, __LINE__ );
		printErrorAttributeInfo( envelope );
		return( status );
		}

	return( bytesOut );
	}

static int destroyEnvelope( CRYPT_ENVELOPE envelope )
	{
	int status;

	/* Destroy the envelope */
	status = cryptDestroyEnvelope( envelope );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyEnvelope() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

/****************************************************************************
*																			*
*							Enveloping Test Routines 						*
*																			*
****************************************************************************/

/* Test raw data enveloping */

static int envelopeData( const char *dumpFileName, 
						 const BOOLEAN useDatasize,
						 const int bufferSize,
						 const CRYPT_FORMAT_TYPE formatType )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	BYTE *inBufPtr, *outBufPtr = globalBuffer;
	int length, bufSize, count;

	switch( bufferSize )
		{
		case 0:
			printf( "Testing %splain data enveloping%s...\n",
					( formatType == CRYPT_FORMAT_PGP ) ? "PGP " : "",
					( useDatasize && ( formatType != CRYPT_FORMAT_PGP ) ) ? \
					" with datasize hint" : "" );
			length = ENVELOPE_TESTDATA_SIZE;
			inBufPtr = ENVELOPE_TESTDATA;
			break;

		case 1:
			printf( "Testing %splain data enveloping of intermediate-size data...\n",
					( formatType == CRYPT_FORMAT_PGP ) ? "PGP " : "" );
			length = 512;
			inBufPtr = globalBuffer;
			for( count = 0; count < length; count++ )
				inBufPtr[ count ] = count & 0xFF;
			break;

		case 2:
			printf( "Testing %senveloping of large data quantity...\n",
					( formatType == CRYPT_FORMAT_PGP ) ? "PGP " : "" );

			/* Allocate a large buffer and fill it with a known value */
			length = ( INT_MAX <= 32768L ) ? 16384 : 1048576;
			if( ( inBufPtr = malloc( length + 128 ) ) == NULL )
				{
				printf( "Couldn't allocate buffer of %d bytes, skipping large "
						"buffer enveloping test.\n", length );
				return( TRUE );
				}
			outBufPtr = inBufPtr;
			for( count = 0; count < length; count++ )
				inBufPtr[ count ] = count & 0xFF;
			break;

		default:
			return( FALSE );
		}
	bufSize = length + 128;

	/* Create the envelope, push in the data, pop the enveloped result, and
	   destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, formatType ) )
		return( FALSE );
	if( useDatasize )
		cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_DATASIZE, length );
	if( bufferSize > 1 )
		cryptSetAttribute( cryptEnvelope, CRYPT_ATTRIBUTE_BUFFERSIZE,
						   length + 1024 );
	count = pushData( cryptEnvelope, inBufPtr, length, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, outBufPtr, bufSize );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );
	if( bufferSize == 0 && \
		count != length + ( ( formatType == CRYPT_FORMAT_PGP ) ? 8 : \
							useDatasize ? 17 : 25 ) )
		{
		printf( "Enveloped data length %d, should be %d.\n", 
				count, length + 25 );
		return( FALSE );
		}

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	if( bufferSize < 2 )
		debugDump( dumpFileName, outBufPtr, count );

	/* Create the envelope, push in the data, pop the de-enveloped result,
	   and destroy the envelope */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	if( bufferSize > 1 )
		cryptSetAttribute( cryptEnvelope, CRYPT_ATTRIBUTE_BUFFERSIZE,
						   length + 1024 );
	count = pushData( cryptEnvelope, outBufPtr, count, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, outBufPtr, bufSize );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Make sure that the result matches what we pushed */
	if( count != length )
		{
		puts( "De-enveloped data length != original length." );
		return( FALSE );
		}
	if( bufferSize > 0 )
		{
		int i;

		for( i = 0; i < length; i++ )
			if( outBufPtr[ i ] != ( i & 0xFF ) )
			{
			printf( "De-enveloped data != original data at byte %d.\n", i );
			return( FALSE );
			}
		}
	else
		if( memcmp( outBufPtr, ENVELOPE_TESTDATA, length ) )
			{
			puts( "De-enveloped data != original data." );
			return( FALSE );
			}

	/* Clean up */
	if( bufferSize > 1 )
		free( inBufPtr );
	puts( "Enveloping of plain data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopeData( void )
	{
	if( !envelopeData( "env_datn", FALSE, 0, CRYPT_FORMAT_CRYPTLIB ) )
		return( FALSE );	/* Indefinite-length */
	if( !envelopeData( "env_dat", TRUE, 0, CRYPT_FORMAT_CRYPTLIB ) )
		return( FALSE );	/* Datasize */
	if( !envelopeData( "env_dat.pgp", TRUE, 0, CRYPT_FORMAT_PGP ) )
		return( FALSE );	/* PGP format */
	return( envelopeData( "env_datl.pgp", TRUE, 1, CRYPT_FORMAT_PGP ) );
	}						/* PGP format, longer data */

int testEnvelopeDataLargeBuffer( void )
	{
	if( !envelopeData( NULL, TRUE, 2, CRYPT_FORMAT_CRYPTLIB ) )
		return( FALSE );	/* Datasize, large buffer */
	return( envelopeData( NULL, TRUE, 2, CRYPT_FORMAT_PGP ) );
	}						/* Large buffer, PGP format */

/* Test compressed enveloping */

static int envelopeDecompress( BYTE *buffer, const int length )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	BYTE smallBuffer[ 128 ];
	int count, zeroCount;

	/* Create the envelope, push in the data, and pop the de-enveloped 
	   result */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	count = pushData( cryptEnvelope, buffer, length, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, FILEBUFFER_SIZE );
	if( cryptStatusError( count ) )
		{
#ifdef __hpux
		if( count == -1 )
			puts( "Older HPUX compilers break zlib, to remedy this you can "
				  "either get a better\ncompiler/OS or grab a debugger and "
				  "try to figure out what HPUX is doing to\nzlib.  To "
				  "continue the self-tests, comment out the call to\n"
				  "testEnvelopeCompress() and rebuild." );
#endif /* __hpux */
		return( FALSE );
		}

	/* See what happens when we try and pop out more data.  This test is done 
	   because some compressed-data formats don't indicate the end of the
	   data properly, and we need to make sure that the de-enveloping code 
	   handles this correctly */
	zeroCount = popData( cryptEnvelope, smallBuffer, 128 );
	if( zeroCount != 0 )
		{
		puts( "Attempt to pop more data after end-of-data had been reached "
			  "succeeded, the\nenvelope should have reported 0 bytes "
			  "available." );
		return( FALSE );
		}

	/* Clean up */
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );
	return( count );
	}

static int envelopeCompress( const char *dumpFileName, 
							 const BOOLEAN useDatasize,
							 const CRYPT_FORMAT_TYPE formatType )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	FILE *inFile;
	BYTE *buffer, *envelopedBuffer;
	int dataCount = 0, count, status;

	printf( "Testing %scompressed data enveloping%s...\n",
			( formatType == CRYPT_FORMAT_PGP ) ? "PGP " : "",
			useDatasize ? " with datasize hint" : ""  );

	/* Since this needs a nontrivial amount of data for the compression, we
	   read it from an external file into dynamically-allocated buffers */
	if( ( ( buffer = malloc( FILEBUFFER_SIZE ) ) == NULL ) || \
		( ( envelopedBuffer = malloc( FILEBUFFER_SIZE ) ) == NULL ) )
		{
		if( buffer != NULL )
			free( buffer );
		puts( "Couldn't allocate test buffers." );
		return( FALSE );
		}
	inFile = fopen( convertFileName( COMPRESS_FILE ), "rb" );
	if( inFile != NULL )
		{
		dataCount = fread( buffer, 1, FILEBUFFER_SIZE, inFile );
		fclose( inFile );
		assert( dataCount < FILEBUFFER_SIZE );
		}
	if( dataCount < 1000 || dataCount == FILEBUFFER_SIZE )
		{
		free( buffer );
		free( envelopedBuffer );
		puts( "Couldn't read test file for compression." );
		return( FALSE );
		}

	/* Create the envelope, push in the data, pop the enveloped result, and
	   destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, formatType ) )
		return( FALSE );
	status = cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_COMPRESSION,
								CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		printf( "Attempt to enable compression failed, status = %d\n.",
				status );
		return( FALSE );
		}
	if( useDatasize )
		cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_DATASIZE, dataCount );
	count = pushData( cryptEnvelope, buffer, dataCount, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, envelopedBuffer, FILEBUFFER_SIZE );
	if( count > dataCount - 1000 )
		{
		printf( "Compression of data failed, %d bytes in -> %d bytes out.\n",
				dataCount, count );
		return( FALSE );
		}
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	debugDump( dumpFileName, envelopedBuffer, count );

	/* De-envelope the data and make sure that the result matches what we
	   pushed */
	count = envelopeDecompress( envelopedBuffer, count );
	if( !count )
		return( FALSE );
	if( count != dataCount || memcmp( buffer, envelopedBuffer, dataCount ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	/* Clean up */
	free( buffer );
	free( envelopedBuffer );
	puts( "Enveloping of compressed data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopeCompress( void )
	{
	/* In practice these two produce identical output since we always have to
	   use the indefinite-length encoding internally because we don't know in
	   advance how large the compressed data will be */
	if( !envelopeCompress( "env_cprn", FALSE, CRYPT_FORMAT_CRYPTLIB ) )
		return( FALSE );	/* Indefinite length */
	if( !envelopeCompress( "env_cpr", TRUE, CRYPT_FORMAT_CRYPTLIB ) )
		return( FALSE );	/* Datasize */
	return( envelopeCompress( "env_cpr.pgp", TRUE, CRYPT_FORMAT_PGP ) );
	}						/* PGP format */

/* Test encrypted enveloping with a raw session key */

static int envelopeSessionCrypt( const char *dumpFileName, 
								 const BOOLEAN useDatasize,
								 const BOOLEAN useLargeBuffer,
								 const CRYPT_FORMAT_TYPE formatType )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_CONTEXT cryptContext;
	CRYPT_ALGO_TYPE cryptAlgo = ( formatType == CRYPT_FORMAT_PGP ) ? \
								selectCipher( CRYPT_ALGO_IDEA ) : \
								selectCipher( CRYPT_ALGO_CAST );
	BYTE *inBufPtr = ENVELOPE_TESTDATA, *outBufPtr = globalBuffer;
	const int length = useLargeBuffer ? \
							( ( INT_MAX <= 32768L ) ? 16384 : 1048576 ) : \
							ENVELOPE_TESTDATA_SIZE;
	const int bufSize = length + 128;
	int count;

	if( useLargeBuffer )
		{
		int i;

		printf( "Testing %sraw-session-key encrypted enveloping of large "
				"data quantity...\n", 
				( formatType == CRYPT_FORMAT_PGP ) ? "PGP " : "" );

		/* Allocate a large buffer and fill it with a known value */
		if( ( inBufPtr = malloc( bufSize ) ) == NULL )
			{
			printf( "Couldn't allocate buffer of %d bytes, skipping large "
					"buffer enveloping test.\n", length );
			return( TRUE );
			}
		outBufPtr = inBufPtr;
		for( i = 0; i < length; i++ )
			inBufPtr[ i ] = i & 0xFF;
		}
	else
		printf( "Testing %sraw-session-key encrypted enveloping%s...\n",
				( formatType == CRYPT_FORMAT_PGP ) ? "PGP " : "",
				( useDatasize && ( formatType != CRYPT_FORMAT_PGP ) ) ? \
				" with datasize hint" : "" );

	if( formatType != CRYPT_FORMAT_PGP )
		{
		/* Create the session key context.  We don't check for errors here
		   since this code will already have been tested earlier */
		cryptCreateContext( &cryptContext, CRYPT_UNUSED, cryptAlgo );
		}
	else
		{
		/* PGP only allows a limited subset of algorithms and modes, in 
		   addition we have to specifically check that IDEA is available 
		   since it's possible to build cryptlib without IDEA support */
		if( cryptAlgo != CRYPT_ALGO_IDEA )
			{
			puts( "Can't test PGP enveloping because the IDEA algorithm "
				  "isn't available in this\nbuild of cryptlib.\n" );
			return( TRUE );
			}
		cryptCreateContext( &cryptContext, CRYPT_UNUSED, cryptAlgo );
		cryptSetAttribute( cryptContext, CRYPT_CTXINFO_MODE, CRYPT_MODE_CFB );
		}
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEY,
							 "0123456789ABCDEF", 16 );

	/* Create the envelope, push in a password and the data, pop the
	   enveloped result, and destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, formatType ) || \
		!addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_SESSIONKEY,
							cryptContext ) )
		return( FALSE );
	if( useDatasize && !useLargeBuffer )
		{
		/* Test the ability to destroy the context after it's been added 
		   (we replace it with a different context that's used later for 
		   de-enveloping) */
		cryptDestroyContext( cryptContext );
		cryptCreateContext( &cryptContext, CRYPT_UNUSED, cryptAlgo );
		cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEY, 
								 "0123456789ABCDEF", 16 );
		}
	if( useDatasize )
		cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_DATASIZE, length );
	if( useLargeBuffer )
		cryptSetAttribute( cryptEnvelope, CRYPT_ATTRIBUTE_BUFFERSIZE,
						   length + 1024 );
	count = pushData( cryptEnvelope, inBufPtr, length, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, outBufPtr, bufSize );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	if( !useLargeBuffer )
		debugDump( dumpFileName, outBufPtr, count );

	/* Create the envelope, push in the data, pop the de-enveloped result,
	   and destroy the envelope */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	if( useLargeBuffer )
		cryptSetAttribute( cryptEnvelope, CRYPT_ATTRIBUTE_BUFFERSIZE,
						   length + 1024 );
	count = pushData( cryptEnvelope, outBufPtr, count, NULL, cryptContext );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, outBufPtr, bufSize );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Make sure that the result matches what we pushed */
	if( count != length )
		{
		puts( "De-enveloped data length != original length." );
		return( FALSE );
		}
	if( useLargeBuffer )
		{
		int i;

		for( i = 0; i < length; i++ )
			if( outBufPtr[ i ] != ( i & 0xFF ) )
			{
			printf( "De-enveloped data != original data at byte %d.\n", i );
			return( FALSE );
			}
		}
	else
		if( memcmp( outBufPtr, ENVELOPE_TESTDATA, length ) )
			{
			puts( "De-enveloped data != original data." );
			return( FALSE );
			}

	/* Clean up */
	if( useLargeBuffer )
		free( inBufPtr );
	cryptDestroyContext( cryptContext );
	puts( "Enveloping of raw-session-key-encrypted data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopeSessionCrypt( void )
	{
	if( !envelopeSessionCrypt( "env_sesn", FALSE, FALSE, CRYPT_FORMAT_CRYPTLIB ) )
		return( FALSE );	/* Indefinite length */
	if( !envelopeSessionCrypt( "env_ses", TRUE, FALSE, CRYPT_FORMAT_CRYPTLIB ) )
		return( FALSE );	/* Datasize */
#if 0
	/* Although in theory PGP supports raw session-key based enveloping, in
	   practice this key is always (implicitly) derived from a user password,
	   so the enveloping code doesn't allow the use of raw session keys */
	return( envelopeSessionCrypt( "env_ses.pgp", TRUE, FALSE, CRYPT_FORMAT_PGP ) );
#endif /* 0 */
	return( TRUE );
	}

int testEnvelopeSessionCryptLargeBuffer( void )
	{
	return( envelopeSessionCrypt( "env_ses", TRUE, TRUE, CRYPT_FORMAT_CRYPTLIB ) );
	}						/* Datasize, large buffer */

/* Test encrypted enveloping */

static int envelopeDecrypt( BYTE *buffer, const int length, 
							const CRYPT_CONTEXT cryptContext )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	int count;

	/* Create the envelope, push in the data, pop the de-enveloped result,
	   and destroy the envelope */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	count = pushData( cryptEnvelope, buffer, length, NULL, cryptContext );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	destroyEnvelope( cryptEnvelope );
	return( count );
	}

static int envelopeCrypt( const char *dumpFileName, 
						  const BOOLEAN useDatasize,
						  const CRYPT_FORMAT_TYPE formatType )
	{
	CRYPT_CONTEXT cryptContext;
	CRYPT_ENVELOPE cryptEnvelope;
	int count;

	printf( "Testing encrypted enveloping%s...\n", 
			useDatasize ? " with datasize hint" : "" );

	/* Create the session key context.  We don't check for errors here
	   since this code will already have been tested earlier */
	cryptCreateContext( &cryptContext, CRYPT_UNUSED, CRYPT_ALGO_3DES );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEY,
							 "0123456789ABCDEF", 16 );

	/* Create the envelope, push in a KEK and the data, pop the enveloped 
	   result, and destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, formatType ) || \
		!addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_KEY, cryptContext ) )
		return( FALSE );
	if( useDatasize )
		cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
						   ENVELOPE_TESTDATA_SIZE );
	count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
					  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, globalBuffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	debugDump( dumpFileName, globalBuffer, count );

	/* De-envelope the data and make sure that the result matches what we
	   pushed */
	count = envelopeDecrypt( globalBuffer, count, cryptContext );
	if( !count )
		return( FALSE );
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( globalBuffer, ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyContext( cryptContext );
	puts( "Enveloping of encrypted data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopeCrypt( void )
	{
	if( !envelopeCrypt( "env_kekn", FALSE, CRYPT_FORMAT_CRYPTLIB ) )
		return( FALSE );	/* Indefinite length */
	return( envelopeCrypt( "env_kek", TRUE, CRYPT_FORMAT_CRYPTLIB ) );
	}						/* Datasize */


/* Test password-based encrypted enveloping */

static int envelopePasswordDecrypt( BYTE *buffer, const int length )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	int count;

	/* Create the envelope, push in the data, pop the de-enveloped result,
	   and destroy the envelope */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	count = pushData( cryptEnvelope, buffer, length, TEXT( "Password" ), 
					  paramStrlen( TEXT( "Password" ) ) );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	destroyEnvelope( cryptEnvelope );
	return( count );
	}

static int envelopePasswordCrypt( const char *dumpFileName, 
								  const BOOLEAN useDatasize, 
								  const BOOLEAN useAltCipher, 
								  const BOOLEAN multiKeys,
								  const CRYPT_FORMAT_TYPE formatType )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	int count;

	printf( "Testing %s%spassword-encrypted enveloping%s",
			( formatType == CRYPT_FORMAT_PGP ) ? "PGP " : "",
			multiKeys ? "multiple-" : "",
			( useDatasize && ( formatType != CRYPT_FORMAT_PGP ) ) ? \
			" with datasize hint" : "" );
	if( useAltCipher )
		printf( ( formatType == CRYPT_FORMAT_PGP ) ? \
				" with non-default cipher type" : " and stream cipher" );
	puts( "..." );

	/* Create the envelope, push in a password and the data, pop the
	   enveloped result, and destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, formatType ) || \
		!addEnvInfoString( cryptEnvelope, CRYPT_ENVINFO_PASSWORD, 
						   TEXT( "Password" ), 
						   paramStrlen( TEXT( "Password" ) ) ) )
		return( FALSE );
	if( useAltCipher )
		{
		CRYPT_CONTEXT sessionKeyContext;
		int status;

		/* Test enveloping with an IV-less stream cipher, which tests the
		   handling of algorithms that can't be used to wrap themselves in 
		   the RecipientInfo */
		status = cryptCreateContext( &sessionKeyContext, CRYPT_UNUSED, 
									 CRYPT_ALGO_RC4 );
		if( cryptStatusOK( status ) )
			{
			cryptGenerateKey( sessionKeyContext );
			status = cryptSetAttribute( cryptEnvelope, 
										CRYPT_ENVINFO_SESSIONKEY, 
										sessionKeyContext );
			cryptDestroyContext( sessionKeyContext );
			}
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't set non-default envelope cipher, error code "
					"%d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		}
	if( multiKeys && \
		( !addEnvInfoString( cryptEnvelope, CRYPT_ENVINFO_PASSWORD, 
							 TEXT( "Password1" ), 
							 paramStrlen( TEXT( "Password1" ) ) ) || \
		  !addEnvInfoString( cryptEnvelope, CRYPT_ENVINFO_PASSWORD, 
							 TEXT( "Password2" ), 
							 paramStrlen( TEXT( "Password2" ) ) ) || \
		  !addEnvInfoString( cryptEnvelope, CRYPT_ENVINFO_PASSWORD, 
							 TEXT( "Password3" ), 
							 paramStrlen( TEXT( "Password3" ) ) ) ) )
		return( FALSE );
	if( useDatasize )
		cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
						   ENVELOPE_TESTDATA_SIZE );
	count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
					  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, globalBuffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	debugDump( dumpFileName, globalBuffer, count );

	/* De-envelope the data and make sure that the result matches what we
	   pushed */
	count = envelopePasswordDecrypt( globalBuffer, count );
	if( !count )
		return( FALSE );
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( globalBuffer, ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	/* Clean up */
	puts( "Enveloping of password-encrypted data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopePasswordCrypt( void )
	{
	if( !envelopePasswordCrypt( "env_pasn", FALSE, FALSE, FALSE, CRYPT_FORMAT_CRYPTLIB ) )
		return( FALSE );	/* Indefinite length */
	if( !envelopePasswordCrypt( "env_pas", TRUE, FALSE, FALSE, CRYPT_FORMAT_CRYPTLIB ) )
		return( FALSE );	/* Datasize */
	if( !envelopePasswordCrypt( "env_mpas", TRUE, FALSE, TRUE, CRYPT_FORMAT_CRYPTLIB ) )
		return( FALSE );	/* Datasize, multiple keys */
	if( !envelopePasswordCrypt( "env_pas.pgp", TRUE, FALSE, FALSE, CRYPT_FORMAT_PGP ) )
		return( FALSE );	/* PGP format */
	return( envelopePasswordCrypt( "env_pasr", TRUE, TRUE, FALSE, CRYPT_FORMAT_CRYPTLIB ) );
	}						/* IV-less cipher */

/* Test PKC-encrypted enveloping */

static int envelopePKCDecrypt( BYTE *buffer, const int length, 
							   const KEYFILE_TYPE keyFileType )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_KEYSET cryptKeyset;
	const C_STR keysetName = getKeyfileName( keyFileType, TRUE );
	const C_STR password = getKeyfilePassword( keyFileType );
	int count, status;

	/* Create the envelope and push in the decryption keyset */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, 
							  keysetName, CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		status = addEnvInfoNumeric( cryptEnvelope,
								CRYPT_ENVINFO_KEYSET_DECRYPT, cryptKeyset );
	cryptKeysetClose( cryptKeyset );
	if( !status )
		return( FALSE );

	/* Push in the data */
	count = pushData( cryptEnvelope, buffer, length, password, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	destroyEnvelope( cryptEnvelope );
	return( count );
	}

static int envelopePKCDecryptDirect( BYTE *buffer, const int length, 
									 const KEYFILE_TYPE keyFileType )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_CONTEXT cryptContext;
	const C_STR keysetName = getKeyfileName( keyFileType, TRUE );
	const C_STR password = getKeyfilePassword( keyFileType );
	int count, status;

	/* Create the envelope and get the decryption key */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	status = getPrivateKey( &cryptContext, 
							getKeyfileName( keyFileType, TRUE ), 
							getKeyfileUserID( keyFileType, TRUE ), 
							getKeyfilePassword( keyFileType ) );
	if( cryptStatusError( status ) )
		return( FALSE );

	/* Push in the data */
	count = pushData( cryptEnvelope, buffer, length, NULL, cryptContext );
	cryptDestroyContext( cryptContext );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	destroyEnvelope( cryptEnvelope );
	return( count );
	}

static int envelopePKCCrypt( const char *dumpFileName, 
							 const BOOLEAN useDatasize,
							 const KEYFILE_TYPE keyFileType,
							 const BOOLEAN useRecipient,
							 const BOOLEAN useMultipleKeyex,
							 const BOOLEAN useAltAlgo,
							 const BOOLEAN useDirectKey,
							 const CRYPT_FORMAT_TYPE formatType )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_KEYSET cryptKeyset;
	CRYPT_HANDLE cryptKey;
	const C_STR keysetName = getKeyfileName( keyFileType, FALSE );
		/* When reading keys we have to explicitly use the first matching 
		   key in the PGP 2.x keyring since the remaining keys are (for some 
		   reason) stored unencrypted, and the keyring read code will 
		   disallow the use of the key if it's stored in this manner */
	const C_STR keyID = ( keyFileType == KEYFILE_PGP ) ? \
				TEXT( "test" ) : getKeyfileUserID( keyFileType, FALSE );
	int count, status;

	if( !keyReadOK )
		{
		puts( "Couldn't find key files, skipping test of public-key "
			  "encrypted enveloping..." );
		return( TRUE );
		}
	printf( "Testing %spublic-key encrypted enveloping",
			( formatType == CRYPT_FORMAT_PGP ) ? \
				( ( keyFileType == KEYFILE_PGP ) ? "PGP " : "OpenPGP " ) : "" );
	if( useDatasize && ( formatType != CRYPT_FORMAT_PGP ) && \
		!( useRecipient || useMultipleKeyex || useDirectKey ) )
		printf( " with datasize hint" );
	printf( " using " );
	printf( ( keyFileType == KEYFILE_PGP || \
			  keyFileType == KEYFILE_OPENPGP ) ? \
				( ( formatType == CRYPT_FORMAT_PGP ) ? \
					"PGP key" : "raw public key" ) : \
			  "X.509 cert" );
	if( useRecipient && !useAltAlgo )
		printf( " and recipient info" );
	if( useMultipleKeyex )
		printf( " and additional keying info" );
	if( useAltAlgo )
		printf( " and alt.encr.algo" );
	if( useDirectKey )
		printf( " and direct key add" );
	puts( "..." );

	/* If we're using OpenPGP keys we have to use a recipient rather than 
	   adding the key directly because there's no way to tell in advance, when 
	   reading a dual DSA/Elgamal key, which one is actually needed.  Since
	   the signing private key is the one which is usually needed in 
	   standalone reads, a straight read will return the DSA rather than 
	   Elgamal key.  It's only through the use of recipient info that the
	   (cryptlib-internal) code can specify a preference for an encryption
	   key */
	assert( ( keyFileType == KEYFILE_OPENPGP && useRecipient ) || \
			!( keyFileType == KEYFILE_OPENPGP ) );

	/* Open the keyset and either get the public key the hard (to make sure
	   that this version works) or leave the keyset open to allow it to be 
	   added to the envelope */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, 
							  keysetName, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't open keyset %s.\n", keysetName );
		return( FALSE );
		}
	if( !useRecipient )
		{
		status = cryptGetPublicKey( cryptKeyset, &cryptKey, CRYPT_KEYID_NAME,
									keyID );
		cryptKeysetClose( cryptKeyset );
		if( cryptStatusError( status ) )
			{
			puts( "Read of public key from file keyset failed." );
			return( FALSE );
			}
		}

	/* Create the envelope, push in the recipient info or public key and data,
	   pop the enveloped result, and destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, formatType ) )
		return( FALSE );
	if( useAltAlgo )
		{
		/* Specify the use of an alternative (non-default) bulk encryption
		   algorithm */
		if( !addEnvInfoNumeric( cryptEnvelope, CRYPT_OPTION_ENCR_ALGO,
								CRYPT_ALGO_BLOWFISH ) )
			return( FALSE );
		}
	if( useRecipient )
		{
		/* Add recipient information to the envelope.  Since we can't
		   guarantee for enveloping with cryptlib native key types that we 
		   have a real public-key keyset available at this time (it's created 
		   by a different part of the self-test code that may not have run 
		   yet) we're actually reading the public key from the private-key 
		   keyset.  Normally we couldn't do this, however since PKCS #15 
		   doesn't store email addresses as key ID's (there's no need to), 
		   the code will drop back to trying for a match on the key label.  
		   Because of this we specify the private key label instead of a real 
		   recipient email address.  Note that this trick only works because 
		   of a coincidence of two or three factors and wouldn't normally be 
		   used, it's only used here because we can't assume that a real 
		   public-key keyset is available for use.
		   
		   An additional test that would be useful is the ability to handle
		   multiple key exchange records, however the keyset kludge makes 
		   this rather difficult.  Since the functionality is tested by the
		   use of multiple passwords in the conventional-encryption test
		   earlier on this isn't a major issue */
		if( !addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_KEYSET_ENCRYPT,
								cryptKeyset ) || \
			!addEnvInfoString( cryptEnvelope, CRYPT_ENVINFO_RECIPIENT,
							   keyID, paramStrlen( keyID ) ) )
			return( FALSE );
		cryptKeysetClose( cryptKeyset );
		}
	else
		{
		if( !addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_PUBLICKEY,
								cryptKey ) )
			return( FALSE );
		cryptDestroyObject( cryptKey );
		}
	if( useMultipleKeyex && \
		!addEnvInfoString( cryptEnvelope, CRYPT_ENVINFO_PASSWORD, 
						   TEXT( "test" ), paramStrlen( TEXT( "test" ) ) ) )
		return( FALSE );
	if( useDatasize )
		cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
						   ENVELOPE_TESTDATA_SIZE );
	count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
					  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, globalBuffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	debugDump( dumpFileName, globalBuffer, count );

	/* De-envelope the data and make sure that the result matches what we
	   pushed */
	if( useDirectKey )
		count = envelopePKCDecryptDirect( globalBuffer, count, keyFileType );
	else
		count = envelopePKCDecrypt( globalBuffer, count, keyFileType );
	if( !count )
		return( FALSE );
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( globalBuffer, ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	/* Clean up */
	puts( "Enveloping of public-key encrypted data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopePKCCrypt( void )
	{
	if( cryptQueryCapability( CRYPT_ALGO_IDEA, NULL ) == CRYPT_ERROR_NOTAVAIL )
		puts( "Skipping raw public-key and PGP enveloping, which requires "
			  "the IDEA cipher to\nbe enabled.\n" );
	else
		{
		if( !envelopePKCCrypt( "env_pkcn", FALSE, KEYFILE_PGP, FALSE, FALSE, FALSE, FALSE, CRYPT_FORMAT_CRYPTLIB ) )
			return( FALSE );	/* Indefinite length, raw key */
		if( !envelopePKCCrypt( "env_pkc", TRUE, KEYFILE_PGP, FALSE, FALSE, FALSE, FALSE, CRYPT_FORMAT_CRYPTLIB ) )
			return( FALSE );	/* Datasize, raw key */
		if( !envelopePKCCrypt( "env_pkc.pgp", TRUE, KEYFILE_PGP, FALSE, FALSE, FALSE, FALSE, CRYPT_FORMAT_PGP ) )
			return( FALSE );	/* PGP format */
		if( !envelopePKCCrypt( "env_pkc.pgp", TRUE, KEYFILE_PGP, TRUE, FALSE, FALSE, FALSE, CRYPT_FORMAT_PGP ) )
			return( FALSE );	/* PGP format, recipient */
		if( !envelopePKCCrypt( "env_pkca.pgp", TRUE, KEYFILE_PGP, TRUE, FALSE, TRUE, FALSE, CRYPT_FORMAT_PGP ) )
			return( FALSE );	/* PGP format, recipient, nonstandard bulk encr.algo */
		if( !envelopePKCCrypt( "env_pkc.gpg", TRUE, KEYFILE_OPENPGP, TRUE, FALSE, FALSE, FALSE, CRYPT_FORMAT_PGP ) )
			return( FALSE );	/* OpenPGP format, recipient (required for DSA/Elgamal keys) */
		if( !envelopePKCCrypt( "env_pkce.der", TRUE, KEYFILE_OPENPGP, TRUE, FALSE, FALSE, FALSE, CRYPT_FORMAT_CRYPTLIB ) )
			return( FALSE );	/* Datasize, recipient w/Elgamal key for indef-length recipient info */
		}
	if( !envelopePKCCrypt( "env_crt.pgp", TRUE, KEYFILE_X509, TRUE, FALSE, FALSE, FALSE, CRYPT_FORMAT_PGP ) )
		return( FALSE );	/* PGP format, certificate */
	if( !envelopePKCCrypt( "env_crtn", FALSE, KEYFILE_X509, FALSE, FALSE, FALSE, FALSE, CRYPT_FORMAT_CRYPTLIB ) )
		return( FALSE );	/* Indefinite length, certificate */
	if( !envelopePKCCrypt( "env_crt", TRUE, KEYFILE_X509, FALSE, FALSE, FALSE, FALSE, CRYPT_FORMAT_CRYPTLIB ) )
		return( FALSE );	/* Datasize, certificate */
	if( !envelopePKCCrypt( "env_crt", TRUE, KEYFILE_X509, FALSE, FALSE, FALSE, TRUE, CRYPT_FORMAT_CRYPTLIB ) )
		return( FALSE );	/* Datasize, certificate, decrypt key provided directly */
	if( !envelopePKCCrypt( "env_crt", TRUE, KEYFILE_X509, TRUE, FALSE, FALSE, FALSE, CRYPT_FORMAT_CRYPTLIB ) )
		return( FALSE );	/* Datasize, cerficate, recipient */
	return( envelopePKCCrypt( "env_crtp", TRUE, KEYFILE_X509, FALSE, TRUE, FALSE, FALSE, CRYPT_FORMAT_CRYPTLIB ) );
	}						/* Datasize, cerficate+password */

/* Test signed enveloping */

static int getSigCheckResult( const CRYPT_ENVELOPE cryptEnvelope,
							  const CRYPT_CONTEXT sigCheckContext,
							  const BOOLEAN showAttributes )
	{
	int value, status;

	/* Display all of the attributes that we've got */
	if( showAttributes && !displayAttributes( cryptEnvelope ) )
		return( FALSE );

	/* Determine the result of the signature check */
	status = cryptGetAttribute( cryptEnvelope, CRYPT_ATTRIBUTE_CURRENT, 
								&value );
	if( cryptStatusError( status ) )
		{
		printf( "Read of required attribute for signature check returned "
				"status %d.\n", status );
		return( FALSE );
		}
	if( value != CRYPT_ENVINFO_SIGNATURE )
		{
		printf( "Envelope requires unexpected enveloping information type "
				"%d.\n", value );
		return( FALSE );
		}
	if( sigCheckContext != CRYPT_UNUSED )
		{
		status = cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_SIGNATURE,
									sigCheckContext );
		if( cryptStatusError( status ) )
			{
			printf( "Attempt to add signature check key returned status "
					"%d.\n", status );
			return( FALSE );
			}
		}
	status = cryptGetAttribute( cryptEnvelope, CRYPT_ENVINFO_SIGNATURE_RESULT,
								&value );
	if( cryptStatusError( status ) )
		{
		printf( "Signature check returned status %d.\n", status );
		return( FALSE );
		}
	switch( value )
		{
		case CRYPT_OK:
			puts( "Signature is valid." );
			return( TRUE );

		case CRYPT_ERROR_NOTFOUND:
			puts( "Cannot find key to check signature." );
			break;

		case CRYPT_ERROR_SIGNATURE:
			puts( "Signature is invalid." );
			break;

		default:
			printf( "Signature check failed, result = %d.\n", value );
		}

	return( FALSE );
	}

static int envelopeSigCheck( BYTE *buffer, const int length, 
							 const CRYPT_CONTEXT hashContext,
							 const CRYPT_CONTEXT sigContext,
							 const BOOLEAN useRawKey, 
							 const BOOLEAN useAltRawKey,
							 const BOOLEAN detachedSig,
							 const CRYPT_FORMAT_TYPE formatType )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	int count, status;

	/* Create the envelope and push in the sig.check keyset if we're not 
	   using a supplied context for the sig.check */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	if( sigContext == CRYPT_UNUSED )
		{
		CRYPT_KEYSET cryptKeyset;

		if( useRawKey )
			status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
									  CRYPT_KEYSET_FILE, 
									  useAltRawKey ? \
										OPENPGP_PUBKEY_FILE : PGP_PUBKEY_FILE,
									  CRYPT_KEYOPT_READONLY );
		else
			status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
									  CRYPT_KEYSET_FILE, USER_PRIVKEY_FILE,
									  CRYPT_KEYOPT_READONLY );
		if( cryptStatusOK( status ) )
			status = addEnvInfoNumeric( cryptEnvelope,
								CRYPT_ENVINFO_KEYSET_SIGCHECK, cryptKeyset );
		cryptKeysetClose( cryptKeyset );
		if( !status )
			return( FALSE );
		}

	/* If the hash value is being supplied externally, add it to the envelope 
	   before we add the signature data */
	if( detachedSig && hashContext != CRYPT_UNUSED )
		{
		status = cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_HASH,
									hashContext );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't add externally-generated hash value to "
					"envelope, status %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		}

	/* Push in the data */
	count = pushData( cryptEnvelope, buffer, length, NULL, 0 );
	if( !cryptStatusError( count ) )
		{
		if( detachedSig )
			{
			if( hashContext == CRYPT_UNUSED )
				count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
								  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
			}
		else
			count = popData( cryptEnvelope, buffer, length );
		}
	if( cryptStatusError( count ) )
		return( FALSE );

	/* Determine the result of the signature check */
	if( !getSigCheckResult( cryptEnvelope, sigContext, TRUE ) )
		return( FALSE );

	/* If we supplied the sig-checking key, make sure that it's handled 
	   correctly by the envelope.  We shouldn't be able to read it back from 
	   a PGP envelope, and from a cryptlib/CMS/SMIME envelope we should get 
	   back only a cert, not the full private key that we added */
	if( sigContext != CRYPT_UNUSED )
		{
		CRYPT_CONTEXT sigCheckContext;

		status = cryptGetAttribute( cryptEnvelope, CRYPT_ENVINFO_SIGNATURE,
									&sigCheckContext );
		if( formatType == CRYPT_FORMAT_PGP )
			{
			/* If it's a PGP envelope, we can't retrieve the signing key from
			   it */
			if( cryptStatusOK( status ) )
				{
				printf( "Attempt to read signature check key from PGP "
						"envelope succeeded when it\nshould have failed, "
						"line %d.\n", __LINE__ );
				return( FALSE );
				}
			}
		else
			{
			CRYPT_ENVELOPE testEnvelope;

			/* If it's a cryptlib/CMS/SMIME envelope, we should be able to
			   retrieve the signing key from it */
			if( cryptStatusError( status ) )
				{
				printf( "Couldn't retrieve signature check key from "
						"envelope, status %d, line %d.\n", status, 
						__LINE__ );
				return( FALSE );
				}
			
			/* The signing key should be a pure cert, not the private key+
			   cert combination that we pushed in.  Note that the following 
			   will result in an error message being printed in 
			   addEnvInfoNumeric() */
			createEnvelope( &testEnvelope, CRYPT_FORMAT_CRYPTLIB );
			if( addEnvInfoNumeric( testEnvelope, CRYPT_ENVINFO_SIGNATURE,
								   sigCheckContext ) )
				{
				printf( "Retrieved signature check key is a private key, not "
						"a certificate, line %d.\n", __LINE__ );
				return( FALSE );
				}
			else
				puts( "  (The above message indicates that the test "
					  "condition was successfully\n   checked)." );
			destroyEnvelope( testEnvelope );
			cryptDestroyCert( sigCheckContext );
			}
		}

	/* Clean up */
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );
	return( count );
	}

static int envelopeSign( const void *data, const int dataLength,
						 const char *dumpFileName, const BOOLEAN useDatasize, 
						 const BOOLEAN useRawKey, const BOOLEAN useAltRawKey, 
						 const BOOLEAN useCustomHash, 
						 const BOOLEAN useSuppliedKey, 
						 const CRYPT_FORMAT_TYPE formatType )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int count, status;

	if( !keyReadOK )
		{
		puts( "Couldn't find key files, skipping test of signed "
			  "enveloping..." );
		return( TRUE );
		}
	printf( "Testing %ssigned enveloping%s",
			( formatType == CRYPT_FORMAT_PGP ) ? "PGP " : \
			( formatType == CRYPT_FORMAT_SMIME ) ? "S/MIME " : "",
			( useDatasize && ( formatType != CRYPT_FORMAT_PGP ) ) ? \
			" with datasize hint" : "" );
	if( useCustomHash )
		printf( " %s custom hash", 
				( formatType == CRYPT_FORMAT_PGP ) ? "with" :"and" );
	printf( " using %s", useAltRawKey ? "raw DSA key" : \
			useRawKey ? "raw public key" : useSuppliedKey ? \
			"supplied X.509 cert" : "X.509 cert" );
	puts( "..." );

	/* Get the private key */
	if( useRawKey || useAltRawKey )
		{
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
								  CRYPT_KEYSET_FILE, useAltRawKey ? \
									OPENPGP_PRIVKEY_FILE : PGP_PRIVKEY_FILE,
								  CRYPT_KEYOPT_READONLY );
		if( cryptStatusOK( status ) )
			{
			status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
										 CRYPT_KEYID_NAME, TEXT( "test" ), 
										 useAltRawKey ? TEXT( "test1" ) : \
														TEXT( "test10" ) );
			cryptKeysetClose( cryptKeyset );
			}
		}
	else
		status = getPrivateKey( &cryptContext, USER_PRIVKEY_FILE,
								USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		puts( "Read of private key from key file failed, cannot test "
			  "enveloping." );
		return( FALSE );
		}

	/* Create the envelope, push in the signing key, any extra information,
	   and the data to sign, pop the enveloped result, and destroy the
	   envelope */
	if( !createEnvelope( &cryptEnvelope, formatType ) )
		return( FALSE );
	if( useCustomHash )
		{
		CRYPT_CONTEXT hashContext;

		/* Add the (nonstandard) hash algorithm information.  We need to do
		   this before we add the signing key since it's automatically
		   associated with the last hash algorithm added */
		cryptCreateContext( &hashContext, CRYPT_UNUSED, CRYPT_ALGO_MD5 );
		status = addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_HASH,
									hashContext );
		cryptDestroyContext( hashContext );
		if( !status )
			return( FALSE );
		}
	if( !addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_SIGNATURE,
							cryptContext ) )
		return( FALSE );
	if( useDatasize && !useRawKey && !useCustomHash && \
		( formatType != CRYPT_FORMAT_PGP ) )
		{
		CRYPT_CONTEXT hashContext;

		/* Make sure that adding a (pseudo-duplicate) hash action that
		   duplicates the one already added implicitly by the addition of
		   the signature key succeeds (internally, nothing is really done
		   since the hash action is already present) */
		cryptCreateContext( &hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA );
		status = addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_HASH,
									hashContext );
		cryptDestroyContext( hashContext );
		if( !status )
			return( FALSE );
		}
	if( cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_SIGNATURE,
						   cryptContext ) != CRYPT_ERROR_INITED )
		{
		puts( "Addition of duplicate key to envelope wasn't detected." );
		return( FALSE );
		}
	if( !useSuppliedKey )
		cryptDestroyContext( cryptContext );
	if( useDatasize )
		cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
						   dataLength );
	count = pushData( cryptEnvelope, data, dataLength, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, globalBuffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	debugDump( dumpFileName, globalBuffer, count );

	/* De-envelope the data and make sure that the result matches what we
	   pushed */
	count = envelopeSigCheck( globalBuffer, count, CRYPT_UNUSED, 
							  ( useSuppliedKey ) ? cryptContext : CRYPT_UNUSED,
							  useRawKey, useAltRawKey, FALSE, formatType );
	if( !count )
		return( FALSE );
	if( count != dataLength || memcmp( globalBuffer, data, dataLength ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}
	if( useSuppliedKey )
		{
		/* If the following fails, there's a problem with handling reference
		   counting for keys */
		status = cryptDestroyContext( cryptContext );
		if( cryptStatusError( status ) )
			{
			printf( "Attempt to destroy externally-added sig.check key "
					"returned %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		}

	/* Clean up */
	puts( "Enveloping of signed data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopeSign( void )
	{
	if( cryptQueryCapability( CRYPT_ALGO_IDEA, NULL ) == CRYPT_ERROR_NOTAVAIL )
		puts( "Skipping raw public-key based signing, which requires the "
			  "IDEA cipher to\nbe enabled.\n" );
	else
		{
		if( !envelopeSign( ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE, "env_sign", FALSE, TRUE, FALSE, FALSE, FALSE, CRYPT_FORMAT_CRYPTLIB ) )
			return( FALSE );	/* Indefinite length, raw key */
		if( !envelopeSign( ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE, "env_sig", TRUE, TRUE, FALSE, FALSE, FALSE, CRYPT_FORMAT_CRYPTLIB ) )
			return( FALSE );	/* Datasize, raw key */
		if( !envelopeSign( ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE, "env_sig.pgp", TRUE, TRUE, FALSE, FALSE, FALSE, CRYPT_FORMAT_PGP ) )
			return( FALSE );	/* PGP format, raw key */
		if( !envelopeSign( ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE, "env_sigd.pgp", TRUE, TRUE, TRUE, FALSE, FALSE, CRYPT_FORMAT_PGP ) )
			return( FALSE );	/* PGP format, raw DSA key */
		}
	if( !envelopeSign( ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE, "env_csgn", FALSE, FALSE, FALSE, FALSE, FALSE, CRYPT_FORMAT_CRYPTLIB ) )
		return( FALSE );	/* Indefinite length, certificate */
	if( !envelopeSign( ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE, "env_csg", TRUE, FALSE, FALSE, FALSE, FALSE, CRYPT_FORMAT_CRYPTLIB ) )
		return( FALSE );	/* Datasize, certificate */
	if( !envelopeSign( ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE, "env_csgs", TRUE, FALSE, FALSE, FALSE, FALSE, CRYPT_FORMAT_SMIME ) )
		return( FALSE );	/* Datasize, certificate, S/MIME semantics */
	if( !envelopeSign( ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE, "env_csg", TRUE, FALSE, FALSE, FALSE, TRUE, CRYPT_FORMAT_CRYPTLIB ) )
		return( FALSE );	/* Datasize, certificate, sigcheck key supplied */
	if( !envelopeSign( ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE, "env_csg.pgp", TRUE, FALSE, FALSE, FALSE, FALSE, CRYPT_FORMAT_PGP ) )
		return( FALSE );	/* PGP format, certificate */
	if( !envelopeSign( ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE, "env_hsg", TRUE, FALSE, FALSE, TRUE, FALSE, CRYPT_FORMAT_CRYPTLIB ) )
		return( FALSE );	/* Datasize, cert, externally-suppl.hash */
	return( envelopeSign( ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE, "env_csg", TRUE, FALSE, FALSE, FALSE, TRUE, CRYPT_FORMAT_CRYPTLIB ) );
	}						/* Externally-supplied key, to test isolation of sig.check key */

/* Test signed envelope with forced envelope buffer overflow */

static int envelopeSignOverflow( const void *data, const int dataLength,
								 const char *dumpFileName,
								 const CRYPT_FORMAT_TYPE formatType )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_CONTEXT cryptContext;
	BYTE localBuffer[ 8192 + 4096 ];
	const BOOLEAN forceOverflow = ( dataLength <= 8192 ) ? TRUE : FALSE;
	int localBufPos, bytesIn, bytesOut, status;

	if( !keyReadOK )
		{
		puts( "Couldn't find key files, skipping test of signed "
			  "enveloping..." );
		return( TRUE );
		}
	printf( "Testing %ssigned enveloping with forced overflow...\n",
			( formatType == CRYPT_FORMAT_PGP ) ? "PGP " : \
			( formatType == CRYPT_FORMAT_SMIME ) ? "S/MIME " : "" );

	/* Get the private key */
	status = getPrivateKey( &cryptContext, USER_PRIVKEY_FILE,
							USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		puts( "Read of private key from key file failed, cannot test "
			  "enveloping." );
		return( FALSE );
		}

	/* Create the envelope and push in the signing key and any extra 
	   information */
	if( !createEnvelope( &cryptEnvelope, formatType ) )
		return( FALSE );
	if( !addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_SIGNATURE,
							cryptContext ) )
		return( FALSE );
	cryptDestroyContext( cryptContext );
	status = cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
								dataLength );
	if( cryptStatusOK( status ) && forceOverflow )
		/* Set an artificially-small buffer to force an overflow */
		status = cryptSetAttribute( cryptEnvelope, CRYPT_ATTRIBUTE_BUFFERSIZE,
									8192 );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't set envelope parameters to force overflow, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Push in the data to sign.  Since we're forcing an overflow, we can't
	   do this via the usual pushData() but have to do it manually to handle
	   the restart once the overflow occurs */
	status = cryptPushData( cryptEnvelope, data, dataLength, &bytesIn );
	if( cryptStatusError( status ) || bytesIn != dataLength )
		{
		printf( "cryptPushData() failed with status %d, copied %d of %d "
				"bytes, line %d.\n", status, bytesIn, dataLength, __LINE__ );
		return( FALSE );
		}
	status = cryptFlushData( cryptEnvelope );
	if( forceOverflow && status != CRYPT_ERROR_OVERFLOW )
		{
		printf( "cryptFlushData() returned status %d, should have been "
				"CRYPT_ERROR_OVERFLOW,\n  line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptPopData( cryptEnvelope, localBuffer, 8192 + 4096, 
						   &bytesOut );
	if( cryptStatusError( status ) )
		{
		printf( "cryptPopData() #1 failed with status %d, line %d.\n", 
				status, bytesOut, dataLength, __LINE__ );
		return( FALSE );
		}
	localBufPos = bytesOut;
	status = cryptFlushData( cryptEnvelope );
	if( cryptStatusError( status ) )
		{
		printf( "cryptFlushData() failed with error code %d, line %d.\n", 
				status, __LINE__ );
		printErrorAttributeInfo( cryptEnvelope );
		return( FALSE );
		}
	status = cryptPopData( cryptEnvelope, localBuffer + localBufPos, 
						   8192 + 4096 - localBufPos, &bytesOut );
	if( cryptStatusError( status ) )
		{
		printf( "cryptPopData() #2 failed with status %d, line %d.\n", 
				status, bytesOut, dataLength, __LINE__ );
		return( FALSE );
		}
	localBufPos += bytesOut;
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", localBufPos );
	debugDump( dumpFileName, localBuffer, localBufPos );

	/* De-envelope the data and make sure that the result matches what we
	   pushed */
	bytesOut = envelopeSigCheck( localBuffer, localBufPos, CRYPT_UNUSED, 
								 CRYPT_UNUSED, FALSE, FALSE, FALSE, 
								 formatType );
	if( !bytesOut )
		return( FALSE );
	if( bytesOut != dataLength || memcmp( localBuffer, data, dataLength ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	/* Clean up */
	puts( "Enveloping of signed data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopeSignOverflow( void )
	{
	BYTE buffer[ 8192 + 1024 ];

	/* Push in just the right amount of data to force an overflow when we 
	   generate the signature, to check overflow handling in the enveloping
	   code.
	   
	   For PGP it's almost impossible to invoke overflow handling since the 
	   enveloping code is set up to either emit the signature directly into 
	   the buffer or, via an over-conservative estimation of buffer space, 
	   ensure that the user leaves enough space in the buffer for the entire 
	   sig.  For an estimated space requirement of 256 bytes, 8192 - 280 
	   will force the sig into the auxBuffer, but since this is an over-
	   conservative estimate it'll then be flushed straight into the 
	   envelope buffer.  The only way to actually force overflow handling
	   would be to use the longest possible key size and a cert with a large
	   issuerAndSerialNumber.

	   (In addition to the envelope buffer-overflow check, we also try
	   enveloping data with a length at the boundary where PGP switches from
	   2-byte to 4-byte lengths, 8384 bytes, to verify that this works OK).

	   For CMS, we can cause an overflow in one of two locations.  The first,
	   with 8192 - 1152 bytes of data, causes an overflow when emitting the
	   signing certs.  This is fairly straightforward, the enveloping code
	   always requires enough room for the signing certs, so all that happens
	   is that the user pops some data and tries again.

	   The second overflow is with 8192 - 1280 bytes of data, which causes an
	   overflow on signing.
	   */
	memset( buffer, '*', 8192 + 1024 );
	if( !envelopeSignOverflow( buffer, 8192 - 280, "env_sigo.pgp", CRYPT_FORMAT_PGP ) )
		return( FALSE );	/* PGP format, raw key */
	if( !envelopeSignOverflow( buffer, 8384 - 6, "env_sigo2.pgp", CRYPT_FORMAT_PGP ) )
		return( FALSE );	/* PGP format, raw key */
	if( !envelopeSignOverflow( buffer, 8192 - 1152, "env_csgo1", CRYPT_FORMAT_SMIME ) )
		return( FALSE );	/* Datasize, certificate, S/MIME semantics */
	return( envelopeSignOverflow( buffer, 8192 - 1280, "env_csgo2", CRYPT_FORMAT_SMIME ) );
	}						/* Datasize, certificate, S/MIME semantics */

/* Test authenticated (MACd) enveloping */

static int envelopeAuthent( const void *data, const int dataLength,
							const BOOLEAN useDatasize )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	int count;

	printf( "Testing authenticated enveloping" );
	if( useDatasize )
		printf( " with datasize hint" );
	puts( "..." );

	/* Create the envelope and push in the password after telling the
	   enveloping code we want to MAC rather than encrypt */
	if( !createEnvelope( &cryptEnvelope, CRYPT_FORMAT_CRYPTLIB ) || \
		!addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_MAC,
							TRUE ) || \
		!addEnvInfoString( cryptEnvelope, CRYPT_ENVINFO_PASSWORD, 
						   TEXT( "Password" ), 
						   paramStrlen( TEXT( "Password" ) ) ) )
		return( FALSE );

	/* Push in the data, pop the enveloped result, and destroy the
	   envelope */
	if( useDatasize )
		cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
						   dataLength );
	count = pushData( cryptEnvelope, data, dataLength, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, globalBuffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	debugDump( useDatasize ? "env_mac" : "env_macn", globalBuffer, count );

	/* Create the envelope */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );

	/* Push in the data */
	count = pushData( cryptEnvelope, globalBuffer, count, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, globalBuffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );

	/* Determine the result of the MAC check */
	if( !getSigCheckResult( cryptEnvelope, CRYPT_UNUSED, TRUE ) || \
		!destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Make sure that the result matches what we pushed */
	if( count != dataLength || memcmp( globalBuffer, data, dataLength ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	/* Clean up */
	puts( "Enveloping of authenticated data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopeAuthenticate( void )
	{
	/* As of mid 2003 there are no known implementations of this CMS
	   mechanism, any attempt to use it will trigger an assertion in the
	   enveloping code intended to catch things like this so we don't try
	   and exercise it */
	return( TRUE );

	if( !envelopeAuthent( ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE,
						  FALSE ) )
		return( FALSE );
	return( envelopeAuthent( ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE,
							 TRUE ) );
	}

/****************************************************************************
*																			*
*							CMS Enveloping Test Routines 					*
*																			*
****************************************************************************/

/* Test CMS signature generation/checking */

static int displaySigResult( const CRYPT_ENVELOPE cryptEnvelope,
							 const CRYPT_CONTEXT sigCheckContext,
							 const BOOLEAN firstSig )
	{
	CRYPT_CERTIFICATE signerInfo;
	BOOLEAN sigStatus = FALSE;
	int status;

	/* Determine the result of the signature check.  We only display the
	   attributes for the first sig since this operation walks the attribute 
	   list,which moves the attribute cursor */
	sigStatus = getSigCheckResult( cryptEnvelope, sigCheckContext, 
								   firstSig );
	if( sigCheckContext != CRYPT_UNUSED )
		/* If the sig.check key is provided externally (which in practice we 
		   only do for PGP sigs), there's no signer info or extra data 
		   present */
		return( sigStatus );

	/* Report on the signer and signature info.  We continue even if the sig.
	   status is bad since we can still try and display signing info even if 
	   the check fails */
	status = cryptGetAttribute( cryptEnvelope, CRYPT_ENVINFO_SIGNATURE,
								&signerInfo );
	if( cryptStatusError( status ) && sigStatus )
		{
		printf( "Cannot retrieve signer information from CMS signature, "
				"status = %d.\n", status );
		return( FALSE );
		}
	if( cryptStatusOK( status ) )
		{
		puts( "Signer information is:" );
		if( !printCertInfo( signerInfo ) )
			return( FALSE );
		cryptDestroyCert( signerInfo );
		}
	status = cryptGetAttribute( cryptEnvelope,
							CRYPT_ENVINFO_SIGNATURE_EXTRADATA, &signerInfo );
	if( cryptStatusError( status ) && sigStatus && \
		status != CRYPT_ERROR_NOTFOUND )
		{
		printf( "Cannot retrieve signature information from CMS signature, "
				"status = %d.\n", status );
		return( FALSE );
		}
	if( cryptStatusOK( status ) )
		{
		puts( "Signature information is:" );
		if( !printCertInfo( signerInfo ) )
			return( FALSE );
		cryptDestroyCert( signerInfo );
		}

	return( sigStatus );
	}

static int cmsEnvelopeSigCheck( const void *signedData,
								const int signedDataLength,
								const CRYPT_CONTEXT sigCheckContext,
								const CRYPT_CONTEXT hashContext,
								const BOOLEAN detachedSig,
								const BOOLEAN hasTimestamp,
								const BOOLEAN checkData )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	int count, status;

	/* Create the (de-)envelope and push in the data.  Since this is a CMS
	   signature that carries its certs with it, there's no need to push in
	   a sig.check keyset.  If it has a detached sig, we need to push two
	   lots of data, first the signature to set the envelope state, then the
	   data, however if the hash is being supplied externally we just set the
	   hash attribute.  In addition if it's a detached sig, there's nothing
	   to be unwrapped so we don't pop any data */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	if( detachedSig && hashContext != CRYPT_UNUSED )
		{
		/* The hash value is being supplied externally, add it to the
		   envelope before we add the signature data */
		status = cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_HASH,
									hashContext );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't add externally-generated hash value to "
					"envelope, status %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		}
	count = pushData( cryptEnvelope, signedData, signedDataLength, NULL, 0 );
	if( !cryptStatusError( count ) )
		{
		if( detachedSig )
			{
			if( hashContext == CRYPT_UNUSED )
				count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
								  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
			}
		else
			count = popData( cryptEnvelope, globalBuffer, BUFFER_SIZE );
		}
	if( cryptStatusError( count ) )
		return( FALSE );

	/* Display the details of the envelope signature and check whether 
	   there's more information such as a timestamp or a second signature 
	   present */
	status = displaySigResult( cryptEnvelope, sigCheckContext, TRUE );
	if( status == TRUE && hasTimestamp )
		{
		CRYPT_ENVELOPE cryptTimestamp;
		int contentType;

		/* Try and get the timestamp info.  We can't safely use 
		   displaySigResult() on this because many timestamps are stripped-
		   down minimal-size CMS messages with no additional sig-checking
		   info present, so we just read the CMS content-type to make sure
		   that everything's OK */
		printf( "Envelope contains a timestamp..." );
		status = cryptGetAttribute( cryptEnvelope, CRYPT_ENVINFO_TIMESTAMP,
									&cryptTimestamp );
		if( cryptStatusError( status ) )
			{
			printf( "\nCouldn't read timestamp from envelope, status %d, "
					"line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		status = cryptGetAttribute( cryptTimestamp,
									CRYPT_ENVINFO_CONTENTTYPE, &contentType );
		if( cryptStatusError( status ) || \
			contentType != CRYPT_CONTENT_TSTINFO )
			{
			printf( "\nTimestamp data envelope doesn't appear to contain a "
					"timestamp, line %d.\n", __LINE__ );
			return( FALSE );
			}
		printf( " timestamp data appears OK.\n" );
		cryptDestroyEnvelope( cryptTimestamp );
		status = TRUE;
		}
	if( status == TRUE && cryptStatusOK( \
			cryptSetAttribute( cryptEnvelope, CRYPT_ATTRIBUTE_CURRENT_GROUP,
							   CRYPT_CURSOR_NEXT ) ) )
		{
		puts( "Data has a second signature:" );
		status = displaySigResult( cryptEnvelope, CRYPT_UNUSED, FALSE );
		}
	if( status == TRUE && cryptStatusOK( \
			cryptSetAttribute( cryptEnvelope, CRYPT_ATTRIBUTE_CURRENT_GROUP,
							   CRYPT_CURSOR_NEXT ) ) )
		{
		/* We can have two, but not three */
		puts( "Data appears to have (nonexistent) third signature." );
		return( FALSE );
		}

	/* Make sure that the result matches what we pushed */
	if( !detachedSig && checkData && ( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( globalBuffer, ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE ) ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	/* Clean up */
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );
	return( status );
	}

static int cmsEnvelopeSign( const BOOLEAN useDatasize,
				const BOOLEAN useAttributes, const BOOLEAN useExtAttributes,
				const BOOLEAN detachedSig, const BOOLEAN useExternalHash,
				const BOOLEAN useTimestamp, const BOOLEAN useNonDataContent,
				const BOOLEAN dualSig, const CRYPT_CONTEXT externalSignContext,
				const CRYPT_FORMAT_TYPE formatType )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_CONTEXT cryptContext, cryptContext2, hashContext = CRYPT_UNUSED;
	BOOLEAN isPGP = ( formatType == CRYPT_FORMAT_PGP ) ? TRUE : FALSE;
	int count, status = CRYPT_OK;

	if( !keyReadOK )
		{
		puts( "Couldn't find key files, skipping test of CMS signed "
			  "enveloping..." );
		return( TRUE );
		}
	printf( "Testing %s %s%s", isPGP ? "PGP" : "CMS", 
			useExtAttributes ? "extended " : "",
			detachedSig ? "detached signature" : \
				dualSig ? "dual signature" : "signed enveloping" );
	if( useNonDataContent )
		printf( " of non-data content" );
	if( useExternalHash )
		printf( " with externally-supplied hash" );
	if( !useAttributes )
		printf( " without signing attributes" );
	if( useDatasize && \
		!( useNonDataContent || useAttributes || useExtAttributes || \
		   detachedSig || useTimestamp ) )
		/* Keep the amount of stuff being printed down */
		printf( " with datasize hint" );
	if( useTimestamp )
		printf( " and timestamp" );
	puts( "..." );

	/* Get the private key.  If we're applying two signatures, we also get 
	   a second signing key.  Since the dual-key file test has created a 
	   second signing key, we use that as the most convenient one */
	if( externalSignContext != CRYPT_UNUSED )
		cryptContext = externalSignContext;
	else
		{
		status = getPrivateKey( &cryptContext, USER_PRIVKEY_FILE,
								USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		if( cryptStatusError( status ) )
			{
			puts( "Read of private key from key file failed, cannot test "
				  "CMS enveloping." );
			return( FALSE );
			}
		}
	if( dualSig )
		{
		status = getPrivateKey( &cryptContext2, DUAL_PRIVKEY_FILE,
								DUAL_SIGNKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		if( cryptStatusError( status ) )
			{
			puts( "Read of private key from key file failed, cannot test "
				  "CMS enveloping." );
			return( FALSE );
			}
		}

	/* Create the CMS envelope, push in the signing key(s) and data, pop the
	   enveloped result, and destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, formatType ) || \
		!addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_SIGNATURE,
							cryptContext ) )
		return( FALSE );
	if( dualSig && 
		!addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_SIGNATURE,
							cryptContext2 ) )
		return( FALSE );
	if( ( externalSignContext == CRYPT_UNUSED ) && !isPGP )
		cryptDestroyContext( cryptContext );
	if( dualSig )
		cryptDestroyContext( cryptContext2 );
	if( useNonDataContent )
		/* Test non-data content type w.automatic attribute handling */
		status = cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_CONTENTTYPE,
									CRYPT_CONTENT_SIGNEDDATA );
	if( cryptStatusOK( status ) && useDatasize )
		status = cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
									ENVELOPE_TESTDATA_SIZE );
	if( cryptStatusOK( status ) && useExtAttributes )
		{
		CRYPT_CERTIFICATE cmsAttributes;

		/* Add an ESS security label and signing description as signing 
		   attributes */
		cryptCreateCert( &cmsAttributes, CRYPT_UNUSED,
						 CRYPT_CERTTYPE_CMS_ATTRIBUTES );
		status = cryptSetAttributeString( cmsAttributes,
							CRYPT_CERTINFO_CMS_SECLABEL_POLICY,
							TEXT( "1 3 6 1 4 1 9999 1" ), 
							paramStrlen( TEXT( "1 3 6 1 4 1 9999 1" ) ) );
		if( cryptStatusOK( status ) )
			status = cryptSetAttribute( cmsAttributes,
							CRYPT_CERTINFO_CMS_SECLABEL_CLASSIFICATION,
							CRYPT_CLASSIFICATION_SECRET );
		if( cryptStatusOK( status ) )
			status = cryptSetAttributeString( cmsAttributes,
							CRYPT_CERTINFO_CMS_SIGNINGDESCRIPTION,
							"This signature isn't worth the paper it's not "
							"printed on", 56 );
		if( cryptStatusOK( status ) )
			status = cryptSetAttribute( cryptEnvelope,
							CRYPT_ENVINFO_SIGNATURE_EXTRADATA, cmsAttributes );
		cryptDestroyCert( cmsAttributes );
		}
	if( cryptStatusOK( status ) && detachedSig )
		status = cryptSetAttribute( cryptEnvelope,
							CRYPT_ENVINFO_DETACHEDSIGNATURE, TRUE );
	if( cryptStatusOK( status ) && !useAttributes )
		status = cryptSetAttribute( CRYPT_UNUSED,
							CRYPT_OPTION_CMS_DEFAULTATTRIBUTES, FALSE );
	if( cryptStatusOK( status ) && useTimestamp )
		{
		CRYPT_SESSION cryptSession;

		/* Create the TSP session, add the TSA URL, and add it to the
		   envelope */
		status = cryptCreateSession( &cryptSession, CRYPT_UNUSED, 
									 CRYPT_SESSION_TSP );
		if( status == CRYPT_ERROR_PARAM3 )	/* TSP session access not available */
			return( CRYPT_ERROR_NOTAVAIL );
		status = cryptSetAttributeString( cryptSession, 
										  CRYPT_SESSINFO_SERVER_NAME, 
										  TSP_DEFAULTSERVER_NAME, 
										  paramStrlen( TSP_DEFAULTSERVER_NAME ) );
		if( cryptStatusError( status ) )
			return( attrErrorExit( cryptSession, "cryptSetAttributeString()", 
								   status, __LINE__ ) );
		status = cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_TIMESTAMP,
									cryptSession );
		cryptDestroySession( cryptSession );
		}
	if( cryptStatusError( status ) )
		{
		printf( "cryptSetAttribute() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
					  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
	if( !useAttributes )
		/* Restore the default attributes setting */
		cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CMS_DEFAULTATTRIBUTES,
						   TRUE );
	if( cryptStatusError( count ) )
		{
		/* The timestamping can fail for a wide range of (non-fatal) reasons,
		   typically either because this build doesn't have networking
		   enabled or because the TSA can't be contacted, so we don't treat
		   this one as a fatal error */
		if( useTimestamp )
			{
			puts( "Envelope timestamping failed due to problems talking to "
				  "TSA, this is a non-\ncritical problem.  Continuing...\n" );
			cryptDestroyEnvelope( cryptEnvelope );
			return( TRUE );
			}
		return( FALSE );
		}
	count = popData( cryptEnvelope, globalBuffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "%s %s has size %d bytes.\n", isPGP ? "PGP" : "CMS",
			( detachedSig ) ? "detached signature" : "signed data", 
			count );
	debugDump( detachedSig ?
				 ( !isPGP ? \
				   ( useDatasize ? "smi_dsg" : "smi_dsgn" ) : \
				   "pgp_dsg.pgp" ) : \
			   useExtAttributes ? \
				 ( useDatasize ? "smi_esg" : "smi_esgn" ) : \
			   useTimestamp ? \
				 ( useDatasize ? "smi_tsg" : "smi_tsgn" ) : \
			   useNonDataContent ? \
				 ( useDatasize ? "smi_ndc" : "smi_ndcn" ) : \
			   dualSig ? \
				 ( useDatasize ? "smi_2sg" : "smi_n2sg" ) : \
			   useDatasize ? "smi_sig" : "smi_sign", globalBuffer, count );

	/* If we're supplying the hash value externally, calculate it now */
	if( useExternalHash )
		{
		status = cryptCreateContext( &hashContext, CRYPT_UNUSED,
									 CRYPT_ALGO_SHA );
		if( cryptStatusOK( status ) )
			status = cryptEncrypt( hashContext, ENVELOPE_TESTDATA,
								   ENVELOPE_TESTDATA_SIZE );
		if( cryptStatusOK( status ) && formatType == CRYPT_FORMAT_CMS )
			status = cryptEncrypt( hashContext, "", 0 );
		if( cryptStatusError( status ) )
			{
			puts( "Couldn't create external hash of data." );
			return( FALSE );
			}
		}

	/* Make sure that the signature is valid */
	status = cmsEnvelopeSigCheck( globalBuffer, count, 
								  isPGP ? cryptContext : CRYPT_UNUSED, 
								  hashContext, detachedSig, FALSE, TRUE );
	if( hashContext != CRYPT_UNUSED )
		cryptDestroyContext( hashContext );
	if( isPGP )
		cryptDestroyContext( cryptContext );
	if( !status )
		return( FALSE );

	if( detachedSig )
		printf( "Creation of %s %sdetached signature %ssucceeded.\n\n",
				isPGP ? "PGP" : "CMS", useExtAttributes ? "extended " : "",
				( hashContext != CRYPT_UNUSED ) ? \
					"with externally-supplied hash " : "" );
	else
		printf( "Enveloping of CMS %s%ssigned data succeeded.\n\n",
				useExtAttributes ? "extended " : "",
				useTimestamp ? "timestamped " : "" );
	return( TRUE );
	}

int testCMSEnvelopeSign( void )
	{
	if( !cmsEnvelopeSign( FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, CRYPT_UNUSED, CRYPT_FORMAT_CMS ) )
		return( FALSE );	/* Minimal (no default S/MIME attributes) */
	if( !cmsEnvelopeSign( FALSE, TRUE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, CRYPT_UNUSED, CRYPT_FORMAT_CMS ) )
		return( FALSE );	/* Standard (default S/MIME signing attributes) */
	if( !cmsEnvelopeSign( TRUE, TRUE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, CRYPT_UNUSED, CRYPT_FORMAT_CMS ) )
		return( FALSE );	/* Datasize and attributes */
	if( !cmsEnvelopeSign( FALSE, TRUE, TRUE, FALSE, FALSE, FALSE, FALSE, FALSE, CRYPT_UNUSED, CRYPT_FORMAT_CMS ) )
		return( FALSE );	/* Extended signing attributes */
	if( !cmsEnvelopeSign( TRUE, TRUE, TRUE, FALSE, FALSE, FALSE, FALSE, FALSE, CRYPT_UNUSED, CRYPT_FORMAT_CMS ) )
		return( FALSE );	/* Datasize and extended attributes */
	return( cmsEnvelopeSign( TRUE, TRUE, FALSE, FALSE, FALSE, FALSE, TRUE, FALSE, CRYPT_UNUSED, CRYPT_FORMAT_CMS ) );
	}						/* Signing of non-data content */

int testCMSEnvelopeDualSign( void )
	{
	return( cmsEnvelopeSign( TRUE, TRUE, FALSE, FALSE, FALSE, FALSE, FALSE, TRUE, CRYPT_UNUSED, CRYPT_FORMAT_CMS ) );
							/* Standard, with two signatures */
	}

int testCMSEnvelopeDetachedSig( void )
	{
	if( !cmsEnvelopeSign( FALSE, TRUE, FALSE, TRUE, FALSE, FALSE, FALSE, FALSE, CRYPT_UNUSED, CRYPT_FORMAT_CMS ) )
		return( FALSE );	/* Detached sig and attributes */
	if( !cmsEnvelopeSign( FALSE, TRUE, FALSE, TRUE, TRUE, FALSE, FALSE, FALSE, CRYPT_UNUSED, CRYPT_FORMAT_CMS ) )
		return( FALSE );	/* Detached sig, attributes, externally-suppl.hash */
	return( cmsEnvelopeSign( TRUE, TRUE, FALSE, TRUE, TRUE, FALSE, FALSE, FALSE, CRYPT_UNUSED, CRYPT_FORMAT_PGP ) );
	}						/* Detached sig, data size, externally-suppl.hash, PGP format */

int testCMSEnvelopeSignEx( const CRYPT_CONTEXT signContext )
	{
	return( cmsEnvelopeSign( TRUE, TRUE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, signContext, CRYPT_FORMAT_CMS ) );
	}						/* Datasize, attributes, external signing context */

int testSessionEnvTSP( void )
	{
	/* This is a pseudo-enveloping test that uses the enveloping
	   functionality but is called as part of the session tests since full
	   testing of the TSP handling requires that it be used to timestamp an
	   S/MIME sig */
	return( cmsEnvelopeSign( TRUE, TRUE, FALSE, FALSE, FALSE, TRUE, FALSE, FALSE, CRYPT_UNUSED, CRYPT_FORMAT_CMS ) );
	}						/* Datasize, attributes, timestamp */

static int cmsImportSignedData( const char *fileName, const int fileNo,
								const BOOLEAN isDetachedSig )
	{
	BYTE *bufPtr = globalBuffer;
	char msgBuffer[ 128 ];
	int count, status;

	/* Read the test data */
	count = getFileSize( fileName ) + 10;
	if( count >= BUFFER_SIZE )
		{
		if( ( bufPtr = malloc( count ) ) == NULL )
			{
			printf( "Couldn't allocate test buffer of %d bytes.\n", count );
			return( FALSE );
			}
		}
	sprintf( msgBuffer, "S/MIME SignedData #%d", fileNo );
	count = readFileData( fileName, msgBuffer, bufPtr, count );
	if( !count )
		{
		if( bufPtr != globalBuffer )
			free( bufPtr );
		return( count );
		}

	/* Check the signature on the data */
	status = cmsEnvelopeSigCheck( bufPtr, count, CRYPT_UNUSED, CRYPT_UNUSED, 
								  FALSE, ( fileNo == 6 ) ? TRUE : FALSE, 
								  FALSE );
	if( bufPtr != globalBuffer )
		free( bufPtr );
	if( status )
		puts( "S/MIME SignedData import succeeded.\n" );
	return( status );
	}

int testCMSEnvelopeSignedDataImport( void )
	{
	FILE *filePtr;
	BYTE fileName[ BUFFER_SIZE ];
	int i;

	/* Make sure that the test data is present so we can return a useful 
	   error message */
	filenameFromTemplate( fileName, SMIME_SIG_FILE_TEMPLATE, 1 );
	if( ( filePtr = fopen( fileName, "rb" ) ) == NULL )
		{
		puts( "Couldn't find S/MIME SignedData file, skipping test of "
			  "SignedData import..." );
		return( TRUE );
		}
	fclose( filePtr );

	/* There are many encoding variations possible for signed data so we try
	   a representative sample to make sure that the code works in all 
	   cases */
	for( i = 1; i <= 6; i++ )
		{
		filenameFromTemplate( fileName, SMIME_SIG_FILE_TEMPLATE, i );
		if( !cmsImportSignedData( fileName, i, ( i == 5 ) ? TRUE : FALSE ) && \
			i != 5 )	/* AuthentiCode sig check fails for some reason */
			return( FALSE );
		}

	puts( "Import of S/MIME SignedData succeeded.\n" );
	return( TRUE );
	}

/* Test CMS enveloping/de-enveloping */

static int cmsEnvelopeDecrypt( const void *envelopedData,
							   const int envelopedDataLength,
							   const CRYPT_HANDLE externalKeyset,
							   const C_STR externalPassword )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	int count, status;

	/* Create the envelope and push in the decryption keyset */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	if( externalKeyset != CRYPT_UNUSED )
		status = addEnvInfoNumeric( cryptEnvelope,
								CRYPT_ENVINFO_KEYSET_DECRYPT, externalKeyset );
	else
		{
		CRYPT_KEYSET cryptKeyset;

		status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
								  CRYPT_KEYSET_FILE, USER_PRIVKEY_FILE,
								  CRYPT_KEYOPT_READONLY );
		if( cryptStatusOK( status ) )
			status = addEnvInfoNumeric( cryptEnvelope,
								CRYPT_ENVINFO_KEYSET_DECRYPT, cryptKeyset );
		cryptKeysetClose( cryptKeyset );
		}
	if( !status )
		return( FALSE );

	/* Push in the data */
	count = pushData( cryptEnvelope, envelopedData, envelopedDataLength,
					  ( externalPassword == NULL ) ? TEST_PRIVKEY_PASSWORD :
					  externalPassword, 0 );
	if( cryptStatusError( count ) )
		return( ( externalPassword != NULL ) ? count : FALSE );
	count = popData( cryptEnvelope, globalBuffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Make sure that the result matches what we pushed */
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( globalBuffer, ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	return( TRUE );
	}

static int cmsEnvelopeCrypt( const char *dumpFileName,
							 const BOOLEAN useDatasize,
							 const BOOLEAN useStreamCipher,
							 const BOOLEAN useLargeBlockCipher,
							 const CRYPT_HANDLE externalCryptContext,
							 const CRYPT_HANDLE externalKeyset,
							 const C_STR externalPassword,
							 const C_STR recipientName )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_HANDLE cryptKey;
	BOOLEAN isKeyAgreementKey = FALSE;
	int count, status;

	if( !keyReadOK )
		{
		puts( "Couldn't find key files, skipping test of CMS encrypted "
			  "enveloping..." );
		return( TRUE );
		}
	printf( "Testing CMS public-key encrypted enveloping" );
	if( externalKeyset != CRYPT_UNUSED && recipientName != NULL )
		printf( " with dual encr./signing certs" );
	else
		if( useStreamCipher )
			printf( " with stream cipher" );
		else
			if( useLargeBlockCipher )
				printf( " with large block size cipher" );
			else
				if( useDatasize )
					printf( " with datasize hint" );
	puts( "..." );

	/* Get the public key.  We use assorted variants to make sure that they 
	   all work */
	if( externalCryptContext != CRYPT_UNUSED )
		{
		int cryptAlgo;

		status = cryptGetAttribute( externalCryptContext, CRYPT_CTXINFO_ALGO,
									&cryptAlgo );
		if( cryptStatusError( status ) )
			{
			puts( "Couldn't determine algorithm for public key, cannot test "
				  "CMS enveloping." );
			return( FALSE );
			}
		if( cryptAlgo == CRYPT_ALGO_KEA )
			isKeyAgreementKey = TRUE;
		cryptKey = externalCryptContext;
		}
	else
		if( recipientName == NULL )
			{
			CRYPT_KEYSET cryptKeyset;

			/* No recipient name, get the public key */
			status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
									  CRYPT_KEYSET_FILE, USER_PRIVKEY_FILE,
									  CRYPT_KEYOPT_READONLY );
			if( cryptStatusOK( status ) )
				status = cryptGetPublicKey( cryptKeyset, &cryptKey,
											CRYPT_KEYID_NAME,
											USER_PRIVKEY_LABEL );
			if( cryptStatusOK( status ) )
				status = cryptKeysetClose( cryptKeyset );
			if( cryptStatusError( status ) )
				{
				puts( "Read of public key from key file failed, cannot test "
					  "CMS enveloping." );
				return( FALSE );
				}
			}

	/* Create the envelope, add the public key and originator key if
	   necessary, push in the data, pop the enveloped result, and destroy
	   the envelope */
	if( !createEnvelope( &cryptEnvelope, CRYPT_FORMAT_CMS ) )
		return( FALSE );
	if( recipientName != NULL )
		{
		CRYPT_KEYSET cryptKeyset;

		/* We're using a recipient name, add the recipient keyset and
		   recipient name */
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
								  DATABASE_KEYSET_TYPE, DATABASE_KEYSET_NAME,
								  CRYPT_KEYOPT_READONLY );
		if( cryptStatusError( status ) )
			{
			puts( "Couldn't open key database, skipping test of CMS "
				  "encrypted enveloping..." );
			cryptDestroyEnvelope( cryptEnvelope );
			return( TRUE );
			}
		if( !addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_KEYSET_ENCRYPT,
								cryptKeyset ) )
			return( FALSE );
		cryptKeysetClose( cryptKeyset );
		if( !addEnvInfoString( cryptEnvelope, CRYPT_ENVINFO_RECIPIENT,
							   recipientName, paramStrlen( recipientName ) ) )
			return( FALSE );
		}
	else
		if( !addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_PUBLICKEY,
								cryptKey ) )
			return( FALSE );
	if( isKeyAgreementKey && \
		!addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_ORIGINATOR,
							cryptKey ) )
		return( FALSE );
	if( externalCryptContext == CRYPT_UNUSED )
		cryptDestroyObject( cryptKey );
	if( useDatasize )
		cryptSetAttribute( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
						   ENVELOPE_TESTDATA_SIZE );
	count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
					  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, globalBuffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	debugDump( dumpFileName, globalBuffer, count );

	/* Make sure that the enveloped data is valid */
	status = cmsEnvelopeDecrypt( globalBuffer, count, externalKeyset,
								 externalPassword );
	if( status <= 0 )	/* Can be FALSE or an error code */
		return( status );

	/* Clean up */
	puts( "Enveloping of CMS public-key encrypted data succeeded.\n" );
	return( TRUE );
	}

int testCMSEnvelopePKCCrypt( void )
	{
	int value, status;

	if( !cmsEnvelopeCrypt( "smi_pkcn", FALSE, FALSE, FALSE, CRYPT_UNUSED, CRYPT_UNUSED, NULL, NULL ) )
		return( FALSE );	/* Standard */
	if( !cmsEnvelopeCrypt( "smi_pkc", TRUE, FALSE, FALSE, CRYPT_UNUSED, CRYPT_UNUSED, NULL, NULL ) )
		return( FALSE );	/* Datasize hint */

	/* Test enveloping with an IV-less stream cipher, which bypasses the usual
	   CBC-mode block cipher handling.  The alternative way of doing this is
	   to manually add a CRYPT_CTXINFO_SESSIONKEY object, doing it this way is
	   less work */
	cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_ALGO, &value );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_ALGO, CRYPT_ALGO_RC4 );
	status = cmsEnvelopeCrypt( "smi_pkcs", TRUE, TRUE, FALSE, CRYPT_UNUSED, CRYPT_UNUSED, NULL, NULL );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_ALGO, value );
	if( !status )			/* Datasize and stream cipher */
		return( status );

	/* Test enveloping with a cipher with a larger-than-usual block size */
	cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_ALGO, &value );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_ALGO, CRYPT_ALGO_AES );
	status = cmsEnvelopeCrypt( "smi_pkcb", TRUE, FALSE, TRUE, CRYPT_UNUSED, CRYPT_UNUSED, NULL, NULL );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_ENCR_ALGO, value );
	return( status );		/* Datasize and large blocksize cipher */
	}

int testCMSEnvelopePKCCryptEx( const CRYPT_HANDLE encryptContext,
							   const CRYPT_HANDLE decryptKeyset,
							   const C_STR password )
	{
	int status;

	status = cmsEnvelopeCrypt( "smi_pkcd", TRUE, FALSE, FALSE, encryptContext, decryptKeyset, password, NULL );
	if( status == CRYPT_ERROR_NOTFOUND )
		{					/* Datasize, keys in crypto device */
		puts( "  (This is probably because the public key certificate was "
			  "regenerated after\n   the certificate stored with the "
			  "private key was created, so that the\n   private key can't "
			  "be identified any more using the public key that was\n   "
			  "used for encryption.  This can happen when the cryptlib "
			  "self-test is run\n   in separate stages, with one stage "
			  "re-using data that was created\n   earlier during a "
			  "previous stage)." );
		return( FALSE );
		}
	return( status );
	}

int testCMSEnvelopePKCCryptDoubleCert( void )
	{
	CRYPT_KEYSET cryptKeyset;
	int status;

	/* The dual-cert test uses cryptlib's internal key management to read the
	   appropriate cert from a database keyset, if this hasn't been set up
	   then the test will fail so we try and detect the presence of the
	   database keyset here.  This isn't perfect since it requires that the
	   database keyset be updated with the certs in the same run as this
	   test, but it's the best we can do */
	if( !doubleCertOK )
		{
		puts( "The certificate database wasn't updated with dual encryption/"
			  "signing certs\nduring this test run (either because database "
			  "keysets aren't enabled in this\nbuild of cryptlib or because "
			  "only some portions of the self-tests are being\nrun), "
			  "skipping the test of CMS enveloping with dual certs.\n" );
		return( TRUE );
		}

	/* Since we're using certs with the same DN and email address present
	   in multiple certs, we can't use the generic user keyset but have to
	   use one that has been set up to have multiple certs that differ
	   only in keyUsage */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  DUAL_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't find keyset with dual encryption/signature certs "
			  "for test of dual cert\nencryption." );
		return( FALSE );
		}
	status = cmsEnvelopeCrypt( "smi_pkcr", TRUE, FALSE, FALSE, CRYPT_UNUSED,
							   cryptKeyset, TEST_PRIVKEY_PASSWORD,
							   TEXT( "dave@wetaburgers.com" ) );
	cryptKeysetClose( cryptKeyset );
	if( status == CRYPT_ERROR_NOTFOUND )
		{					/* Datasize, recipient */
		puts( "  (This is probably because the public key certificate was "
			  "regenerated after\n   the certificate stored with the "
			  "private key was created, so that the\n   private key can't "
			  "be identified any more using the public key that was\n   "
			  "used for encryption.  This can happen when the cryptlib "
			  "self-test is run\n   in separate stages, with one stage "
			  "re-using data that was created\n   earlier during a "
			  "previous stage)." );
		return( FALSE );
		}
	return( status );
	}

/****************************************************************************
*																			*
*							Test Data Import Routines 						*
*																			*
****************************************************************************/

/* Import PGP 2.x and OpenPGP-generated password-encrypted data */

int testEnvelopePasswordCryptImport( void )
	{
	BYTE fileName[ BUFFER_SIZE ];
	int count;

	/* Process the PGP 2.x data */
	filenameFromTemplate( fileName, PGP_ENC_FILE_TEMPLATE, 1 );
	count = readFileData( fileName, "PGP password-encrypted data", 
						  globalBuffer, BUFFER_SIZE );
	if( !count )
		return( FALSE );
	count = envelopePasswordDecrypt( globalBuffer, count );
	if( !count )
		return( FALSE );
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( globalBuffer, ENVELOPE_PGP_TESTDATA, 
				ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}
	puts( "Import of PGP password-encrypted data succeeded." );

	/* Process the OpenPGP data */
	filenameFromTemplate( fileName, PGP_ENC_FILE_TEMPLATE, 2 );
	count = readFileData( fileName, "OpenPGP password-encrypted data", 
						  globalBuffer, BUFFER_SIZE );
	if( !count )
		return( FALSE );
	if( !envelopePasswordDecrypt( globalBuffer, count ) )
		return( FALSE );
	if( memcmp( globalBuffer, ENVELOPE_PGP_TESTDATA, 
				ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}
	filenameFromTemplate( fileName, PGP_ENC_FILE_TEMPLATE, 3 );
	count = readFileData( fileName, "OpenPGP password-encrypted data", 
						  globalBuffer, BUFFER_SIZE );
	if( !count )
		return( FALSE );
	if( !envelopePasswordDecrypt( globalBuffer, count ) )
		return( FALSE );
	if( memcmp( globalBuffer, ENVELOPE_PGP_TESTDATA, 
				ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}
	puts( "Import of OpenPGP password-encrypted data succeeded.\n" );
	return( TRUE );
	}

/* Import PGP 2.x and OpenPGP-generated PKC-encrypted data */

int testEnvelopePKCCryptImport( void )
	{
	BYTE fileName[ BUFFER_SIZE ];
	int count;

	/* Process the PGP 2.x data */
	filenameFromTemplate( fileName, PGP_PKE_FILE_TEMPLATE, 1 );
	count = readFileData( fileName, "PGP-encrypted data", globalBuffer, 
						  BUFFER_SIZE );
	if( !count )
		return( FALSE );
	count = envelopePKCDecrypt( globalBuffer, count, KEYFILE_PGP );
	if( !count )
		return( FALSE );
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( globalBuffer, ENVELOPE_PGP_TESTDATA, 
				ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}
	filenameFromTemplate( fileName, PGP_PKE_FILE_TEMPLATE, 2 );
	count = readFileData( fileName, "PGP (NAI)-encrypted data", globalBuffer, 
						  BUFFER_SIZE );
	if( !count )
		return( FALSE );
	count = envelopePKCDecrypt( globalBuffer, count, KEYFILE_NAIPGP );
	if( !count )
		return( FALSE );
	if( globalBuffer[ 0 ] != 0xA3 || globalBuffer[ 1 ] != 0x01 || \
		globalBuffer[ 2 ] != 0x5B || globalBuffer[ 3 ] != 0x53 )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}
	puts( "Import of PGP-encrypted data succeeded." );

	/* Process the OpenPGP data.  The first file uses RSA and 3DES, the 
	   second uses Elgamal and AES with MDC, the third Elgamal and Blowfish 
	   with MDC */
	filenameFromTemplate( fileName, OPENPGP_PKE_FILE_TEMPLATE, 1 );
	count = readFileData( fileName, "OpenPGP (GPG)-encrypted data", 
						  globalBuffer, BUFFER_SIZE );
	if( !count )
		return( FALSE );
	count = envelopePKCDecrypt( globalBuffer, count, KEYFILE_PGP );
	if( !count )
		return( FALSE );
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( globalBuffer, ENVELOPE_PGP_TESTDATA, 
				ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}
	filenameFromTemplate( fileName, OPENPGP_PKE_FILE_TEMPLATE, 2 );
	count = readFileData( fileName, "OpenPGP (GPG)-encrypted data with "
						  "AES + MDC", globalBuffer, BUFFER_SIZE );
	if( !count )
		return( FALSE );
	count = envelopePKCDecrypt( globalBuffer, count, KEYFILE_OPENPGP );
	if( !count )
		return( FALSE );
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( globalBuffer, ENVELOPE_PGP_TESTDATA, 
				ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}
	filenameFromTemplate( fileName, OPENPGP_PKE_FILE_TEMPLATE, 3 );
	count = readFileData( fileName, "OpenPGP (GPG)-encrypted data with "
						  "Blowfish + MDC", globalBuffer, BUFFER_SIZE );
	if( !count )
		return( FALSE );
	count = envelopePKCDecrypt( globalBuffer, count, KEYFILE_OPENPGP );
	if( !count )
		return( FALSE );
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( globalBuffer, ENVELOPE_PGP_TESTDATA, 
				ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}
	puts( "Import of OpenPGP-encrypted data succeeded.\n" );
	return( TRUE );
	}

/* Import PGP 2.x and OpenPGP-generated signed data */

int testEnvelopeSignedDataImport( void )
	{
	CRYPT_CONTEXT hashContext;
	BYTE fileName[ BUFFER_SIZE ];
	int count, status;

	/* Process the PGP 2.x data */
	filenameFromTemplate( fileName, PGP_SIG_FILE_TEMPLATE, 1 );
	count = readFileData( fileName, "PGP-signed data", globalBuffer, 
						  BUFFER_SIZE );
	if( !count )
		return( FALSE );
	count = envelopeSigCheck( globalBuffer, count, CRYPT_UNUSED, 
							  CRYPT_UNUSED, TRUE, FALSE, FALSE, 
							  CRYPT_FORMAT_PGP );
	if( !count )
		return( FALSE );
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( globalBuffer, ENVELOPE_PGP_TESTDATA, 
				ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}
	puts( "Import of PGP-signed data succeeded." );

	/* Process the OpenPGP (actually a weird 2.x/OpenPGP hybrid produced by
	   PGP 5.0) data */
	filenameFromTemplate( fileName, PGP_SIG_FILE_TEMPLATE, 2 );
	count = readFileData( fileName, "PGP 2.x/OpenPGP-hybrid-signed data", 
						  globalBuffer, BUFFER_SIZE );
	if( !count )
		return( FALSE );
	count = envelopeSigCheck( globalBuffer, count, CRYPT_UNUSED, 
							  CRYPT_UNUSED, TRUE, FALSE, FALSE, 
							  CRYPT_FORMAT_PGP );
	if( !count )
		return( FALSE );
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( globalBuffer, ENVELOPE_PGP_TESTDATA, 
				ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}
	puts( "Import of PGP 2.x/OpenPGP-hybrid-signed data succeeded." );

	/* Process the OpenPGP data */
	filenameFromTemplate( fileName, PGP_SIG_FILE_TEMPLATE, 3 );
	count = readFileData( fileName, "OpenPGP-signed data", 
						  globalBuffer, BUFFER_SIZE );
	if( !count )
		return( FALSE );
	count = envelopeSigCheck( globalBuffer, count, CRYPT_UNUSED, 
							  CRYPT_UNUSED, TRUE, TRUE, FALSE, 
							  CRYPT_FORMAT_PGP );
	if( !count )
		return( FALSE );
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( globalBuffer, ENVELOPE_PGP_TESTDATA, 
				ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}
	puts( "Import of OpenPGP-signed data succeeded." );

	/* Process the OpenPGP detached signature data.  The data is provided 
	   externally so we have to hash it ourselves.  Since PGP hashes further
	   data after hashing the content, we can't complete the hashing but have
	   to use the partially-completed hash */
	status = cryptCreateContext( &hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA );
	if( cryptStatusOK( status ) )
		status = cryptEncrypt( hashContext, ENVELOPE_PGP_TESTDATA,
							   ENVELOPE_TESTDATA_SIZE );
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't create external hash of data." );
		return( FALSE );
		}
	filenameFromTemplate( fileName, PGP_SIG_FILE_TEMPLATE, 4 );
	count = readFileData( fileName, "OpenPGP-signed data with "
						  "externally-supplied hash", globalBuffer, 
						  BUFFER_SIZE );
	if( !count )
		return( FALSE );
	count = envelopeSigCheck( globalBuffer, count, hashContext, 
							  CRYPT_UNUSED, TRUE, TRUE, TRUE, 
							  CRYPT_FORMAT_PGP );
	cryptDestroyContext( hashContext );
	if( !count )
		return( FALSE );
	puts( "Import of OpenPGP-signed data with externally-supplied hash "
		  "succeeded.\n" );
	return( TRUE );
	}

/* Import PGP 2.x and OpenPGP-generated compressed data */

int testEnvelopeCompressedDataImport( void )
	{
	BYTE fileName[ BUFFER_SIZE ], *bufPtr;
	int count;

	/* Since this needs a nontrivial amount of data for the compression, we
	   use a dynamically-allocated buffer */
	if( ( bufPtr = malloc( FILEBUFFER_SIZE ) ) == NULL )
		{
		puts( "Couldn't allocate test buffer." );
		return( FALSE );
		}

	/* Process the PGP 2.x data */
	filenameFromTemplate( fileName, PGP_COPR_FILE_TEMPLATE, 1 );
	count = readFileData( fileName, "PGP 2.x compressed data", 
						  bufPtr, FILEBUFFER_SIZE );
	if( !count )
		return( FALSE );
	count = envelopeDecompress( bufPtr, count );
	if( count && memcmp( bufPtr, ENVELOPE_COMPRESSEDDATA, 
						 ENVELOPE_COMPRESSEDDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}
	if( !count )
		return( FALSE );
	puts( "Import of PGP 2.x compressed data succeeded.\n" );

	/* Process the OpenPGP nested data */
	filenameFromTemplate( fileName, PGP_COPR_FILE_TEMPLATE, 2 );
	count = readFileData( fileName, "OpenPGP compressed signed data", 
						  bufPtr, FILEBUFFER_SIZE );
	if( !count )
		return( FALSE );
	count = envelopeDecompress( bufPtr, count );
	if( count && \
		( bufPtr[ 0 ] != 0x90 || bufPtr[ 1 ] != 0x0D || \
		  bufPtr[ 2 ] != 0x03 || bufPtr[ 3 ] != 0x00 ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}
	if( !count )
		return( FALSE );
	memcpy( globalBuffer, bufPtr, count );
	free( bufPtr );
	count = envelopeSigCheck( globalBuffer, count, CRYPT_UNUSED, 
							  CRYPT_UNUSED, TRUE, TRUE, FALSE, 
							  CRYPT_FORMAT_PGP );
	if( !count )
		return( FALSE );
	if( count && memcmp( globalBuffer, ENVELOPE_COMPRESSEDDATA, 
						 ENVELOPE_COMPRESSEDDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}
	puts( "Import of OpenPGP compressed signed data succeeded.\n" );
	return( TRUE );
	}

/* Generic test routines used for debugging.  These are only meant to be 
   used interactively, and throw exceptions rather than returning status 
   values */

static void dataImport( int count, const BOOLEAN resultBad )
	{
	CRYPT_ENVELOPE cryptEnvelope;

	createDeenvelope( &cryptEnvelope );
	count = pushData( cryptEnvelope, globalBuffer, count, NULL, 0 );
	if( resultBad )
		{
		assert( cryptStatusError( count ) );
		return;
		}
	assert( !cryptStatusError( count ) );
	count = popData( cryptEnvelope, globalBuffer, BUFFER_SIZE );
	assert( !cryptStatusError( count ) );
	destroyEnvelope( cryptEnvelope );
	}

void xxxDataImport( const char *fileName )
	{
	int count;

	count = getFileSize( fileName ) + 10;
	if( count >= BUFFER_SIZE )
		assert( 0 );
	count = readFileData( fileName, "Generic test data", globalBuffer, count );
	assert( count );
	dataImport( count, FALSE );
	}

void xxxEnvTest( void )
	{
	char fileName[ 256 ], text[ 64 ];
	int count, i;

#if 1
	for( i = 1; i <= 4; i++ )
		{
		sprintf( fileName, "/tmp/oct_odd_%d.der", i );
		sprintf( text, "odd test file %d", i );
		count = readFileData( fileName, text, globalBuffer, BUFFER_SIZE );
		assert( count );
		dataImport( count, FALSE );
		}
#endif /* 0 */
#if 1
	for( i = 1; i <= 7; i++ )
		{
		sprintf( fileName, "/tmp/oct_bad_%d.der", i );
		sprintf( text, "bad test file %d", i );
		count = readFileData( fileName, text, globalBuffer, BUFFER_SIZE );
		assert( count );
		dataImport( count, TRUE );
		}
#endif /* 0 */
	}

void xxxSignedDataImport( const char *fileName )
	{
	int count, status;

	count = getFileSize( fileName ) + 10;
	if( count >= BUFFER_SIZE )
		assert( 0 );
	count = readFileData( fileName, "S/MIME test data", globalBuffer, count );
	assert( count );
	status = cmsEnvelopeSigCheck( globalBuffer, count, CRYPT_UNUSED, 
								  CRYPT_UNUSED, FALSE, FALSE, FALSE );
	assert( status );
	}

void xxxEncryptedDataImport( const char *fileName )
	{
	int count, status;

	count = getFileSize( fileName ) + 10;
	if( count >= BUFFER_SIZE )
		assert( 0 );
	count = readFileData( fileName, "S/MIME test data", globalBuffer, count );
	assert( count );
	status = cmsEnvelopeDecrypt( globalBuffer, count, CRYPT_UNUSED, NULL );
	assert( status );
	}
