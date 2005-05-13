/****************************************************************************
*																			*
*						cryptlib Certificate Utility						*
*					  Copyright Peter Gutmann 1997-2002						*
*																			*
****************************************************************************/

/* The following exists only as a debugging tool intended for use during
   cryptlib development.  THIS CODE IS NOT MAINTAINED, AND ITS USE IS NOT
   SUPPORTED */

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

/* Define the following to wrap the main() function in the standalone program
   with a simple wrapper that tests various options */

/* #define WRAP_STANDALONE */

/****************************************************************************
*																			*
*								Standalone main()							*
*																			*
****************************************************************************/

/* Windoze defines ERROR_FILE_EXISTS somewhere even though it's not
   documented */

#undef ERROR_FILE_EXISTS

/* Error codes.  cryptlib return codes are converted to a positive value
   (some OS's don't like negative status codes), application-specific codes
   unrelated to cryptlib are given below */

#define ERROR_BADARG		500		/* Bad argument */
#define ERROR_FILE_EXISTS	501		/* Output file already exists */
#define ERROR_FILE_INPUT	502		/* Error opening input file */
#define ERROR_FILE_OUTPUT	503		/* Error opening/creating output file */

/* Stucture to store DN components passed in by the caller */

typedef struct {
	const CRYPT_ATTRIBUTE_TYPE type;
	const char *name;
	char *value;
	} DN_INFO;

/* Check whether a file already exists */

static int checkFileExists( const char *fileName,
							const BOOLEAN overwriteFile )
	{
	FILE *filePtr;

	/* Make sure the output file doesn't already exist */
	if( fileName == NULL || ( filePtr = fopen( fileName, "rb" ) ) == NULL )
		return( CRYPT_OK );
	fclose( filePtr );
	if( !overwriteFile )
		{
		printf( "Output file %s already exists.\n", fileName );
		return( ERROR_FILE_EXISTS );
		}
	return( CRYPT_OK );
	}

/* Break up a DN into its components */

static int parseDN( DN_INFO *dnInfo, char *dn )
	{
	char *dnPtr = dn;

	while( *dnPtr )
		{
		int i;

		/* Find the info on the current DN component */
		for( i = 0; dnInfo[ i ].type != SENTINEL; i++ )
			if( !strnicmp( dnPtr, dnInfo[ i ].name,
						   strlen( dnInfo[ i ].name ) ) )
				break;
		if( dnInfo[ i ].type == SENTINEL )
			{
			printf( "Bad DN format '%s'.\n", dn );
			return( ERROR_BADARG );
			}
		if( dnInfo[ i ].value != NULL )
			{
			printf( "Duplicate component in DN '%s'.\n", dn );
			return( ERROR_BADARG );
			}
		dnPtr += strlen( dnInfo[ i ].name );
		if( *dnPtr++ != '=' )
			{
			printf( "Missing '=' in DN '%s'.\n", dn );
			return( ERROR_BADARG );
			}

		dnInfo[ i ].value = dnPtr;
		for( i = 0; dnPtr[ i ] != ',' && dnPtr[ i ]; i++ );
		if( dnPtr[ i ] )
			{
			/* There's more to follow, add a terminator and point to the rest
			   of the string */
			dnPtr[ i ] = '\0';
			dnPtr++;
			}
		dnPtr += i;
		}

	return( CRYPT_OK );
	}

/* Generate a new key + cert request/self-signed cert */

static int generateKey( const char *keysetName, const char *password,
						const char *label, const DN_INFO *dnInfo,
						const BOOLEAN createSelfSigned )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT cryptContext;
	const char *keyLabel = ( label == NULL ) ? "Private key" : label;
	int status;

	/* Create a new RSA key */
	cryptCreateContext( &cryptContext, CRYPT_UNUSED, CRYPT_ALGO_RSA );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL, keyLabel,
							 strlen( keyLabel ) );
	status = cryptGenerateKey( cryptContext );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( cryptContext );
		printf( "Key generation failed with error %d.\n", status );
		return( status );
		}

	/* Write the key to the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  keysetName, CRYPT_KEYOPT_CREATE );
	if( cryptStatusOK( status ) )
		{
		status = cryptAddPrivateKey( cryptKeyset, cryptContext, password );
		cryptKeysetClose( cryptKeyset );
		}
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( cryptContext );
		printf( "Private keyset save failed with error code %d.\n", status );
		return( status );
		}

	/* Create the certification request/certificate */
	cryptCreateCert( &cryptCert, CRYPT_UNUSED, createSelfSigned ? \
					 CRYPT_CERTTYPE_CERTIFICATE : CRYPT_CERTTYPE_CERTREQUEST );
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusOK( status ) )
		{
		int i;

		/* Add each of the DN components */
		for( i = 0; dnInfo[ i ].type != SENTINEL; i++ )
			if( dnInfo[ i ].value != NULL )
				{
				status = cryptSetAttributeString( cryptCert, dnInfo[ i ].type,
							dnInfo[ i ].value, strlen( dnInfo[ i ].value ) );
				if( cryptStatusError( status ) )
					break;
				}
		}
	if( cryptStatusOK( status ) && createSelfSigned )
		{
		/* Make it a self-signed CA cert */
		status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SELFSIGNED, TRUE );
		if( cryptStatusOK( status ) )
			status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_KEYUSAGE,
					CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN );
		if( cryptStatusOK( status ) )
			status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_CA, TRUE );
		}
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, cryptContext );
	cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate creation failed with error code %d.\n",
				status );
		printErrorAttributeInfo( cryptCert );
		cryptDestroyCert( cryptCert );
		return( status );
		}

	/* Update the private key keyset with the cert request/certificate */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  keysetName, CRYPT_KEYOPT_NONE );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetPrivateKey( cryptKeyset, NULL, CRYPT_KEYID_NONE,
									 NULL, password );
		if( cryptStatusOK( status ) )
			status = cryptAddPrivateKey( cryptKeyset, cryptCert, NULL );
		cryptKeysetClose( cryptKeyset );
		}

	/* Clean up */
	cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		printf( "Private key update failed with error code %d.\n", status );
	return( status );
	}

/* Create a certificate from a cert request */

static int createCertificate( CRYPT_CERTIFICATE *certificate,
							  const CRYPT_CERTTYPE_TYPE certType,
							  const CRYPT_CERTIFICATE certRequest,
							  const CRYPT_CONTEXT caKeyContext )
	{
	int status;

	/* Verify the certification request */
	status = cryptCheckCert( certRequest, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the certificate */
	status = cryptCreateCert( certificate, CRYPT_UNUSED, certType );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptSetAttribute( *certificate,
					CRYPT_CERTINFO_CERTREQUEST, certRequest );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( *certificate, caKeyContext );

	return( status );
	}

/* Display the help info */

static void showHelp( void )
	{
	puts( "Usage: certutil -d<DN> -v -k{s} -s{c} -o -f<private key> -l<key label>" );
	puts( "                -p<password> <infile> <outfile>" );
	puts( "       -k = generate new key and create cert request" );
	puts( "       -ks = create self-signed CA root instead of cert request" );
	puts( "       -s = sign a cert request and create cert" );
	puts( "       -sc = create cert chain instead of cert" );
	puts( "       -u = update a private key with a cert object" );
	puts( "       -v = view/check cert object" );
	puts( "       -x = extract cert object from private key" );
	puts( "" );
	puts( "       -d = specify DN (components = C, SP, L, O, OU, CN, Email, URI)" );
	puts( "       -f = specify private key file" );
	puts( "       -o = overwrite output file" );
	puts( "       -p = specify password" );
	puts( "" );
	puts( "Examples:" );
	puts( "certutil -k -l\"My key\" keyfile         - Generate private key + cert.request" );
	puts( "certutil -k -d\"C=US,O=Foo Corp,CN=John Doe,Email=doe@foo.com\" keyfile   - DN" );
	puts( "certutil -ks keyfile            - Generate private key + self-signed CA cert" );
	puts( "certutil -s -pcakey infile outfile                       - Sign cert request" );
	puts( "certutil -u -puserkey infile  - Update users private key with cert in infile" );
	puts( "certutil -x -pkeyfile outfile      - Extract certificate object from keyfile" );
	puts( "certutil -v infile             - Display certificate object(s), verify sigs." );
	puts( "" );
	puts( "Long example: Create self-signed CA root, certify a cert.request:" );
	puts( "certutil -ks -l\"CA key\" -d<DN> cakey - Generate CA key + self-signed CA root" );
	puts( "certutil -k -l\"User key\" -d<DN> userkey - Generate user key and cert request" );
	puts( "certutil -x -puserkey certreq           - Extract cert request from user key" );
	puts( "certutil -s -pcakey certreq cert            - Sign cert request with CA root" );
	puts( "certutil -u -puserkey cert                   - Update user key with new cert" );
	}

/* The main program.  If we're not calling this from a test wrapper, use it
   as our main() */

#ifndef WRAP_STANDALONE
  #define wrappedMain	main
#endif /* WRAP_STANDALONE */

int wrappedMain( int argc, char **argv )
	{
	CRYPT_CERTIFICATE certificate;
	DN_INFO dnInfo[] = {
		{ CRYPT_CERTINFO_COMMONNAME, "CN", NULL },
		{ CRYPT_CERTINFO_COUNTRYNAME, "C", NULL },
		{ CRYPT_CERTINFO_RFC822NAME, "Email", NULL },
		{ CRYPT_CERTINFO_LOCALITYNAME, "L", NULL },
		{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, "OU", NULL },
		{ CRYPT_CERTINFO_ORGANIZATIONNAME, "O", NULL },
		{ CRYPT_CERTINFO_STATEORPROVINCENAME, "SP", NULL },
		{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, "URI", NULL },
		{ SENTINEL, NULL, NULL }
		};
	char *keyFileName = NULL, *password = NULL, *label = NULL;
	char dnBuffer[ CRYPT_MAX_TEXTSIZE * 8 ];
	BOOLEAN doView = FALSE, doExtract = FALSE, doOverwriteOutput = FALSE;
	BOOLEAN doSign = FALSE, doUpdate = FALSE, doKeygen = FALSE;
	BOOLEAN optionFlag = FALSE;
	int status;

	/* Process the input parameters */
	puts( "Certificate utility for cryptlib 3.0beta.  Copyright Peter Gutmann 1998, 1999." );
	puts( "Warning: This is a debugging tool, not a user program!" );
	puts( "" );
	if( argc < 3 )
		{
		showHelp();
		return( ERROR_BADARG );
		}

	/* VisualAge C++ doesn't set the TZ correctly */
#if defined( __IBMC__ ) || defined( __IBMCPP__ )
	tzset();
#endif /* VisualAge C++ */

	/* Initialise cryptlib */
	status = cryptInit();
	if( cryptStatusError( status ) )
		{
		printf( "cryptlib initialisation failed with error code %d.\n",
				status );
		return( -status );
		}
	atexit( (void(*)(void)) cryptEnd );		/* Auto cleanup on exit */

	/* Check for arguments */
	while( argc > 1 && *argv[ 1 ] == '-' )
		{
		char *argPtr = argv[ 1 ] + 1;

		while( *argPtr )
			{
			switch( toupper( *argPtr ) )
				{
				case 'D':
					argPtr++;
					if( strlen( argPtr ) > CRYPT_MAX_TEXTSIZE * 8 )
						{
						puts( "DN too long" );
						return( ERROR_BADARG );
						}
					strcpy( dnBuffer, argPtr );
					argPtr += strlen( argPtr );
					status = parseDN( dnInfo, dnBuffer );
					if( cryptStatusError( status ) )
						return( status );
					break;

				case 'F':
					keyFileName = argPtr + 1;
					argPtr += strlen( argPtr );
					break;

				case 'K':
					doKeygen = TRUE;
					if( argPtr[ 1 ] )
						{
						if( toupper( argPtr[ 1 ] ) != 'S' )
							{
							puts( "Unknown key generation parameter." );
							return( ERROR_BADARG );
							}
						optionFlag = TRUE;
						argPtr++;
						}
					argPtr++;
					break;

				case 'L':
					label = argPtr + 1;
					argPtr += strlen( argPtr );
					break;

				case 'O':
					doOverwriteOutput = TRUE;
					argPtr++;
					break;

				case 'P':
					password = argPtr + 1;
					argPtr += strlen( argPtr );
					break;

				case 'S':
					doSign = TRUE;
					if( argPtr[ 1 ] )
						{
						if( toupper( argPtr[ 1 ] ) != 'C' )
							{
							puts( "Unknown output format parameter." );
							return( ERROR_BADARG );
							}
						optionFlag = TRUE;
						argPtr++;
						}
					argPtr++;
					break;

				case 'U':
					doUpdate = TRUE;
					argPtr++;
					break;

				case 'V':
					doView = TRUE;
					argPtr++;
					break;

				case 'X':
					doExtract = TRUE;
					argPtr++;
					break;

				default:
					printf( "Unknown option '%c'.\n", *argPtr );
					return( ERROR_BADARG );
				}
			}

		argc--;
		argv++;
		}

	/* Make sure we aren't trying to do too many things at once */
	status = 0;
	if( doView ) status++;
	if( doExtract ) status++;
	if( doKeygen ) status++;
	if( doSign ) status++;
	if( doUpdate ) status++;
	if( !status )
		{
		puts( "Nothing to do, you need to specify a command option." );
		return( ERROR_BADARG );
		}
	if( status > 1 )
		{
		puts( "You can't perform that many types of operation at once." );
		return( ERROR_BADARG );
		}

	/* Generate a key */
	if( doKeygen )
		{
		/* Make sure the file arg is in order */
		if( argc <= 1 )
			{
			puts( "You need to specify an output file for the key to be "
				  "generated into." );
			return( ERROR_BADARG );
			}
		status = checkFileExists( argv[ 1 ], doOverwriteOutput );
		if( status != CRYPT_OK )
			return( status );

		/* Generate the key + cert request/cert */
		status = generateKey( argv[ 1 ], password, label, dnInfo, optionFlag );
		}

	/* Extract a key from a private key file */
	if( doExtract )
		{
		CRYPT_KEYSET cryptKeyset;
		CRYPT_HANDLE cryptHandle;
		FILE *outFile;
		BYTE buffer[ BUFFER_SIZE ];
		int size;

		/* Make sure the files are right */
		if( keyFileName == NULL )
			{
			puts( "You must specify a keyfile to export the cert object from." );
			return( ERROR_BADARG );
			}
		if( argc <= 1 )
			{
			puts( "You need to specify an output file to export the cert "
				  "object into." );
			return( ERROR_BADARG );
			}
		status = checkFileExists( argv[ 1 ], doOverwriteOutput );
		if( status != CRYPT_OK )
			return( status );
		if( ( outFile = fopen( argv[ 1 ], "wb" ) ) == NULL )
			{
			perror( argv[ 1 ] );
			return( ERROR_FILE_INPUT );
			}

		/* Get the public key (with attached cert info) from the private key
		   keyset */
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
								  keyFileName, CRYPT_KEYOPT_READONLY );
		if( cryptStatusOK( status ) )
			{
			status = cryptGetPublicKey( cryptKeyset, &cryptHandle,
										CRYPT_KEYID_NONE, NULL );
			cryptKeysetClose( cryptKeyset );
			}
		if( cryptStatusError( status ) )
			{
			fclose( outFile );
			printf( "Couldn't read certificate object from private key "
					"file, error code %d.\n", status );
			return( -status );
			}

		/* Export the certificate object to the output file */
		status = cryptExportCert( buffer, BUFFER_SIZE, &size,
							CRYPT_CERTFORMAT_CERTIFICATE, cryptHandle );
		if( cryptStatusOK( status ) )
			fwrite( buffer, 1, size, outFile );
		cryptDestroyObject( cryptHandle );
		if( cryptStatusError( status ) )
			printf( "Couldn't extract certificate object, error code %d.\n",
					status );

		/* Clean up */
		fclose( outFile );
		}

	/* Display/check a cert object */
	if( doView )
		{
		FILE *inFile;
		BYTE buffer[ BUFFER_SIZE ];
		int count;

		if( argc <= 1 )
			{
			puts( "You need to specify an input file to read the cert "
				  "object from." );
			return( ERROR_BADARG );
			}
		if( ( inFile = fopen( argv[ 1 ], "rb" ) ) == NULL )
			{
			perror( argv[ 1 ] );
			return( ERROR_FILE_INPUT );
			}

		/* Import the cert object from the file */
		count = fread( buffer, 1, BUFFER_SIZE, inFile );
		fclose( inFile );
		if( count == BUFFER_SIZE )	/* Item too large for buffer */
			{
			printf( "Certificate object in file %s is too large for the "
					"internal buffer.\n", argv[ 1 ] );
			return( ERROR_FILE_INPUT );
			}
		status = cryptImportCert( buffer, count, CRYPT_UNUSED, &certificate );

		/* Display it */
		if( cryptStatusOK( status ) )
			printCertInfo( certificate );
		}

	/* Sign a cert request */
	if( doSign )
		{
		CRYPT_CONTEXT signContext;
		CRYPT_CERTIFICATE certificate, certRequest;
		FILE *outFile;
		BYTE buffer[ BUFFER_SIZE ];
		int count;

		/* Make sure the files are right */
		if( keyFileName == NULL )
			{
			puts( "You must specify a keyfile to sign the cert object with." );
			return( ERROR_BADARG );
			}
		if( argc <= 2 )
			{
			puts( "You need to specify an input file for the cert request "
				  "and and output file for the cert." );
			return( ERROR_BADARG );
			}

		/* Get the private key and cert request */
		status = getPrivateKey( &signContext, keyFileName, label, NULL );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't get private key, error code = %d.\n", status );
			return( -status );
			}
		status = importCertFile( &certRequest, argv[ 1 ] );
		if( cryptStatusError( status ) )
			{
			cryptDestroyContext( signContext );
			printf( "Couldn't import cert request, error code = %d.\n",
					status );
			return( -status );
			}

		/* Create the certificate from the cert request */
		status = createCertificate( &certificate, optionFlag ? \
					CRYPT_CERTTYPE_CERTCHAIN : CRYPT_CERTTYPE_CERTIFICATE,
					certRequest, signContext );
		cryptDestroyContext( signContext );
		cryptDestroyCert( certRequest );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't create certificate from cert request, error "
					"code = %d.\n", status );
			return( -status );
			}

		/* Export the cert and write it to the output file */
		cryptExportCert( buffer, BUFFER_SIZE, &count, optionFlag ? \
					CRYPT_CERTFORMAT_CERTCHAIN : CRYPT_CERTFORMAT_CERTIFICATE,
					certificate );
		cryptDestroyCert( certificate );
		if( ( outFile = fopen( argv[ 2 ], "wb" ) ) == NULL )
			{
			perror( argv[ 2 ] );
			return( ERROR_FILE_INPUT );
			}
		fwrite( buffer, 1, count, outFile );
		fclose( outFile );
		}

	/* Update a private key with a cert object */
	if( doUpdate )
		{
		CRYPT_KEYSET cryptKeyset;
		CRYPT_CERTIFICATE certificate;

		/* Make sure the files are right */
		if( keyFileName == NULL )
			{
			puts( "You must specify a keyfile to upate." );
			return( ERROR_BADARG );
			}
		if( argc <= 1 )
			{
			puts( "You need to specify an input file to read the cert "
				  "object from." );
			return( ERROR_BADARG );
			}

		/* Import the cert object */
		status = importCertFile( &certificate, argv[ 1 ] );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't import cert object, error code = %d.\n",
					status );
			return( -status );
			}

		/* Update the private key keyset with the cert object */
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
								  keyFileName, CRYPT_KEYOPT_NONE );
		if( cryptStatusOK( status ) )
			{
			status = cryptGetPrivateKey( cryptKeyset, NULL, CRYPT_KEYID_NONE,
										 NULL, password );
			if( cryptStatusOK( status ) )
				status = cryptAddPrivateKey( cryptKeyset, certificate, NULL );
			cryptKeysetClose( cryptKeyset );
			}
		if( cryptStatusError( status ) )
			printf( "Couldn't update keyset with certificate object, error "
					"code %d.\n", status );
		}

	/* Clean up.  The cryptlib cleanup is handled by the atexit() function */
	if( cryptStatusError( status ) )
		{
		printf( "Certificate processing failed with error code %d.\n",
				status );
		return( -status );
		}
	return( EXIT_SUCCESS );
	}

#ifdef WRAP_STANDALONE

int main( int argc, char **argv )
	{
	char *args1[] = {
		"", "-ks",
		"-dC=US,O=Certificates R US,OU=Test CA,CN=John Doe,Email=doe@certsrus.com",
		"c:/temp/cakey.der"
		};
	char *args2[] = {
		"", "-k",
		"-dC=US,O=Foo Bar and Grill,OU=Hamburgers,CN=Burger Bob",
		"c:/temp/userkey.der"
		};
	char *args3[] = {
		"", "-x", "-fc:/temp/userkey.der", "c:/temp/certreq.der"
		};
	char *args4[] = {
		"", "-sc", "-fc:/temp/cakey.der", "c:/temp/certreq.der", "c:/temp/certchain.der"
		};
	char *args5[] = {
		"", "-u", "-fc:/temp/userkey.der", "c:/temp/certchain.der"
		};

	/* Generate self-signed CA root */
	wrappedMain( 4, args1 );

	/* Generate user key and cert request */
	wrappedMain( 4, args2 );

	/* Extract cert request from user key */
	wrappedMain( 4, args3 );

	/* Sign cert request with CA root to give cert chain */
	wrappedMain( 5, args4 );

	/* Update user key with new cert chain */
	wrappedMain( 4, args5 );
	}
#endif /* WRAP_STANDALONE */
