/****************************************************************************
*																			*
*						cryptlib File Keyset Test Routines					*
*						Copyright Peter Gutmann 1995-2003					*
*																			*
****************************************************************************/

#ifdef _MSC_VER
  #include "../cryptlib.h"
  #include "../test/test.h"
#else
  #include "cryptlib.h"
  #include "test/test.h"
#endif /* Braindamaged MSC include handling */

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII. */
  #pragma convlit( suspend )
#endif /* EBCDIC systems */

/* External flags that indicate that the key read/update routines worked OK.
   This is set by earlier self-test code, if it isn't set some of the tests 
   are disabled */

extern int keyReadOK, doubleCertOK;

/* When using the code below to generate test CA or other special-purpose
   certs, the following will enable special-case extensions such as 
   extKeyUsages or protocol-specific AIA entries, as well as a validity
   period of 5 years instead of the usual 1 to avoid problems when users
   run the self-test on very old copies of the code */

/*#define CREATE_CA_CERT		/* CA, 5-year validity */
/*#define CREATE_ICA_CERT		/* Intermediate CA in chain, 5-year validity */
/*#define CREATE_SCEPCA_CERT	/* keyUsage allows encr+sig, 5-year validity */
/*#define CREATE_TSA_CERT		/* TSP extKeyUsage, 5-year validity */
/*#define CREATE_SERVER_CERT	/* CN=localhost, OCSP AIA, 5-year validity */
/*#define CREATE_USER_CERT		/* email address */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Key file and password-handling functions for general-purpose test code */

const char *getKeyfileName( const KEYFILE_TYPE type, 
							const BOOLEAN isPrivKey )
	{
	switch( type )
		{
		case KEYFILE_X509:
			return( USER_PRIVKEY_FILE );
		case KEYFILE_PGP:
			return( isPrivKey ? PGP_PRIVKEY_FILE : PGP_PUBKEY_FILE );
		case KEYFILE_OPENPGP:
			return( isPrivKey ? OPENPGP_PRIVKEY_FILE : OPENPGP_PUBKEY_FILE );
		case KEYFILE_OPENPGP_HASH:
			return( isPrivKey ? OPENPGP_PRIVKEY_HASH_FILE : OPENPGP_PUBKEY_HASH_FILE );
		case KEYFILE_NAIPGP:
			return( isPrivKey ? NAIPGP_PRIVKEY_FILE : NAIPGP_PUBKEY_FILE );
		}
	assert( 0 );
	return( "notfound" );
	}

const char *getKeyfilePassword( const KEYFILE_TYPE type )
	{
	switch( type )
		{
		case KEYFILE_X509:
			return( TEST_PRIVKEY_PASSWORD );
		case KEYFILE_PGP:
		case KEYFILE_NAIPGP:
			return( "test10" );
		case KEYFILE_OPENPGP:
		case KEYFILE_OPENPGP_HASH:
			return( "test1" );
		}
	assert( 0 );
	return( "notfound" );
	}

const char *getKeyfileUserID( const KEYFILE_TYPE type )
	{
	/* If possible we specify user IDs for keys in the middle of the keyring
	   to make sure we test the ability to correctly handle multiple keys */
	switch( type )
		{
		case KEYFILE_X509:
			return( USER_PRIVKEY_LABEL );
		case KEYFILE_PGP:
			return( "test6" );
		case KEYFILE_NAIPGP:
			return( "test cryptlib" );
		case KEYFILE_OPENPGP:
		case KEYFILE_OPENPGP_HASH:
			return( "test1" );
		}
	assert( 0 );
	return( "notfound" );
	}

/****************************************************************************
*																			*
*						PGP/PKCS #12 Key Read/Write Tests					*
*																			*
****************************************************************************/

/* Get a public key from a PGP keyring */

static int getPGPPublicKey( const KEYFILE_TYPE keyFileType, 
							const char *description )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	FILE *filePtr;
	const char *keysetName = getKeyfileName( keyFileType, FALSE );
	int status;

	/* If this is the first file read, check that the file actually exists 
	   so we can return an appropriate error message */
	if( keyFileType == KEYFILE_PGP )
		{
		if( ( filePtr = fopen( keysetName, "rb" ) ) == NULL )
			return( CRYPT_ERROR_FAILED );
		fclose( filePtr );
		keyReadOK = FALSE;
		}

	printf( "Testing %s public key read...\n", description );

	/* Open the keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  keysetName, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Get the key */
	status = cryptGetPublicKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
								getKeyfileUserID( keyFileType ) );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPublicKey() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	printf( "Read of public key from %s keyring succeeded.\n\n", 
			description );
	return( TRUE );
	}

int testGetPGPPublicKey( void )
	{
	if( !getPGPPublicKey( KEYFILE_PGP, "PGP" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_OPENPGP, "OpenPGP (GPG)" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_OPENPGP_HASH, "OpenPGP (GPG/hashed key)" ) )
		return( FALSE );
	return( getPGPPublicKey( KEYFILE_NAIPGP, "OpenPGP (NAI)" ) );
	}

/* Get a private key from a PGP keyring */

static int getPGPPrivateKey( const KEYFILE_TYPE keyFileType, 
							 const char *description )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	const char *keysetName = getKeyfileName( keyFileType, TRUE );
	const char *password = getKeyfilePassword( keyFileType );
	int status;

	printf( "Testing %s private key read...\n", description );

	/* Open the keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  keysetName, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Get the key.  First we try it without a password, if that fails we
	   retry it with the password - this tests a lot of the private-key get
	   functionality including things like key cacheing */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
 								 "test", NULL );
	if( status == CRYPT_ERROR_WRONGKEY )
		{
		/* We need a password for this private key, get it from the user and
		   get the key again */
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME, "test", password );
		}
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPrivateKey() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure we can use the read key.  We can only do this with PGP 2.x 
	   keys, OpenPGP's peculiar multi-keys identify two (or more) keys with
	   the same label and we can't specify (at this level) which key we want
	   to use (the enveloping code can be more specific and so doesn't run
	   into this problem) */
	if( keyFileType == KEYFILE_PGP )
		{
		status = testCrypt( cryptContext, cryptContext, NULL, FALSE, FALSE );
		if( cryptStatusError( status ) )
			return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* The public and private key reads worked, remember this for later when
	   we use the keys in other tests */
	keyReadOK = TRUE;

	printf( "Read of private key from %s keyring succeeded.\n\n", 
			description );
	return( TRUE );
	}

int testGetPGPPrivateKey( void )
	{
	if( !getPGPPrivateKey( KEYFILE_PGP, "PGP" ) )
		return( FALSE );
	if( !getPGPPrivateKey( KEYFILE_OPENPGP, "OpenPGP (GPG)" ) )
		return( FALSE );
	if( !getPGPPrivateKey( KEYFILE_OPENPGP_HASH, "OpenPGP (GPG/hashed key)" ) )
		return( FALSE );
	return( getPGPPrivateKey( KEYFILE_NAIPGP, "OpenPGP (NAI)" ) );
	}

/* Get a key from a PKCS #12 file.  Because of the security problems 
   associated with this format, the code only checks the data format but
   doesn't try to read or use the keys.  If anyone wants this, they'll
   have to add the code themselves.  Your security warranty is void if you 
   implement this */

int testGetBorkenKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	FILE *filePtr;
	int status;

	/* Check that the file actually exists so we can return an appropriate
	   error message */
	if( ( filePtr = fopen( PKCS12_FILE, "rb" ) ) == NULL )
		return( CRYPT_ERROR_FAILED );
	fclose( filePtr );

/*	puts( "Testing PKCS #12 key read..." ); */

	/* Open the keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, 
							  PKCS12_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		/* If support for this isn't enabled (which is normal, since the code
		   doesn't exist), just exit quietly */
		if( status == CRYPT_ERROR_PARAM3 )
			return( TRUE );

		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Get the key  - this is currently hardwired to CRYPT_ERROR_NOTAVAIL 
	   after unwrapping the first dozen or so layers of PKCS #12 garbage */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
 								 "test", NULL );
/*	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPrivateKey() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext ); */

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

/*	puts( "Read of key from PKCS #12 file succeeded.\n" ); */
	return( TRUE );
	}

/****************************************************************************
*																			*
*						Public/Private Key Read/Write Tests					*
*																			*
****************************************************************************/

/* Read/write a private key from a file */

static int readFileKey( const BOOLEAN useRSA )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int status;

	printf( "Testing %s private key read from key file...\n", useRSA ? "RSA" : "DSA" );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the key from the file */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
								 CRYPT_KEYID_NAME, 
								 useRSA ? RSA_PRIVKEY_LABEL : DSA_PRIVKEY_LABEL,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPrivateKey() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can use the read key */
	if( useRSA )
		{
		status = testCrypt( cryptContext, cryptContext, NULL, FALSE, FALSE );
		if( cryptStatusError( status ) )
			return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	printf( "Read of %s private key from key file succeeded.\n\n",
			useRSA ? "RSA" : "DSA" );
	return( TRUE );
	}

static int writeFileKey( const BOOLEAN useRSA, const BOOLEAN useAltKeyfile )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT privateKeyContext;
	int status;

	printf( "Testing %s private key write to key file...\n", useRSA ? "RSA" : "DSA" );

	/* Create the private key context */
	if( useRSA )
		{
		if( !loadRSAContexts( CRYPT_UNUSED, NULL, &privateKeyContext ) )
			return( FALSE );
		}
	else
		if( !loadDSAContexts( CRYPT_UNUSED, &privateKeyContext, NULL ) )
			return( FALSE );

	/* Create/open the file keyset.  For the first call (with RSA) we create 
	   a new keyset, for subsequent calls we update the existing keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
					useAltKeyfile ? TEST_PRIVKEY_ALT_FILE : TEST_PRIVKEY_FILE, 
					useRSA ? CRYPT_KEYOPT_CREATE : CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		if( useAltKeyfile && status == CRYPT_ERROR_PARAM2 )
			{
			/* If the format isn't supported, this isn't a problem */
			puts( "Write of RSA private key to key file skipped.\n" );
			return( CRYPT_OK );
			}
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Write the key to the file */
	status = cryptAddPrivateKey( cryptKeyset, privateKeyContext, 
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPrivateKey() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyContext( privateKeyContext );
	printf( "Write of %s private key to key file succeeded.\n\n",
			useRSA ? "RSA" : "DSA" );
	return( TRUE );
	}

int testReadWriteFileKey( void )
	{
	int status;

	status = writeFileKey( TRUE, FALSE );
	if( status )
		status = readFileKey( TRUE );
#if !( defined( CREATE_CA_CERT ) || defined( CREATE_SCEPCA_CERT ) )
	/* CA test keys only uses RSA */
	if( status )
		status = writeFileKey( FALSE, FALSE );
	if( status )
		status = readFileKey( FALSE );
#endif /* CREATE_CA_CERT || CREATE_SCEPCA_CERT */
	return( status );
	}

int testWriteAltFileKey( void )
	{
	return( writeFileKey( TRUE, TRUE ) );
	}

int testReadBigFileKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int status;

	printf( "Testing private key read from large key file...\n" );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  BIG_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the key from the file */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
								 CRYPT_KEYID_NAME, "John Smith 0", 
								 "password" );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPrivateKey() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Read of private key from large key file succeeded.\n" );
	return( TRUE );
	}

/* Read only the public key/cert/cert chain portion of a keyset */

int testReadFilePublicKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int cryptAlgo, status;

	puts( "Testing public key read from key file..." );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the public key from the file and make sure it really is a public-
	   key context */
	status = cryptGetPublicKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
								RSA_PRIVKEY_LABEL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPublicKey() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptGetAttribute( cryptContext, CRYPT_CTXINFO_ALGO, &cryptAlgo );
	if( cryptStatusError( status ) || \
		cryptAlgo < CRYPT_ALGO_FIRST_PKC || cryptAlgo > CRYPT_ALGO_LAST_PKC )
		{
		puts( "Returned object isn't a public-key context." );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	cryptDestroyContext( cryptContext );

	puts( "Read of public key from key file succeeded.\n" );
	return( TRUE );
	}

static int readCert( const char *certTypeName,
					 const CRYPT_CERTTYPE_TYPE certType,
					 const BOOLEAN readPrivateKey )
	{
	CRYPT_KEYSET cryptKeyset;
	int value, status;

	printf( "Testing %s read from key file...\n", certTypeName );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the certificate from the file and make sure it really is a cert */
	if( readPrivateKey )
		{
		CRYPT_CONTEXT cryptContext;

		status = cryptGetPrivateKey( cryptKeyset, &cryptContext, 
									 CRYPT_KEYID_NAME, RSA_PRIVKEY_LABEL,
									 TEST_PRIVKEY_PASSWORD );
		if( cryptStatusError( status ) )
			{
			printf( "cryptGetPrivateKey() failed with error code %d, line "
					"%d.\n", status, __LINE__ );
			return( FALSE );
			}
		status = cryptGetAttribute( cryptContext, CRYPT_CERTINFO_CERTTYPE, 
									&value );
		if( cryptStatusError( status ) || value != certType )
			{
			printf( "Returned object isn't a %s.\n", certTypeName );
			return( FALSE );
			}

		/* Make sure we can't use the read key (the cert constrains it from
		   being used externally) */
		status = testCrypt( cryptContext, cryptContext, NULL, FALSE, TRUE );
		if( status != CRYPT_ERROR_NOTAVAIL )
			{
			puts( "Attempt to perform external operation on context with "
				  "internal-only action\npermissions succeeded. " );
			return( FALSE );
			}
		cryptDestroyContext( cryptContext );
		}
	else
		{
		CRYPT_CERTIFICATE cryptCert;

		status = cryptGetPublicKey( cryptKeyset, &cryptCert, CRYPT_KEYID_NAME,
									( certType == CRYPT_CERTTYPE_CERTIFICATE ) ? \
									RSA_PRIVKEY_LABEL : USER_PRIVKEY_LABEL );
		if( cryptStatusError( status ) )
			{
			printf( "cryptGetPublicKey() failed with error code %d, line %d.\n",
					status, __LINE__ );
			return( FALSE );
			}
		status = cryptGetAttribute( cryptCert, CRYPT_CERTINFO_CERTTYPE, &value );
		if( cryptStatusError( status ) || value != certType )
			{
			printf( "Returned object isn't a %s.\n", certTypeName );
			return( FALSE );
			}
		cryptDestroyCert( cryptCert );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	printf( "Read of %s from key file succeeded.\n\n", certTypeName );
	return( TRUE );
	}

int testReadFileCert( void )
	{
	return( readCert( "certificate", CRYPT_CERTTYPE_CERTIFICATE, FALSE ) );
	}
int testReadFileCertPrivkey( void )
	{
	return( readCert( "private key with certificate", CRYPT_CERTTYPE_CERTIFICATE, TRUE ) );
	}
int testReadFileCertChain( void )
	{
	return( readCert( "cert chain", CRYPT_CERTTYPE_CERTCHAIN, FALSE ) );
	}

/****************************************************************************
*																			*
*							Certificate Read/Write Tests					*
*																			*
****************************************************************************/

/* Update a keyset to contain a certificate */

int testAddTrustedCert( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE trustedCert;
	int status;

	puts( "Testing trusted certificate add to key file..." );

	/* Read the CA root cert */
	status = importCertFromTemplate( &trustedCert, CERT_FILE_TEMPLATE, 1 );
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't read certificate from file, skipping test of trusted "
			  "cert write..." );
		return( TRUE );
		}

	/* Open the keyset, update it with the trusted certificate, and close it.
	   Before we make the cert trusted, we try adding it as a standard cert,
	   which should fail */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, trustedCert );
	if( cryptStatusOK( status ) )
		{
		printf( "cryptAddPublicKey() of non-trusted cert succeeded when it "
				"should have failed, line %d.\n", __LINE__ );
		return( FALSE );
		}
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );
	status = cryptAddPublicKey( cryptKeyset, trustedCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPublicKey() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyCert( trustedCert );
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Trusted certificate add to key file succeeded.\n" );
	return( TRUE );
	}

int testAddGloballyTrustedCert( void )
	{
	CRYPT_CERTIFICATE trustedCert;
	int status;

	puts( "Testing globally trusted certificate add..." );

	/* Read the CA root cert and make it trusted */
	status = importCertFromTemplate( &trustedCert, CERT_FILE_TEMPLATE, 1 );
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't read certificate from file, skipping test of trusted "
			  "cert write..." );
		return( TRUE );
		}
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );

	/* Update the config file with the globally trusted cert */
	status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED, 
								FALSE );
	if( cryptStatusError( status ) )
		{
		printf( "Globally trusted certificate add failed with error code "
				"%d.\n", status );
		return( FALSE );
		}

	/* Make the cert untrusted and update the config again */
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, FALSE );
	status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED, 
								FALSE );
	if( cryptStatusError( status ) )
		{
		printf( "Globally trusted certificate delete failed with error code "
				"%d.\n", status );
		return( FALSE );
		}

	puts( "Globally trusted certificate add succeeded.\n" );
	return( TRUE );
	}

static const CERT_DATA cACertData[] = {
	/* Identification information.  Note the non-heirarchical order of the
	   components to test the automatic arranging of the DN */
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers and CA" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave Himself" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Certification Division" },
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },

	/* Self-signed X.509v3 certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	/* CA key usage */
#if defined( CREATE_SCEPCA_CERT )
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC, CRYPT_KEYUSAGE_KEYCERTSIGN | \
										   CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
										   CRYPT_KEYUSAGE_KEYENCIPHERMENT },
#else
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
#endif /* SCEP vs.standard CA */
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testUpdateFileCert( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT publicKeyContext, privateKeyContext;
	int status;

	puts( "Testing certificate update to key file ..." );

	/* Create a self-signed CA certificate using the in-memory key (which is
	   the same as the one in the keyset) */
#if defined( CREATE_CA_CERT ) || defined( CREATE_SCEPCA_CERT )
	status = cryptCreateContext( &cryptKey, CRYPT_UNUSED, CRYPT_ALGO_RSA );
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptKey, CRYPT_CTXINFO_LABEL,
										  USER_PRIVKEY_LABEL, 
										  strlen( USER_PRIVKEY_LABEL ) );
	if( cryptStatusOK( status ) )
		{
		cryptSetAttribute( cryptKey, CRYPT_CTXINFO_KEYSIZE, 64 );
		status = cryptGenerateKey( cryptKey );
		}
	if( cryptStatusError( status ) )
		{
		printf( "Test key generation failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
#else
	if( !loadRSAContexts( CRYPT_UNUSED, &publicKeyContext, &privateKeyContext ) )
		return( FALSE );
#endif /* Special-purpose cert creation */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED, 
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d.\n", status );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptCert,
						CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, publicKeyContext );
	if( cryptStatusOK( status ) && !addCertFields( cryptCert, cACertData ) )
		return( FALSE );
#if defined( CREATE_CA_CERT ) || defined( CREATE_SCEPCA_CERT )
	{
	const time_t validity = time( NULL ) + ( 86400L * 365 * 5 );

	/* Make it valid for 5 years instead of 1 to avoid problems when users
	   run the self-test with very old copies of the code */
	cryptSetAttributeString( cryptCert,
					CRYPT_CERTINFO_VALIDTO, &validity, sizeof( time_t ) );
	}
#endif /* Special-purpose cert creation */
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, privateKeyContext );
	destroyContexts( CRYPT_UNUSED, publicKeyContext, privateKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate creation failed with error code %d.\n", status );
		cryptDestroyCert( status );
		return( FALSE );
		}

	/* Open the keyset, update it with the certificate, and close it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPublicKey() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyCert( cryptCert );
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Certificate update to key file succeeded.\n" );
	return( TRUE );
	}

/* Update a keyset to contain a cert chain */

static const CERT_DATA certRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers" },
#if defined( CREATE_SERVER_CERT )
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Server cert" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "localhost" },
#elif defined( CREATE_ICA_CERT )
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Intermediate CA cert" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave's Spare CA" },
#elif defined( CREATE_SCEPCA_CERT )
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Intermediate CA cert" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave's SCEP CA" },
#else
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Procurement" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave Smith" },
	{ CRYPT_CERTINFO_EMAIL, IS_STRING, 0, "dave@wetaburgers.com" },
	{ CRYPT_CERTINFO_SUBJECTNAME, IS_NUMERIC, CRYPT_UNUSED },	/* Re-select subject DN */
#endif /* CREATE_SERVER_CERT */

	/* Extensions for various special-case usages such as OCSP and CMP */
#ifdef CREATE_TSA_CERT
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC, CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },

	{ CRYPT_CERTINFO_EXTKEY_TIMESTAMPING, IS_NUMERIC, CRYPT_UNUSED },
#endif /* CREATE_TSA_CERT */
#ifdef CREATE_SERVER_CERT
	{ CRYPT_CERTINFO_AUTHORITYINFO_OCSP, IS_NUMERIC, CRYPT_UNUSED },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, "http://localhost" },
#endif /* CREATE_SERVER_CERT */
#if defined( CREATE_ICA_CERT )
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC, CRYPT_KEYUSAGE_KEYCERTSIGN },
#elif defined( CREATE_SCEPCA_CERT )
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC, CRYPT_KEYUSAGE_KEYCERTSIGN | \
										   CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
										   CRYPT_KEYUSAGE_KEYENCIPHERMENT },
#endif /* Assorted CA certs */
	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

static int writeFileCertChain( const BOOLEAN writeLongChain )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCertChain;
	CRYPT_CONTEXT cryptCAKey, cryptKey;
	int status;

	printf( "Testing %scert chain write to key file ...\n", 
			writeLongChain ? "long " : "" );

	/* Generate a key to certify.  We can't just reuse the built-in test key
	   because this has already been used as the CA key and the keyset code
	   won't allow it to be added to a keyset as both a CA key and user key,
	   so we have to generate a new one */
	status = cryptCreateContext( &cryptKey, CRYPT_UNUSED, CRYPT_ALGO_RSA );
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptKey, CRYPT_CTXINFO_LABEL,
										  USER_PRIVKEY_LABEL, 
										  strlen( USER_PRIVKEY_LABEL ) );
	if( cryptStatusOK( status ) )
		{
		cryptSetAttribute( cryptKey, CRYPT_CTXINFO_KEYSIZE, 64 );
		status = cryptGenerateKey( cryptKey );
		}
	if( cryptStatusError( status ) )
		{
		printf( "Test key generation failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Get the CA's key.  The length of the chain is determined by the 
	   number of certs attached to the CAs cert, so handling long vs.short
	   chains is pretty simple */
	if( writeLongChain )
		status = getPrivateKey( &cryptCAKey, ICA_PRIVKEY_FILE, 
								USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	else
		status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE, 
								CA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "CA private key read failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Create the keyset and add the private key to it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPrivateKey( cryptKeyset, cryptKey, 
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPrivateKey() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Create the cert chain for the new key */
	status = cryptCreateCert( &cryptCertChain, CRYPT_UNUSED, 
							  CRYPT_CERTTYPE_CERTCHAIN );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptCertChain,
							CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptKey );
	cryptDestroyContext( cryptKey );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptCertChain, certRequestData ) )
		return( FALSE );
#if defined( CREATE_TSA_CERT ) || defined( CREATE_SERVER_CERT ) || \
	defined( CREATE_USER_CERT )
	{
	const time_t validity = time( NULL ) + ( 86400L * 365 * 5 );

	/* Make it valid for 5 years instead of 1 to avoid problems when users
	   run the self-test with very old copies of the code */
	cryptSetAttributeString( cryptCertChain,
					CRYPT_CERTINFO_VALIDTO, &validity, sizeof( time_t ) );
	}
#endif /* Special-purpose cert creation */
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCertChain, cryptCAKey );
	cryptDestroyContext( cryptCAKey );
	if( cryptStatusError( status ) )
		{
		printf( "Cert chain creation failed with error code %d, line %d.\n",
				status, __LINE__ );
		printErrorAttributeInfo( cryptCertChain );
		return( FALSE );
		}

	/* Add the cert chain to the file */
	status = cryptAddPublicKey( cryptKeyset, cryptCertChain );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPrivateKey() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyCert( cryptCertChain );
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Cert chain write to key file succeeded.\n" );
	return( TRUE );
	}

int testWriteFileCertChain( void )
	{
	return( writeFileCertChain( FALSE ) );
	}

int testWriteFileLongCertChain( void )
	{
	return( writeFileCertChain( TRUE ) );
	}

/* Delete a key from a file */

int testDeleteFileKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int status;

	puts( "Testing delete from key file..." );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Delete the key from the file.  Since we don't need the DSA key any 
	   more we use it as the key to delete */
	status = cryptDeleteKey( cryptKeyset, CRYPT_KEYID_NAME, 
							 DSA_PRIVKEY_LABEL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDeleteKey() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptGetPublicKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME, 
								DSA_PRIVKEY_LABEL );
	if( cryptStatusOK( status ) )
		{
		cryptDestroyContext( cryptContext );
		puts( "cryptDeleteKey() claimed the key was deleted but it's still "
			  "present." );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Delete from key file succeeded.\n" );
	return( TRUE );
	}

/* Change the password for a key in a file */

int testChangeFileKeyPassword( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int status;

	puts( "Testing change of key password for key file..." );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the key using the old password, delete it, and write it back
	   using the new password.  To keep things simple we just use the same
	   password (since the key will be used again later), the test of the
	   delete function earlier on has already confirmed that the old key 
	   and password will be deleted so there's no chance of a false positive */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
								 CRYPT_KEYID_NAME, RSA_PRIVKEY_LABEL,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusOK( status ) )
		status = cryptDeleteKey( cryptKeyset, CRYPT_KEYID_NAME, 
								 RSA_PRIVKEY_LABEL );
	if( cryptStatusOK( status ) )
		status = cryptAddPrivateKey( cryptKeyset, cryptContext,
									 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "Password change failed with error code %d, line %d.\n", 
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Password change for key in key file succeeded.\n" );
	return( TRUE );
	}

/* Write a key and cert to a file in a single operation */

static int writeSingleStepFileCert( const BOOLEAN useAltKeyfile )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT cryptContext;
	int status;

	puts( "Testing single-step key+cert write to key file ..." );

	/* Create a self-signed CA certificate */
	if( !loadRSAContexts( CRYPT_UNUSED, NULL, &cryptContext ) )
		return( FALSE );
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED, 
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d.\n", status );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptCert,
						CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusOK( status ) && !addCertFields( cryptCert, cACertData ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, cryptContext );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate creation failed with error code %d.\n", status );
		cryptDestroyCert( status );
		return( FALSE );
		}

	/* Open the keyset, write the key and certificate, and close it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
					useAltKeyfile ? TEST_PRIVKEY_ALT_FILE : TEST_PRIVKEY_FILE,
					CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPrivateKey( cryptKeyset, cryptContext,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPrivateKey() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPublicKey() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );
	cryptDestroyCert( cryptCert );

	/* Try and read the key+cert back before we close the keyset.  This 
	   ensures that the in-memory data has been updated correctly.  We use 
	   the generic RSA key label to read it since this isn't a real user 
	   key */
	if( !useAltKeyfile )
		{
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext, 
									 CRYPT_KEYID_NAME, RSA_PRIVKEY_LABEL, 
									 TEST_PRIVKEY_PASSWORD );
		cryptDestroyContext( cryptContext );
		if( cryptStatusError( status ) )
			{
			printf( "Private key read from in-memory cached keyset data "
					"failed with error code %d,\n line %d.\n", status, 
					__LINE__ );
			return( FALSE );
			}
		}

	/* Close the keyset, which flushes the in-memory changes to disk.  The
	   cacheing of data in memory ensures that all keyset updates are atomic,
	   so that it's nearly impossible to corrupt a private key keyset during
	   an update */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Try and read the key+cert back from disk rather than the cached, in-
	   memory version */
	if( !useAltKeyfile )
		{
		status = getPrivateKey( &cryptContext, TEST_PRIVKEY_FILE,
								RSA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		cryptDestroyContext( cryptContext );
		if( cryptStatusError( status ) )
			{
			printf( "Private key read from on-disk keyset data failed with "
					"error code %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		}

	puts( "Single-step key+cert write to key file succeeded.\n" );
	return( TRUE );
	}

int testSingleStepFileCert( void )
	{
	return( writeSingleStepFileCert( FALSE ) );
	}

int testSingleStepAltFileCert( void )
	{
	return( writeSingleStepFileCert( TRUE ) );
	}

/* Write two keys and certs (signature + encryption) with the same DN to a 
   file */

int testDoubleCertFile( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptSigCert, cryptEncryptCert;
	CRYPT_CONTEXT cryptCAKey, cryptSigContext, cryptEncryptContext;
	int status;

	puts( "Testing separate signature+encryption certificate write to key "
		  "file..." );
	doubleCertOK = FALSE;

	/* Get the CA's key */
	status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "CA private key read failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Generate two keys to certify.  We can't just use the built-in test key 
	   because cryptlib will detect it being added to the keyset a second time 
	   (if we reuse it for both keys) and because the label is a generic one
	   that doesn't work if there are two keys */
	status = cryptCreateContext( &cryptSigContext, CRYPT_UNUSED, 
								 CRYPT_ALGO_RSA );
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptSigContext, 
							CRYPT_CTXINFO_LABEL, DUAL_SIGNKEY_LABEL, 
							strlen( DUAL_SIGNKEY_LABEL ) );
	if( cryptStatusOK( status ) )
		{
		cryptSetAttribute( cryptSigContext, CRYPT_CTXINFO_KEYSIZE, 64 );
		status = cryptGenerateKey( cryptSigContext );
		}
	if( cryptStatusError( status ) )
		{
		printf( "Test key generation failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCreateContext( &cryptEncryptContext, CRYPT_UNUSED, 
								 CRYPT_ALGO_RSA );
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptEncryptContext, 
							CRYPT_CTXINFO_LABEL, DUAL_ENCRYPTKEY_LABEL, 
							strlen( DUAL_ENCRYPTKEY_LABEL ) );
	if( cryptStatusOK( status ) )
		{
		cryptSetAttribute( cryptEncryptContext, CRYPT_CTXINFO_KEYSIZE, 64 );
		status = cryptGenerateKey( cryptEncryptContext );
		}
	if( cryptStatusError( status ) )
		{
		printf( "Test key generation failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Create the certs containing the keys.  In order to avoid clashes with
	   other keys with the same CN in the public-key database, we give the
	   certs abnormal CNs.  This isn't necessary for cryptlib to manage them,
	   but because later code tries to delete leftover certs from previous
	   runs with the generic name used in the self-tests, which would also
	   delete these certs */
	status = cryptCreateCert( &cryptSigCert, CRYPT_UNUSED, 
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptSigCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptSigContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptSigCert, certRequestData ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		{
		status = cryptDeleteAttribute( cryptSigCert, 
									   CRYPT_CERTINFO_COMMONNAME );
		if( cryptStatusOK( status ) )
			status = cryptSetAttributeString( cryptSigCert,
					CRYPT_CERTINFO_COMMONNAME, "Dave Smith (Dual)", 17 );
		}
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptSigCert,
					CRYPT_CERTINFO_KEYUSAGE, CRYPT_KEYUSAGE_DIGITALSIGNATURE );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptSigCert, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		printf( "Signature cert creation failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		printErrorAttributeInfo( cryptSigCert );
		return( FALSE );
		}
	status = cryptCreateCert( &cryptEncryptCert, CRYPT_UNUSED, 
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptEncryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptEncryptContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptEncryptCert, certRequestData ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		{
		status = cryptDeleteAttribute( cryptEncryptCert, 
									   CRYPT_CERTINFO_COMMONNAME );
		if( cryptStatusOK( status ) )
			status = cryptSetAttributeString( cryptEncryptCert,
					CRYPT_CERTINFO_COMMONNAME, "Dave Smith (Dual)", 17 );
		}
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptEncryptCert,
					CRYPT_CERTINFO_KEYUSAGE, CRYPT_KEYUSAGE_KEYENCIPHERMENT );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptEncryptCert, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		printf( "Encryption cert creation failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		printErrorAttributeInfo( cryptEncryptCert );
		return( FALSE );
		}
	cryptDestroyContext( cryptCAKey );

	/* Open the keyset, write the keys and certificates, and close it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  DUAL_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPrivateKey( cryptKeyset, cryptSigContext,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusOK( status ) )
		status = cryptAddPrivateKey( cryptKeyset, cryptEncryptContext,
									 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPrivateKey() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptSigCert );
	if( cryptStatusOK( status ) )
		status = cryptAddPublicKey( cryptKeyset, cryptEncryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPublicKey() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Write the two certs to a public-key database if there's one available
	   (because it may not be present, we fail quietly if access to this 
	   keyset type isn't available or the keyset isn't present, it'll be 
	   picked up later by other tests).  
	   
	   This cert write is needed later to test the encryption vs. signature 
	   cert handling.  Since they may have been added earlier, we try and 
	   delete them first (we can't use the existing version since the 
	   issuerAndSerialNumber won't match the ones in the private-key 
	   keyset) */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, 
							  DATABASE_KEYSET_TYPE, DATABASE_KEYSET_NAME, 
							  CRYPT_KEYOPT_NONE );
	if( status != CRYPT_ERROR_PARAM3 && status != CRYPT_ERROR_OPEN )
		{
		char name[ CRYPT_MAX_TEXTSIZE + 1 ];
		int length;

		if( cryptStatusError( status ) )
			{
			printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
					status, __LINE__ );
			if( status == CRYPT_ERROR_OPEN )
				return( CRYPT_ERROR_FAILED );
			return( FALSE );
			}
		cryptGetAttributeString( cryptSigCert, CRYPT_CERTINFO_COMMONNAME,
								 name, &length );
		name[ length ] = '\0';
		do
			status = cryptDeleteKey( cryptKeyset, CRYPT_KEYID_NAME, name );
		while( cryptStatusOK( status ) );
		if( status != CRYPT_ERROR_NOTFOUND )
			/* Deletion of the existing keys failed for some reason, we can't
			   continue */
			return( extErrorExit( cryptKeyset, "cryptDeleteKey()", 
								  status, __LINE__ ) );
		status = cryptAddPublicKey( cryptKeyset, cryptSigCert );
		if( status == CRYPT_ERROR_NOTFOUND )
			/* This can occur if a database keyset is defined but hasn't been
			   initialised yet so the necessary tables don't exist, it can be
			   opened but an attempt to add a key will return a not found
			   error since it's the table itself rather than any item within
			   it that isn't being found */
			status = CRYPT_OK;
		else
			{
			if( cryptStatusOK( status ) )
				status = cryptAddPublicKey( cryptKeyset, cryptEncryptCert );
			if( cryptStatusError( status ) )
				return( extErrorExit( cryptKeyset, "cryptAddPublicKey()", 
									  status, __LINE__ ) );

			/* The double-cert keyset is set up, remember this for later
			   tests */
			doubleCertOK = TRUE;
			}
		cryptKeysetClose( cryptKeyset );
		}

	/* Clean up */
	cryptDestroyContext( cryptSigContext );
	cryptDestroyContext( cryptEncryptContext );
	cryptDestroyCert( cryptSigCert );
	cryptDestroyCert( cryptEncryptCert );

	/* Try and read the keys+certs back */
	status = getPrivateKey( &cryptSigContext, DUAL_PRIVKEY_FILE,
							DUAL_SIGNKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	cryptDestroyContext( cryptSigContext );
	if( cryptStatusOK( status ) )
		{
		status = getPrivateKey( &cryptEncryptContext, DUAL_PRIVKEY_FILE,
								DUAL_ENCRYPTKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		cryptDestroyContext( cryptEncryptContext );
		}
	if( cryptStatusError( status ) )
		{
		printf( "Private key read failed with error code %d, line %d.\n", 
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Separate signature+encryption certificate write to key file "
		  "succeeded.\n" );
	return( TRUE );
	}

/* Write a key and two certs of different validity periods to a file */

int testRenewedCertFile( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptOldCert, cryptNewCert;
	CRYPT_CONTEXT cryptCAKey, cryptContext;
	time_t writtenValidTo, readValidTo;
	int dummy, status;

	puts( "Testing renewed certificate write to key file..." );

	/* Get the CA's key and the key to certify */
	status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "CA private key read failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	if( !loadRSAContexts( CRYPT_UNUSED, NULL, &cryptContext ) )
		return( FALSE );

	/* Create the certs containing the keys */
	status = cryptCreateCert( &cryptOldCert, CRYPT_UNUSED, 
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptOldCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptOldCert, certRequestData ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		{
		time_t validity = time( NULL );

		/* Valid for one month ending tomorrow (we can't make it already-
		   expired or cryptlib will complain) */
		validity += 86400;
		cryptSetAttributeString( cryptOldCert,
					CRYPT_CERTINFO_VALIDTO, &validity, sizeof( time_t ) );
		validity -= ( 86400 * 31 );
		status = cryptSetAttributeString( cryptOldCert,
					CRYPT_CERTINFO_VALIDFROM, &validity, sizeof( time_t ) );
		}
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptOldCert, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		printf( "Signature cert creation failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		printErrorAttributeInfo( cryptOldCert );
		return( FALSE );
		}
	status = cryptCreateCert( &cryptNewCert, CRYPT_UNUSED, 
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptNewCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptNewCert, certRequestData ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		{
		time_t validity = time( NULL );

		/* Valid for one month starting yesterday (it's actually valid for
		   one month + one day to sidestep the one-month sanity check in the
		   private key read code that warns of about-to-expire keys) */
		validity -= 86400;
		cryptSetAttributeString( cryptNewCert,
					CRYPT_CERTINFO_VALIDFROM, &validity, sizeof( time_t ) );
		validity += ( 86400 * 32 );
		status = cryptSetAttributeString( cryptNewCert,
					CRYPT_CERTINFO_VALIDTO, &validity, sizeof( time_t ) );
		writtenValidTo = validity;
		}
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptNewCert, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		printf( "Encryption cert creation failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		printErrorAttributeInfo( cryptNewCert );
		return( FALSE );
		}
	cryptDestroyContext( cryptCAKey );

	/* First, open the keyset, write the key and certificates (using an
	   in-memory update), and close it.  This tests the ability to use
	   information cached in memory to handle the update */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  RENEW_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPrivateKey( cryptKeyset, cryptContext,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPrivateKey() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptOldCert );
	if( cryptStatusOK( status ) )
		status = cryptAddPublicKey( cryptKeyset, cryptNewCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPublicKey() (in-memory update) failed with error "
				"code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Then try again, but this time perform an on-disk update, closing the
	   keyset between the first and second update.  This tests the ability 
	   to recover the information needed to handle the update from data in 
	   the keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  RENEW_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	if( cryptStatusOK( status ) )
		status = cryptAddPrivateKey( cryptKeyset, cryptContext,
									 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusOK( status ) )
		status = cryptAddPublicKey( cryptKeyset, cryptOldCert );
	if( cryptStatusOK( status ) )
		status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "Keyset creation in preparation for on-disk update failed "
				"with error code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  RENEW_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusOK( status ) )
		status = cryptAddPublicKey( cryptKeyset, cryptNewCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPublicKey() (on-disk update) failed with error "
				"code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyContext( cryptContext );
	cryptDestroyCert( cryptOldCert );
	cryptDestroyCert( cryptNewCert );

	/* Try and read the (newest) key+cert back */
	status = getPrivateKey( &cryptContext, RENEW_PRIVKEY_FILE,
							RSA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "Private key read failed with error code %d, line %d.\n", 
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptGetAttributeString( cryptContext,
					CRYPT_CERTINFO_VALIDTO, &readValidTo, &dummy );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptContext, "cryptGetAttributeString",
							   status, __LINE__ ) );
	if( writtenValidTo != readValidTo )
		{
		const int diff = readValidTo - writtenValidTo;
		const char *units = ( diff % 60 ) ? "seconds" : "minutes";

		printf( "Returned cert != latest valid cert, diff.= %d %s, line "
				"%d.\n", ( diff % 60 ) ? diff : diff / 60, units, __LINE__ );
		if( diff == 3600 || diff ==  -3600 )
			/* See the comment on DST issues in testcert.c */
			puts( "  (This is probably due to a difference between DST at "
				  "cert creation and DST\n   now, and isn't a serious "
				  "problem)." );
		else
			return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	puts( "Renewed certificate write to key file succeeded.\n" );
	return( TRUE );
	}
