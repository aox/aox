/****************************************************************************
*																			*
*						  cryptlib Device Test Routines						*
*						Copyright Peter Gutmann 1997-2003					*
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

/* Set the following to a nonzero value to test cryptlib's device init
   capability.  THIS WILL ZEROISE/ERASE THE DEVICE BEING TESTED AS A PART
   OF THE PROCESS.  All data contained in it will be destroyed */

#define TEST_INITIALISE_CARD	0

/* Set the following to test the keygen capabilities of the device.  If the
   device is very slow (e.g. a smart card), you can set this once initially
   to generate the test keys and then clear it to use the initially-
   generated keys from then on */

#define TEST_KEYGEN				0

/****************************************************************************
*																			*
*								Device Information							*
*																			*
****************************************************************************/

/* Device information tables for PKCS #11 device types.  This lists all the
   devices we know about and can check for.  If you have a PKCS #11 device
   that isn't listed below, you need to add an entry with its name and a
   password and key object label usable for testing to the table, and also
   add the name of the driver as a CRYPT_OPTION_DEVICE_PKCS11_DVRxx entry so
   cryptlib can load the appropriate driver for it.  To add this, use the
   updateConfig() function in testlib.c, see the code comments there for more
   details.

   The SEIS EID cards name their private key objects slightly differently
   from the name used in the software-only eID driver, if you're using a
   card-based version you need to switch the commented lines below to the
   alternate name.

   The Rainbow iKey uses Datakey drivers, so the Datakey test below will work
   for both Datakey cards/keys and iKeys.

   The iD2 driver implements multiple virtual slots, one for each key type,
   so the entry is given in the extended driver::slot name format to tell
   cryptlib which slot to use.

   To reset the Rainbow card after it locks up and stops responding to
   commands, run /samples/cryptoki20/sample.exe, enter 1 CR, 4 CR, 5 CR,
   7 CR 2 CR "rainbow" CR, g CR "test" CR q CR (you need to follow that 
   sequence exactly for it to work).

   The presence of a device entry in this table doesn't necessarily mean
   that the PKCS #11 driver that it comes with functions correctly, or at
   all.  In particular the ActivCard driver is so broken it's incredible it
   works at all, the iButton driver is still in beta so it has some features
   unimplemented, the Telesec driver is even more broken than the ActivCard
   one (this one's so bad it doesn't even work with Netscape), and the
   Utimaco driver apparently has some really strange bugs, as well as
   screwing up Windows power management so that suspends either aren't
   possible any more or will crash apps.  At the other end of the scale the
   Datakey, Eracom, iD2, and nCipher drivers are pretty good */

typedef struct {
	const char *name;
	const char *description;
	const char *password;
	const char *keyLabel;
	} DEVICE_CONFIG_INFO;

static const DEVICE_CONFIG_INFO pkcs11DeviceInfo[] = {
	{ "[Autodetect]", "Automatically detect device", "test", "Test user key" },
	{ "ActivCard Cryptoki Library", "ActivCard", "test", "Test user key" },
	{ "CryptoFlex", "CryptoFlex", "ABCD1234", "012345678901234567890123456789ME" },
	{ "Cryptographic Token Interface", "AET SafeSign", "test", "Test user key" },
	{ "Cryptoki for CardMan API", "Utimaco", "test", "Test user key" },
	{ "Cryptoki for eID", "Nexus soft-token", "1234", "Private key" },
	{ "Cryptoki for eID", "Nexus signature token", "1234", "eID private nonrepudiation key" },
	{ "Cryptoki for eID", "Nexus signature token", "1234", "eID private key encipherment key" },
	{ "CryptoKit Extended Version", "Eutron (via Cylink)", "12345678", "Test user key" },
	{ "Datakey Cryptoki DLL - NETSCAPE", "Datakey pre-4.1, post-4.4 driver", "test", "Test user key" },
	{ "Datakey Cryptoki DLL - Version", "Datakey 4.1-4.4 driver", "test", "Test user key" },
	{ "Eracom Cryptoki", "Eracom", "test", "Test user key" },
	{ "ERACOM Software Only", "Eracom 1.x soft-token", "0000", "Test user key" },
	{ "Software Only", "Eracom 2.x soft-token", "0000", "Test user key" },
	{ "G&D PKCS#11 Library", "Giesecke and Devrient", "test", "Test user key" },
	{ "iButton", "Dallas iButton", "test", "Test user key" },
	{ "iD2 Cryptographic Library::iD2 Smart Card (PIN1)", "iD2 signature token::Slot 1", "1234", "Digital Signature" },
	{ "iD2 Cryptographic Library::iD2 Smart Card (PIN2)", "iD2 signature token::Slot 2", "5678", "Non Repudiation" },
	{ "ISG", "CryptoSwift HSM", "test", "Test user key" },
	{ "ISG Cryptoki API library", "CryptoSwift card", "test", "Test user key" },
	{ "NShield 75", "nCipher", "test", "Test user key" },
	{ "PKCS#11 Private Cryptoki", "GemSAFE", "1234", "Test user key" },
	{ "Safelayer PKCS#11", "Safelayer", "test", "Test user key" },
	{ "Schlumberger", "Schlumberger", "QWERTYUI", "Test user key" },
	{ "SignLite security module", "IBM SignLite", "test", "Test user key" },
	{ "Spyrus Rosetta", "Spyrus Rosetta", "test", "Test user key" },
	{ "Spyrus Lynks", "Spyrus Lynks", "test", "Test user key" },
	{ "TCrypt", "Telesec", "123456", "Test user key" },
	{ "TrustCenter PKCS#11 Library", "GPKCS11", "12345678", "Test user key" },
	{ NULL, NULL, NULL }
	};

/* Device information for Fortezza cards */

#define FORTEZZA_ZEROISE_PIN		"ZeroizedCard"
#define FORTEZZA_SSO_DEFAULT_PIN	"Mosaic"
#define FORTEZZA_SSO_PIN			"0000"
#define FORTEZZA_USER_PIN			"0000"

static const DEVICE_CONFIG_INFO fortezzaDeviceInfo = \
	{ "[Autodetect]", "Automatically detect device", FORTEZZA_USER_PIN, "Test user key" };

/* Device information for CryptoAPI */

static const DEVICE_CONFIG_INFO capiDeviceInfo[] = {
	{ "[Autodetect]", "Automatically detect device", "test", "Test user key" },
	{ "Microsoft Base Cryptographic Provider v1.0::User", "Microsoft Base Cryptographic Provider", "test", "Test user key" },
	{ NULL, NULL, NULL }
	};

/* Data used to create certs in the device */

static const CERT_DATA paaCertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Honest Dave's PAA" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Certification Policy Division" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave the PAA" },

	/* Self-signed X.509v3 CA certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC,
	  CRYPT_KEYUSAGE_KEYCERTSIGN },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

static const CERT_DATA cACertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers and CA" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Certification Division" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave Himself" },

	/* Self-signed X.509v3 CA certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

static const CERT_DATA userCertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave's key" },

	/* X.509v3 general-purpose certificate */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC,
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE | CRYPT_KEYUSAGE_KEYENCIPHERMENT },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

static const CERT_DATA userSigOnlyCertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave's signing key" },

	/* X.509v3 signature-only certificate */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC, CRYPT_KEYUSAGE_DIGITALSIGNATURE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

static const CERT_DATA userKeyAgreeCertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave's key agreement key" },

	/* X.509v3 key agreement certificate */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC, CRYPT_KEYUSAGE_KEYAGREEMENT },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Delete leftover keys created during testing */

static void deleteTestKey( const CRYPT_DEVICE cryptDevice,
						   const char *keyName, const char *keyDescription )
	{
	if( cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, keyName ) == CRYPT_OK )
		printf( "(Deleted a %s key object, presumably a leftover from a "
				"previous run).\n", keyDescription );
	}

/* Create a key and certificate in a device */

static BOOLEAN createKey( const CRYPT_DEVICE cryptDevice,
						  const CRYPT_ALGO_TYPE cryptAlgo,
						  const char *description, const char *dumpName,
						  const CRYPT_CONTEXT signingKey )
	{
	CRYPT_CONTEXT cryptContext;
	CRYPT_CERTIFICATE cryptCert;
	BYTE certBuffer[ BUFFER_SIZE ], labelBuffer[ CRYPT_MAX_TEXTSIZE ];
	const BOOLEAN isCA = ( signingKey == CRYPT_UNUSED ) ? TRUE : FALSE;
	const CERT_DATA *certData = ( isCA ) ? cACertData : \
			( cryptAlgo == CRYPT_ALGO_RSA ) ? userCertData : \
			( cryptAlgo == CRYPT_ALGO_DSA ) ? userSigOnlyCertData : \
			userKeyAgreeCertData;
	int certificateLength, status;

	sprintf( labelBuffer, "Test %s key", description );

	/* Generate a key in the device */
	printf( "Generating a %s key in the device...", description );
	status = cryptDeviceCreateContext( cryptDevice, &cryptContext,
									   cryptAlgo );
	if( cryptStatusError( status ) )
		{
		printf( "\ncryptDeviceCreateContext() failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL, labelBuffer,
							 strlen( labelBuffer ) );
	status = cryptGenerateKey( cryptContext );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( cryptContext );
		printf( "\ncryptGenerateKey() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	puts( " succeeded." );

	/* Create a certificate for the key */
	printf( "Generating a certificate for the key..." );
	cryptCreateCert( &cryptCert, CRYPT_UNUSED, ( isCA ) ? \
					 CRYPT_CERTTYPE_CERTIFICATE : CRYPT_CERTTYPE_CERTCHAIN );
	status = cryptSetAttribute( cryptCert,
						CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptCert, certData ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, isCA ? cryptContext : signingKey );
	cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		{
		cryptDestroyCert( cryptCert );
		printf( "\nCreation of certificate failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	puts( " succeeded." );

	/* Dump the resulting cert for debugging */
	if( dumpName != NULL )
		{
		status = cryptExportCert( certBuffer, &certificateLength, isCA ? \
					CRYPT_CERTFORMAT_CERTIFICATE : CRYPT_CERTFORMAT_CERTCHAIN,
					cryptCert );
		if( cryptStatusOK( status ) )
			debugDump( dumpName, certBuffer, certificateLength );
		}

	/* Update the key with the cert */
	printf( "Updating device with certificate..." );
	status = cryptAddPublicKey( cryptDevice, cryptCert );
	cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "\ncryptAddPublicKey() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	puts( " succeeded." );

	return( TRUE );
	}

/****************************************************************************
*																			*
*							Device Logon/Initialisation						*
*																			*
****************************************************************************/

/* Print information about a device and log in if necessary */

static const DEVICE_CONFIG_INFO *checkLogonDevice( const CRYPT_DEVICE cryptDevice,
												   const CRYPT_DEVICE_TYPE deviceType,
												   const DEVICE_CONFIG_INFO *deviceInfo,
												   const BOOLEAN isAutoDetect,
												   const BOOLEAN willInitialise )
	{
	char tokenLabel[ CRYPT_MAX_TEXTSIZE + 1 ];
	int loggedOn, tokenLabelSize, status;

	/* Tell the user what we're talking to */
	status = cryptGetAttributeString( cryptDevice, CRYPT_DEVINFO_LABEL,
									  tokenLabel, &tokenLabelSize );
	if( cryptStatusError( status ) )
		puts( "(Device doesn't appear to have a label)." );
	else
		{
		tokenLabel[ tokenLabelSize ] = '\0';
		printf( "Device label is '%s'.\n", tokenLabel );
		}

	/* Check whether the device corresponds to a known device.  We do this 
	   because some devices require specific test passwords and whatnot in 
	   order to work */
	if( isAutoDetect )
		{
		int i;

		for( i = 1; pkcs11DeviceInfo[ i ].name != NULL; i++ )
			if( tokenLabelSize == \
							( int ) strlen( pkcs11DeviceInfo[ i ].name ) && \
				!memcmp( pkcs11DeviceInfo[ i ].name, tokenLabel, 
						 tokenLabelSize ) )
				{
				printf( "Found a match for pre-defined device '%s', using\n"
						"  pre-set parameters.\n", 
						pkcs11DeviceInfo[ i ].description );
				deviceInfo = &pkcs11DeviceInfo[ i ];
				break;
				}
			}

	/* See if we need to authenticate ourselves */
	status = cryptGetAttribute( cryptDevice, CRYPT_DEVINFO_LOGGEDIN, 
								&loggedOn );
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't obtain device login status." );
		return( NULL );
		}
	if( loggedOn )
		{
		/* Device may not require a login, or has already been logged in
		   via a keypad or similar mechanism */
		puts( "Device is already logged in, skipping login." );
		return( deviceInfo );
		}

	/* Try and log in */
	printf( "Logging on to the device..." );
	status = cryptSetAttributeString( cryptDevice,
							CRYPT_DEVINFO_AUTHENT_USER, deviceInfo->password,
							strlen( deviceInfo->password ) );
	if( status == CRYPT_ERROR_NOTINITED )
		{
		/* It's an uninitialised device, tell the user and exit */
		puts( " device needs to be initialised." );
		printf( "cryptlib will not automatically initialise the device "
				"during the self-test\n  in case it contains data that "
				"needs to be preserved or requires special\n  steps to be "
				"taken before the initialisation is performed.  If you want "
				"to\n  initialise it, set TEST_INITIALISE_CARD at the top "
				"of " __FILE__ "\n  to a nonzero value.\n" );
		return( NULL );
		}
	if( cryptStatusError( status ) )
		{
		printf( "\nDevice %s failed with error code %d, line %d.\n",
				( status == CRYPT_ERROR_WRONGKEY ) ? \
				"login" : "initialisation/setup", status, __LINE__ );
		if( isAutoDetect )
			puts( "This may be because the auto-detection test uses a fixed "
				  "login value rather\n  than one specific to the device "
				  "type." );
		else
			if( status == CRYPT_ERROR_WRONGKEY && willInitialise )
				{
				/* If we're going to initialise the card, being in the wrong
				   (or even totally uninitialised) state isn't an error */
				puts( "This may be because the device isn't in the user-"
					  "initialised state, in which\n  case the standard "
					  "user PIN can't be used to log on to it." );
				return( deviceInfo );
				}
		return( NULL );
		}
	puts( " succeeded." );
	return( deviceInfo );
	}

/* Initialise a device.  Note that when doing this with a Fortezza card,
   these operations have to be done in a more or less continuous sequence 
   (i.e. without an intervening device open call) because it's not possible 
   to escape from some of the states if the card is closed and reopened in
   between.  In addition the PKCS #11 interface maps some of the 
   initialisation steps differently than the CI interface, so we have to
   special-case this below */

static BOOLEAN initialiseDevice( const CRYPT_DEVICE cryptDevice,
								 const CRYPT_DEVICE_TYPE deviceType,
								 const DEVICE_CONFIG_INFO *deviceInfo )
	{
	const char *defaultSSOPIN = ( deviceType == CRYPT_DEVICE_FORTEZZA ) ? \
								FORTEZZA_SSO_DEFAULT_PIN : \
								deviceInfo->password;
	const char *ssoPIN = ( deviceType == CRYPT_DEVICE_FORTEZZA ) ? \
						 FORTEZZA_SSO_PIN : deviceInfo->password;
	const char *userPIN = deviceInfo->password;
	int status;

	/* PKCS #11 doesn't distinguish between zeroisation and initialisation, 
	   so we only perform the zeroise test if it's a Fortezza card */
	if( deviceType == CRYPT_DEVICE_FORTEZZA )
		{
		printf( "Zeroising device..." );
		status = cryptSetAttributeString( cryptDevice,
						CRYPT_DEVINFO_ZEROISE, FORTEZZA_ZEROISE_PIN,
						strlen( FORTEZZA_ZEROISE_PIN ) );
		if( cryptStatusError( status ) )
			{
			printf( "\nZeroise failed with error code %d, line %d.\n", 
					status, __LINE__ );
			return( FALSE );
			}
		puts( " succeeded." );
		}

	/* Initialise the device and set the SO PIN.   */
	printf( "Initialising device..." );
	status = cryptSetAttributeString( cryptDevice, CRYPT_DEVINFO_INITIALISE, 
									  defaultSSOPIN, strlen( defaultSSOPIN ) );
	if( cryptStatusError( status ) )
		{
		printf( "\nCouldn't initialise device, status = %d, line %d.\n", 
				status, __LINE__ );
		return( FALSE );
		}
	puts( " succeeded." );
	printf( "Setting SO PIN to '%s'...", ssoPIN );
	status = cryptSetAttributeString( cryptDevice, 
									  CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR,
									  ssoPIN, strlen( ssoPIN ) );
	if( cryptStatusError( status ) )
		{
		printf( "\nCouldn't set SO PIN, status = %d, line %d.\n", status, 
				__LINE__ );
		return( FALSE );
		}
	puts( " succeeded." );

	/* If it's a Fortezza card, create a CA root key and install its cert.
	   We have to do it at this point because the operation is only allowed
	   in the SSO initialised state.  In addition we can't use the card for 
	   this operation because cert slot 0 is a data-only slot (that is, it 
	   can't correspond to a key held on the card), so we create a dummy 
	   external cert and use that */
	if( deviceType == CRYPT_DEVICE_FORTEZZA )
		{
		CRYPT_CERTIFICATE cryptCert;
		CRYPT_CONTEXT signContext;

		printf( "Loading PAA certificate..." );
		if( !loadDSAContexts( CRYPT_UNUSED, &signContext, NULL ) )
			return( FALSE );
		cryptCreateCert( &cryptCert, CRYPT_UNUSED, 
						 CRYPT_CERTTYPE_CERTIFICATE );
		status = cryptSetAttribute( cryptCert,
						CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, signContext );
		if( cryptStatusOK( status ) && \
			!addCertFields( cryptCert, paaCertData ) )
			return( FALSE );
		if( cryptStatusOK( status ) )
			status = cryptSignCert( cryptCert, signContext );
		cryptDestroyContext( signContext );
		if( cryptStatusError( status ) )
			{
			cryptDestroyCert( cryptCert );
			printf( "\nCreation of certificate failed with error code %d, "
					"line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		status = cryptAddPublicKey( cryptDevice, cryptCert );
		cryptDestroyCert( cryptCert );
		if( cryptStatusError( status ) )
			{
			printf( "\ncryptAddPublicKey() failed with error code %d, line "
					"%d.\n", status, __LINE__ );
			return( FALSE );
			}
		puts( " succeeded." );
		}

	/* Set the user PIN and log on as the user */
	printf( "Setting user PIN to '%s'...", userPIN );
	status = cryptSetAttributeString( cryptDevice, 
									  CRYPT_DEVINFO_SET_AUTHENT_USER,
									  userPIN, strlen( userPIN ) );
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptDevice, 
										  CRYPT_DEVINFO_AUTHENT_USER,
										  userPIN, strlen( userPIN ) );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't set user PIN/log on as user, status = %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}
	puts( " succeeded." );

	return( TRUE );
	}

/****************************************************************************
*																			*
*									Device Tests							*
*																			*
****************************************************************************/

/* Test the general capabilities of a device */

static BOOLEAN testDeviceCapabilities( const CRYPT_DEVICE cryptDevice,
									   const char *deviceName,
									   const BOOLEAN isWriteProtected )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	int testCount = 0, failCount = 0;

	printf( "Checking %s capabilities...\n", deviceName );
	for( cryptAlgo = CRYPT_ALGO_FIRST_CONVENTIONAL;
		 cryptAlgo <= CRYPT_ALGO_LAST; cryptAlgo++ )
		if( cryptStatusOK( cryptDeviceQueryCapability( cryptDevice,
													   cryptAlgo, NULL ) ) )
			{
			testCount++;
			if( !testLowlevel( cryptDevice, cryptAlgo, isWriteProtected ) )
				/* The test failed, we don't exit at this point but only 
				   remember that there was a problem since we want to test 
				   every possible algorithm */
				failCount++;
			}

	if( isWriteProtected )
		puts( "No tests were performed since the device is write-protected." );
	else
		if( failCount )
			printf( "%d of %d test%s failed.\n", failCount, testCount,
					( testCount > 1 ) ? "s" : "" );
		else
			puts( "Device capabilities test succeeded." );

	return( ( failCount == testCount ) ? FALSE : TRUE );
	}

/* Test the high-level functionality provided by a device */

static BOOLEAN testDeviceHighlevel( const CRYPT_DEVICE cryptDevice,
									const CRYPT_DEVICE_TYPE deviceType,
									const char *keyLabel,
									const char *password,
									const BOOLEAN isWriteProtected )
	{
	CRYPT_CONTEXT pubKeyContext, privKeyContext, sigKeyContext;
	int status;

	if( !isWriteProtected && TEST_KEYGEN )
		{
		const CRYPT_ALGO_TYPE cryptAlgo = \
						( deviceType == CRYPT_DEVICE_PKCS11 ) ? \
						CRYPT_ALGO_RSA : CRYPT_ALGO_DSA;

		/* Create a CA key in the device */
		if( !createKey( cryptDevice, cryptAlgo, "CA",
						( deviceType == CRYPT_DEVICE_PKCS11 ) ? \
						"dp_cacert" : "df_cacert", CRYPT_UNUSED ) )
			return( FALSE );

		/* Read back the CA key for use in generating end entity certs */
		status = cryptGetPrivateKey( cryptDevice, &sigKeyContext,
									 CRYPT_KEYID_NAME, "Test CA key",
									 NULL );
		if( cryptStatusError( status ) )
			{
			printf( "\nRead of CA key failed with error code %d, line %d.\n",
					status, __LINE__ );
			return( FALSE );
			}

		/* Create end-entity certificate(s) for keys using the previously-
		   generated CA key.  If it's a Fortezza card and we're using KEA we 
		   have to generate two sets of keys/certs, one for signing and one 
		   for encryption */
		status = createKey( cryptDevice, cryptAlgo, "user",
							( deviceType == CRYPT_DEVICE_PKCS11 ) ? \
							"dp_usrcert" : "df_usrcert", sigKeyContext );
#ifdef USE_KEA
		if( status && deviceType == CRYPT_DEVICE_FORTEZZA )
			status = createKey( cryptDevice, CRYPT_ALGO_KEA, "KEA",
								"df_keacert", sigKeyContext );
#endif /* USE_KEA */
		cryptDestroyContext( sigKeyContext );
		if( !status )
			return( FALSE );
		}

	/* See whether there are any existing keys or certs - some tokens have
	   these built in and don't allow anything new to be created, after this
	   point the handling is somewhat special-case but we can at least report
	   their presence.  Although generally we can reuse a private key context
	   for both public and private operations, some devices or drivers (and
	   by extension the cryptlib kernel) don't allow public-key ops with
	   private keys so we have to eplicitly handle public and private keys.
	   This gets somewhat messy because some devices don't have public keys
	   but allow public-key ops with their private keys, while others
	   separate public and private keys and don't allow the private key to do
	   public-key ops */
	status = cryptGetPublicKey( cryptDevice, &pubKeyContext,
								CRYPT_KEYID_NAME, keyLabel );
	if( cryptStatusOK( status ) )
		{
		int value;

		puts( "Found a public key in the device, details follow..." );
		printCertChainInfo( pubKeyContext );
		if( cryptStatusOK( \
				cryptGetAttribute( pubKeyContext,
								   CRYPT_CERTINFO_SELFSIGNED, &value ) ) && \
			value )
			{
			/* It's a self-signed cert/cert chain, make sure that it's
			   valid.  Because it's probably not trusted, we make it
			   temporarily implicitly trusted in order for the sig.check to 
			   succeed */
			status = cryptGetAttribute( pubKeyContext, 
								CRYPT_CERTINFO_TRUSTED_IMPLICIT, &value );
			if( cryptStatusOK( status ) )
				status = cryptSetAttribute( pubKeyContext, 
									CRYPT_CERTINFO_TRUSTED_IMPLICIT, 1 );
			if( cryptStatusOK( status ) )
				status = cryptCheckCert( pubKeyContext, CRYPT_UNUSED );
			if( cryptStatusError( status ) )
				{
				printf( "Signature on public key certificate is invalid, "
						"line %d.\n", __LINE__ );
				return( FALSE );
				}
			cryptSetAttribute( pubKeyContext, 
							   CRYPT_CERTINFO_TRUSTED_IMPLICIT, value );
			}
		}
	else
		{
		puts( "Error: Couldn't locate public key in device." );
		pubKeyContext = CRYPT_UNUSED;
		}
	status = cryptGetPrivateKey( cryptDevice, &privKeyContext,
								 CRYPT_KEYID_NAME, keyLabel, NULL );
	if( cryptStatusOK( status ) )
		{
		puts( "Found a private key in the device, details follow..." );
		printCertChainInfo( privKeyContext );
		if( pubKeyContext == CRYPT_UNUSED )
			{
			/* No explicit public key found, try using the private key for
			   both key types */
			puts( "No public key found, attempting to continue using the "
				  "private key as both a\n  public and a private key." );
			pubKeyContext = privKeyContext;
			}
		}
	else
		{
		puts( "Error: Couldn't locate private key in device." );
		privKeyContext = CRYPT_UNUSED;
		}
	sigKeyContext = privKeyContext;
	if( deviceType == CRYPT_DEVICE_FORTEZZA )
		{
		cryptDestroyContext( pubKeyContext );	/* pubK is sig.only */
		status = cryptGetPrivateKey( cryptDevice, &privKeyContext,
									 CRYPT_KEYID_NAME, "Test KEA key", NULL );
		if( cryptStatusOK( status ) )
			{
			puts( "Found a key agreement key in the device, details follow..." );
			printCertChainInfo( privKeyContext );
			pubKeyContext = privKeyContext;		/* Fortezza allows both uses */
			}
		else
			{
			pubKeyContext = CRYPT_UNUSED;
			privKeyContext = CRYPT_UNUSED;
			}
		}

	/* If we got something, try some simple operations with it */
	if( pubKeyContext != CRYPT_UNUSED )
		{
		if( !testCMSEnvelopePKCCryptEx( pubKeyContext, cryptDevice, password ) )
			return( FALSE );
		}
	else
		puts( "Public-key enveloping tests skipped because no key was "
			  "available.\n" );
	if( sigKeyContext != CRYPT_UNUSED )
		{
		if( !testCMSEnvelopeSignEx( sigKeyContext ) )
			return( FALSE );
		}
	else
		puts( "Signed enveloping tests skipped because no key was "
			  "available." );

	/* Test the key with a server session, meant to imitate use with an HSM.
	   This is disabled by default since it requires the simultaneous use of
	   both a client and server session, which has to be done manually */
#if 0
	testSessionTSPServerEx( sigKeyContext );
#endif /* 0 */

	/* Clean up */
	if( pubKeyContext == CRYPT_UNUSED && sigKeyContext == CRYPT_UNUSED )
		return( FALSE );
	if( privKeyContext != CRYPT_UNUSED )
		cryptDestroyContext( privKeyContext );
	if( sigKeyContext != CRYPT_UNUSED && privKeyContext != sigKeyContext )
		cryptDestroyContext( sigKeyContext );
	if( pubKeyContext != CRYPT_UNUSED && pubKeyContext != privKeyContext )
		cryptDestroyContext( pubKeyContext );
	return( TRUE );
	}

/* General device test routine */

static int testCryptoDevice( const CRYPT_DEVICE_TYPE deviceType,
							 const char *deviceName,
							 const DEVICE_CONFIG_INFO *deviceInfo )
	{
	CRYPT_DEVICE cryptDevice;
	BOOLEAN isWriteProtected = FALSE, isAutoDetect = FALSE;
	BOOLEAN initDevice = FALSE, testResult = FALSE, partialSuccess = FALSE;
	int status;

	/* Open a connection to the device */
	if( deviceType == CRYPT_DEVICE_PKCS11 || \
		deviceType == CRYPT_DEVICE_CRYPTOAPI )
		{
		if( !memcmp( deviceInfo->name, "[A", 2 ) )
			{
			printf( "\nTesting %s with autodetection...\n", deviceName );
			isAutoDetect = TRUE;
			}
		else
			printf( "\nTesting %s %s...\n", deviceInfo->name, deviceName );
		status = cryptDeviceOpen( &cryptDevice, CRYPT_UNUSED, deviceType,
								  deviceInfo->name );
		}
	else
		{
		printf( "\nTesting %s...\n", deviceName );
		status = cryptDeviceOpen( &cryptDevice, CRYPT_UNUSED, deviceType,
								  deviceName );
		}
	if( status == CRYPT_ERROR_PARAM2 )
		{
		puts( "Support for this device type isn't enabled in this build of "
			  "cryptlib." );
		return( CRYPT_ERROR_NOTAVAIL );	/* Device access not available */
		}
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_PARAM3 || status == CRYPT_ERROR_NOTFOUND )
			puts( "Crypto device not detected, skipping test." );
		else
			printf( "cryptDeviceOpen() failed with error code %d, line %d.\n",
					status, __LINE__ );
		return( FALSE );
		}

	/* If it's one of the smarter classes of device, authenticate ourselves to
	   the device, which is usually required in order to allow it to be used
	   fully */
	if( deviceType == CRYPT_DEVICE_PKCS11 || deviceType == CRYPT_DEVICE_FORTEZZA )
		{
		deviceInfo = checkLogonDevice( cryptDevice, deviceType, deviceInfo, 
									   isAutoDetect, TEST_INITIALISE_CARD );
		if( deviceInfo == NULL )
			return( FALSE );
		}

	/* Write-protected devices won't allow contexts to be created in them,
	   before we try the general device capabilities test we make sure we
	   can actually perform the operation */
	if( deviceType == CRYPT_DEVICE_PKCS11 )
		{
		CRYPT_CONTEXT cryptContext;

		/* Try and create a DES object.  The following check for read-only
		   devices always works because the device object ACL is applied at
		   a much higher level than any device capability checking, the
		   device will never even see the create object message if it's
		   write-protected so all we have to do is make sure that whatever
		   we create is ephemeral */
		status = cryptDeviceCreateContext( cryptDevice, &cryptContext,
										   CRYPT_ALGO_DES );
		if( cryptStatusOK( status ) )
			cryptDestroyContext( cryptContext );
		if( status == CRYPT_ERROR_PERMISSION )
			isWriteProtected = TRUE;
		}

	/* To force the code not to try to create keys and certs in a writeable
	   device, uncomment the following line of code.  This requires that keys/
	   certs of the required type are already present in the device */
/*	KLUDGE_WARN( "write-protect status" );
	isWriteProtected = TRUE;				/**/
	if( !isWriteProtected && TEST_KEYGEN )
		{
		/* If it's a device that we can initialise (currently limited to 
		   soft-tokens only to avoid wiping crypto hardware that may have 
		   keys on it), go through a full initialisation */
		if( !strcmp( deviceInfo->name, "ERACOM Software Only" ) || \
			!strcmp( deviceInfo->name, "Software Only" ) || \
			TEST_INITIALISE_CARD )
			{
			status = initialiseDevice( cryptDevice, deviceType, 
									   deviceInfo );
			if( status == FALSE )
				{
				cryptDeviceClose( cryptDevice );
				return( FALSE );
				}
			}
		else
			{
			/* There may be test keys lying around from an earlier run, in 
			   which case we try to delete them to make sure they won't 
			   interfere with the current one */
			deleteTestKey( cryptDevice, "Test CA key", "CA" );
			deleteTestKey( cryptDevice, deviceInfo->keyLabel, "user" );
			if( deviceType == CRYPT_DEVICE_PKCS11 )
				{
				deleteTestKey( cryptDevice, RSA_PUBKEY_LABEL, "RSA public" );
				deleteTestKey( cryptDevice, RSA_PRIVKEY_LABEL, "RSA private" );
				deleteTestKey( cryptDevice, DSA_PUBKEY_LABEL, "DSA public" );
				deleteTestKey( cryptDevice, DSA_PRIVKEY_LABEL, "DSA private" );
				}
			if( deviceType == CRYPT_DEVICE_FORTEZZA )
				deleteTestKey( cryptDevice, "Test KEA key", "KEA" );
			}
		}

	/* Report what the device can do.  This is intended mostly for simple
	   crypto accelerators and may fail with for devices that work only
	   with the higher-level functions centered around certificates,
	   signatures,and key wrapping, so we skip the tests for devices that
	   allow only high-level access */
	if( deviceType != CRYPT_DEVICE_FORTEZZA )
		testResult = testDeviceCapabilities( cryptDevice, deviceName,
											 isWriteProtected );


	/* If it's a smart device, try various device-specific operations */
	if( deviceType == CRYPT_DEVICE_FORTEZZA || \
		deviceType == CRYPT_DEVICE_PKCS11 )
		partialSuccess = testDeviceHighlevel( cryptDevice, deviceType,
								deviceInfo->keyLabel, deviceInfo->password,
								isWriteProtected );

	/* Clean up */
	status = cryptDeviceClose( cryptDevice );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDeviceClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	if( !testResult && !partialSuccess )
		return( FALSE );
	if( testResult && partialSuccess )
		printf( "%s tests succeeded.\n\n", deviceName );
	else
		printf( "Some %s tests succeeded.\n\n", deviceName );
	return( TRUE );
	}

int testDevices( void )
	{
	int i, status;

	/* Test Fortezza devices */
#if 1
	status = testCryptoDevice( CRYPT_DEVICE_FORTEZZA, "Fortezza card",
							   &fortezzaDeviceInfo );
	if( cryptStatusError( status ) && status != CRYPT_ERROR_NOTAVAIL )
		return( status );
#endif /* 0 */

	/* Test PKCS #11 devices */
#if 1
	for( i = 0; pkcs11DeviceInfo[ i ].name != NULL; i++ )
		{
		status = testCryptoDevice( CRYPT_DEVICE_PKCS11, "PKCS #11 crypto token",
								   &pkcs11DeviceInfo[ i ] );
		if( cryptStatusError( status ) && \
			!( status == CRYPT_ERROR_NOTAVAIL || \
			   ( i == 0 && status == CRYPT_ERROR_WRONGKEY ) ) )
			return( status );
		}
#endif /* 0 */

#if 0	/* For test purposes only to check CAPI data, don't use the CAPI code */
#ifdef __WINDOWS__
	for( i = 0; capiDeviceInfo[ i ].name != NULL; i++ )
		{
		status = testCryptoDevice( CRYPT_DEVICE_CRYPTOAPI, "Microsoft CryptoAPI",
								   &capiDeviceInfo[ i ] );
		if( cryptStatusError( status ) && \
			!( status == CRYPT_ERROR_NOTAVAIL || \
			   ( i == 0 && status == CRYPT_ERROR_WRONGKEY ) ) )
			return( status );
		}
#endif /* __WINDOWS__ */
#endif /* 0 */
	putchar( '\n' );
	return( TRUE );
	}

/****************************************************************************
*																			*
*							User Management Routines Test					*
*																			*
****************************************************************************/

int testUser( void )
	{
	CRYPT_USER cryptUser;
	int status;

	puts( "Testing (minimal) user management functions..." );

	/* Perform a zeroise.  This currently isn't done because (a) it would
	   zeroise all user data whenever anyone runs the self-test and (b) the
	   external API to trigger this isn't defined yet */
/*	status = cryptZeroise( ... ); */

	/* Log in as primary SO using the zeroisation password.  Because of the
	   above situation this currently performs an implicit zeroise */
	status = cryptLogin( &cryptUser, "Security officer", "zeroised" );
	if( cryptStatusError( status ) )
		{
		printf( "cryptLogin() (Primary SO) failed with error code %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Set the SO password */
	status = cryptSetAttributeString( cryptUser, CRYPT_USERINFO_PASSWORD,
									  "password", 8 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptSetAttributeString() failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Log out and log in again with the new password.  At the moment it's
	   possible to use any password until the PKCS #15 attribute situation
	   is resolved */
	status = cryptLogout( cryptUser );
	if( cryptStatusError( status ) )
		{
		printf( "cryptLogout() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptLogin( &cryptUser, "Security officer", "password" );
	if( cryptStatusError( status ) )
		{
		printf( "cryptLogin() (SO) failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptLogout( cryptUser );
	puts( "User management tests succeeded.\n" );
	return( TRUE );
	}
