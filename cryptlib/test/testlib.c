/****************************************************************************
*																			*
*								cryptlib Test Code							*
*						Copyright Peter Gutmann 1995-2005					*
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
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */

/* Whether various keyset tests worked, the results are used later to test
   other routines.  We initially set the key read result to TRUE in case the
   keyset read tests are never called, so we can still trying reading the
   keys in other tests */

int keyReadOK = TRUE, doubleCertOK = FALSE;

#ifdef TEST_CONFIG

/* The names of the configuration options we check for */

static struct {
	const CRYPT_ATTRIBUTE_TYPE option;	/* Option */
	const char *name;					/* Option name */
	const BOOLEAN isNumeric;			/* Whether it's a numeric option */
	} configOption[] = {
	{ CRYPT_OPTION_INFO_DESCRIPTION, "CRYPT_OPTION_INFO_DESCRIPTION", FALSE },
	{ CRYPT_OPTION_INFO_COPYRIGHT, "CRYPT_OPTION_INFO_COPYRIGHT", FALSE },
	{ CRYPT_OPTION_INFO_MAJORVERSION, "CRYPT_OPTION_INFO_MAJORVERSION", TRUE },
	{ CRYPT_OPTION_INFO_MINORVERSION, "CRYPT_OPTION_INFO_MINORVERSION", TRUE },
	{ CRYPT_OPTION_INFO_STEPPING, "CRYPT_OPTION_INFO_STEPPING", TRUE },

	{ CRYPT_OPTION_ENCR_ALGO, "CRYPT_OPTION_ENCR_ALGO", TRUE },
	{ CRYPT_OPTION_ENCR_HASH, "CRYPT_OPTION_ENCR_HASH", TRUE },
	{ CRYPT_OPTION_ENCR_MAC, "CRYPT_OPTION_ENCR_MAC", TRUE },

	{ CRYPT_OPTION_PKC_ALGO, "CRYPT_OPTION_PKC_ALGO", TRUE },
	{ CRYPT_OPTION_PKC_KEYSIZE, "CRYPT_OPTION_PKC_KEYSIZE", TRUE },

	{ CRYPT_OPTION_SIG_ALGO, "CRYPT_OPTION_SIG_ALGO", TRUE },
	{ CRYPT_OPTION_SIG_KEYSIZE, "CRYPT_OPTION_SIG_KEYSIZE", TRUE },

	{ CRYPT_OPTION_KEYING_ALGO, "CRYPT_OPTION_KEYING_ALGO", TRUE },
	{ CRYPT_OPTION_KEYING_ITERATIONS, "CRYPT_OPTION_KEYING_ITERATIONS", TRUE },

	{ CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, "CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES", TRUE },
	{ CRYPT_OPTION_CERT_VALIDITY, "CRYPT_OPTION_CERT_VALIDITY", TRUE },
	{ CRYPT_OPTION_CERT_UPDATEINTERVAL, "CRYPT_OPTION_CERT_UPDATEINTERVAL", TRUE },
	{ CRYPT_OPTION_CERT_COMPLIANCELEVEL, "CRYPT_OPTION_CERT_COMPLIANCELEVEL", TRUE },
	{ CRYPT_OPTION_CERT_REQUIREPOLICY, "CRYPT_OPTION_CERT_REQUIREPOLICY", TRUE },

	{ CRYPT_OPTION_CMS_DEFAULTATTRIBUTES, "CRYPT_OPTION_CMS_DEFAULTATTRIBUTES", TRUE },

	{ CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS, "CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE, "CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE", TRUE },
	{ CRYPT_OPTION_KEYS_LDAP_FILTER, "CRYPT_OPTION_KEYS_LDAP_FILTER", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CACERTNAME, "CRYPT_OPTION_KEYS_LDAP_CACERTNAME", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CERTNAME, "CRYPT_OPTION_KEYS_LDAP_CERTNAME", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CRLNAME, "CRYPT_OPTION_KEYS_LDAP_CRLNAME", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_EMAILNAME, "CRYPT_OPTION_KEYS_LDAP_EMAILNAME", FALSE },

	{ CRYPT_OPTION_DEVICE_PKCS11_DVR01, "CRYPT_OPTION_DEVICE_PKCS11_DVR01", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR02, "CRYPT_OPTION_DEVICE_PKCS11_DVR02", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR03, "CRYPT_OPTION_DEVICE_PKCS11_DVR03", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR04, "CRYPT_OPTION_DEVICE_PKCS11_DVR04", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR05, "CRYPT_OPTION_DEVICE_PKCS11_DVR05", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY, "CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY", TRUE },

	{ CRYPT_OPTION_NET_SOCKS_SERVER, "CRYPT_OPTION_NET_SOCKS_SERVER", FALSE },
	{ CRYPT_OPTION_NET_SOCKS_USERNAME, "CRYPT_OPTION_NET_SOCKS_USERNAME", FALSE },
	{ CRYPT_OPTION_NET_HTTP_PROXY, "CRYPT_OPTION_NET_HTTP_PROXY", FALSE },
	{ CRYPT_OPTION_NET_CONNECTTIMEOUT, "CRYPT_OPTION_NET_CONNECTTIMEOUT", TRUE },
	{ CRYPT_OPTION_NET_READTIMEOUT, "CRYPT_OPTION_NET_READTIMEOUT", TRUE },
	{ CRYPT_OPTION_NET_WRITETIMEOUT, "CRYPT_OPTION_NET_WRITETIMEOUT", TRUE },

	{ CRYPT_OPTION_MISC_ASYNCINIT, "CRYPT_OPTION_MISC_ASYNCINIT", TRUE },
	{ CRYPT_OPTION_MISC_SIDECHANNELPROTECTION, "CRYPT_OPTION_MISC_SIDECHANNELPROTECTION", TRUE },

	{ CRYPT_ATTRIBUTE_NONE, NULL, 0 }
	};
#endif /* TEST_CONFIG */

/* There are some sizeable (for DOS) data structures used, so we increase the
   stack size to allow for them */

#if defined( __MSDOS16__ ) && defined( __TURBOC__ )
  extern unsigned _stklen = 16384;
#endif /* __MSDOS16__ && __TURBOC__ */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* The tests that use databases and cert stores require that the user set
   up a suitable ODBC data source (at least when running under Windows).  To
   help people who don't read documentation, we try and create the data
   source if it isn't present */

#if defined( _MSC_VER ) && defined( _WIN32 ) && !defined( _WIN32_WCE )

#define DATABASE_AUTOCONFIG

#include <odbcinst.h>

#define DATABASE_ATTR_NAME		"DSN=" DATABASE_KEYSET_NAME_ASCII "\0" \
								"DESCRIPTION=cryptlib test key database\0" \
								"DBQ="
#define DATABASE_ATTR_CREATE	"DSN=" DATABASE_KEYSET_NAME_ASCII "\0" \
								"DESCRIPTION=cryptlib test key database\0" \
								"CREATE_DB="
#define DATABASE_ATTR_TAIL		DATABASE_KEYSET_NAME_ASCII ".mdb\0"
#define CERTSTORE_ATTR_NAME		"DSN=" CERTSTORE_KEYSET_NAME_ASCII "\0" \
								"DESCRIPTION=cryptlib test key database\0" \
								"DBQ="
#define CERTSTORE_ATTR_CREATE	"DSN=" CERTSTORE_KEYSET_NAME_ASCII "\0" \
								"DESCRIPTION=cryptlib test key database\0" \
								"CREATE_DB="
#define CERTSTORE_ATTR_TAIL		CERTSTORE_KEYSET_NAME_ASCII ".mdb\0"
#ifdef USE_SQLSERVER
  #define DRIVER_NAME			TEXT( "SQL Server" )
#else
  #define DRIVER_NAME			TEXT( "Microsoft Access Driver (*.MDB)" )
#endif /* USE_SQLSERVER */

static void buildDBString( char *buffer, const char *attrName,
						   const int attrNameSize,
						   const char *attrTail, const char *path )
	{
	const int attrTailSize = strlen( attrTail ) + 2;
	const int pathSize = strlen( path );

	memcpy( buffer, attrName, attrNameSize + 1 );
	memcpy( buffer + attrNameSize - 1, path, pathSize );
	memcpy( buffer + attrNameSize - 1 + pathSize, attrTail, attrTailSize );
	}

static void checkCreateDatabaseKeysets( void )
	{
	CRYPT_KEYSET cryptKeyset;
	char tempPathBuffer[ 512 ];
	int length, status;

	if( !( length = GetTempPath( 512, tempPathBuffer ) ) )
		{
		strcpy( tempPathBuffer, "C:\\Temp\\" );
		length = 8;
		}

	/* Try and open the test keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
							  CRYPT_KEYSET_ODBC, DATABASE_KEYSET_NAME,
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		cryptKeysetClose( cryptKeyset );
	else
		{
		if( status == CRYPT_ERROR_OPEN )
			{
			char attrBuffer[ 1024 ];
#ifdef UNICODE_STRINGS
			wchar_t wcAttrBuffer[ 1024 ];
#endif /* UNICODE_STRINGS */

			/* Try and create the DSN.  This is a two-step process, first we
			   create the DSN and then the underlying file that contains the
			   database */
			puts( "Database keyset " DATABASE_KEYSET_NAME_ASCII " not "
				  "found, attempting to create data source..." );
			buildDBString( attrBuffer, DATABASE_ATTR_NAME,
						   sizeof( DATABASE_ATTR_NAME ),
						   DATABASE_ATTR_TAIL, tempPathBuffer );
#ifdef UNICODE_STRINGS
			mbstowcs( wcAttrBuffer, attrBuffer, strlen( attrBuffer ) + 1 );
			status = SQLConfigDataSource( NULL, ODBC_ADD_DSN, DRIVER_NAME,
										  wcAttrBuffer );
#else
			status = SQLConfigDataSource( NULL, ODBC_ADD_DSN, DRIVER_NAME,
										  attrBuffer );
#endif /* UNICODE_STRINGS */
			if( status == 1 )
				{
				buildDBString( attrBuffer, DATABASE_ATTR_CREATE,
							   sizeof( DATABASE_ATTR_CREATE ),
							   DATABASE_ATTR_TAIL, tempPathBuffer );
#ifdef UNICODE_STRINGS
				mbstowcs( wcAttrBuffer, attrBuffer, strlen( attrBuffer ) + 1 );
				status = SQLConfigDataSource( NULL, ODBC_ADD_DSN,
											  DRIVER_NAME, wcAttrBuffer );
#else
				status = SQLConfigDataSource( NULL, ODBC_ADD_DSN,
											  DRIVER_NAME, attrBuffer );
#endif /* UNICODE_STRINGS */
				}
			puts( ( status == 1 ) ? "Data source creation succeeded." : \
				  "Data source creation failed.\n\nYou need to create the "
				  "keyset data source as described in the cryptlib manual\n"
				  "for the database keyset tests to run." );
			}
		}

	/* Try and open the test cert store.  This can return a
	   CRYPT_ARGERROR_PARAM3 as a normal condition since a freshly-created
	   database is empty and therefore can't be identified as a cert store
	   until data is written to it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
							  CRYPT_KEYSET_ODBC_STORE, CERTSTORE_KEYSET_NAME,
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		cryptKeysetClose( cryptKeyset );
	else
		{
		if( status == CRYPT_ERROR_OPEN )
			{
			char attrBuffer[ 1024 ];
#ifdef UNICODE_STRINGS
			wchar_t wcAttrBuffer[ 1024 ];
#endif /* UNICODE_STRINGS */

			/* Try and create the DSN.  As before, this is a two-step
			   process */
			puts( "Certificate store " CERTSTORE_KEYSET_NAME_ASCII " not "
				  "found, attempting to create data source..." );
			buildDBString( attrBuffer, CERTSTORE_ATTR_NAME,
						   sizeof( CERTSTORE_ATTR_NAME ),
						   CERTSTORE_ATTR_TAIL, tempPathBuffer );
#ifdef UNICODE_STRINGS
			mbstowcs( wcAttrBuffer, attrBuffer, strlen( attrBuffer ) + 1 );
			status = SQLConfigDataSource( NULL, ODBC_ADD_DSN, DRIVER_NAME,
										  wcAttrBuffer );
#else
			status = SQLConfigDataSource( NULL, ODBC_ADD_DSN, DRIVER_NAME,
										  attrBuffer );
#endif /* UNICODE_STRINGS */
			if( status == 1 )
				{
				buildDBString( attrBuffer, CERTSTORE_ATTR_CREATE,
							   sizeof( CERTSTORE_ATTR_CREATE ),
							   CERTSTORE_ATTR_TAIL, tempPathBuffer );
#ifdef UNICODE_STRINGS
				mbstowcs( wcAttrBuffer, attrBuffer, strlen( attrBuffer ) + 1 );
				status = SQLConfigDataSource( NULL, ODBC_ADD_DSN,
											  DRIVER_NAME, wcAttrBuffer );
#else
				status = SQLConfigDataSource( NULL, ODBC_ADD_DSN,
											  DRIVER_NAME, attrBuffer );
#endif /* UNICODE_STRINGS */
				}
			puts( ( status == 1 ) ? "Data source creation succeeded.\n" : \
				  "Data source creation failed.\n\nYou need to create the "
				  "certificate store data source as described in the\n"
				  "cryptlib manual for the certificate management tests to "
				  "run.\n" );
			}
		}
	}
#endif /* Win32 with VC++ */

/****************************************************************************
*																			*
*								Misc.Kludges								*
*																			*
****************************************************************************/

/* Prototypes for general debug routines used to evaluate problems with certs
   and envelopes from other apps */

void xxxCertImport( const char *fileName );
void xxxDataImport( const char *fileName );
void xxxSignedDataImport( const char *fileName );
void xxxEncryptedDataImport( const char *fileName );
void xxxEnvTest( void );

/* Prototype for stress test interface routine */

void smokeTest( void );

/* Update the cryptlib config file.  This code can be used to set the
   information required to load PKCS #11 device drivers:

	- Set the driver path in the CRYPT_OPTION_DEVICE_PKCS11_DVR01 setting
	  below.
	- Add a call to updateConfig() from somewhere (e.g.the test kludge function).
	- Run the test code until it calls updateConfig().
	- Remove the updateConfig() call, then run the test code as normal.
	  The testDevices() call will report the results of trying to use your
	  driver.

   Note that under Windows XP the path name changes from 'WinNT' to just 
   'Windows' */

static void updateConfig( void )
	{
#if 0
	const char *driverPath = "c:/winnt/system32/aetpkss1.dll";	/* AET */
	const char *driverPath = "c:/winnt/system32/etpkcs11.dll";  /* Aladdin eToken */
	const char *driverPath = "c:/winnt/system32/cryst32.dll";	/* Chrysalis */
	const char *driverPath = "c:/program files/luna/cryst201.dll";	/* Chrysalis */
	const char *driverPath = "c:/winnt/system32/pkcs201n.dll";	/* Datakey */
	const char *driverPath = "c:/winnt/system32/dkck201.dll";	/* Datakey (for Entrust) */
	const char *driverPath = "c:/winnt/system32/dkck232.dll";	/* Datakey/iKey (NB: buggy, use 201) */
	const char *driverPath = "c:/program files/eracom/cprov sw/cryptoki.dll";	/* Eracom (old, OK) */
	const char *driverPath = "c:/program files/eracom/cprov runtime/cryptoki.dll";	/* Eracom (new, buggy) */
	const char *driverPath = "c:/winnt/system32/sadaptor.dll";	/* Eutron */
	const char *driverPath = "c:/winnt/system32/pk2priv.dll";	/* Gemplus */
	const char *driverPath = "c:/program files/gemplus/gclib.dll";	/* Gemplus */
	const char *driverPath = "c:/winnt/system32/cryptoki.dll";	/* IBM */
	const char *driverPath = "c:/winnt/system32/cknfast.dll";	/* nCipher */
	const char *driverPath = "c:/winnt/system32/nxpkcs11.dll";	/* Nexus */
	const char *driverPath = "c:/winnt/system32/micardoPKCS11.dll";	/* Orga Micardo */
	const char *driverPath = "c:/winnt/system32/cryptoki22.dll";/* Rainbow HSM (for USB use Datakey dvr) */
	const char *driverPath = "c:/winnt/system32/p11card.dll";	/* Safelayer HSM (for USB use Datakey dvr) */
	const char *driverPath = "c:/winnt/system32/slbck.dll";		/* Schlumberger */
	const char *driverPath = "c:/winnt/system32/SpyPK11.dll";	/* Spyrus */
#endif /* 0 */
	const char *driverPath = "c:/winnt/system32/SpyPK11.dll";	/* Spyrus */

	printf( "Updating cryptlib configuration to load PKCS #11 driver\n  "
			"'%s'\n  as default driver...", driverPath );

	/* Set the path for a PKCS #11 device driver.  We only enable one of
	   these at a time to speed the startup time */
	cryptSetAttributeString( CRYPT_UNUSED, CRYPT_OPTION_DEVICE_PKCS11_DVR01,
							 driverPath, strlen( driverPath ) );

	/* Update the options */
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED, FALSE );

	puts( " done." );
	}

/* Add trusted certs to the config file and make sure that they're
   persistent.  This can't be done in the normal self-test since it requires
   that cryptlib be restarted as part of the test to re-read the config file,
   and because it modifies the cryptlib config file */

static void updateConfigCert( void )
	{
	CRYPT_CERTIFICATE trustedCert;

	/* Import the first cert, make it trusted, and commit the changes */
	importCertFromTemplate( &trustedCert, CERT_FILE_TEMPLATE, 1 );
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED, FALSE );
	cryptDestroyCert( trustedCert );
	cryptEnd();

	/* Do the same with a second cert.  At the conclusion of this, we should
	   have two trusted certs on disk */
	cryptInit();
	importCertFromTemplate( &trustedCert, CERT_FILE_TEMPLATE, 2 );
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED, FALSE );
	cryptDestroyCert( trustedCert );
	cryptEnd();
	}

/* Generic test code insertion point.  The following routine is called
   before any of the other tests are run and can be used to handle special-
   case tests that aren't part of the main test suite */

void testKludge( void )
	{
	/* Performance-testing test harness */
#if 0
	void performanceTests( const CRYPT_DEVICE cryptDevice );

	performanceTests( CRYPT_UNUSED );
#endif /* 0 */

	/* Memory diagnostic test harness */
#if 0
	testReadFileCertPrivkey();
	testEnvelopePKCCrypt();		/* Use "Datasize, certificate" */
	testEnvelopeSign();			/* Use "Datasize, certificate" */
#endif /* 0 */

	/* Simple (brute-force) server code. NB: Remember to change
	   setLocalConnect() to not bind the server to localhost if expecting
	   external connections */
#if 0
	while( TRUE )
		testSessionTSPServer();
#endif /* 0 */

	/* Functions that can be pressed into service in combination with the
	   special-purpose defines at the start of testkeyf.c to generate custom
	   certs/keys for the self-test */
#if 0
	testWriteFileCertChain();	/* To generate user/intermed.CA priv.key+cert */
#endif /* 0 */
#if 0
	testReadWriteFileKey();
	testUpdateFileCert();		/* To generate CA priv.key+cert */
#endif /* 0 */
#if 0
	puts( "Hit a key..." );
	getchar();
	if( cryptEnd() == CRYPT_ERROR_INCOMPLETE )
		{
		puts( "Objects remained allocated." );
		getchar();
		}
	exit( 0 );
#endif /* 0 */
	}

/****************************************************************************
*																			*
*								Main Test Code								*
*																			*
****************************************************************************/

#ifdef __WINDOWS__
  #define INC_CHILD
#endif /* __WINDOWS__ */

/* Comprehensive cryptlib stress test.  To get the following to run under
   WinCE as a native console app, it's necessary to change the entry point
   in Settings | Link | Output from WinMainCRTStartup to the undocumented
   mainACRTStartup, which calls main() rather than WinMain(), however this
   only works if the system has a native console-mode driver (most don't) */

int main( int argc, char **argv )
	{
#ifdef TEST_LOWLEVEL
	CRYPT_ALGO_TYPE cryptAlgo;
#endif /* TEST_LOWLEVEL */
#ifdef TEST_CONFIG
	int i;
#endif /* TEST_CONFIG */
#ifdef TEST_SELFTEST
	int value;
#endif /* TEST_SELFTEST */
	int status;
	void testSystemSpecific( void );

	/* Get rid of compiler warnings */
	if( argc || argv );

	/* Make sure various system-specific features are set right */
	testSystemSpecific();

	/* VisualAge C++ doesn't set the TZ correctly.  The check for this isn't
	   as simple as it would seem since most IBM compilers define the same
	   preprocessor values even though it's not documented anywhere, so we
	   have to enable the tzset() call for (effectively) all IBM compilers
	   and then disable it for ones other than VisualAge C++ */
#if ( defined( __IBMC__ ) || defined( __IBMCPP__ ) ) && !defined( __VMCMS__ )
	tzset();
#endif /* VisualAge C++ */

	/* Initialise cryptlib */
	status = cryptInit();
	if( cryptStatusError( status ) )
		{
		printf( "cryptInit() failed with error code %d.\n", status );
		exit( EXIT_FAILURE );
		}

#ifndef TEST_RANDOM
	/* In order to avoid having to do a randomness poll for every test run,
	   we bypass the randomness-handling by adding some junk.  This is only
	   enabled when cryptlib is built in debug mode, so it won't work with
	   any production systems */
	cryptAddRandom( "xyzzy", 5 );
#endif /* TEST_RANDOM */

	/* Perform a general sanity check to make sure that the self-test is
	   being run the right way */
	if( !checkFileAccess() )
		exit( EXIT_FAILURE );

	/* For general testing purposes we can insert test code at this point to
	   test special cases that aren't covered in the general tests below */
	testKludge();

#ifdef SMOKE_TEST
	/* Perform a general smoke test of the kernel */
	smokeTest();
#endif /* SMOKE_TEST */

#ifdef TEST_SELFTEST
	/* Perform the self-test.  First we write the value to true to force a
	   self-test, then we read it back to see whether it succeeded */
	status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_SELFTESTOK,
								CRYPT_USE_DEFAULT );
	if( cryptStatusError( status ) )
		{
		printf( "Attempt to perform cryptlib algorithm self-test failed "
				"with error code %d.\n", status );
		exit( EXIT_FAILURE );
		}
	status = cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_SELFTESTOK, &value );
	if( cryptStatusError( status ) || value != CRYPT_USE_DEFAULT )
		{
		puts( "cryptlib algorithm self-test failed." );
		exit( EXIT_FAILURE );
		}
	puts( "cryptlib algorithm self-test succeeded.\n" );
#endif /* TEST_SELFTEST */

#ifdef TEST_LOWLEVEL
	/* Test the conventional encryption routines */
	for( cryptAlgo = CRYPT_ALGO_FIRST_CONVENTIONAL;
		 cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) && \
			!testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
			goto errorExit;

	/* Test the public-key encryption routines */
	for( cryptAlgo = CRYPT_ALGO_FIRST_PKC;
		 cryptAlgo <= CRYPT_ALGO_LAST_PKC; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) && \
			!testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
			goto errorExit;

	/* Test the hash routines */
	for( cryptAlgo = CRYPT_ALGO_FIRST_HASH;
		 cryptAlgo <= CRYPT_ALGO_LAST_HASH; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) && \
			!testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
			goto errorExit;

	/* Test the MAC routines */
	for( cryptAlgo = CRYPT_ALGO_FIRST_MAC;
		 cryptAlgo <= CRYPT_ALGO_LAST_MAC; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) && \
			!testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
			goto errorExit;

	printf( "\n" );
#else
	puts( "Skipping test of low-level encryption routines...\n" );
#endif /* TEST_LOWLEVEL */

	/* Test the randomness-gathering routines */
#ifdef TEST_RANDOM
	if( !testRandomRoutines() )
		{
		puts( "The self-test will proceed without using a strong random "
			  "number source.\n" );

		/* Kludge the randomness routines so we can continue the self-tests */
		cryptAddRandom( "xyzzy", 5 );
		}
#else
	puts( "Skipping test of randomness routines...\n" );
#endif /* TEST_RANDOM */

	/* Test the configuration options routines */
#ifdef TEST_CONFIG
	for( i = 0; configOption[ i ].option != CRYPT_ATTRIBUTE_NONE; i++ )
		{
		if( configOption[ i ].isNumeric )
			{
			int value;

			cryptGetAttribute( CRYPT_UNUSED, configOption[ i ].option, &value );
			printf( "%s = %d.\n", configOption[ i ].name, value );
			}
		else
			{
			C_CHR buffer[ 256 ];
			int length;

			cryptGetAttributeString( CRYPT_UNUSED, configOption[ i ].option,
									 buffer, &length );
#ifdef UNICODE_STRINGS
			buffer[ length / sizeof( wchar_t ) ] = TEXT( '\0' );
			printf( "%s = %S.\n", configOption[ i ].name, buffer );
#else
			buffer[ length ] = TEXT( '\0' );
			printf( "%s = %s.\n", configOption[ i ].name, buffer );
#endif /* UNICODE_STRINGS */
			}
		}
	printf( "\n" );
#else
	puts( "Skipping display of config options...\n" );
#endif /* TEST_CONFIG */

	/* Test the crypto device routines */
#ifdef TEST_DEVICE
	status = testDevices();
	if( status == CRYPT_ERROR_NOTAVAIL )
		puts( "Handling for crypto devices doesn't appear to be enabled in "
			  "this build of\ncryptlib.\n" );
	else
		if( !status )
			goto errorExit;
#else
	puts( "Skipping test of crypto device routines...\n" );
#endif /* TEST_DEVICE */

	/* Test the mid-level routines */
#ifdef TEST_MIDLEVEL
	if( !testLargeBufferEncrypt() )
		goto errorExit;
	if( !testDeriveKey() )
		goto errorExit;
	if( !testConventionalExportImport() )
		goto errorExit;
	if( !testMACExportImport() )
		goto errorExit;
	if( !testKeyExportImport() )
		goto errorExit;
	if( !testSignData() )
		goto errorExit;
/*	Disabled for now since there's no useful DH mechanism defined in any
	standard.  Note that KEA is still tested via the Fortezza device test
	if( !testKeyAgreement() )
		goto errorExit; */
	if( !testKeygen() )
		goto errorExit;
	if( !testKeygenAsync() )
		goto errorExit;
	/* No need for putchar, mid-level functions leave a blank line at end */
#else
	puts( "Skipping test of mid-level encryption routines...\n" );
#endif /* TEST_MIDLEVEL */

	/* Test the certificate management routines */
#ifdef TEST_CERT
	if( !testCert() )
		goto errorExit;
	if( !testCACert() )
		goto errorExit;
	if( !testXyzzyCert() )
		goto errorExit;
	if( !testTextStringCert() )
		goto errorExit;
	if( !testComplexCert() )
		goto errorExit;
	if( !testCertExtension() )
		goto errorExit;
	if( !testCustomDNCert() )
		goto errorExit;
	if( !testSETCert() )
		goto errorExit;
	if( !testAttributeCert() )
		goto errorExit;
	if( !testCertRequest() )
		goto errorExit;
	if( !testComplexCertRequest() )
		goto errorExit;
	if( !testCRMFRequest() )
		goto errorExit;
	if( !testComplexCRMFRequest() )
		goto errorExit;
	if( !testCRL() )
		goto errorExit;
	if( !testComplexCRL() )
		goto errorExit;
	if( !testRevRequest() )
		goto errorExit;
	if( !testCertChain() )
		goto errorExit;
	if( !testCMSAttributes() )
		goto errorExit;
	if( !testOCSPReqResp() )
		goto errorExit;
	if( !testCertImport() )
		goto errorExit;
	if( !testCertReqImport() )
		goto errorExit;
	if( !testCRLImport() )
		goto errorExit;
	if( !testCertChainImport() )
		goto errorExit;
	if( !testOCSPImport() )
		goto errorExit;
	if( !testBase64CertImport() )
		goto errorExit;
	if( !testBase64CertChainImport() )
		goto errorExit;
	if( !testMiscImport() )
		goto errorExit;
	if( !testCertComplianceLevel() )
		goto errorExit;
#if 0	/* This takes a while to run and produces a lot of output that won't 
		   be meaningful to anyone other than cryptlib developers so it's
		   disabled by default */
	if( !testPathProcessing() )
		goto errorExit;
#endif /* 0 */
#else
	puts( "Skipping test of certificate managment routines...\n" );
#endif /* TEST_CERT */

	/* Test the keyset read routines */
#ifdef TEST_KEYSET
  #ifdef DATABASE_AUTOCONFIG
	checkCreateDatabaseKeysets();
  #endif /* DATABASE_AUTOCONFIG */
	if( !testGetPGPPublicKey() )
		goto errorExit;
	if( !testGetPGPPrivateKey() )
		goto errorExit;
	if( !testGetBorkenKey() )
		goto errorExit;
	if( !testReadWriteFileKey() )
		goto errorExit;
	if( !testReadBigFileKey() )
		goto errorExit;
	if( !testReadFilePublicKey() )
		goto errorExit;
	if( !testDeleteFileKey() )
		goto errorExit;
	if( !testUpdateFileCert() )
		goto errorExit;
	if( !testReadFileCert() )
		goto errorExit;
	if( !testReadFileCertPrivkey() )
		goto errorExit;
	if( !testWriteFileCertChain() )
		goto errorExit;
	if( !testReadFileCertChain() )
		goto errorExit;
	if( !testAddTrustedCert() )
		goto errorExit;
#if 0	/* This changes the global config file and is disabled by default */
	if( !testAddGloballyTrustedCert() )
		goto errorExit;
#endif /* 0 */
	if( !testWriteFileLongCertChain() )
		goto errorExit;
	if( !testSingleStepFileCert() )
		goto errorExit;
	if( !testDoubleCertFile() )
		goto errorExit;
	if( !testRenewedCertFile() )
		goto errorExit;
	status = testWriteCert();
	if( status == CRYPT_ERROR_NOTAVAIL )
		puts( "Handling for certificate databases doesn't appear to be "
			  "enabled in this\nbuild of cryptlib, skipping the test of "
			  "the certificate database routines.\n" );
	else
		if( status )
			{
			if( !testReadCert() )
				goto errorExit;
			if( !testKeysetQuery() )
				goto errorExit;

			/* The database plugin test will usually fail unless the user has
			   set up a plugin, so we don't check the return value */
			testWriteCertDbx();
			}
	/* For the following tests we may have read access but not write access,
	   so we test a read of known-present certs before trying a write -
	   unlike the local keysets we don't need to add a cert before we can try
	   reading it */
	status = testReadCertLDAP();
	if( status == CRYPT_ERROR_NOTAVAIL )
		puts( "Handling for LDAP certificate directories doesn't appear to "
			  "be enabled in\nthis build of cryptlib, skipping the test of "
			  "the certificate directory\nroutines.\n" );
	else
		/* LDAP access can fail if the directory doesn't use the standard
		   du jour, so we don't treat a failure as a fatal error */
		if( status )
			{
			/* LDAP writes are even worse than LDAP reads, so we don't
			   treat failures here as fatal either */
			testWriteCertLDAP();
			}
	status = testReadCertURL();
	if( status == CRYPT_ERROR_NOTAVAIL )
		puts( "Handling for fetching certificates from web pages doesn't "
			  "appear to be\nenabled in this build of cryptlib, skipping "
			  "the test of the HTTP routines.\n" );
	else
		/* Being able to read a cert from a web page is rather different from
		   access to an HTTP cert store, so we don't treat an error here as
		   fatal */
		if( status )
			testReadCertHTTP();
#else
	puts( "Skipping test of keyset read routines...\n" );
#endif /* TEST_KEYSET */

	/* Test the certificate processing and CA cert management functionality */
#ifdef TEST_CERTPROCESS
	if( !testCertProcess() )
		goto errorExit;
	status = testCertManagement();
	if( status == CRYPT_ERROR_NOTAVAIL )
		puts( "Handling for CA certificate stores doesn't appear to be "
			  "enabled in this\nbuild of cryptlib, skipping the test of "
			  "the certificate management routines.\n" );
	else
		if( !status )
			goto errorExit;
#else
	puts( "Skipping test of certificate handling/CA management...\n" );
#endif /* TEST_CERTPROCESS */

	/* Test the high-level routines (these are similar to the mid-level
	   routines but rely on things like certificate management to work) */
#ifdef TEST_HIGHLEVEL
	if( !testKeyExportImportCMS() )
		goto errorExit;
	if( !testSignDataCMS() )
		goto errorExit;
#endif /* TEST_HIGHLEVEL */

	/* Test the enveloping routines */
#ifdef TEST_ENVELOPE
	if( !testEnvelopeData() )
		goto errorExit;
	if( !testEnvelopeDataLargeBuffer() )
		goto errorExit;
	if( !testEnvelopeCompress() )
		goto errorExit;
	if( !testEnvelopeCompressedDataImport() )
		goto errorExit;
	if( !testEnvelopeSessionCrypt() )
		goto errorExit;
	if( !testEnvelopeSessionCryptLargeBuffer() )
		goto errorExit;
	if( !testEnvelopeCrypt() )
		goto errorExit;
	if( !testEnvelopePasswordCrypt() )
		goto errorExit;
	if( !testEnvelopePasswordCryptImport() )
		goto errorExit;
	if( !testEnvelopePKCCrypt() )
		goto errorExit;
	if( !testEnvelopePKCCryptImport() )
		goto errorExit;
	if( !testEnvelopeSign() )
		goto errorExit;
	if( !testEnvelopeSignOverflow() )
		goto errorExit;
	if( !testEnvelopeSignedDataImport() )
		goto errorExit;
	if( !testEnvelopeAuthenticate() )
		goto errorExit;
	if( !testCMSEnvelopePKCCrypt() )
		goto errorExit;
	if( !testCMSEnvelopePKCCryptDoubleCert() )
		goto errorExit;
	if( !testCMSEnvelopeSign() )
		goto errorExit;
	if( !testCMSEnvelopeDualSign() )
		goto errorExit;
	if( !testCMSEnvelopeDetachedSig() )
		goto errorExit;
	if( !testCMSEnvelopeSignedDataImport() )
		goto errorExit;
#else
	puts( "Skipping test of enveloping routines...\n" );
#endif /* TEST_ENVELOPE */

	/* Test the session routines */
#ifdef TEST_SESSION
	status = testSessionUrlParse();
	if( !status )
		goto errorExit;
	if( status == CRYPT_ERROR_NOTAVAIL )
		puts( "Network access doesn't appear to be enabled in this build of "
			  "cryptlib,\nskipping the test of the secure session routines.\n" );
	else
		{
		if( !testSessionSSHv1() )
			goto errorExit;
		if( !testSessionSSH() )
			goto errorExit;
		if( !testSessionSSHPortforward() )
			goto errorExit;
		if( !testSessionSSL() )
			goto errorExit;
		if( !testSessionSSLLocalSocket() )
			goto errorExit;
		if( !testSessionTLS() )
			goto errorExit;
		if( !testSessionTLS11() )
			goto errorExit;
		if( !testSessionOCSP() )
			goto errorExit;
		if( !testSessionTSP() )
			goto errorExit;
		if( !testSessionEnvTSP() )
			goto errorExit;
		if( !testSessionCMP() )
			goto errorExit;

		/* Test loopback client/server sessions.  These require a threaded
		   OS and are aliased to nops on non-threaded systems.  In addition
		   there can be synchronisation problems between the two threads if
		   the server is delayed for some reason, resulting in the client
		   waiting for a socket that isn't opened yet.  This isn't easy to
		   fix without a lot of explicit intra-thread synchronisation, if
		   there's a problem it's easier to just re-run the tests */
		if( !testSessionSSHv1ClientServer() )
			goto errorExit;
		if( !testSessionSSHClientServer() )
			goto errorExit;
		if( !testSessionSSHClientServerFingerprint() )
			goto errorExit;
		if( !testSessionSSHClientServerPortForward() )
			goto errorExit;
		if( !testSessionSSHClientServerMultichannel() )
			goto errorExit;
		if( !testSessionSSLClientServer() )
			goto errorExit;
		if( !testSessionSSLClientCertClientServer() )
			goto errorExit;
		if( !testSessionTLSClientServer() )
			goto errorExit;
		if( !testSessionTLSSharedKeyClientServer() )
			goto errorExit;
		if( !testSessionTLSBulkTransferClientServer() )
			goto errorExit;
		if( !testSessionTLS11ClientServer() )
			goto errorExit;
		if( !testSessionHTTPCertstoreClientServer() )
			goto errorExit;
		if( !testSessionRTCSClientServer() )
			goto errorExit;
		if( !testSessionOCSPClientServer() )
			goto errorExit;
		if( !testSessionTSPClientServer() )
			goto errorExit;
		if( !testSessionTSPClientServerPersistent() )
			goto errorExit;
		if( !testSessionSCEPClientServer() )
			goto errorExit;
		if( !testSessionCMPClientServer() )
			goto errorExit;
		if( !testSessionCMPPKIBootClientServer() )
			goto errorExit;
		if( !testSessionPNPPKIClientServer() )
			goto errorExit;
		if( !testSessionPNPPKICAClientServer() )
			goto errorExit;
		}
#endif /* TEST_SESSION */

	/* Test the user routines */
#ifdef TEST_USER
	if( !testUser() )
		goto errorExit;
#endif /* TEST_USER */

	/* Shut down cryptlib */
	status = cryptEnd();
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_INCOMPLETE )
			puts( "cryptEnd() failed with error code CRYPT_ERROR_INCOMPLETE, "
				  "a code path in the\nself-test code resulted in an error "
				  "return without a full cleanup of objects.\nIf you were "
				  "running the multithreaded loopback tests this may be "
				  "because one\nor more threads lost sync with other threads "
				  "and exited without cleaning up\nits objects.  This "
				  "happens occasionally due to network timing issues or\n"
				  "thread scheduling differences." );
		else
			printf( "cryptEnd() failed with error code %d.\n", status );
		goto errorExit1;
		}

	puts( "All tests concluded successfully." );
	return( EXIT_SUCCESS );

	/* All errors end up here */
#if defined( TEST_LOWLEVEL ) || defined( TEST_MIDLEVEL ) || \
	defined( TEST_DEVICE ) || defined( TEST_CERT ) || \
	defined( TEST_KEYSET ) || defined( TEST_CERTPROCESS ) || \
	defined( TEST_CERTMANAGEMENT ) || defined( TEST_HIGHLEVEL ) || \
	defined( TEST_ENVELOPE ) || defined( TEST_SESSION ) || \
	defined( TEST_SESSION ) || defined( TEST_USER )
errorExit:
	cryptEnd();
#endif /* Eliminate compiler warning about unreferenced label */
errorExit1:
	puts( "\nThe test was aborted due to an error being detected.  If you "
		  "want to report\nthis problem, please provide as much information "
		  "as possible to allow it to\nbe diagnosed, for example the call "
		  "stack, the location inside cryptlib where\nthe problem occurred, "
		  "and the values of any variables that might be\nrelevant." );
#ifdef WINDOWS_THREADS
	puts( "\nIf the error occurred during one of the multi-threaded network "
		  "loopback\ntests, this was probably due to the different threads "
		  "losing synchronisation.\nFor the secure sessions this usually "
		  "results in read/write, timeout, or\nconnection-closed errors "
		  "when one thread is pre-empted for too long.  For the\n"
		  "certificate-management sessions it usually results in an error "
		  "related to the\nserver being pre-empted for too long by database "
		  "updates.  Since the self-\ntest exists only to exercise "
		  "cryptlib's capabilities, it doesn't bother with\ncomplex thread "
		  "synchronisation during the multi-threaded loopback tests.\nThis "
		  "type of error is non-fatal, and should disappear if the test is "
		  "re-run." );
#endif /* WINDOWS_THREADS */
#ifdef __WINDOWS__
	/* The pseudo-CLI VC++ output windows are closed when the program exits
	   so we have to explicitly wait to allow the user to read them */
	puts( "\nHit a key..." );
	getchar();
#endif /* __WINDOWS__ */
	return( EXIT_FAILURE );
	}

/* PalmOS wrapper for main() */

#ifdef __PALMSOURCE__

#include <CmnErrors.h>
#include <CmnLaunchCodes.h>

uint32_t PilotMain( uint16_t cmd, void *cmdPBP, uint16_t launchFlags )
	{
	switch( cmd )
		{
		case sysAppLaunchCmdNormalLaunch:
			main( 0, NULL );
		}

	return( errNone );
	}
#endif /* __PALMSOURCE__ */

/* Test the system-specific defines in crypt.h.  This is the last function in
   the file because we want to avoid any definitions in crypt.h messing with
   the rest of the test.c code.

   The following include is needed only so we can check whether the defines
   are set right.  crypt.h should never be included in a program that uses
   cryptlib */

#undef __WINDOWS__
#undef __WIN16__
#undef __WIN32__
#undef BOOLEAN
#undef BYTE
#undef FALSE
#undef TRUE
#if defined( __MVS__ ) || defined( __VMCMS__ )
  #pragma convlit( resume )
#endif /* Resume ASCII use on EBCDIC systems */
#if defined( __ILEC400__ )
  #pragma convert( 819 )
#endif /* Resume ASCII use on EBCDIC systems */
#ifdef _MSC_VER
  #include "../crypt.h"
#else
  #include "crypt.h"
#endif /* Braindamaged MSC include handling */
#if defined( __MVS__ ) || defined( __VMCMS__ )
  #pragma convlit( suspend )
#endif /* Suspend ASCII use on EBCDIC systems */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* Suspend ASCII use on EBCDIC systems */
#undef mktime		/* Undo mktime() bugfix in crypt.h */

#ifndef _WIN32_WCE

static time_t testTime( const int year )
	{
	struct tm theTime;

	memset( &theTime, 0, sizeof( struct tm ) );
	theTime.tm_isdst = -1;
	theTime.tm_year = 100 + year;
	theTime.tm_mon = 5;
	theTime.tm_mday = 5;
	theTime.tm_hour = 12;
	theTime.tm_min = 13;
	theTime.tm_sec = 14;
	return( mktime( &theTime ) );
	}
#endif /* !WinCE */

void testSystemSpecific( void )
	{
	int bigEndian;
#ifndef _WIN32_WCE
	int i;
#endif /* WinCE */

	/* Make sure that we've got the endianness set right.  If the machine is
	   big-endian (up to 64 bits) the following value will be signed,
	   otherwise it will be unsigned.  We can't easily test for things like
	   middle-endianness without knowing the size of the data types, but
	   then again it's unlikely we're being run on a PDP-11 */
	bigEndian = ( *( long * ) "\x80\x00\x00\x00\x00\x00\x00\x00" < 0 );
#ifdef DATA_LITTLEENDIAN
	if( bigEndian )
		{
		puts( "The CPU endianness define is set wrong in crypt.h, this "
			  "machine appears to be\nbig-endian, not little-endian.  Edit "
			  "the file and rebuild cryptlib." );
		exit( EXIT_FAILURE );
		}
#else
	if( !bigEndian )
		{
		puts( "The CPU endianness define is set wrong in crypt.h, this "
			  "machine appears to be\nlittle-endian, not big-endian.  Edit "
			  "the file and rebuild cryptlib." );
		exit( EXIT_FAILURE );
		}
#endif /* DATA_LITTLEENDIAN */

	/* Make sure that the compiler doesn't use variable-size enums */
	if( sizeof( CRYPT_ALGO_TYPE ) != sizeof( int ) || \
		sizeof( CRYPT_MODE_TYPE ) != sizeof( int ) ||
		sizeof( CRYPT_ATTRIBUTE_TYPE ) != sizeof( int ) )
		{
		puts( "The compiler you are using treats enumerated types as "
			  "variable-length non-\ninteger values, making it impossible "
			  "to reliably pass the address of an\nenum as a function "
			  "parameter.  To fix this, you need to rebuild cryptlib\nwith "
			  "the appropriate compiler option or pragma to ensure that\n"
			  "sizeof( enum ) == sizeof( int )." );
		exit( EXIT_FAILURE );
		}

	/* Make sure that mktime() works properly (there are some systems on
	   which it fails well before 2038) */
#ifndef _WIN32_WCE
	for( i = 10; i < 36; i ++ )
		{
		const time_t theTime = testTime( i );

		if( theTime < 0 )
			{
			printf( "Warning: This system has a buggy mktime() that can't "
					"handle dates beyond %d.\n         Some certificate tests "
					"will fail, and long-lived CA certificates\n         won't "
					"be correctly imported.\n", 2000 + i );
			break;
			}
		}
#endif /* !WinCE */

	/* If we're compiling under Unix with threading support, make sure the
	   default thread stack size is sensible.  We don't perform the check for
	   UnixWare/SCO since this already has the workaround applied */
#if defined( UNIX_THREADS ) && !defined( __SCO_VERSION__ )
	{
	pthread_attr_t attr;
	size_t stackSize;

	pthread_attr_init( &attr );
	pthread_attr_getstacksize( &attr, &stackSize );
    pthread_attr_destroy( &attr );
  #if ( defined( sun ) && OSVERSION > 4 )
	/* Slowaris uses a special-case value of 0 (actually NULL) to indicate
	   the default stack size of 1MB (32-bit) or 2MB (64-bit), so we have to
	   handle this specially */
	if( stackSize < 32768 && stackSize != 0 )
  #else
	if( stackSize < 32768 )
  #endif /* Slowaris special-case handling */
		{
		printf( "The pthread stack size is defaulting to %d bytes, which is "
				"too small for\ncryptlib to run in.  To fix this, edit the "
				"thread-creation function macro in\ncryptos.h and recompile "
				"cryptlib.\n", stackSize );
		exit( EXIT_FAILURE );
		}
	}
#endif /* UNIX_THREADS */
	}
