/****************************************************************************
*																			*
*				cryptlib Cert Management Session Test Routines				*
*						Copyright Peter Gutmann 1998-2003					*
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

/* Prototypes for functions in testsreq.c */

BOOLEAN setLocalConnect( const CRYPT_SESSION cryptSession, const int port );
void printConnectInfo( const CRYPT_SESSION cryptSession );

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Run a persistent server session, recycling the connection if the client
   kept the link open */

static int activatePersistentServerSession( const CRYPT_SESSION cryptSession,
											const BOOLEAN showOperationType )
	{
	BOOLEAN connectionActive = FALSE;
	int status;

	do
		{
		/* Activate the connection */
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, 
									TRUE );
		if( status == CRYPT_ERROR_READ && connectionActive )
			/* The other side closed the connection after a previous 
			   successful transaction, this isn't an error */
			return( CRYPT_OK );

		/* Print connection info and check whether the connection is still
		   active.  If it is, we recycle the session so that we can process 
		   another request */
		printConnectInfo( cryptSession );
		if( cryptStatusOK( status ) && showOperationType )
			{
			char userID[ CRYPT_MAX_TEXTSIZE ];
			int userIDsize, requestType;

			status = cryptGetAttribute( cryptSession, 
										CRYPT_SESSINFO_CMP_REQUESTTYPE,
										&requestType );
			if( cryptStatusOK( status ) )
				status = cryptGetAttributeString( cryptSession, 
											CRYPT_SESSINFO_USERNAME,
											userID, &userIDsize );
			if( cryptStatusError( status ) )
				printf( "cryptGetAttribute/AttributeString() failed with "
						"error code %d, line %d.\n", status, __LINE__ );
			else
				{
				userID[ userIDsize ] = '\0';
				printf( "SVR: Operation type was %d, user '%s'.\n", 
						requestType, userID );
				}
			}
		cryptGetAttribute( cryptSession, CRYPT_SESSINFO_CONNECTIONACTIVE,
						   &connectionActive );
		}
	while( cryptStatusOK( status ) && connectionActive );

	return( status );
	}

/* Get information on a PKI user */

static int getPkiUserInfo( char *userID, char *issuePW, char *revPW )
	{
	CRYPT_KEYSET cryptCertStore;
	CRYPT_CERTIFICATE cryptPKIUser;
	int length, status;

	/* cryptlib implements per-user (rather than shared interop) IDs and
	   passwords so we need to read the user ID and password information
	   before we can perform any operations.  First we get the PkiUser
	   object */
	status = cryptKeysetOpen( &cryptCertStore, CRYPT_UNUSED,
							  CERTSTORE_KEYSET_TYPE, CERTSTORE_KEYSET_NAME,
							  CRYPT_KEYOPT_NONE );
	if( status == CRYPT_ERROR_PARAM3 )
		{
		/* This type of keyset access isn't available, return a special error
		   code to indicate that the test wasn't performed, but that this
		   isn't a reason to abort processing */
		puts( "No certificate store available, aborting CMP test.\n" );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCAGetItem( cryptCertStore, &cryptPKIUser,
							 CRYPT_CERTTYPE_PKIUSER, CRYPT_KEYID_NAME,
							 "Test PKI user" );
	cryptKeysetClose( cryptCertStore );
	if( cryptStatusError( status ) )
		return( extErrorExit( cryptCertStore, "cryptCAGetItem()", status,
							  __LINE__ ) );

	/* If it's a presence check only, we're done */
	if( userID == NULL )
		{
		cryptDestroyCert( cryptPKIUser );
		return( CRYPT_OK );
		}

	/* Then we extract the information from the PkiUser object */
	status = cryptGetAttributeString( cryptPKIUser,
									  CRYPT_CERTINFO_PKIUSER_ID,
									  userID, &length );
	if( cryptStatusOK( status ) )
		{
		userID[ length ] = '\0';
		status = cryptGetAttributeString( cryptPKIUser,
									CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD,
									issuePW, &length );
		}
	if( cryptStatusOK( status ) )
		issuePW[ length ] = '\0';
	if( cryptStatusOK( status ) && revPW != NULL )
		{
		status = cryptGetAttributeString( cryptPKIUser,
									CRYPT_CERTINFO_PKIUSER_REVPASSWORD,
									revPW, &length );
		if( cryptStatusOK( status ) )
			revPW[ length ] = '\0';
		}
	cryptDestroyCert( cryptPKIUser );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptPKIUser, "cryptGetAttribute()", status,
							   __LINE__ ) );

	/* We've got what we need, tell the user what we're doing */
	printf( "Using user name %s, password %s.\n", userID, issuePW );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								SCEP Routines Test							*
*																			*
****************************************************************************/

/* There are various SCEP test servers available, the following mappings 
   can be used to test different ones.  Implementation peculiarities:

	#1 - cryptlib:
	
	#2 - SSH (www.ssh.com/support/testzone/pki.html): Invalid CA certs.
	
	#3 - OpenSCEP (openscep.othello.ch): Seems to be permanently unavailable.

	#4 - Entrust (freecerts.entrust.com/vpncerts/cep.htm): Only seems to be 
			set up to handle Cisco gear */

#define SCEP_NO		1

typedef struct {
	const char *name, *url, *user, *password, *caCertUrl;
	} SCEP_INFO;

static const SCEP_INFO scepInfo[] = {
	{ NULL },	/* Dummy so index == SCEP_NO */
	{ /*1*/ "cryptlib", "http://localhost", NULL, NULL, NULL },
	{ /*2*/ "SSH", "http://pki.ssh.com:8080/scep/", "ssh", "ssh",
			"http://pki.ssh.com:8080/scep/pkiclient.exe?operation=GetCACert&message=test-ca1.ssh.com" },
	{ /*3*/ "OpenSCEP", "http://openscep.othello.ch/", "????", "????", NULL },
	{ /*4*/ "Entrust", "http://vpncerts.entrust.com/", "????", "????", NULL },
	};

/* Cert request data for the cert from the SCEP server.  Note that we have 
   to set the CN to the PKI user CN, for CMP ir's we just omit the DN 
   entirely and have the server provide it for us but since SCEP uses PKCS 
   #10 requests we need to provide a DN, and since we provide it it has to
   match the PKI user DN */

static const CERT_DATA scepRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Procurement" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Test PKI user" },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, "dave@wetas-r-us.com" },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, "http://www.wetas-r-us.com" },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

/* Get an SCEP CA cert */

static int getScepCACert( const char *caCertUrl, 
						  CRYPT_CERTIFICATE *cryptCACert )
	{
	CRYPT_KEYSET cryptKeyset;
	int status;

	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_HTTP, 
							  caCertUrl, CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetPublicKey( cryptKeyset, cryptCACert, CRYPT_KEYID_NAME,
									"[None]" );
		cryptKeysetClose( cryptKeyset );
		}
	if( cryptStatusError( status ) )
		return( extErrorExit( cryptKeyset, "cryptGetPublicKey()", 
							  status, __LINE__ ) );

	return( CRYPT_OK );
	}

/* Perform an SCEP test */

int testSessionSCEP( void )
	{
	CRYPT_SESSION cryptSession;
	CRYPT_CERTIFICATE cryptRequest, cryptResponse, cryptCACert;
	CRYPT_CONTEXT cryptContext;
	char userID[ 64 ], password[ 64 ];
	const char *userPtr = scepInfo[ SCEP_NO ].user;
	const char *passwordPtr = scepInfo[ SCEP_NO ].password;
	int status;

	puts( "Testing SCEP session..." );

	/* Get the issuing CA's cert */
	if( scepInfo[ SCEP_NO ].caCertUrl != NULL )
		status = getScepCACert( scepInfo[ SCEP_NO ].caCertUrl,
								&cryptCACert );
	else
		status = importCertFromTemplate( &cryptCACert, SCEP_CA_FILE_TEMPLATE,
										 SCEP_NO );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't get SCEP CA certificate, status = %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* cryptlib implements per-user (rather than shared interop) IDs and
	   passwords so we need to read the user ID and password information
	   before we can perform any operations */
#if ( SCEP_NO == 1 )
	status = getPkiUserInfo( userID, password, NULL );
	if( cryptStatusError( status ) )
		{
		cryptDestroyCert( cryptCACert );
		return( ( status == CRYPT_ERROR_NOTAVAIL ) ? TRUE : FALSE );
		}
	userPtr = userID;
	passwordPtr = password;
#endif /* cryptlib SCEP_NO == 1 */

	/* Create the SCEP session */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED,
								 CRYPT_SESSION_SCEP );
	if( status == CRYPT_ERROR_PARAM3 )	/* SCEP session access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSession() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Set up the user and server information */
	status = cryptSetAttributeString( cryptSession,
									  CRYPT_SESSINFO_USERNAME, 
									  userPtr, strlen( userPtr ) );
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptSession,
										  CRYPT_SESSINFO_PASSWORD, 
										  passwordPtr, strlen( passwordPtr ) );
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_SERVER_NAME, 
									scepInfo[ SCEP_NO ].url,
									strlen( scepInfo[ SCEP_NO ].url ) );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptSession,
									CRYPT_SESSINFO_CACERTIFICATE, 
									cryptCACert );
	cryptDestroyCert( cryptCACert );
	if( cryptStatusError( status ) )
		{
		printf( "Addition of session information failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Create the (unsigned) PKCS #10 request */
#if ( SCEP_NO == 1 )
	cryptCreateContext( &cryptContext, CRYPT_UNUSED, CRYPT_ALGO_RSA );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL,
							 USER_PRIVKEY_LABEL,
							 strlen( USER_PRIVKEY_LABEL ) );
	cryptSetAttribute( cryptContext, CRYPT_CTXINFO_KEYSIZE, 64 );
	status = cryptGenerateKey( cryptContext );
#else
	loadRSAContextsEx( CRYPT_UNUSED, NULL, &cryptContext, NULL,
					   USER_PRIVKEY_LABEL );
#endif /* cryptlib SCEP_NO == 1 */
	status = cryptCreateCert( &cryptRequest, CRYPT_UNUSED, 
							  CRYPT_CERTTYPE_CERTREQUEST );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptRequest,
							CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptRequest, scepRequestData ) )
		status = CRYPT_ERROR_FAILED;
#if 0
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptRequest, cryptContext );
#endif
	if( cryptStatusError( status ) )
		{
		printf( "Creation of PKCS #10 request failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Set up the private key and request, and activate the session */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_PRIVATEKEY,
								cryptContext );
	cryptDestroyContext( cryptContext );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_REQUEST,
									cryptRequest );
	cryptDestroyCert( cryptRequest );
	if( cryptStatusError( status ) )
		{
		printf( "cryptSetAttribute() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptSession, "Attempt to activate SCEP client "
					   "session", status, __LINE__ );
		cryptDestroySession( cryptSession );
		if( status == CRYPT_ERROR_OPEN || status == CRYPT_ERROR_READ )
			{
			/* These servers are constantly appearing and disappearing so if
			   we get a straight connect error we don't treat it as a serious
			   failure */
			puts( "  (Server could be down, faking it and continuing...)\n" );
			return( CRYPT_ERROR_FAILED );
			}
		return( FALSE );
		}

	/* Obtain the response information */
	status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_RESPONSE,
								&cryptResponse );
	cryptDestroySession( cryptSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetAttribute() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
#if ( SCEP_NO != 1 ) 
	puts( "Returned certificate details are:" );
	printCertInfo( cryptResponse );
#endif /* Keep the cryptlib results on one screen */

	/* Clean up */
	cryptDestroyCert( cryptResponse );
	puts( "SCEP client session succeeded.\n" );
	return( TRUE );
	}

int testSessionSCEPServer( void )
	{
	CRYPT_SESSION cryptSession;
	CRYPT_CONTEXT cryptPrivateKey;
	CRYPT_KEYSET cryptCertStore;
	int status;

	puts( "SVR: Testing SCEP server session ..." );

	/* Perform a test create of a SCEP server session to verify that we can
	   do this test */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED,
								 CRYPT_SESSION_SCEP_SERVER );
	if( status == CRYPT_ERROR_PARAM3 )	/* SCEP session access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: cryptCreateSession() failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	cryptDestroySession( cryptSession );

	/* Get the cert store and server private key to use with the session.
	   Before we add the store we perform a cleanup action to remove any
	   leftover requests from previous runs */
	status = cryptKeysetOpen( &cryptCertStore, CRYPT_UNUSED,
							  CERTSTORE_KEYSET_TYPE, CERTSTORE_KEYSET_NAME,
							  CRYPT_KEYOPT_CREATE );
	if( status == CRYPT_ERROR_PARAM3 )
		{
		/* This type of keyset access isn't available, return a special error
		   code to indicate that the test wasn't performed, but that this
		   isn't a reason to abort processing */
		puts( "SVR: No certificate store available, aborting SCEP server "
			  "test.\n" );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	if( status == CRYPT_ERROR_DUPLICATE )
		status = cryptKeysetOpen( &cryptCertStore, CRYPT_UNUSED,
								  CERTSTORE_KEYSET_TYPE, CERTSTORE_KEYSET_NAME,
								  CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: cryptKeysetOpen() failed with error code %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}
	cryptCACertManagement( NULL, CRYPT_CERTACTION_CLEANUP, cryptCertStore,
						   CRYPT_UNUSED, CRYPT_UNUSED );
	status = getPrivateKey( &cryptPrivateKey, SCEPCA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: CA private key read failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Create the SCEP session and add the CA key and cert store */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED,
								 CRYPT_SESSION_SCEP_SERVER );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: cryptCreateSession() failed with error code %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptSession,
							CRYPT_SESSINFO_PRIVATEKEY, cryptPrivateKey );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptSession,
							CRYPT_SESSINFO_KEYSET, cryptCertStore );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptSession, "SVR: cryptSetAttribute()", 
							   status, __LINE__ ) );

	/* Activate the session */
	status = activatePersistentServerSession( cryptSession, FALSE );
	if( cryptStatusError( status ) )
		{
		cryptKeysetClose( cryptCertStore );
		cryptDestroyContext( cryptPrivateKey );
		return( extErrorExit( cryptSession, "SVR: Attempt to activate SCEP "
							  "server session", status, __LINE__ ) );
		}

	/* Clean up */
	cryptDestroySession( cryptSession );
	cryptKeysetClose( cryptCertStore );
	cryptDestroyContext( cryptPrivateKey );

	puts( "SVR: SCEP session succeeded.\n" );
	return( TRUE );
	}

/* Perform a client/server loopback test */

#ifdef WINDOWS_THREADS

unsigned __stdcall scepServerThread( void *dummy )
	{
	testSessionSCEPServer();
	_endthreadex( 0 );
	return( 0 );
	}

int testSessionSCEPClientServer( void )
	{
	HANDLE hThread;
	unsigned threadID;
	int status;

#if ( SCEP_NO != 1 )
	/* Because the code has to handle so many CA-specific peculiarities, we
	   can only perform this test when the CA being used is the cryptlib 
	   CA */
	puts( "Error: The local SCEP session test only works with SCEP_NO == 1." );
	return( FALSE );
#endif /* cryptlib CA */

	/* Start the server and wait for it to initialise (this takes a bit
	   longer than the other servers because we have to work with a cert
	   store so we wait a bit longer than usual) */
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, &scepServerThread,
										 NULL, 0, &threadID );
	Sleep( 3000 );

	/* Connect to the local server */
	status = testSessionSCEP();
	if( WaitForSingleObject( hThread, 15000 ) == WAIT_TIMEOUT )
		{
		puts( "Warning: Server thread is still active due to session "
			  "negotiation failure,\n         this will cause an error "
			  "condition when cryptEnd() is called due\n         to "
			  "resources remaining allocated.  Press a key to continue." );
		getchar();
		}
	CloseHandle( hThread );

	return( status );
	}
#endif /* WINDOWS_THREADS */

/****************************************************************************
*																			*
*								CMP Routines Test							*
*																			*
****************************************************************************/

/* There are various CMP test CAs available, the following mappings can be
   used to test different ones.  Implementation peculiarities:

	#1 - cryptlib: Implicitly revokes cert being replaced during a kur (this
			is a requirement for maintaining cert store consistency).
			Tested: ir, cr/kur, rr
	#2 - Certicom: Requires signature for revocation rather than MAC,
			requires that all certs created after the ir one have the same
			DN as the ir cert.
			Tested: ir, cr/kur, rr
	#3 - ssh: None (recently re-issued their CA cert which is broken, CA
			couldn't be re-tested.  In addition since CMP identifies the
			sender by DN the new cert can't be distinguished from the old
			one, causing all sig checks to fail).
			Tested (late 2000): ir, cr/kur, rr
	#4 - Entrust: Won't allow altNames, changes sender and request DN,
			returns rejected response under an altered DN belonging to a
			completely different EE for anything but ir.
			Tested: ir
	#5 - Trustcenter: Requires HTTPS and pre-existing trusted private key
			distributed as PKCS #12 file, couldn't be tested.
	#6 - Baltimore: Server unavailable for testing.
			Tested: -
	#7 - Initech: Needs DN cn=CryptLIB EE 1,o=INITECH,c=KR.
			Tested: ir, cr/kur, rr
	#8 - RSA labs: Rejects signed requests, couldn't be tested beyond initial
			(MACd) ir.  Attempt to revoke newly-issued cert with MACd rr
			returns error indicating that the cert is already revoked.
			Tested: ir
	#9 - Cylink: Invalid CA root cert, requires use of DN from RA rather
			than CA when communicating with server.
			Tested: - */

#define CA_NO	1

typedef struct {
	const char *name, *url, *user, *password;
	} CA_INFO;

static const CA_INFO caInfo[] = {
	{ NULL },	/* Dummy so index == CA_NO */
	{ /*1*/ "cryptlib", "http://localhost", "interop", "interop" },
	{ /*2*/ "Certicom", "cmp://gandalf.trustpoint.com:8081", "interop", "interop" },
	{ /*3*/ "ssh", "cmp://interop-ca.ssh.com:8290", "123456", "interop" },
	{ /*4*/ "Entrust", "cmp://204.101.128.45:829", "39141091", "ABCDEFGHIJK" },
	{ /*5*/ "Trustcenter", "cmp://demo.trustcenter.de/cgi-bin/cmp:829", "interop", "interop" },
	{ /*6*/ "Baltimore", "cmp://hip.baltimore.ie:8290", "pgutmann", "the-magical-land-near-oz" },
	{ /*7*/ "Initech", "cmp://61.74.133.49:8290", "interop", "interop" },
	{ /*8*/ "RSA", "cmp://ca1.kcspilot.com:32829", "interop", "interop" },
	{ /*9*/ "Cylink", "cmp://216.252.217.227:8082", "3986", "11002" /* "3987", "6711" */ },
	{ /*A*/	"cryptlib/PKIBoot", /*"_pkiboot._tcp.cryptoapps.com"*/"http://localhost", "interop", "interop" }
	};

/* The following defines can be used to selectively enable or disable some
   of the test (for example to do an ir + rr, or ir + kur + rr) */

#if ( CA_NO == 1 ) || ( CA_NO == 10 )
  #define TEST_IR
  #define TEST_KUR
  #define TEST_CR
  #define TEST_RR
  #define NO_CA_REQUESTS	4	/* 3 cert reqs, 1 rev.req (kur = impl.rev) */
#else
  #define TEST_IR
  #define TEST_KUR
  #define TEST_CR
  #define TEST_RR
  #define NO_CA_REQUESTS	0	/* Loopback test requires CA_NO == 1 or 10 */
#endif /* CA_NO == 1 || CA_NO == 10 */

/* Define the following to enable testing of servers where the initial DN is
   supplied by the server (i.e. the user supplies a null DN) */

#if ( CA_NO == 1 ) || ( CA_NO == 10 )
  #define SERVER_PROVIDES_DN
#endif /* CAs where the server provides the DN */

/* Cert request data for the various types of certs that a CMP CA can return */

static const CERT_DATA cmpRsaSignRequestData[] = {
	/* Identification information */
  #if CA_NO == 7
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "KR" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "INITECH" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "CryptLIB EE 1" },
  #else
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Procurement" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave's Signature Key" },
  #endif /* Initech requires fixed DN */

	/* Subject altName */
#if CA_NO != 4
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, "dave@wetas-r-us.com" },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, "http://www.wetas-r-us.com" },
#endif /* Entrust doesn't allow altName */

	/* Signature-only key */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC, CRYPT_KEYUSAGE_DIGITALSIGNATURE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};
static const CERT_DATA cmpRsaSignRequestNoDNData[] = {
	/* Identification information - none, it's provided by the server */

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, "dave@wetas-r-us.com" },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, "http://www.wetas-r-us.com" },

	/* Signature-only key */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC, CRYPT_KEYUSAGE_DIGITALSIGNATURE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};
static const CERT_DATA cmpRsaEncryptRequestData[] = {
	/* Identification information */
#if CA_NO == 7
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "KR" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "INITECH" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "CryptLIB EE 1" },
#else
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Procurement" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave's Encryption Key" },
#endif /* Initech requires fixed DN */

	/* Subject altName */
#if CA_NO != 4
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, "dave@wetas-r-us.com" },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, "http://www.wetas-r-us.com" },
#endif /* Entrust doesn't allow altName */

	/* Encryption-only key */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC, CRYPT_KEYUSAGE_KEYENCIPHERMENT },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};
static const CERT_DATA cmpDsaRequestData[] = {
	/* Identification information */
#if CA_NO == 7
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "KR" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "INITECH" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "CryptLIB EE 1" },
#else
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Procurement" },
  #if CA_NO == 2
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave's Signature Key" },
  #else
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave's DSA Key" },
  #endif /* Certicom requires same DN as for init.request */
#endif /* Initech requires fixed DN */

	/* Subject altName */
#if CA_NO != 4
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, "dave@wetas-r-us.com" },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, "http://www.wetas-r-us.com" },
#endif /* Entrust doesn't allow altName */

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

/* Create various CMP objects */

static int createCmpRequest( const CERT_DATA *requestData,
							 const CRYPT_CONTEXT privateKey,
							 const CRYPT_ALGO_TYPE cryptAlgo,
							 const BOOLEAN useFixedKey,
							 const CRYPT_KEYSET cryptKeyset )
	{
	CRYPT_CERTIFICATE cryptRequest;
	int status;

	/* Create the CMP (CRMF) request */
	if( privateKey != CRYPT_UNUSED )
		{
		time_t startTime;
		int dummy;

		/* If we're updating an existing cert we have to vary something in
		   the request to make sure that the result doesn't duplicate an 
		   existing cert, to do this we fiddle the start time */
		status = cryptGetAttributeString( privateKey, CRYPT_CERTINFO_VALIDFROM,
										  &startTime, &dummy );
		if( cryptStatusError( status ) )
			return( FALSE );
		startTime++;

		/* It's an update of existing information, sign the request with the
		   given private key */
		status = cryptCreateCert( &cryptRequest, CRYPT_UNUSED,
								  CRYPT_CERTTYPE_REQUEST_CERT );
		if( cryptStatusOK( status ) )
			status = cryptSetAttribute( cryptRequest, 
						CRYPT_CERTINFO_CERTIFICATE, privateKey );
		if( cryptStatusOK( status ) )
			status = cryptSetAttributeString( cryptRequest,
						CRYPT_CERTINFO_VALIDFROM, &startTime, sizeof( time_t ) );
		if( cryptStatusOK( status ) )
			status = cryptSignCert( cryptRequest, privateKey );
		if( cryptKeyset != CRYPT_UNUSED )
			{
			if( cryptStatusError( \
					cryptAddPrivateKey( cryptKeyset, privateKey,
										TEST_PRIVKEY_PASSWORD ) ) )
				return( FALSE );
			}
		}
	else
		{
		CRYPT_CONTEXT cryptContext;

		/* It's a new request, generate a private key and create a self-
		   signed request */
		if( useFixedKey )
			{
			/* Use a fixed private key, for testing purposes */
			if( cryptAlgo == CRYPT_ALGO_RSA )
				loadRSAContextsEx( CRYPT_UNUSED, NULL, &cryptContext, NULL,
								   USER_PRIVKEY_LABEL );
			else
				loadDSAContextsEx( CRYPT_UNUSED, &cryptContext, NULL,
								   USER_PRIVKEY_LABEL, NULL );
			status = CRYPT_OK;
			}
		else
			{
			cryptCreateContext( &cryptContext, CRYPT_UNUSED, cryptAlgo );
			cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL,
									 USER_PRIVKEY_LABEL,
									 strlen( USER_PRIVKEY_LABEL ) );
			cryptSetAttribute( cryptContext, CRYPT_CTXINFO_KEYSIZE, 64 );
			status = cryptGenerateKey( cryptContext );
			}
		if( cryptStatusOK( status ) )
			status = cryptCreateCert( &cryptRequest, CRYPT_UNUSED,
									  CRYPT_CERTTYPE_REQUEST_CERT );
		if( cryptStatusOK( status ) )
			status = cryptSetAttribute( cryptRequest,
						CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
		if( cryptStatusOK( status ) && \
			!addCertFields( cryptRequest, requestData ) )
			status = CRYPT_ERROR_FAILED;
		if( cryptStatusOK( status ) )
			status = cryptSignCert( cryptRequest, cryptContext );
		if( cryptKeyset != CRYPT_UNUSED )
			{
			if( cryptStatusError( \
					cryptAddPrivateKey( cryptKeyset, cryptContext,
										TEST_PRIVKEY_PASSWORD ) ) )
				return( FALSE );
			}
		cryptDestroyContext( cryptContext );
		}
	if( cryptStatusError( status ) )
		{
		printf( "Creation of CMP request failed with error code %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}

	return( cryptRequest );
	}

static int createCmpRevRequest( const CRYPT_CERTIFICATE cryptCert )
	{
	CRYPT_CERTIFICATE cryptRequest;
	int status;

	/* Create the CMP (CRMF) revocation request */
	status = cryptCreateCert( &cryptRequest, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_REQUEST_REVOCATION );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptRequest, CRYPT_CERTINFO_CERTIFICATE,
									cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "Creation of CMP revocation request failed with error code "
				"%d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	return( cryptRequest );
	}

static int createCmpSession( const CRYPT_CONTEXT cryptCACert,
							 const char *server, const char *user,
							 const char *password,
							 const CRYPT_CONTEXT privateKey,
							 const BOOLEAN isRevocation,
							 const BOOLEAN isUpdate, 
							 const BOOLEAN isPKIBoot )
	{
	CRYPT_SESSION cryptSession;
	int status;

	/* Create the CMP session */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED,
								 CRYPT_SESSION_CMP );
	if( status == CRYPT_ERROR_PARAM3 )	/* CMP session access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSession() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Set up the user and server information.  Revocation requests can be
	   signed or MACd so we handle either.  When requesting a cert using a
	   signed request (i.e.not an initialisation request) we use an update
	   since we're reusing the previously-generated cert data to request a
	   new one and some CAs won't allow this reuse for a straight request
	   but require explicit use of an update request */
	if( privateKey != CRYPT_UNUSED )
		{
		status = cryptSetAttribute( cryptSession, 
									CRYPT_SESSINFO_CMP_REQUESTTYPE,
									isRevocation ? \
										CRYPT_REQUESTTYPE_REVOCATION : \
									isUpdate ? \
										CRYPT_REQUESTTYPE_KEYUPDATE : \
										CRYPT_REQUESTTYPE_CERTIFICATE );
		if( cryptStatusOK( status ) )
			status = cryptSetAttribute( cryptSession,
										CRYPT_SESSINFO_PRIVATEKEY,
										privateKey );
		}
	else
		{
		status = cryptSetAttributeString( cryptSession,
										  CRYPT_SESSINFO_USERNAME, user,
										  strlen( user ) );
		if( cryptStatusOK( status ) )
			status = cryptSetAttribute( cryptSession, 
										CRYPT_SESSINFO_CMP_REQUESTTYPE,
										isPKIBoot ? \
											CRYPT_REQUESTTYPE_PKIBOOT : \
										isRevocation ? \
											CRYPT_REQUESTTYPE_REVOCATION : \
											CRYPT_REQUESTTYPE_INITIALISATION );
		if( cryptStatusOK( status ) )
			status = cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_PASSWORD, password,
									strlen( password ) );
		}
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptSession,
										CRYPT_SESSINFO_SERVER_NAME, server,
										strlen( server ) );
	if( cryptStatusOK( status ) && cryptCACert != CRYPT_UNUSED )
		status = cryptSetAttribute( cryptSession, 
									CRYPT_SESSINFO_CACERTIFICATE, 
									cryptCACert );
	if( cryptStatusError( status ) )
		{
		printf( "Addition of session information failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	return( cryptSession );
	}

/* Request a particular cert type */

static int requestCert( const char *description, const CA_INFO *caInfoPtr,
						const char *readKeysetName,  
						const char *writeKeysetName,
						const CERT_DATA *requestData,
						const CRYPT_ALGO_TYPE cryptAlgo,
						const CRYPT_CONTEXT cryptCACert, 
						const BOOLEAN isPKIBoot,
						CRYPT_CERTIFICATE *issuedCert )
	{
	CRYPT_SESSION cryptSession;
	CRYPT_KEYSET cryptKeyset = CRYPT_UNUSED;
	CRYPT_CONTEXT privateKey = CRYPT_UNUSED;
	CRYPT_CERTIFICATE cryptCmpRequest, cryptCmpResponse;
	const BOOLEAN useExistingKey = ( requestData == NULL ) ? TRUE : FALSE;
	int status;

#ifdef SERVER_PROVIDES_DN
	printf( "Testing %s processing with absent subject DN...\n", description );
#else
	printf( "Testing %s processing...\n", description );
#endif /* SERVER_PROVIDES_DN */

	/* Read the key needed to request a new cert from a keyset if necessary,
	   and create a keyset to save a new key to if required.  We have to do
	   the write last in case the read and write keyset are the same */
	if( readKeysetName != NULL )
		{
		status = getPrivateKey( &privateKey, readKeysetName,
								USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't get private key to request new certificate, "
					"status = %d.\n", status );
			return( FALSE );
			}
		}
	if( writeKeysetName != NULL )
		{
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
								  CRYPT_KEYSET_FILE, writeKeysetName,
								  CRYPT_KEYOPT_CREATE );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't create keyset to store certificate to, "
					"status = %d.\n", status );
			return( FALSE );
			}
		}

	/* Create the CMP session */
	cryptSession = createCmpSession( cryptCACert, caInfoPtr->url,
									 caInfoPtr->user, caInfoPtr->password,
									 privateKey, FALSE, useExistingKey,
									 isPKIBoot );
	if( cryptSession <= 0 )
		{
		if( cryptKeyset != CRYPT_UNUSED )
			cryptKeysetClose( cryptKeyset );
		return( cryptSession );
		}

	/* Set up the request.  Some CAs explicitly disallow multiple dissimilar 
	   certs to exist for the same key (in fact for non-test servers other 
	   CAs probably enforce this as well) but generating a new key for each 
	   request is time-consuming so we only do it if it's enforced by the 
	   CA */
	if( !isPKIBoot )
		{
#if ( CA_NO == 1 ) || ( CA_NO == 7 ) || ( CA_NO == 10 )
		cryptCmpRequest = createCmpRequest( requestData,
								useExistingKey ? privateKey : CRYPT_UNUSED,
								cryptAlgo, FALSE, cryptKeyset );
#else
		KLUDGE_WARN( "fixed key for request" );
		cryptCmpRequest = createCmpRequest( requestData,
								useExistingKey ? privateKey : CRYPT_UNUSED,
								cryptAlgo, TRUE, cryptKeyset );
#endif /* cryptlib and Initech won't allow two certs for same key */
		if( !cryptCmpRequest )
			return( FALSE );
		if( privateKey != CRYPT_UNUSED )
			cryptDestroyContext( privateKey );
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_REQUEST,
									cryptCmpRequest );
		cryptDestroyCert( cryptCmpRequest );
		if( cryptStatusError( status ) )
			{
			printf( "cryptSetAttribute() failed with error code %d, line %d.\n",
					status, __LINE__ );
			return( FALSE );
			}
		}

	/* Activate the session */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
	if( cryptStatusError( status ) )
		{
		if( cryptKeyset != CRYPT_UNUSED )
			cryptKeysetClose( cryptKeyset );
		printExtError( cryptSession, "Attempt to activate CMP client session",
					   status, __LINE__ );
		cryptDestroySession( cryptSession );
		if( status == CRYPT_ERROR_OPEN || status == CRYPT_ERROR_READ )
			{
			/* These servers are constantly appearing and disappearing so if
			   we get a straight connect error we don't treat it as a serious
			   failure */
			puts( "  (Server could be down, faking it and continuing...)\n" );
			return( CRYPT_ERROR_FAILED );
			}
		if( status == CRYPT_ERROR_FAILED )
			{
			/* A general failed response is more likely to be due to the
			   server doing something unexpected than a cryptlib problem so
			   we don't treat it as a fatal error */
			puts( "  (This is more likely to be an issue with the server than "
				  "with cryptlib,\n   faking it and continuing...)\n" );
			return( CRYPT_ERROR_FAILED );
			}
		return( FALSE );
		}

	/* If it's a PKIBoot, which just sets (implicitly) trusted certs, we're 
	   done */
	if( isPKIBoot )
		{
		cryptDestroySession( cryptSession );
		return( TRUE );
		}

	/* Obtain the response information */
	status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_RESPONSE,
								&cryptCmpResponse );
	cryptDestroySession( cryptSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetAttribute() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
#if ( CA_NO != 1 ) && ( CA_NO != 10 )
	puts( "Returned certificate details are:" );
	printCertInfo( cryptCmpResponse );
#endif /* Keep the cryptlib results on one screen */
	if( cryptKeyset != CRYPT_UNUSED )
		{
		status = cryptAddPublicKey( cryptKeyset, cryptCmpResponse );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't write certificate to keyset, status = %d.\n",
					status );
			return( FALSE );
			}
		cryptKeysetClose( cryptKeyset );
		}
	if( issuedCert != NULL )
		*issuedCert = cryptCmpResponse;
	else
		cryptDestroyCert( cryptCmpResponse );

	/* Clean up */
	printf( "%s processing succeeded.\n\n", description );
	return( TRUE );
	}

/* Revoke a previously-issued cert */

static int revokeCert( const char *description, const CA_INFO *caInfoPtr,
					   const char *keysetName,
					   const CRYPT_CERTIFICATE certToRevoke,
					   const CRYPT_CONTEXT cryptCACert,
					   const BOOLEAN signRequest )
	{
	CRYPT_SESSION cryptSession;
	CRYPT_CONTEXT privateKey = CRYPT_UNUSED;
	CRYPT_CERTIFICATE cryptCmpRequest, cryptCert = certToRevoke;
	int status;

	printf( "Testing %s revocation processing...\n", description );

	/* Get the cert to revoke if necessary.  In some cases the server won't
	   accept a revocation password, so we have to get the private key as
	   well to sign the request */
	if( signRequest || cryptCert == CRYPT_UNUSED )
		{
		CRYPT_KEYSET cryptKeyset;

		status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
								  CRYPT_KEYSET_FILE, keysetName,
								  CRYPT_KEYOPT_READONLY );
		if( cryptStatusOK( status ) && signRequest )
			status = getPrivateKey( &privateKey, keysetName,
									USER_PRIVKEY_LABEL,
									TEST_PRIVKEY_PASSWORD );
		if( cryptStatusOK( status ) && cryptCert == CRYPT_UNUSED )
			status = cryptGetPublicKey( cryptKeyset, &cryptCert,
										CRYPT_KEYID_NAME,
										USER_PRIVKEY_LABEL );
		cryptKeysetClose( cryptKeyset );
		if( cryptStatusError( status ) )
			{
			puts( "Couldn't fetch certificate/key to revoke.\n" );
			return( FALSE );
			}
		}

	/* Create the CMP session and revocation request */
	cryptSession = createCmpSession( cryptCACert, caInfoPtr->url,
									 caInfoPtr->user, caInfoPtr->password,
									 privateKey, TRUE, FALSE, FALSE );
	if( privateKey != CRYPT_UNUSED )
		cryptDestroyContext( privateKey );
	if( cryptSession <= 0 )
		return( cryptSession );
	cryptCmpRequest = createCmpRevRequest( cryptCert );
	if( !cryptCmpRequest )
		return( FALSE );

	/* Set up the request and activate the session */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_REQUEST,
								cryptCmpRequest );
	cryptDestroyCert( cryptCmpRequest );
	if( cryptStatusError( status ) )
		{
		printf( "cryptSetAttribute() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptSession, "Attempt to activate CMP client session",
					   status, __LINE__ );
		cryptDestroySession( cryptSession );
		if( cryptCert != certToRevoke )
			cryptDestroyCert( cryptCert );
		if( status == CRYPT_ERROR_OPEN || status == CRYPT_ERROR_READ )
			{
			/* These servers are constantly appearing and disappearing so if
			   we get a straight connect error we don't treat it as a serious
			   failure */
			puts( "  (Server could be down, faking it and continuing...)\n" );
			return( CRYPT_ERROR_FAILED );
			}
		if( status == CRYPT_ERROR_FAILED )
			{
			/* A general failed response is more likely to be due to the
			   server doing something unexpected than a cryptlib problem so
			   we don't treat it as a fatal error */
			puts( "  (This is more likely to be an issue with the server than "
				  "with cryptlib,\n   faking it and continuing...)\n" );
			return( CRYPT_ERROR_FAILED );
			}
		return( FALSE );
		}

	/* Clean up */
	if( cryptCert != certToRevoke )
		cryptDestroyCert( cryptCert );
	cryptDestroySession( cryptSession );
	printf( "%s processing succeeded.\n\n", description );
	return( TRUE );
	}

/* Test the full range of CMP functionality.  This performs the following
   tests:

	RSA sign:
		ir + ip + reject (requires cmp.c mod)
		ir + ip + certconf + pkiconf
		kur + kup + certconf + pkiconf
		cr + cp + certconf + pkiconf (not performed since same as kur)
		rr + rp (of ir cert)
		rr + rp (of kur cert)
	RSA encr.:
		ir + ip + reject (requires cmp.c mod)
		ir + ip + certconf + pkiconf
		rr + rp (of ir cert)
	DSA:
		cr + cp + certconf + pkiconf (success implies that ir/kur/rr
						works since they've already been tested for RSA) */

static int connectCMP( const BOOLEAN usePKIBoot )
	{
	CRYPT_CERTIFICATE cryptCACert = CRYPT_UNUSED, cryptCert;
	BYTE readFileName[ BUFFER_SIZE ], writeFileName[ BUFFER_SIZE ];
#if ( CA_NO == 1 ) || ( CA_NO == 10 )
	CA_INFO cryptlibCAInfo, *caInfoPtr = &cryptlibCAInfo;
  #ifdef TEST_IR
	char userID[ 64 ], issuePW[ 64 ];
  #endif /* TEST_IR */
#else
	const CA_INFO *caInfoPtr = &caInfo[ CA_NO ];
#endif /* cryptlib */
	int status;

#if ( CA_NO == 1 ) || ( CA_NO == 10 )
	/* Set up the fixed info in the CA info record */
	memcpy( &cryptlibCAInfo, &caInfo[ CA_NO ], sizeof( CA_INFO ) );
	cryptlibCAInfo.name = "cryptlib";

  #ifndef TEST_IR
	/* If we're not doing an initialisation request (which fetches user info 
	   for the request), make sure that the required user info is present.
	   If it isn't, cryptlib's CA auditing will detect a request from a 
	   nonexistant user and refuse to issue a certificate */
	status = getPkiUserInfo( NULL, NULL, NULL );
	if( cryptStatusError( status ) )
		{
		puts( "CA certificate store doesn't contain the PKI user "
			  "information needed to\nauthenticate certificate issue "
			  "operations, can't perform CMP test." );
		return( FALSE );
		}
  #endif /* TEST_IR */
#endif /* cryptlib CA_NO == 1 or CA_NO == 10 */

	/* Get the cert of the CA who will issue the cert unless we're doing a 
	   PKIBoot, in which case the cert is obtained during the PKIBoot 
	   process */
#if ( CA_NO != 1 ) && ( CA_NO != 10 )
	printf( "Using the %s CMP server.\n", caInfoPtr->name );
#endif /* !cryptlib */
#if CA_NO != 10
	status = importCertFromTemplate( &cryptCACert, CMP_CA_FILE_TEMPLATE, 
									 CA_NO );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't get CMP CA certificate, status = %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
#endif /* PKIBoot */

	/* Test each cert request type: Initialisation, cert request using cert
	   from initialisation for authentication, key update of cert from
	   initialisation, revocation of both certs.  We insert a 1s delay 
	   between requests to give the server time to recycle */

	/* Initialisation request */
#ifdef TEST_IR
  #if ( CA_NO == 1 ) || ( CA_NO == 10 )
	/* cryptlib implements per-user (rather than shared interop) IDs and
	   passwords so we need to read the user ID and password information
	   before we can perform any operations */
	status = getPkiUserInfo( userID, issuePW, NULL );
	if( cryptStatusError( status ) )
		{
#if CA_NO != 10
		cryptDestroyCert( cryptCACert );
#endif /* PKIBoot */
		return( ( status == CRYPT_ERROR_NOTAVAIL ) ? TRUE : FALSE );
		}

	/* Set up the variable info in the CA info record */
	cryptlibCAInfo.user = userID;
	cryptlibCAInfo.password = issuePW;
  #endif /* cryptlib CA_NO == 1 or CA_NO == 10 */
	/* Initialisation.  We define REVOKE_FIRST_CERT to indicate that we can
	   revoke this one later on */
	#define REVOKE_FIRST_CERT
	filenameFromTemplate( writeFileName, CMP_PRIVKEY_FILE_TEMPLATE, 1 );
	status = requestCert( "RSA signing cert.init.request", caInfoPtr, NULL, 
						  usePKIBoot ? NULL : writeFileName,
#ifdef SERVER_PROVIDES_DN
						  cmpRsaSignRequestNoDNData, 
#else
						  cmpRsaSignRequestData, 
#endif /* SERVER_PROVIDES_DN */
						  CRYPT_ALGO_RSA, cryptCACert, usePKIBoot, 
						  &cryptCert );
	if( status != TRUE )
		{
		/* If this is the self-test and there's a non-fatal error, make sure
		   we don't fail with a CRYPT_ERROR_INCOMPLETE when we're finished */
		cryptDestroyCert( cryptCACert );
		return( status );
		}
	if( usePKIBoot )
		{
		/* If we're testing the PKIBoot capability, there's only a single 
		   request to process */
		cryptDestroyCert( cryptCACert );
		return( TRUE );
		}
	delayThread( 1 );
#endif /* TEST_IR */

	/* Cert request.  We have to perform this test before the kur since some
	   CAs implicitly revoke the cert being replaced, which means we can't
	   use it to authenticate requests any more once the kur has been 
	   performed */
#ifdef TEST_CR
	/* We define REVOKE_SECOND_CERT to indicate that we can revoke this one
	   later on alongside the ir/kur'd cert, and save a copy to a file for
	   later use */
	#define REVOKE_SECOND_CERT
	filenameFromTemplate( readFileName, CMP_PRIVKEY_FILE_TEMPLATE, 1 );
	filenameFromTemplate( writeFileName, CMP_PRIVKEY_FILE_TEMPLATE, 2 );
	status = requestCert( "RSA signing certificate request", caInfoPtr,
						  readFileName, writeFileName, cmpRsaSignRequestData,
						  CRYPT_ALGO_RSA, cryptCACert, FALSE, NULL );
	if( status != TRUE )
		{
  #if defined( TEST_IR )
		cryptDestroyCert( cryptCert );
  #endif /* TEST_IR || TEST_KUR */
		cryptDestroyCert( cryptCACert );
		return( status );
		}
	delayThread( 1 );
#endif /* TEST_CR */

	/* Key update request */
#ifdef TEST_KUR
  #ifdef TEST_IR
	/* We just created the cert, delete it so we can replace it with the
	   updated form */
	cryptDestroyCert( cryptCert );
  #endif /* TEST_IR */

	/* If it's a CA that implicitly revokes the cert being replaced (in
	   which case tracking things gets a bit too complicated since we now
	   need to use the updated rather than original cert to authenticate the
	   request) we just leave it unrevoked (the first cert is always
	   revoked) */
  #if ( CA_NO == 1 ) || ( CA_NO == 10 )
	#undef REVOKE_FIRST_CERT
  #endif /* cryptlib */

	/* Key update */
	filenameFromTemplate( readFileName, CMP_PRIVKEY_FILE_TEMPLATE, 1 );
	status = requestCert( "RSA signing certificate update", caInfoPtr,
						  readFileName, NULL, NULL, CRYPT_UNUSED,
						  cryptCACert, FALSE, &cryptCert );
	if( status != TRUE )
		{
		cryptDestroyCert( cryptCACert );
		return( status );
		}
	delayThread( 1 );
#endif /* TEST_KUR */
#if 0
	/* DSA cert request.  We have to get this now because we're about to
	   revoke the cert we're using to sign the requests */
	filenameFromTemplate( readFileName, CMP_PRIVKEY_FILE_TEMPLATE, 1 );
	status = requestCert( "DSA certificate", caInfoPtr, readFileName, NULL,
						  cmpDsaRequestData, CRYPT_ALGO_DSA, cryptCACert,
						  FALSE, NULL );
	if( status != TRUE )
		return( status );
	delayThread( 1 );
#endif /* 0 */
#if 0
	/* Encryption-only cert request.  This test requires a change in
	   certsign.c because when creating a cert request cryptlib always
	   allows signing for the request even if it's an encryption-only key
	   (this is required for PKCS #10, see the comment in the kernel code).
	   Because of this a request will always appear to be associated with a
	   signature-enabled key so it's necessary to make a code change to
	   disallow this.  Disallowing sigs for encryption-only keys would break
	   PKCS #10 since it's then no longer possible to create the self-signed
	   request, this is a much bigger concern than CMP.  Note that this 
	   functionality is tested by the PnP PKI test, which creates the 
	   necessary encryption-only requests internally and can do things that
	   we can't do from the outside */
	status = requestCert( "RSA encryption certificate", caInfoPtr,
						  readFileName, writeFileName, cmpRsaEncryptRequestData,
						  CRYPT_ALGO_RSA, cryptCACert, FALSE, NULL );
	if( status != TRUE )
		return( status );
	delayThread( 1 );
#endif /* 0 */

	/* Revocation request */
#ifdef TEST_RR
	filenameFromTemplate( readFileName, CMP_PRIVKEY_FILE_TEMPLATE, 1 );
  #ifdef REVOKE_FIRST_CERT
	#if CA_NO == 2
	status = revokeCert( "RSA initial/updated certificate", caInfoPtr,
						 readFileName, cryptCert, cryptCACert, TRUE );
	#else
	status = revokeCert( "RSA initial/updated certificate", caInfoPtr,
						 readFileName, cryptCert, cryptCACert, FALSE );
	#endif /* Certicom requires signed request */
	cryptDestroyCert( cryptCert );
	delayThread( 1 );
  #elif !defined( TEST_KUR ) || ( ( CA_NO != 1 ) && ( CA_NO != 10 ) )
	/* We didn't issue the first cert in this run, try revoking it from
	   the cert stored in the key file unless we're talking to a CA that
	   implicitly revokes the cert being replaced during a kur */
	status = revokeCert( "RSA initial/updated certificate", caInfoPtr,
						 readFileName, CRYPT_UNUSED, cryptCACert, TRUE );
  #else
	/* This is a kur'd cert for which the original has been implicitly
	   revoked, we can't do much else with it */
	cryptDestroyCert( cryptCert );
  #endif /* REVOKE_FIRST_CERT */
	if( status != TRUE )
		{
		cryptDestroyCert( cryptCACert );
		return( status );
		}
  #ifdef REVOKE_SECOND_CERT
	/* We requested a second cert, revoke that too.  Note that we have to
	   sign this with the second cert since the first one may have just been
	   revoked */
	filenameFromTemplate( readFileName, CMP_PRIVKEY_FILE_TEMPLATE, 2 );
	status = revokeCert( "RSA signing certificate", caInfoPtr, readFileName,
						 CRYPT_UNUSED, cryptCACert, TRUE );
	if( status != TRUE )
		{
		cryptDestroyCert( cryptCACert );
		return( status );
		}
  #endif /* REVOKE_SECOND_CERT */
#endif /* TEST_RR */

	/* Clean up */
	cryptDestroyCert( cryptCACert );
	return( TRUE );
	}

int testSessionCMP( void )
	{
	return( connectCMP( FALSE ) );
	}

/* Test the plug-and-play PKI functionality */

static int connectPNPPKI( void )
	{
	CRYPT_SESSION cryptSession;
	CRYPT_KEYSET cryptKeyset;
	char userID[ 64 ], issuePW[ 64 ];
	int status;

	/* Create the CMP session */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED,
								 CRYPT_SESSION_CMP );
	if( status == CRYPT_ERROR_PARAM3 )	/* CMP session access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSession() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Create the keyset to contain the keys */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
							  CRYPT_KEYSET_FILE, PNP_PRIVKEY_FILE,
							  CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Get information needed for enrolment */
	status = getPkiUserInfo( userID, issuePW, NULL );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ERROR_NOTAVAIL ) ? TRUE : FALSE );

	/* Set up the information we need for the plug-and-play PKI process */
	status = cryptSetAttributeString( cryptSession,
									  CRYPT_SESSINFO_USERNAME, userID,
									  strlen( userID ) );
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptSession,
										  CRYPT_SESSINFO_PASSWORD,
										  issuePW, strlen( issuePW ) );
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptSession,
										  CRYPT_SESSINFO_SERVER_NAME,
										  caInfo[ 10 ].url, 
										  strlen( caInfo[ 10 ].url ) );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptSession,
									CRYPT_SESSINFO_CMP_PRIVKEYSET,
									cryptKeyset );
	cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "Addition of session information failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Activate the session */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptSession, "Attempt to activate plug-and-play PKI "
					   "client session", status, __LINE__ );
		cryptDestroySession( cryptSession );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroySession( cryptSession );
	return( TRUE );
	}

int testSessionPNPPKI( void )
	{
	return( connectPNPPKI() );
	}

/* Test the CMP server */

static int cmpServerSingleIteration( const CRYPT_CONTEXT cryptPrivateKey,
									 const CRYPT_KEYSET cryptCertStore )
	{
	CRYPT_SESSION cryptSession;
	int status;

	/* Create the CMP session and add the CA key and cert store */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED,
								 CRYPT_SESSION_CMP_SERVER );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: cryptCreateSession() failed with error code %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptSession,
							CRYPT_SESSINFO_PRIVATEKEY, cryptPrivateKey );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptSession,
							CRYPT_SESSINFO_KEYSET, cryptCertStore );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptSession, "SVR: cryptSetAttribute()", 
							   status, __LINE__ ) );
	if( !setLocalConnect( cryptSession, 80 ) )
		return( FALSE );

	/* Activate the session */
	status = activatePersistentServerSession( cryptSession, TRUE );
	if( cryptStatusError( status ) )
		return( extErrorExit( cryptSession, "SVR: Attempt to activate CMP "
							  "server session", status, __LINE__ ) );

	/* We processed the request, clean up */
	cryptDestroySession( cryptSession );
	return( TRUE );
	}

static int cmpServerInit( CRYPT_CONTEXT *cryptPrivateKey,
						  CRYPT_KEYSET *cryptCertStore )
	{
	int status;

	/* Get the cert store and server private key to use with the session.
	   Before we add the store we perform a cleanup action to remove any
	   leftover requests from previous runs */
	status = cryptKeysetOpen( cryptCertStore, CRYPT_UNUSED,
							  CERTSTORE_KEYSET_TYPE, CERTSTORE_KEYSET_NAME,
							  CRYPT_KEYOPT_CREATE );
	if( status == CRYPT_ERROR_PARAM3 )
		{
		/* This type of keyset access isn't available, return a special error
		   code to indicate that the test wasn't performed, but that this
		   isn't a reason to abort processing */
		puts( "SVR: No certificate store available, aborting CMP server "
			  "test.\n" );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	if( status == CRYPT_ERROR_DUPLICATE )
		status = cryptKeysetOpen( cryptCertStore, CRYPT_UNUSED,
								  CERTSTORE_KEYSET_TYPE, CERTSTORE_KEYSET_NAME,
								  CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: cryptKeysetOpen() failed with error code %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}
	cryptCACertManagement( NULL, CRYPT_CERTACTION_CLEANUP, *cryptCertStore,
						   CRYPT_UNUSED, CRYPT_UNUSED );
	status = getPrivateKey( cryptPrivateKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: CA private key read failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	
	return( TRUE );
	}

int testSessionCMPServer( void )
	{
	CRYPT_SESSION cryptSession;
	CRYPT_CONTEXT cryptCAKey;
	CRYPT_KEYSET cryptCertStore;
	int caCertTrusted, i, status;

	puts( "SVR: Testing CMP server session..." );

	/* Perform a test create of a CMP server session to verify that we can
	   do this test */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED,
								 CRYPT_SESSION_CMP_SERVER );
	if( status == CRYPT_ERROR_PARAM3 )	/* CMP session access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: cryptCreateSession() failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	cryptDestroySession( cryptSession );

	/* Get the information needed by the server */
	if( !cmpServerInit( &cryptCAKey, &cryptCertStore ) )
		return( FALSE );

	/* Make the CA key trusted for PKIBoot functionality */
	cryptGetAttribute( cryptCAKey, CRYPT_CERTINFO_TRUSTED_IMPLICIT, 
					   &caCertTrusted );
	cryptSetAttribute( cryptCAKey, CRYPT_CERTINFO_TRUSTED_IMPLICIT, 1 );

	/* Run the server several times to handle the different requests */
	for( i = 0; i < NO_CA_REQUESTS; i++ )
		{
		printf( "SVR: Running server iteration %d.\n", i + 1 );
		if( !cmpServerSingleIteration( cryptCAKey, cryptCertStore ) )
			break;
		}
	if( i == 0 )
		/* None of the requests succeeded */
		return( FALSE );
	printf( "SVR: %d of %d server requests were processed.\n", i, 
			NO_CA_REQUESTS );

	/* Issue a CRL to make sure that the revocation was performed correctly.
	   We do this now because the cert management self-test can't easily
	   perform the check because it requires a CMP-revoked cert in order to
	   function */
	if( i == NO_CA_REQUESTS )
		{
		CRYPT_CERTIFICATE cryptCRL;
		int noEntries = 0;

		/* Issue the CRL */
		status = cryptCACertManagement( &cryptCRL, CRYPT_CERTACTION_ISSUE_CRL,
										cryptCertStore, cryptCAKey,
										CRYPT_UNUSED );
		if( cryptStatusError( status ) )
			return( extErrorExit( cryptCertStore, "cryptCACertManagement()", 
								  status, __LINE__ ) );

		/* Make sure that the CRL contains at least one entry */
		if( cryptStatusOK( cryptSetAttribute( cryptCRL,
											  CRYPT_CERTINFO_CURRENT_CERTIFICATE,
											  CRYPT_CURSOR_FIRST ) ) )
			do
				noEntries++;
			while( cryptSetAttribute( cryptCRL,
									  CRYPT_CERTINFO_CURRENT_CERTIFICATE,
									  CRYPT_CURSOR_NEXT ) == CRYPT_OK );
		if( noEntries <= 0 )
			{
			puts( "CRL created from revoked certificate is empty, should "
				  "contain at least one\ncertificate entry." );
			return( FALSE );
			}

		/* Clean up */
		cryptDestroyCert( cryptCRL );
		}

	/* Clean up */
	if( !caCertTrusted )
		cryptSetAttribute( cryptCAKey, CRYPT_CERTINFO_TRUSTED_IMPLICIT, 0 );
	cryptKeysetClose( cryptCertStore );
	cryptDestroyContext( cryptCAKey );

	puts( "SVR: CMP session succeeded.\n" );
	return( TRUE );
	}

/* Perform a client/server loopback test */

#ifdef WINDOWS_THREADS

static int pnppkiServer( const BOOLEAN isPkiBoot )
	{
	CRYPT_CONTEXT cryptPrivateKey;
	CRYPT_KEYSET cryptCertStore;
	int caCertTrusted;

	printf( "SVR: Testing %s server session...\n",
			isPkiBoot ? "PKIBoot" : "plug-and-play PKI" );

	/* Get the information needed by the server */
	if( !cmpServerInit( &cryptPrivateKey, &cryptCertStore ) )
		return( FALSE );

	/* Make the CA key trusted for PKIBoot functionality */
	cryptGetAttribute( cryptPrivateKey, CRYPT_CERTINFO_TRUSTED_IMPLICIT, 
					   &caCertTrusted );
	cryptSetAttribute( cryptPrivateKey, CRYPT_CERTINFO_TRUSTED_IMPLICIT, 1 );

	/* Run the server once to handle the plug-and-play PKI process */
	if( !cmpServerSingleIteration( cryptPrivateKey, cryptCertStore ) )
		return( FALSE );

	/* Clean up */
	if( !caCertTrusted )
		cryptSetAttribute( cryptPrivateKey, 
						   CRYPT_CERTINFO_TRUSTED_IMPLICIT, 0 );
	cryptKeysetClose( cryptCertStore );
	cryptDestroyContext( cryptPrivateKey );

	puts( "SVR: Plug-and-play PKI session succeeded.\n" );
	return( TRUE );
	}

unsigned __stdcall cmpServerThread( void *dummy )
	{
	testSessionCMPServer();
	_endthreadex( 0 );
	return( 0 );
	}

int testSessionCMPClientServer( void )
	{
	HANDLE hThread;
	unsigned threadID;
	int status;

#if ( CA_NO != 1 ) && ( CA_NO != 10 )
	/* Because the code has to handle so many CA-specific peculiarities, we
	   can only perform this test when the CA being used is the cryptlib 
	   CA */
	puts( "Error: The local CMP session test only works with CA_NO == 1 "
		  "or 10." );
	return( FALSE );
#endif /* cryptlib CA */

	/* Start the server and wait for it to initialise (this takes a bit
	   longer than the other servers because we have to work with a cert
	   store so we wait a bit longer than usual) */
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, &cmpServerThread,
										 NULL, 0, &threadID );
	Sleep( 3000 );

	/* Connect to the local server */
	status = connectCMP( FALSE );
	if( WaitForSingleObject( hThread, 15000 ) == WAIT_TIMEOUT )
		{
		puts( "Warning: Server thread is still active due to session "
			  "negotiation failure,\n         this will cause an error "
			  "condition when cryptEnd() is called due\n         to "
			  "resources remaining allocated.  Press a key to continue." );
		getchar();
		}
	CloseHandle( hThread );

	return( status );
	}

unsigned __stdcall cmpPKIBootServerThread( void *dummy )
	{
	pnppkiServer( TRUE );
	_endthreadex( 0 );
	return( 0 );
	}

int testSessionCMPPKIBootClientServer( void )
	{
	HANDLE hThread;
	unsigned threadID;
	int status;

#if ( CA_NO != 1 ) && ( CA_NO != 10 )
	/* Because the code has to handle so many CA-specific peculiarities, we
	   can only perform this test when the CA being used is the cryptlib 
	   CA */
	puts( "Error: The local CMP session test only works with CA_NO == 1 "
		  "or 10." );
	return( FALSE );
#endif /* cryptlib CA */

	/* Start the server and wait for it to initialise (this takes a bit
	   longer than the other servers because we have to work with a cert
	   store so we wait a bit longer than usual) */
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, &cmpPKIBootServerThread,
										 NULL, 0, &threadID );
	Sleep( 3000 );

	/* Connect to the local server with PKIBoot enabled */
	status = connectCMP( TRUE );
	if( WaitForSingleObject( hThread, 15000 ) == WAIT_TIMEOUT )
		{
		puts( "Warning: Server thread is still active due to session "
			  "negotiation failure,\n         this will cause an error "
			  "condition when cryptEnd() is called due\n         to "
			  "resources remaining allocated.  Press a key to continue." );
		getchar();
		}
	CloseHandle( hThread );

	return( status );
	}

unsigned __stdcall cmpPnPPKIServerThread( void *dummy )
	{
	pnppkiServer( FALSE );
	_endthreadex( 0 );
	return( 0 );
	}

int testSessionPNPPKIClientServer( void )
	{
	HANDLE hThread;
	unsigned threadID;
	int status;

	/* Start the server and wait for it to initialise (this takes a bit
	   longer than the other servers because we have to work with a cert
	   store so we wait a bit longer than usual) */
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, &cmpPnPPKIServerThread,
										 NULL, 0, &threadID );
	Sleep( 3000 );

	/* Connect to the local server with PKIBoot enabled */
	status = connectPNPPKI();
	if( WaitForSingleObject( hThread, 15000 ) == WAIT_TIMEOUT )
		{
		puts( "Warning: Server thread is still active due to session "
			  "negotiation failure,\n         this will cause an error "
			  "condition when cryptEnd() is called due\n         to "
			  "resources remaining allocated.  Press a key to continue." );
		getchar();
		}
	CloseHandle( hThread );

	return( status );
	}
#endif /* WINDOWS_THREADS */
