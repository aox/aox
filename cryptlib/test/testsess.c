/****************************************************************************
*																			*
*					  cryptlib Secure Session Test Routines					*
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

/* Uncomment the following to ask the user for a password rather than using
   a hardcoded password when testing against live accounts */

/* #define USER_SUPPLIED_PASSWORD	/**/
#ifdef USER_SUPPLIED_PASSWORD
  #undef SSH2_SERVER_NAME
  #undef SSH_USER_NAME
  #define SSH2_SERVER_NAME	"testserver"
  #define SSH_USER_NAME		"testname"
#endif /* USER_SUPPLIED_PASSWORD */

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Print information in the peer we're talking to */

static void printConnectInfo( const CRYPT_SESSION cryptSession )
	{
	time_t theTime;
	char serverName[ 128 ];
	int serverNameLength, serverPort, status;

	time( &theTime );
	status = cryptGetAttributeString( cryptSession, CRYPT_SESSINFO_CLIENT_NAME,
									  serverName, &serverNameLength );
	if( cryptStatusError( status ) )
		return;
	serverName[ serverNameLength ] = '\0';
	cryptGetAttribute( cryptSession, CRYPT_SESSINFO_CLIENT_PORT, &serverPort );
	printf( "SVR: Connect attempt from %s, port %d, on %s", serverName, 
			serverPort, ctime( &theTime ) );
	}

/* Set up a client/server to connect locally.  For the client his simply
   tells it where to connect, for the server this binds it to the local
   address so we don't inadvertently open up outside ports (admittedly
   they can't do much except run the hardcoded self-test, but it's better
   not to do this at all) */

static BOOLEAN setLocalConnect( const CRYPT_SESSION cryptSession,
								const int port )
	{
	int status;

	status = cryptSetAttributeString( cryptSession,
									  CRYPT_SESSINFO_SERVER_NAME,
									  "localhost", 9 );
#ifdef __UNIX__
	/* If we're running under Unix, set the port to a nonprivileged one so
	   we don't have to run as root.  For anything other than very low-
	   numbered ports (e.g. SSH), the way we determine the port is to repeat 
	   the first digit, so e.g. TSA on 318 becomes 3318, this seems to be 
	   the method most commonly used */
	if( cryptStatusOK( status ) && port < 1024 )
		{
		if( port < 100 )
			status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_SERVER_PORT,
										port + 4000 );
		else
			status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_SERVER_PORT,
										( ( port / 100 ) * 1000 ) + port );
		}
#endif /* __UNIX__ */
	if( cryptStatusError( status ) )
		{
		printf( "cryptSetAttribute/AttributeString() failed with error code "
				"%d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

/* Test the ability to parse URLs */

static const struct {
	const char *url;			/* Server URL */
	const char *name;			/* Parsed server name */
	const int port;				/* Parsed server port */
	const char *userInfo;		/* Parsed user info */
	} urlParseInfo[] = {
	/* IP address forms */
	{ "1.2.3.4", "1.2.3.4", 0, NULL },
	{ "1.2.3.4:80", "1.2.3.4", 80, NULL },
	{ "user@1.2.3.4", "1.2.3.4", 0, "user" },
	{ "[1:2:3:4]", "1:2:3:4", 0, NULL },
	{ "[1:2:3:4]:80", "1:2:3:4", 80, NULL },
	{ "user@[1:2:3:4]", "1:2:3:4", 0, "user" },

	/* General URI forms */
	{ "www.server.com", "www.server.com", 0, NULL },
	{ "www.server.com:80", "www.server.com", 80, NULL },
	{ "http://www.server.com:80", "www.server.com", 80, NULL },
	{ "http://user@www.server.com:80", "www.server.com", 80, "user" },

	/* Spurious whitespace */
	{ "  www.server.com  :   80 ", "www.server.com", 80, NULL },
	{ "http:// user  @ www.server.com  :   80 ", "www.server.com", 80, "user" },
	{ NULL, NULL, 0, NULL }
	};

int testSessionUrlParse( void )
	{
	CRYPT_SESSION cryptSession;
	int i, status;

	puts( "Testing session URL parsing..." );

	/* Create a session of the most generic type */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED, CRYPT_SESSION_SSL );
	if( status == CRYPT_ERROR_PARAM3 )	/* SSL session access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSession() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Set various URLs as the server name and retrieve the parsed form */
	for( i = 0; urlParseInfo[ i ].url != NULL; i++ )
		{
		char nameBuffer[ 256 ], userInfoBuffer[ 256 ];
		int lengthLength, userInfoLength, port;

		/* Clear any leftover attributes from previous tests */
		cryptDeleteAttribute( cryptSession, CRYPT_SESSINFO_SERVER_NAME );
		cryptDeleteAttribute( cryptSession, CRYPT_SESSINFO_SERVER_PORT );
		cryptDeleteAttribute( cryptSession, CRYPT_SESSINFO_USERNAME );

		/* Set the URL */
		status = cryptSetAttributeString( cryptSession, 
										  CRYPT_SESSINFO_SERVER_NAME,
										  urlParseInfo[ i ].url,
										  strlen( urlParseInfo[ i ].url ) );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't set URL '%s', line %d.\n", 
					urlParseInfo[ i ].url, __LINE__ );
			return( FALSE );
			}
		
		/* Make sure the parsed form is OK */
		status = cryptGetAttributeString( cryptSession, 
										  CRYPT_SESSINFO_SERVER_NAME,
										  nameBuffer, &lengthLength );
		if( cryptStatusOK( status ) && urlParseInfo[ i ].port )
			status = cryptGetAttribute( cryptSession, 
										CRYPT_SESSINFO_SERVER_PORT, &port );
		if( cryptStatusOK( status ) && urlParseInfo[ i ].userInfo != NULL )
			status = cryptGetAttributeString( cryptSession, 
											  CRYPT_SESSINFO_USERNAME,
											  userInfoBuffer, 
											  &userInfoLength );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't get parsed URL info for '%s', line %d.\n", 
					urlParseInfo[ i ].url, __LINE__ );
			return( FALSE );
			}
		if( memcmp( nameBuffer, urlParseInfo[ i ].name, lengthLength ) || \
			( urlParseInfo[ i ].port && port != urlParseInfo[ i ].port ) || \
			( urlParseInfo[ i ].userInfo != NULL && \
			  memcmp( userInfoBuffer, urlParseInfo[ i ].userInfo, 
			  userInfoLength ) ) )
			{
			printf( "Parsed URL info for '%s' is incorrect, line %d.\n", 
					urlParseInfo[ i ].url, __LINE__ );
			return( FALSE );
			}
		}

	/* Clean up */
	status = cryptDestroySession( cryptSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroySession() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	puts( "Session URL parsing succeeded.\n" );
	return( TRUE );
	}

/****************************************************************************
*																			*
*								SSH Routines Test							*
*																			*
****************************************************************************/

/* There are various servers running that we can use for testing, the
   following remapping allows us to switch between them.  Notes:

	Server 1: Local loopback.
	Server 2: Sends extraneous lines of text before the SSH ID string 
			  (technically allowed by the RFC, but probably not in the way 
			  that it's being used here).
	Server 3: Reference ssh.com implementation.
	Server 4: Reference OpenSSH implementation 

   To test local -> remote/remote -> local forwarding: 

	ssh localhost -v -l test -pw test -L 110:pop3.test.com:110
	ssh localhost -v -l test -pw test -R 110:pop3.test.com:110

  For test purposes we connect to the OpenSSH server for the SSHv2 test 
  because this is the most frequently-used one around, so maintaining 
  compatibility with it whenever it changes is important.  Using it for test 
  connects is slightly antisocial but in practice few people seem to run the 
  self-test and we never get past the initial handshake phase so it shouldn't 
  be a big deal.  Testing SSHv1 is a bit tricky since there are few of these
  servers still around, in the absence of a convenient test server we just 
  try a local connect, which either times out or goes through an SSHv2 
  handshake if there's a server there */

static const char *ssh1Info[] = {
	NULL,
	"localhost",
	NULL
	};
static const char *ssh2Info[] = {
	NULL,
	"localhost",
	"sorrel.humboldt.edu:222",
	"www.ssh.com",
	"openssh.com",
	NULL
	};

#define SSH1_SERVER_NO	1
#define SSH2_SERVER_NO	4

/* Establish an SSH session.  The generic SSHv1 client test will always step 
   up to SSHv2 if the server is v2 (which almost all are), so v1 can't 
   easily be generically tested without hardcoding v1-only into 
   session/ssh.c.  However, the loopback test, which forces the use of a
   v1-only server, does test the client as a v1 client */

static int connectSSH( const CRYPT_SESSION_TYPE sessionType,
					   const BOOLEAN useClientCert, const BOOLEAN useSubsystem,
					   const BOOLEAN usePortForwarding, 
					   const BOOLEAN localSession, const BOOLEAN useSSHv2,
					   const BOOLEAN useFingerprint )
	{
	CRYPT_SESSION cryptSession;
	const char *serverName = localSession ? "localhost" : \
							 useSSHv2 ? ssh2Info[ SSH2_SERVER_NO ] : \
										ssh1Info[ SSH1_SERVER_NO ];
	const BOOLEAN isServer = ( sessionType == CRYPT_SESSION_SSH_SERVER ) ? \
							   TRUE : FALSE;
	char buffer[ BUFFER_SIZE ];
	int cryptAlgo, keySize, version, bytesCopied, status;

	printf( "%sTesting %sSSH%s%s session...\n", isServer ? "SVR: " : "",
			localSession ? "local " : "", useSSHv2 ? "v2" : "v1",
			useSubsystem ? " SFTP" : \
				usePortForwarding ? " port-forwarding" : "" );
	if( !isServer && !localSession )
		printf( "  Remote host: %s.\n", serverName );

	/* Create the session */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED, sessionType );
	if( status == CRYPT_ERROR_PARAM3 )	/* SSH session access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSession() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Set up the server and user information and activate the session */
	if( isServer )
		{
		CRYPT_CONTEXT privateKey;

		if( !setLocalConnect( cryptSession, 22 ) )
			return( FALSE );
		status = getPrivateKey( &privateKey, SSH_PRIVKEY_FILE,
								SSH_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttribute( cryptSession,
										CRYPT_SESSINFO_PRIVATEKEY, privateKey );
			cryptDestroyContext( privateKey );
			}
		}
	else
		{
		if( localSession )
			{
			if( !setLocalConnect( cryptSession, 22 ) )
				return( FALSE );
			}
		else
			{
			status = cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_SERVER_NAME,
									serverName, strlen( serverName ) );
			}
		if( cryptStatusOK( status ) )
			status = cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_USERNAME,
									SSH_USER_NAME, strlen( SSH_USER_NAME ) );
		if( cryptStatusOK( status ) )
			{
			if( useClientCert )
				{
				CRYPT_CONTEXT privateKey;

				status = getPrivateKey( &privateKey, USER_PRIVKEY_FILE,
									USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
				if( cryptStatusOK( status ) )
					{
					status = cryptSetAttribute( cryptSession,
									CRYPT_SESSINFO_PRIVATEKEY, privateKey );
					cryptDestroyContext( privateKey );
					}
				}
			else
				{
#ifdef USER_SUPPLIED_PASSWORD
				char password[ 256 ];

				printf( "Enter SSHv2 server password: " );
				fgets( password, 255, stdin );
				password[ strlen( password ) - 1 ] = '\0';
				status = cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_PASSWORD,
									password, strlen( password ) );
#else
				status = cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_PASSWORD,
									SSH_PASSWORD, strlen( SSH_PASSWORD ) );
#endif /* User-supplied password */
				}
			}
		if( cryptStatusOK( status ) && useSubsystem )
			status = cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_SSH_SUBSYSTEM, "sftp", 4 );
		if( cryptStatusOK( status ) && usePortForwarding )
			status = cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_SSH_PORTFORWARD, 
									"localhost:1234", 14 );
		if( cryptStatusOK( status ) && useFingerprint )
			{
			BYTE fingerPrint[ CRYPT_MAX_HASHSIZE ];

			/* Set a dummy (all-zero) fingerprint to force the connect to 
			   fail */
			memset( fingerPrint, 0, CRYPT_MAX_HASHSIZE );
			status = cryptSetAttributeString( cryptSession, 
											  CRYPT_SESSINFO_SERVER_FINGERPRINT, 
											  fingerPrint, 16 );
			}
		}
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_VERSION,
									useSSHv2 ? 2 : 1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptSetAttribute/AttributeString() failed with error code "
				"%d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
	if( isServer )
		{
		char subsystem[ CRYPT_MAX_TEXTSIZE + 1 ];
		int length;

		printConnectInfo( cryptSession );
		if( cryptStatusOK( \
			cryptGetAttributeString( cryptSession, CRYPT_SESSINFO_SSH_SUBSYSTEM,
									 subsystem, &length ) ) )
			{
			subsystem[ length ] = '\0';
			printf( "SVR: Client requested '%s' subsystem.\n", subsystem );
			}
		else
			if( useSubsystem )
				{
				printf( "SVR: Client requested subsystem but server didn't "
						"report it, line %d.\n", __LINE__ );
				return( FALSE );
				}
		}
	if( cryptStatusError( status ) )
		{
		if( useFingerprint )
			{
			/* We've forced the connect to fail by using a dummy fingerprint,
			   everything is OK */
			cryptDestroySession( cryptSession );
			puts( "SVR: SSH client session succeeded.\n" );
			return( TRUE );
			}
		printExtError( cryptSession, isServer ? \
					   "SVR: Attempt to activate SSH server session" : \
					   "Attempt to activate SSH client session", status,
					   __LINE__ );
		cryptDestroySession( cryptSession );
		if( status == CRYPT_ERROR_OPEN )
			{
			/* These servers are constantly appearing and disappearing so if
			   we get a straight connect error we don't treat it as a serious
			   failure */
			puts( "  (Server could be down, faking it and continuing...)\n" );
			return( CRYPT_ERROR_FAILED );
			}
		if( status == CRYPT_ERROR_WRONGKEY )
			{
			/* This is another possible soft error condition, the default
			   username and password shouldn't be able to get into many
			   machines */
			puts( "  (Incorrect username/password, continuing...)\n" );
			return( TRUE );
			}
		if( status == CRYPT_ERROR_NOSECURE )
			{
			/* Another soft error condition, the server can't handle the
			   security level we want (usually occurs when trying to perform
			   an SSHv2 connect to an SSHv1 server) */
			puts( "  (Insufficiently secure protocol parameters, continuing...)\n" );
			return( TRUE );
			}
		return( FALSE );
		}
	if( useFingerprint )
		{
		printf( "Attempt to connect with invalid key fingerprint succeeded "
				"when it should\nhave failed, line %d.\n", __LINE__ );
		return( FALSE );
		}

	/* Report the session security info details */
	status = cryptGetAttribute( cryptSession, CRYPT_CTXINFO_ALGO,
								&cryptAlgo );
	if( cryptStatusOK( status ) )
		status = cryptGetAttribute( cryptSession, CRYPT_CTXINFO_KEYSIZE,
									&keySize );
	if( cryptStatusOK( status ) )
		status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_VERSION,
									&version );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't query encryption algorithm and keysize used for "
				"session, status %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	printf( "%sSSHv%d session is protected using algorithm %d with a %d "
			"bit key.\n", isServer ? "SVR: " : "", version, cryptAlgo, 
			keySize * 8 );
	if( !isServer )
		{
		BYTE fingerPrint[ CRYPT_MAX_HASHSIZE ];
		int length, i;

		status = cryptGetAttributeString( cryptSession, 
										  CRYPT_SESSINFO_SERVER_FINGERPRINT, 
										  fingerPrint, &length );
		if( cryptStatusError( status ) )
			{
			printf( "cryptGetAttributeString() failed with error code "
					"%d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		printf( "Server key fingerprint =" );
		for( i = 0; i < length; i++ )
			printf( " %02X", fingerPrint[ i ] );
		puts( "." );
		}

	/* If we're using the SFTP subsystem as a server, use the special-case 
	   routines for this */
#ifdef WINDOWS_THREADS
	if( useSubsystem )
		{
		if( isServer )
			{
			int sftpServer( const CRYPT_SESSION cryptSession );

			status = sftpServer( cryptSession );
			if( cryptStatusError( status ) )
				{
				printf( "SVR: Couldn't receive SFTP data from client, status %d, "
						"line %d.\n", status, __LINE__ );
				return( FALSE );
				}
			cryptDestroySession( cryptSession );
			puts( "SVR: SFTP server session succeeded.\n" );
			return( TRUE );
			}
		else
			{
			int sftpClient( const CRYPT_SESSION cryptSession );

			status = sftpClient( cryptSession );
			if( cryptStatusError( status ) )
				{
				printf( "Couldn't send SFTP data to server, status %d, line "
						"%d.\n", status, __LINE__ );
				return( FALSE );
					}
			cryptDestroySession( cryptSession );
			puts( "SFTP client session succeeded.\n" );
			return( TRUE );
			}
		}
#endif /* WINDOWS_THREADS */

	/* Send data over the SSH link */
	cryptSetAttribute( cryptSession, CRYPT_OPTION_NET_TIMEOUT, 5 );
	if( isServer )
		{
		/* Send a status message to the client */
		status = cryptPushData( cryptSession, "Welcome to cryptlib, now go "
								"away.\r\n", 35, &bytesCopied );
		if( cryptStatusOK( status ) )
			status = cryptFlushData( cryptSession );
		if( cryptStatusError( status ) || bytesCopied != 35 )
			{
			printf( "SVR: Couldn't send data to client, status %d, line "
					"%d.\n", status, __LINE__ );
			return( FALSE );
			}
		}

	/* Wait a bit while data arrives */
	delayThread( 2 );

	/* Print the first lot of output from the other side */
	status = cryptPopData( cryptSession, buffer, BUFFER_SIZE, &bytesCopied );
	if( cryptStatusError( status ) )
		{
		printf( "%sCouldn't read data from %s, status %d, line %d.\n",
				isServer ? "SVR: " : "", isServer ? "client" : "server", 
				status, __LINE__ );
		return( FALSE );
		}
	buffer[ bytesCopied ] = '\0';
	printf( "%s---- %s returned %d bytes ----\n", isServer ? "SVR: " : "",
			isServer ? "Client" : "Server", bytesCopied );
	puts( buffer );
	printf( "%s---- End of output ----\n", isServer ? "SVR: " : "" );

	/* See if the client requested port forwarding.  We have to do this now
	   rather than right after the connect because this is generally a
	   post-handshake function (unless the client already has a forwarded
	   connection waiting), so we won't see it until after we try reading
	   some data */
	if( isServer && \
		cryptStatusOK( \
			cryptGetAttributeString( cryptSession, 
									 CRYPT_SESSINFO_SSH_PORTFORWARD, 
									 NULL, &status ) ) )
		{
		int length;

		status = cryptGetAttributeString( cryptSession, 
										  CRYPT_SESSINFO_SSH_PORTFORWARD, 
										  buffer, &length );
		if( cryptStatusError( status ) )
			{
			printf( "cryptGetAttributeString() failed with error code "
					"%d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		buffer[ length ] = '\0';
		printf( "Client requested port forwarding to '%s'.\n", buffer );
		}

	/* If we're the server, echo the command to the client */
	if( isServer )
		{
		const int clientBytesCopied = bytesCopied;
		int dummy, i;

		for( i = 0; i < clientBytesCopied; i++ )
			if( buffer[ i ] < ' ' || buffer[ i ] >= 0x7F )
				buffer[ i ] = '.';
		status = cryptPushData( cryptSession, "Input was [", 11, &dummy );
		if( cryptStatusOK( status ) && clientBytesCopied > 0 )
			status = cryptPushData( cryptSession, buffer, clientBytesCopied, 
									&bytesCopied );
		if( cryptStatusOK( status ) )
			status = cryptPushData( cryptSession, "]\r\n", 3, &dummy );
		if( cryptStatusOK( status ) )
			status = cryptFlushData( cryptSession );
		if( cryptStatusError( status ) || bytesCopied != clientBytesCopied )
			{
			printf( "SVR: Couldn't send data to client, status %d, line "
					"%d.\n", status, __LINE__ );
			return( FALSE );
			}
		}
	else
		{
		/* We're the client, if it's a session to a Unix ssh server, send a 
		   sample command and display the output */
		if( !localSession )
			{
			/* Send a command to the server and get the results */
			status = cryptPushData( cryptSession, "ls -l | head -25\n", 18,
									&bytesCopied );
			if( cryptStatusOK( status ) )
				status = cryptFlushData( cryptSession );
			if( cryptStatusError( status ) || bytesCopied != 18 )
				{
				printf( "Couldn't send data to server, status %d, line "
						"%d.\n", status, __LINE__ );
				return( FALSE );
				}
			delayThread( 3 );
			status = cryptPopData( cryptSession, buffer, BUFFER_SIZE,
								   &bytesCopied );
			if( cryptStatusError( status ) )
				{
				printf( "Couldn't read data from server, status %d, line "
						"%d.\n", status, __LINE__ );
				return( FALSE );
				}
			buffer[ bytesCopied ] = '\0';
			printf( "---- Sent 'ls -l | head -25', server returned %d bytes "
					"----\n", bytesCopied );
			puts( buffer );
			puts( "---- End of output ----" );
			}
		else
			{
			/* It's a local session, just send a simple text string for 
			   testing */
			status = cryptPushData( cryptSession, "Some test data", 14,
									&bytesCopied );
			if( cryptStatusOK( status ) )
				status = cryptFlushData( cryptSession );
			if( cryptStatusError( status ) || bytesCopied != 14 )
				{
				printf( "Couldn't send data to server, status %d, line "
						"%d.\n", status, __LINE__ );
				return( FALSE );
				}

			/* Make sure we stay around long enough to get the server's
			   response */
			delayThread( 1 );
			}
		}

	/* Clean up */
	status = cryptDestroySession( cryptSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroySession() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( isServer ? "SVR: SSH server session succeeded.\n" : \
					 "SSH client session succeeded.\n" );
	return( TRUE );
	}

int testSessionSSHv1( void )
	{
	return( connectSSH( CRYPT_SESSION_SSH, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE ) );
	}
int testSessionSSHv2( void )
	{
	return( connectSSH( CRYPT_SESSION_SSH, FALSE, FALSE, FALSE, FALSE, TRUE, FALSE ) );
	}
int testSessionSSHClientCert( void )
	{
	return( connectSSH( CRYPT_SESSION_SSH, TRUE, FALSE, FALSE, FALSE, FALSE, FALSE ) );
	}
int testSessionSSH_SFTP( void )
	{
	return( connectSSH( CRYPT_SESSION_SSH, FALSE, TRUE, FALSE, FALSE, TRUE, FALSE ) );
	}
int testSessionSSHv1Server( void )
	{
	return( connectSSH( CRYPT_SESSION_SSH_SERVER, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE ) );
	}
int testSessionSSHv2Server( void )
	{
	return( connectSSH( CRYPT_SESSION_SSH_SERVER, FALSE, FALSE, FALSE, FALSE, TRUE, FALSE ) );
	}
int testSessionSSH_SFTPServer( void )
	{
	return( connectSSH( CRYPT_SESSION_SSH_SERVER, FALSE, FALSE, TRUE, FALSE, TRUE, FALSE ) );
	}

/* Perform a client/server loopback test */

#ifdef WINDOWS_THREADS

unsigned __stdcall ssh1ServerThread( void *dummy )
	{
	connectSSH( CRYPT_SESSION_SSH_SERVER, FALSE, FALSE, FALSE, TRUE, FALSE, FALSE );
	_endthreadex( 0 );
	return( 0 );
	}
unsigned __stdcall ssh2ServerThread( void *dummy )
	{
	connectSSH( CRYPT_SESSION_SSH_SERVER, FALSE, FALSE, FALSE, TRUE, TRUE, FALSE );
	_endthreadex( 0 );
	return( 0 );
	}
unsigned __stdcall sftpServerThread( void *dummy )
	{
	connectSSH( CRYPT_SESSION_SSH_SERVER, FALSE, TRUE, FALSE, TRUE, TRUE, FALSE );
	_endthreadex( 0 );
	return( 0 );
	}

static int sshClientServer( const BOOLEAN useFingerprint,
							const BOOLEAN useSSHv2,
							const BOOLEAN useSFTP,
							const BOOLEAN usePortForwarding )
	{
	HANDLE hThread;
	unsigned threadID;
	int status;

	/* Start the server and wait for it to initialise */
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, useSFTP ? \
											sftpServerThread : \
										 useSSHv2 ? \
											ssh2ServerThread : \
											&ssh1ServerThread,
										 NULL, 0, &threadID );
	Sleep( 1000 );

	/* Connect to the local server */
	status = connectSSH( CRYPT_SESSION_SSH, FALSE, useSFTP, 
						 usePortForwarding, TRUE, useSSHv2, useFingerprint );
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

int testSessionSSHv1ClientServer( void )
	{
	return( sshClientServer( FALSE, FALSE, FALSE, FALSE ) );
	}
int testSessionSSHv2ClientServer( void )
	{
	return( sshClientServer( FALSE, TRUE, FALSE, FALSE ) );
	}
int testSessionSSHClientServerFingerprint( void )
	{
	return( sshClientServer( TRUE, FALSE, FALSE, FALSE ) );
	}
int testSessionSSHClientServerSFTP( void )
	{
	return( sshClientServer( FALSE, TRUE, TRUE, FALSE ) );
	}
int testSessionSSHClientServerPortForward( void )
	{
	return( sshClientServer( FALSE, TRUE, FALSE, TRUE ) );
	}
#endif /* WINDOWS_THREADS */

/****************************************************************************
*																			*
*								SSL/TLS Routines Test						*
*																			*
****************************************************************************/

/* If we're using local sockets, we have to pull in the winsock defines */

#ifdef __WINDOWS__
  #include <winsock.h>
#endif /* __WINDOWS__ */

/* There are various servers running that we can use for testing, the
   following remapping allows us to switch between them.  Notes:

	Server 1: Local loopback.
	Server 2: Generic test server.
	Server 3: ~40K data returned.
	Server 4: Sends zero-length blocks (actually a POP server).
	Server 5: Requires CRYPT_OPTION_CERT_COMPLIANCELEVEL = 
			  CRYPT_COMPLIANCELEVEL_OBLIVIOUS due to b0rken certs.
	Server 6: (Causes MAC failure during handshake when called from PMail, 
			   works OK when called here).
	Server 7: Can only do crippled crypto (not even conventional crippled 
			  crypto but RC4-56) and instead of sending an alert for this 
			  just drops the connection (this may be caused by the NetApp
			  NetCache it's using).  This site is also running an Apache 
			  server that claims it's optimised for MSIE, and that the page 
			  won't work properly for non-MSIE browsers.  The mind boggles...
	Server 8: Server ("Hitachi Web Server 02-00") can only do SSL, when 
			  cryptlib is set to perform a TLS handshake (i.e. cryptlib is 
			  told to expect TLS but falls back to SSL), goes through the 
			  full handshake, then returns a handshake failure alert.  The
			  same occurs for other apps (e.g. MSIE) when TLS is enabled.
	Server 9: Buggy older IIS that can only do crippled crypto and drops
			  the connection as soon as it sees the client hello advertising 
			  strong crypto only.
	Server 10:Newer IIS (certificate is actually for akamai.net, so the SSL
			  may not be Microsoft's at all).
	Server 11:IBM (Websphere?).
	Server 12:Server is running TLS with SSL disabled, drops connection when
			  it sees an SSL handshake.  MSIE in its default config (TLS
			  disabled) can't connect to this server */

#define SSL_SERVER_NO	2
#define TLS_SERVER_NO	2
#define TLS11_SERVER_NO	2

static const struct {
	const char *name, *path;
	} sslInfo[] = {
	{ NULL, NULL },
	/*  1 */ { "localhost", "/" },
	/*  2 */ { "https://www.amazon.com", "/" },
	/*  3 */ { "https://www.cs.berkeley.edu", "/~daw/people/crypto.html" },
	/*  4 */ { "pop.web.de:995", "/" },
	/*  5 */ { "imap4-gw.uni-regensburg.de:993", "/" },
	/*  6 */ { "securepop.t-online.de:995", "/" },
	/*  7 */ { "https://homedir.wlv.ac.uk", "/" },
	/*  8 */ { "https://www.horaso.com:20443", "/" },
	/*  9 */ { "https://homedir.wlv.ac.uk", "/" },
	/* 10 */ { "https://www.microsoft.com", "/" },
	/* 11 */ { "https://alphaworks.ibm.com/", "/" },
	/* 12 */ { "https://webmount.turbulent.ca/", "/" },
	{ NULL, NULL }
	};

/* Various servers used for STARTTLS/STLS/AUTH TLS testing.  Notes:

	Server 1: SMTP: mailbox.ucsd.edu:25 (132.239.1.57) requires a client cert.
	Server 2: POP: pop.cae.wisc.edu:1110 (144.92.240.11) OK
	Server 3: SMTP: smtpauth.cae.wisc.edu:25 (144.92.12.93) requires a client 
			  cert 
	Server 4: SMTP: send.columbia.edu:25 (128.59.59.23) returns invalid cert 
			  (lower compliance level to fix) 
	Server 5: POP: pop3.myrealbox.com:110 (192.108.102.201) returns invalid 
			  cert (lower compliance level to fix) 
	Server 6: Encrypted POP: securepop.t-online.de:995 (194.25.134.46) direct 
			  SSL connect 
	Server 7: FTP: ftp.windsorchapel.net:21 (68.38.166.195) sends redundant 
			  client cert request with invalid length

			  To test FTP with SSL/TLS manually: Disable auto-login with FTP, 
			  then send RFC 2389 FEAT command to check security facilities.  
			  If this is supported, one of the responses will be either 
			  AUTH SSL or AUTH TLS, use this to turn on SSL/TLS.  If FEAT 
			  isn't supported, AUTH TLS should usually work:

				ftp -n ftp.windsorchapel.net
				quote feat
				quote auth ssl

			  or just:

				telnet ftp.windsorchapel.net 21
				auth ssl */

#define STARTTLS_SERVER_NO	2

typedef enum { PROTOCOL_NONE, PROTOCOL_SMTP, PROTOCOL_POP, 
			   PROTOCOL_IMAP, PROTOCOL_POP_DIRECT, PROTOCOL_FTP 
			 } PROTOCOL_TYPE;

static const struct {
	const char *name;
	const int port;
	PROTOCOL_TYPE protocol;
	} starttlsInfo[] = {
	{ NULL, 0 },
	{ "132.239.1.57", 25, PROTOCOL_SMTP },
	{ "144.92.240.11", 1110, PROTOCOL_POP },
	{ "144.92.12.93", 25, PROTOCOL_SMTP },
	{ "128.59.59.23", 25, PROTOCOL_SMTP },
	{ "192.108.102.201", 110, PROTOCOL_POP },
	{ "194.25.134.46", 995, PROTOCOL_POP_DIRECT },
	{ "68.38.166.195", 21, PROTOCOL_FTP },
	{ NULL, 0 }
	};

/* Large buffer size to test bulk data transfer capability for secure
   sessions */

#define BULKDATA_BUFFER_SIZE	300000L

static int checksumData( const void *data, const int dataLength )
	{
	const BYTE *dataPtr = data;
	int sum1 = 0, sum2 = 0, i;

	/* Calculate a 16-bit Fletcher-like checksum of the data (it doesn't
	   really matter if it's not exactly right, as long as the behaviour is 
	   the same for all data) */
	for( i = 0; i < dataLength; i++ )
		{
		sum1 += dataPtr[ i ];
		sum2 += sum1;
		}

	return( sum2 & 0xFFFF );
	}

static BOOLEAN handleBulkBuffer( BYTE *buffer, const BOOLEAN isInit )
	{
	int checkSum, i;

	/* If we're initialising the buffer, fill it with [0...256]* followed by
	   a checksum of the buffer contents */
	if( isInit )
		{
		for( i = 0; i < BULKDATA_BUFFER_SIZE - 2; i++ )
			buffer[ i ] = i & 0xFF;
		checkSum = checksumData( buffer, BULKDATA_BUFFER_SIZE - 2 );
		buffer[ BULKDATA_BUFFER_SIZE - 2 ] = ( checkSum >> 8 ) & 0xFF;
		buffer[ BULKDATA_BUFFER_SIZE - 1 ] = checkSum & 0xFF;

		return( TRUE );
		}

	/* We're being sent an initialised buffer, make sure that it's OK */
	for( i = 0; i < BULKDATA_BUFFER_SIZE - 2; i++ )
		if( buffer[ i ] != ( i & 0xFF )	)
			return( FALSE );
	checkSum = checksumData( buffer, BULKDATA_BUFFER_SIZE - 2 );
	if( buffer[ BULKDATA_BUFFER_SIZE - 2 ] != ( ( checkSum >> 8 ) & 0xFF ) || \
		buffer[ BULKDATA_BUFFER_SIZE - 1 ] != ( checkSum & 0xFF ) )
		return( FALSE );

	return( TRUE );
	}

/* Negotiate through a STARTTLS */

#ifdef __WINDOWS__

static int readLine( SOCKET netSocket, char *buffer )
	{
	int bufPos = 0, status = CRYPT_OK;

	for( bufPos = 0; \
		 status >= 0 && bufPos < 1024 && \
			( bufPos < 1 || buffer[ bufPos -1 ] != '\n' ); 
		 bufPos++ )
		status = recv( netSocket, buffer + bufPos, 1, 0 );
	while( bufPos > 1 && isspace( buffer[ bufPos - 1 ] ) )
		bufPos--;
	if( bufPos >= 3 )
		{
		while( bufPos > 1 && isspace( buffer[ bufPos - 1 ] ) )
			bufPos--;
		buffer[ min( bufPos, 56 ) ] = '\0';
		}
	return( bufPos );
	}

static int negotiateSTARTTLS( int *protocol )
	{
	SOCKET netSocket;
	struct sockaddr_in serverAddr;
	char buffer[ 1024 ];
	int bufPos, status;

	puts( "Negotiating SMTP/POP/IMAP/FTP session through to TLS start..." );
	*protocol = starttlsInfo[ STARTTLS_SERVER_NO ].protocol;

	/* Connect to a generally-available server to test STARTTLS/STLS 
	   functionality */
	memset( &serverAddr, 0, sizeof( struct sockaddr_in ) );
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons( ( u_short ) starttlsInfo[ STARTTLS_SERVER_NO ].port );
	serverAddr.sin_addr.s_addr = inet_addr( starttlsInfo[ STARTTLS_SERVER_NO ].name );
	netSocket = socket( PF_INET, SOCK_STREAM, 0 );
	if( netSocket == INVALID_SOCKET )
		{
		printf( "Couldn't create socket, line %d.\n", __LINE__ );
		return( CRYPT_ERROR_FAILED );
		}
	status = connect( netSocket, ( struct sockaddr * ) &serverAddr,
					  sizeof( struct sockaddr_in ) );
	if( status == SOCKET_ERROR )
		{
		closesocket( netSocket );
		printf( "Couldn't connect socket, line %d.\n", __LINE__ );
		return( CRYPT_OK );
		}

	/* If it's a direct connect, there's nothing left to do */
	if( *protocol == PROTOCOL_POP_DIRECT )
		{
		*protocol = PROTOCOL_POP;
		return( netSocket );
		}

	/* Perform (very crude) SMTP/POP/IMAP negotiation to switch to TLS */
	bufPos = readLine( netSocket, buffer );
	if( bufPos < 3 || ( strncmp( buffer, "220", 3 ) && \
						strncmp( buffer, "+OK", 3 ) && \
						strncmp( buffer, "OK", 2 ) ) )
		{
		closesocket( netSocket );
		printf( "Got response '%s', line %d.\n", buffer, __LINE__ );
		return( CRYPT_OK );
		}
	printf( "  Server said: '%s'\n", buffer );
	assert( ( *protocol == PROTOCOL_SMTP && !strncmp( buffer, "220", 3 ) ) || \
			( *protocol == PROTOCOL_POP && !strncmp( buffer, "+OK", 3 ) ) || \
			( *protocol == PROTOCOL_IMAP && !strncmp( buffer, "OK", 2 ) ) || \
			( *protocol == PROTOCOL_FTP && !strncmp( buffer, "220", 3 ) ) || \
			*protocol == PROTOCOL_NONE );
	switch( *protocol )
		{
		case PROTOCOL_POP:
			send( netSocket, "STLS\r\n", 6, 0 );
			puts( "  We said: 'STLS'" );
			break;

		case PROTOCOL_IMAP:
			/* It's possible for some servers that we may need to explicitly 
			   send a CAPABILITY command first to enable STARTTLS:
				a001 CAPABILITY
				> CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED
				> OK CAPABILITY completed */
			send( netSocket, "a001 STARTTLS\r\n", 15, 0 );
			puts( "  We said: 'STARTTLS'" );
			break;

		case PROTOCOL_SMTP:
			send( netSocket, "EHLO foo.bar.com\r\n", 18, 0 );
			puts( "  We said: 'EHLO foo.bar.com'" );
			do
				{
				bufPos = readLine( netSocket, buffer );
				if( bufPos < 3 || strncmp( buffer, "250", 3 ) )
					{
					closesocket( netSocket );
					printf( "Got response '%s', line %d.\n", buffer, __LINE__ );
					return( CRYPT_OK );
					}
				printf( "  Server said: '%s'\n", buffer );
				}
			while( !strncmp( buffer, "250-", 4 ) );
			send( netSocket, "STARTTLS\r\n", 10, 0 );
			puts( "  We said: 'STARTTLS'" );
			break;

		case PROTOCOL_FTP:
			send( netSocket, "AUTH TLS\r\n", 10, 0 );
			puts( "  We said: 'AUTH TLS'" );
			break;

		default:
			assert( FALSE );
		}
	bufPos = readLine( netSocket, buffer );
	if( bufPos < 3 || ( strncmp( buffer, "220", 3 ) && \
						strncmp( buffer, "+OK", 3 ) && \
						strncmp( buffer, "OK", 2 ) && \
						strncmp( buffer, "234", 3 ) ) )
		{
		printf( "Got response '%s', line %d.\n", buffer, __LINE__ );
		return( CRYPT_OK );
		}
	printf( "  Server said: '%s'\n", buffer );
	return( netSocket );
	}
#endif /* __WINDOWS__ */

/* Establish an SSL/TLS session */

static int connectSSLTLS( const CRYPT_SESSION_TYPE sessionType,
						  const int version, const BOOLEAN useClientCert,
						  const BOOLEAN localSession,
						  const BOOLEAN bulkTransfer, 
						  const BOOLEAN localSocket,
						  const BOOLEAN sharedKey )
	{
	CRYPT_SESSION cryptSession;
	const BOOLEAN isServer = ( sessionType == CRYPT_SESSION_SSL_SERVER ) ? \
							   TRUE : FALSE;
	const char *versionStr[] = { "SSL", "TLS", "TLS 1.1" };
	const char *serverName = ( version == 0 ) ? \
								sslInfo[ SSL_SERVER_NO ].name : \
							 ( version == 1 ) ? \
								sslInfo[ TLS_SERVER_NO ].name : \
								sslInfo[ TLS11_SERVER_NO ].name;
	BYTE *bulkBuffer;
	char buffer[ FILEBUFFER_SIZE ];
#ifdef __WINDOWS__
	int netSocket;
#endif /* __WINDOWS__ */
	int cryptAlgo, keySize, bytesCopied, protocolVersion;
	int protocol = PROTOCOL_SMTP, status;

	printf( "%sTesting %s%s session%s...\n", isServer ? "SVR: " : "",
			localSession ? "local " : "", versionStr[ version ],
			useClientCert ? " with client certs" : \
			localSocket ? " with local socket" : \
			bulkTransfer ? " for bulk data transfer" : \
			sharedKey ? " with shared key" : "" );
	if( !isServer && !localSession )
		printf( "  Remote host: %s.\n", serverName );

	/* Create the SSL/TLS session */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED, sessionType );
	if( status == CRYPT_ERROR_PARAM3 )	/* SSL/TLS session access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSession() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_VERSION, version );
	if( cryptStatusError( status ) )
		{
		printf( "cryptSetAttribute() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* If we're doing a bulk data transfer, set up the necessary buffer */
	if( bulkTransfer )
		{
		if( ( bulkBuffer = malloc( BULKDATA_BUFFER_SIZE ) ) == NULL )
			{
			printf( "Failed to allocated %ld bytes, line %d.\n",
					BULKDATA_BUFFER_SIZE, __LINE__ );
			return( FALSE );
			}
		if( isServer )
			handleBulkBuffer( bulkBuffer, TRUE );
		}

	/* Set up the server information and activate the session */
	if( isServer )
		{
		CRYPT_CONTEXT privateKey;

		if( !setLocalConnect( cryptSession, 443 ) )
			return( FALSE );
		status = getPrivateKey( &privateKey, SERVER_PRIVKEY_FILE,
								USER_PRIVKEY_LABEL, 
								TEST_PRIVKEY_PASSWORD );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttribute( cryptSession,
										CRYPT_SESSINFO_PRIVATEKEY, 
										privateKey );
			cryptDestroyContext( privateKey );
			}
		if( cryptStatusOK( status ) && useClientCert )
			{
			CRYPT_KEYSET cryptKeyset;

			status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
								DATABASE_KEYSET_TYPE, DATABASE_KEYSET_NAME,
								CRYPT_KEYOPT_READONLY );
			if( cryptStatusError( status ) )
				{
				printf( "SVR: Client cert keyset open failed with error code "
						"%d, line %d.\n", status, __LINE__ );
				return( FALSE );
				}
			status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_KEYSET,
										cryptKeyset );
			cryptKeysetClose( cryptKeyset );
			}
		}
	else
		{
		if( localSocket )
			{
			/* Testing this fully requires a lot of OS-specific juggling so
			   unless we're running under Windows we just supply the handle 
			   to stdin, which will return a read/write error during the 
			   connect.  This checks that the handle has been assigned 
			   corectly without requiring a lot of OS-specific socket 
			   handling code.  Under Windows, we use a (very cut-down) set
			   of socket calls to set up a minimal socket.  Since there's
			   very little error-checking done, we don't treat a failure
			   as fatal */
#if defined( __WINDOWS__ )
			WSADATA wsaData;

			if( WSAStartup( 2, &wsaData ) )
				{
				printf( "Couldn't initialise sockets interface, line %d.\n", 
						__LINE__ );
				return( FALSE );
				}

			/* Try and negotiate a STARTTLS session.  We don't treat most 
			   types of failure as fatal since there are a great many minor
			   things that can go wrong that we don't want to have to handle
			   without writing half an MUA */
			netSocket = negotiateSTARTTLS( &protocol );
			if( netSocket <= 0 )
				{
				cryptDestroySession( cryptSession );
				WSACleanup();
				if( netSocket == CRYPT_OK )
					{
					puts( "This is a nonfatal error (a great many other "
						  "things can go wrong while\nnegotiating through "
						  "to the TLS upgrade).\n" );
					return( TRUE );
					}
				return( FALSE );
				}

			/* Hand the socket to cryptlib */
			status = cryptSetAttribute( cryptSession,
							CRYPT_SESSINFO_NETWORKSOCKET, netSocket );
#elif defined( DDNAME_IO )
			/* The fileno() function doesn't work for DDNAMEs */
			status = cryptSetAttribute( cryptSession, 
							CRYPT_SESSINFO_NETWORKSOCKET, 0 );
#else
			status = cryptSetAttribute( cryptSession,
							CRYPT_SESSINFO_NETWORKSOCKET, fileno( stdin ) );
#endif /* __WINDOWS__ */
			}
		else
			{
			if( localSession )
				{
				if( !setLocalConnect( cryptSession, 443 ) )
					return( FALSE );
				}
			else
				status = cryptSetAttributeString( cryptSession,
								CRYPT_SESSINFO_SERVER_NAME, serverName,
								strlen( serverName ) );
			}
		if( cryptStatusOK( status ) && useClientCert )
			{
			CRYPT_CONTEXT privateKey;

			status = getPrivateKey( &privateKey, USER_PRIVKEY_FILE,
								USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
			if( cryptStatusOK( status ) )
				{
				status = cryptSetAttribute( cryptSession,
								CRYPT_SESSINFO_PRIVATEKEY, privateKey );
				cryptDestroyContext( privateKey );
				}
			}
		}
	if( cryptStatusOK( status ) && sharedKey )
		{
		status = cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_USERNAME, SSL_USER_NAME,
									strlen( SSL_USER_NAME ) );
		if( cryptStatusOK( status ) )
			status = cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_PASSWORD, SSL_PASSWORD,
									strlen( SSL_PASSWORD ) );
		if( isServer )
			{
			/* If it's a server session, set an additional username/password
			   to test the ability of the session cache to store multiple
			   shared secrets */
			status = cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_USERNAME, "0000", 4 );
			if( cryptStatusOK( status ) )
				status = cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_PASSWORD, "0000", 4 );
			if( cryptStatusOK( status ) && \
				cryptStatusOK( \
					cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_USERNAME, "0000", 4 ) ) )
				{
				printf( "SVR: Addition of duplicate entry to SSL session "
						"cache wasn't detected, line %d.\n", __LINE__ );
				return( FALSE );
				}
			}
		}
	if( cryptStatusError( status ) )
		{
		if( localSocket )
			{
#ifdef __WINDOWS__
			closesocket( netSocket );
			WSACleanup();
#else
			/* Creating a socket in a portable manner is too difficult so 
			   we've passed in a stdio handle, this should return an error 
			   since it's not a blocking socket */
			return( TRUE );
#endif /* __WINDOWS__ */
			}
		printf( "cryptSetAttribute/AttributeString() failed with error code "
				"%d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
#if SSL_SERVER_NO == 5
	cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   &version );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   CRYPT_COMPLIANCELEVEL_OBLIVIOUS );
#endif /* SSL server with b0rken certs */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
#if SSL_SERVER_NO == 5
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   version );
#endif /* SSL server with b0rken certs */
	if( isServer )
		printConnectInfo( cryptSession );
	if( cryptStatusError( status ) )
		{
		char strBuffer[ 128 ];

		if( localSocket )
			{
#ifdef __WINDOWS__
			closesocket( netSocket );
			WSACleanup();
#else
			/* If we're using a dummy local socket, we'll get a R/W error at 
			   this point since it's not connected to anything, so we 
			   intercept it before it gets any further */
			if( status == CRYPT_ERROR_READ || status == CRYPT_ERROR_WRITE )
				{
				cryptDestroySession( cryptSession );
				return( TRUE );
				}
#endif /* __WINDOWS__ */
			}
		sprintf( strBuffer, "%sAttempt to activate %s%s session",
				 isServer ? "SVR: " : "", localSession ? "local " : "", 
				 versionStr[ version ] );
		printExtError( cryptSession, strBuffer, status, __LINE__ );
		cryptDestroySession( cryptSession );
		if( bulkTransfer )
			free( bulkBuffer );
		if( status == CRYPT_ERROR_OPEN )
			{
			/* These servers are constantly appearing and disappearing so if
			   we get a straight connect error we don't treat it as a serious
			   failure */
			puts( "  (Server could be down, faking it and continuing...)\n" );
			return( CRYPT_ERROR_FAILED );
			}
		return( FALSE );
		}

	/* Report the session security info details */
	status = cryptGetAttribute( cryptSession, CRYPT_CTXINFO_ALGO,
								&cryptAlgo );
	if( cryptStatusOK( status ) )
		status = cryptGetAttribute( cryptSession, CRYPT_CTXINFO_KEYSIZE,
									&keySize );
	if( cryptStatusOK( status ) )
		status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_VERSION,
									&protocolVersion );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't query session details, status %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "%sSession is protected using algorithm %d with a %d bit key,\n"
			"  protocol version %d.\n", isServer ? "SVR: " : "",
			cryptAlgo, keySize * 8, protocolVersion );
	if( !isServer && !sharedKey )
		{
		BYTE fingerPrint[ CRYPT_MAX_HASHSIZE ];
		int length, i;

		status = cryptGetAttributeString( cryptSession, 
										  CRYPT_SESSINFO_SERVER_FINGERPRINT, 
										  fingerPrint, &length );
		if( cryptStatusError( status ) )
			{
			printf( "cryptGetAttributeString() failed with error code "
					"%d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		printf( "Server key fingerprint =" );
		for( i = 0; i < length; i++ )
			printf( " %02X", fingerPrint[ i ] );
		puts( "." );
		}
	if( ( !localSession && !isServer ) || 
		( localSession && isServer && useClientCert ) )
		{
		CRYPT_CERTIFICATE cryptCertificate;

		status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_RESPONSE,
									&cryptCertificate );
		if( cryptStatusError( status ) )
			{
			printf( "%sCouldn't get %s certificate, status %d, line %d.\n",
					isServer ? "SVR: " : "", isServer ? "client" : "server", 
					status, __LINE__ );
			return( FALSE );
			}
		puts( localSession ? "SVR: Client cert details are:" : \
							 "Server cert details are:" );
		printCertChainInfo( cryptCertificate );
		cryptDestroyCert( cryptCertificate );
		}
	if( isServer && sharedKey )
		{
		int length;

		status = cryptGetAttributeString( cryptSession,
										  CRYPT_SESSINFO_USERNAME, buffer,
										  &length );
		if( cryptStatusError( status ) )
			{
			printf( "SVR: Couldn't read client user name, status %d, line "
					"%d.\n", status, __LINE__ );
			return( FALSE );
			}
		buffer[ length ] = '\0';
		printf( "SVR: Client user name = '%s'.\n", buffer );
		}

	/* Send data over the SSL/TLS link */
#if SSL_SERVER_NO == 3
	/* This server has a large amount of data on it, used to test high-
	   latency bulk transfers, so we set a larger timeout for the read */
	status = cryptSetAttribute( cryptSession, CRYPT_OPTION_NET_TIMEOUT, 15 );
#else
	status = cryptSetAttribute( cryptSession, CRYPT_OPTION_NET_TIMEOUT, 5 );
#endif /* SSL_SERVER_NO == 3 */
	if( bulkTransfer )
		{
		if( isServer )
			{
			status = cryptPushData( cryptSession, bulkBuffer,
									BULKDATA_BUFFER_SIZE, &bytesCopied );
			if( cryptStatusOK( status ) )
				status = cryptFlushData( cryptSession );
			if( cryptStatusError( status ) || \
				bytesCopied != BULKDATA_BUFFER_SIZE )
				{
				printf( "SVR: Couldn't send bulk data to client, status %d, "
						"line %d.\n", status, __LINE__ );
				return( FALSE );
				}
			}
		else
			{
			long byteCount = 0;

			do
				{
				status = cryptPopData( cryptSession, bulkBuffer + byteCount,
									   BULKDATA_BUFFER_SIZE - byteCount, 
									   &bytesCopied );
				byteCount += bytesCopied;
				}
			while( cryptStatusOK( status ) && \
				   byteCount < BULKDATA_BUFFER_SIZE );
			if( cryptStatusError( status ) )
				{
				printf( "Couldn't read bulk data from server, status %d, "
						"line %d.\n", status, __LINE__ );
				return( FALSE );
				}
			if( byteCount != BULKDATA_BUFFER_SIZE )
				{
				printf( "Only received %ld of %ld bytes.\n", byteCount,
						BULKDATA_BUFFER_SIZE );
				return( FALSE );
				}
			if( !handleBulkBuffer( bulkBuffer, FALSE ) )
				{
				puts( "Received buffer contents don't match sent buffer "
					  "contents." );
				return( FALSE );
				}
			}

		free( bulkBuffer );
		}
	else
		/* It's a standard transfer, send/receive and HTTP request/response.  
		   We clean up if we exit due to an error, if we're running a local
		   loopback test the client and server threads can occasionally lose
		   sync, which isn't a fatal error but can turn into a 
		   CRYPT_ERROR_INCOMPLETE once all the tests are finished */
		if( isServer )
			{
#if defined( __MVS__ ) || defined( __VMCMS__ )
  #pragma convlit( resume )
#endif /* EBCDIC systems */
			const char serverReply[] = \
				"HTTP/1.0 200 OK\n"
				"Date: Fri, 7 June 1999 20:02:07 GMT\n"
				"Server: cryptlib SSL/TLS test\n"
				"Content-Type: text/html\n"
				"\n"
				"<!DOCTYPE HTML SYSTEM \"html.dtd\">\n"
				"<html>\n"
				"<head>\n"
				"<title>cryptlib SSL/TLS test page</title>\n"
				"<body>\n"
				"Test message from the cryptlib SSL/TLS server<p>\n"
				"</body>\n"
				"</html>\n";
#if defined( __MVS__ ) || defined( __VMCMS__ )
  #pragma convlit( suspend )
#endif /* EBCDIC systems */

			/* Print the text of the request from the client */
			status = cryptPopData( cryptSession, buffer, FILEBUFFER_SIZE, 
								   &bytesCopied );
			if( cryptStatusError( status ) )
				{
				printExtError( cryptSession, "SVR: Attempt to read data "
							   "from client", status, __LINE__ );
				cryptDestroySession( cryptSession );
				return( FALSE );
				}
			buffer[ bytesCopied ] = '\0';
#if defined( __MVS__ ) || defined( __VMCMS__ )
			asciiToEbcdic( buffer, bytesCopied );
#endif /* EBCDIC systems */
			printf( "---- Client sent %d bytes ----\n", bytesCopied );
			puts( buffer );
			puts( "---- End of output ----" );

			/* Send a reply */
			status = cryptPushData( cryptSession, serverReply,
									sizeof( serverReply ) - 1, &bytesCopied );
			if( cryptStatusOK( status ) )
				status = cryptFlushData( cryptSession );
			if( cryptStatusError( status ) || \
				bytesCopied != sizeof( serverReply ) - 1 )
				{
				printExtError( cryptSession, "Attempt to send data to "
							   "client", status, __LINE__ );
				cryptDestroySession( cryptSession );
				return( FALSE );
				}
			}
		else
			{
			char fetchString[ 128 ];
			int fetchStringLen;

			/* Send a fetch request to the server */
			if( localSocket )
				{
				if( protocol == PROTOCOL_SMTP )
					strcpy( fetchString, "EHLO foo.bar.com\r\n" );
				else
					if( protocol == PROTOCOL_POP )
						strcpy( fetchString, "CAPA\r\n" );
					else
						if( protocol == PROTOCOL_IMAP )
							strcpy( fetchString, "a003 CAPABILITY\r\n" );
						else
							strcpy( fetchString, "USER test\r\n" );
				}
			else
				sprintf( fetchString, "GET %s HTTP/1.0\r\n\r\n", 
						 sslInfo[ SSL_SERVER_NO ].path );
			fetchStringLen = strlen( fetchString );
#if defined( __MVS__ ) || defined( __VMCMS__ )
			ebcdicToAscii( fetchString, fetchStringLen );
#endif /* EBCDIC systems */
			status = cryptPushData( cryptSession, fetchString, 
									fetchStringLen, &bytesCopied );
			if( cryptStatusOK( status ) )
				status = cryptFlushData( cryptSession );
			if( cryptStatusError( status ) || bytesCopied != fetchStringLen )
				{
				printExtError( cryptSession, "Attempt to send data to "
							   "server", status, __LINE__ );
				cryptDestroySession( cryptSession );
				return( FALSE );
				}

			/* Print the text of the reply from the server */
			status = cryptPopData( cryptSession, buffer, FILEBUFFER_SIZE, 
								   &bytesCopied );
			if( cryptStatusError( status ) )
				{
				printExtError( cryptSession, "Attempt to read data from "
							   "server", status, __LINE__ );
				cryptDestroySession( cryptSession );
				return( FALSE );
				}
			if( bytesCopied == 0 )
				{
				/* We've set a 5s timeout, we should get at least some 
				   data */
				puts( "Server returned no data in response to our request." );
				cryptDestroySession( cryptSession );
				return( FALSE );
				}
			buffer[ bytesCopied ] = '\0';
#if defined( __MVS__ ) || defined( __VMCMS__ )
			asciiToEbcdic( buffer, bytesCopied );
#endif /* EBCDIC systems */
			printf( "---- Server sent %d bytes ----\n", bytesCopied );
#if SSL_SERVER_NO == 3
			puts( "  (Large data quantity omitted)" );
#else
			puts( buffer );
#endif /* SSL_SERVER_NO == 3 */
			puts( "---- End of output ----" );

#if SSL_SERVER_NO == 3
			/* If we're reading a lot of data, more may have arrived in the  
			   meantime */
			status = cryptPopData( cryptSession, buffer, FILEBUFFER_SIZE, 
								   &bytesCopied );
			if( cryptStatusError( status ) )
				{
				if( status == CRYPT_ERROR_READ )
					/* Since this is HTTP, the other side can close the 
					   connection with no further warning, even though SSL 
					   says you shouldn't really do this */
					puts( "Remote system closed connection." );
				else
					{
					printExtError( cryptSession, "Attempt to read data from "
								   "server", status, __LINE__ );
					cryptDestroySession( cryptSession );
					return( FALSE );
					}
				}
			else
				{
				buffer[ bytesCopied ] = '\0';
#if defined( __MVS__ ) || defined( __VMCMS__ )
				asciiToEbcdic( buffer, bytesCopied );
#endif /* EBCDIC systems */
				printf( "---- Server sent further %d bytes ----\n", 
						bytesCopied );
				puts( buffer );
				puts( "---- End of output ----" );
				}
#endif /* SSL_SERVER_NO == 3 */

			/* If it's a chatty protocol, exchange some more pleasantries */
			if( localSocket )
				{
				if( protocol == PROTOCOL_SMTP )
					strcpy( fetchString, "QUIT\r\n" );
				else
					if( protocol == PROTOCOL_POP )
						strcpy( fetchString, "USER test\r\n" );
					else
						if( protocol == PROTOCOL_IMAP )
							strcpy( fetchString, "a004 LOGIN test\r\n" );
				fetchStringLen = strlen( fetchString );
#if defined( __MVS__ ) || defined( __VMCMS__ )
				ebcdicToAscii( fetchString, fetchStringLen );
#endif /* EBCDIC systems */
				status = cryptPushData( cryptSession, fetchString, 
										fetchStringLen, &bytesCopied );
				if( cryptStatusOK( status ) )
					status = cryptFlushData( cryptSession );
				if( cryptStatusError( status ) || bytesCopied != fetchStringLen )
					{
					printExtError( cryptSession, "Attempt to send data to "
								   "server", status, __LINE__ );
					cryptDestroySession( cryptSession );
					return( FALSE );
					}
				status = cryptPopData( cryptSession, buffer, FILEBUFFER_SIZE, 
									   &bytesCopied );
				if( cryptStatusError( status ) )
					{
					printExtError( cryptSession, "Attempt to read data from "
								   "server", status, __LINE__ );
					cryptDestroySession( cryptSession );
					return( FALSE );
					}
				buffer[ bytesCopied ] = '\0';
#if defined( __MVS__ ) || defined( __VMCMS__ )
				asciiToEbcdic( buffer, bytesCopied );
#endif /* EBCDIC systems */
				printf( "---- Server sent %d bytes ----\n", bytesCopied );
				puts( buffer );
				puts( "---- End of output ----" );
				}
			}

	/* Clean up */
	status = cryptDestroySession( cryptSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroySession() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
#ifdef __WINDOWS__
	if( localSocket )
		{
		closesocket( netSocket );
		WSACleanup();
		}
#endif /* __WINDOWS__ */

	printf( "%s%s session succeeded.\n\n", isServer ? "SVR: " : "",
			versionStr[ version ] );
	return( TRUE );
	}

int testSessionSSL( void )
	{
	return( connectSSLTLS( CRYPT_SESSION_SSL, 0, FALSE, FALSE, FALSE, FALSE, FALSE ) );
	}
int testSessionSSLLocalSocket( void )
	{
	return( connectSSLTLS( CRYPT_SESSION_SSL, 0, FALSE, FALSE, FALSE, TRUE, FALSE ) );
	}
int testSessionSSLClientCert( void )
	{
	return( connectSSLTLS( CRYPT_SESSION_SSL, 0, TRUE, FALSE, FALSE, FALSE, FALSE ) );
	}
int testSessionSSLSharedKey( void )
	{
	return( connectSSLTLS( CRYPT_SESSION_SSL, 0, TRUE, FALSE, FALSE, FALSE, TRUE ) );
	}

int testSessionSSLServer( void )
	{
	return( connectSSLTLS( CRYPT_SESSION_SSL_SERVER, 0, FALSE, FALSE, FALSE, FALSE, FALSE ) );
	}
int testSessionSSLServerCached( void )
	{
	int status;

	/* Run the server twice to check session cacheing.  Testing this requires
	   manual reconnection with a browser to localhost, since it's too
	   complex to handle easily via a loopback test */
	status = connectSSLTLS( CRYPT_SESSION_SSL_SERVER, 0, FALSE, FALSE, FALSE, FALSE, FALSE );
	if( status <= 0 )
		return( status );
	return( connectSSLTLS( CRYPT_SESSION_SSL_SERVER, 0, FALSE, FALSE, FALSE, FALSE, FALSE ) );
	}
int testSessionSSLServerClientCert( void )
	{
	return( connectSSLTLS( CRYPT_SESSION_SSL_SERVER, 0, TRUE, FALSE, FALSE, FALSE, FALSE ) );
	}

int testSessionTLS( void )
	{
	return( connectSSLTLS( CRYPT_SESSION_SSL, 1, FALSE, FALSE, FALSE, FALSE, FALSE ) );
	}

int testSessionTLSServer( void )
	{
	return( connectSSLTLS( CRYPT_SESSION_SSL_SERVER, 1, FALSE, FALSE, FALSE, FALSE, FALSE ) );
	}
int testSessionTLSServerSharedKey( void )
	{
	return( connectSSLTLS( CRYPT_SESSION_SSL_SERVER, 1, FALSE, FALSE, FALSE, FALSE, TRUE ) );
	}

int testSessionTLS11( void )
	{
	return( connectSSLTLS( CRYPT_SESSION_SSL, 2, FALSE, FALSE, FALSE, FALSE, FALSE ) );
	}

/* Perform a client/server loopback test */

#ifdef WINDOWS_THREADS

unsigned __stdcall sslServerThread( void *dummy )
	{
	connectSSLTLS( CRYPT_SESSION_SSL_SERVER, 0, FALSE, TRUE, FALSE, FALSE, FALSE );
	_endthreadex( 0 );
	return( 0 );
	}

int testSessionSSLClientServer( void )
	{
	HANDLE hThread;
	unsigned threadID;
	int status;

	/* Start the server and wait for it to initialise */
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, &sslServerThread,
										 NULL, 0, &threadID );
	Sleep( 1000 );

	/* Connect to the local server */
	status = connectSSLTLS( CRYPT_SESSION_SSL, 0, FALSE, TRUE, FALSE, FALSE, FALSE );
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

unsigned __stdcall sslClientCertServerThread( void *dummy )
	{
	connectSSLTLS( CRYPT_SESSION_SSL_SERVER, 0, TRUE, TRUE, FALSE, FALSE, FALSE );
	_endthreadex( 0 );
	return( 0 );
	}

int testSessionSSLClientCertClientServer( void )
	{
	HANDLE hThread;
	unsigned threadID;
	int status;

	/* Start the server and wait for it to initialise */
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, &sslClientCertServerThread,
										 NULL, 0, &threadID );
	Sleep( 1000 );

	/* Connect to the local server */
	status = connectSSLTLS( CRYPT_SESSION_SSL, 0, TRUE, TRUE, FALSE, FALSE, FALSE );
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

unsigned __stdcall tlsServerThread( void *dummy )
	{
	connectSSLTLS( CRYPT_SESSION_SSL_SERVER, 1, FALSE, TRUE, FALSE, FALSE, FALSE );
	_endthreadex( 0 );
	return( 0 );
	}

int testSessionTLSClientServer( void )
	{
	HANDLE hThread;
	unsigned threadID;
	int status;

	/* Start the server and wait for it to initialise */
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, &tlsServerThread,
										 NULL, 0, &threadID );
	Sleep( 1000 );

	/* Connect to the local server */
	status = connectSSLTLS( CRYPT_SESSION_SSL, 1, FALSE, TRUE, FALSE, FALSE, FALSE );
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

unsigned __stdcall tlsSharedKeyServerThread( void *dummy )
	{
	connectSSLTLS( CRYPT_SESSION_SSL_SERVER, 1, FALSE, TRUE, FALSE, FALSE, TRUE );
	_endthreadex( 0 );
	return( 0 );
	}

int testSessionTLSSharedKeyClientServer( void )
	{
	HANDLE hThread;
	unsigned threadID;
	int status;

	/* Start the server and wait for it to initialise */
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, &tlsSharedKeyServerThread,
										 NULL, 0, &threadID );
	Sleep( 1000 );

	/* Connect to the local server */
	status = connectSSLTLS( CRYPT_SESSION_SSL, 1, FALSE, TRUE, FALSE, FALSE, TRUE );
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

unsigned __stdcall tlsBulkTransferServerThread( void *dummy )
	{
	connectSSLTLS( CRYPT_SESSION_SSL_SERVER, 1, FALSE, TRUE, TRUE, FALSE, FALSE );
	_endthreadex( 0 );
	return( 0 );
	}

int testSessionTLSBulkTransferClientServer( void )
	{
	HANDLE hThread;
	unsigned threadID;
	int status;

	/* Start the server and wait for it to initialise */
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, &tlsBulkTransferServerThread,
										 NULL, 0, &threadID );
	Sleep( 1000 );

	/* Connect to the local server */
	status = connectSSLTLS( CRYPT_SESSION_SSL, 1, FALSE, TRUE, TRUE, FALSE, FALSE );
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

unsigned __stdcall tls11ServerThread( void *dummy )
	{
	connectSSLTLS( CRYPT_SESSION_SSL_SERVER, 2, FALSE, TRUE, FALSE, FALSE, FALSE );
	_endthreadex( 0 );
	return( 0 );
	}

int testSessionTLS11ClientServer( void )
	{
	HANDLE hThread;
	unsigned threadID;
	int status;

	/* Start the server and wait for it to initialise */
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, &tls11ServerThread,
										 NULL, 0, &threadID );
	Sleep( 1000 );

	/* Connect to the local server */
	status = connectSSLTLS( CRYPT_SESSION_SSL, 2, FALSE, TRUE, FALSE, FALSE, FALSE );
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

/****************************************************************************
*																			*
*							SFTP Routines for SSH							*
*																			*
****************************************************************************/

/* The following code is a bare-bones SFTP implementation created purely for
   interop/performance testing of cryptlib's SSH implementation.  It does 
   the bare minimum needed to set up an SFTP transfer, and shouldn't be used 
   for anything other than testing.

   Rather than creating our own versions of code already present in cryptlib,
   we pull in the cryptlib code wholesale here.  This is a pretty ugly hack,
   but saves having to copy over a pile of cryptlib code.

   Because cryptlib has an internal BYTE type, we need to no-op it out before
   we pull in any cryptlib code */

#undef BYTE
#define BYTE	_BYTE_DUMMY
#if defined( SYMANTEC_C ) || defined( __BEOS__ )
  #define INC_ALL
  #include "misc_rw.c"
#elif defined( _MSC_VER )
  #define INC_CHILD
  #include "../misc/misc_rw.c"
#else
  #include "misc/misc_rw.c"
#endif /* Compiler-specific includes */
#undef BYTE
#define BYTE	unsigned char

/* Replacements for cryptlib stream routines */

#define sMemDisconnect( stream )
#define sMemConnect		sMemOpen

int sMemOpen( STREAM *stream, const void *buffer, const int bufSize )
	{
	memset( stream, 0, sizeof( STREAM ) );
	stream->buffer = ( void * ) buffer;
	stream->bufEnd = bufSize;
	return( CRYPT_OK );
	}

int sread( STREAM *stream, void *buffer, const int count )
	{
	if( stream->bufPos + count > stream->bufEnd )
		{
		sSetError( stream, CRYPT_ERROR_UNDERFLOW );
		return( CRYPT_ERROR_UNDERFLOW );
		}
	memcpy( buffer, stream->buffer + stream->bufPos, count );
	stream->bufPos += count;
	return( CRYPT_OK );
	}

int swrite( STREAM *stream, const void *buffer, const int count )
	{
	if( stream->buffer != NULL )
		{
		if( stream->bufPos + count > stream->bufEnd )
			{
			sSetError( stream, CRYPT_ERROR_OVERFLOW );
			return( CRYPT_ERROR_OVERFLOW );
			}
		memcpy( stream->buffer + stream->bufPos, buffer, count );
		}
	stream->bufPos += count;
	return( CRYPT_OK );
	}

int sgetc( STREAM *stream )
	{
	int ch;

	if( stream->bufPos + 1 > stream->bufEnd )
		{
		sSetError( stream, CRYPT_ERROR_UNDERFLOW );
		return( CRYPT_ERROR_UNDERFLOW );
		}
	ch = stream->buffer[ stream->bufPos ];
	stream->bufPos++;
	return( ch );
	}

int sputc( STREAM *stream, const int data )
	{
	if( stream->buffer != NULL )
		{
		if( stream->bufPos + 1 > stream->bufEnd )
			{
			sSetError( stream, CRYPT_ERROR_OVERFLOW );
			return( CRYPT_ERROR_OVERFLOW );
			}
		stream->buffer[ stream->bufPos++ ] = data;
		}
	else
		stream->bufPos++;
	return( CRYPT_OK );
	}

int sseek( STREAM *stream, const long position )
	{
	return( 0 );
	}

int sPeek( STREAM *stream )
	{
	return( 0 );
	}

/* Dummy routines needed in misc_rw.c */

int BN_num_bits( const BIGNUM *a ) { return 0; }
int BN_high_bit( BIGNUM *a ) { return 0; }
BIGNUM *BN_bin2bn( const unsigned char *s, int len, BIGNUM *ret ) { return NULL; }
int	BN_bn2bin( const BIGNUM *a, unsigned char *to ) { return 0; }

/* SFTP command types */

#define SSH_FXP_INIT			1
#define SSH_FXP_VERSION			2
#define SSH_FXP_OPEN			3
#define SSH_FXP_CLOSE			4
#define SSH_FXP_READ			5
#define SSH_FXP_WRITE			6
#define SSH_FXP_LSTAT			7
#define SSH_FXP_FSTAT			8
#define SSH_FXP_SETSTAT			9
#define SSH_FXP_FSETSTAT		10
#define SSH_FXP_OPENDIR			11
#define SSH_FXP_READDIR			12
#define SSH_FXP_REMOVE			13
#define SSH_FXP_MKDIR			14
#define SSH_FXP_RMDIR			15
#define SSH_FXP_REALPATH		16
#define SSH_FXP_STAT			17
#define SSH_FXP_RENAME			18
#define SSH_FXP_READLINK		19
#define SSH_FXP_SYMLINK			20
#define SSH_FXP_STATUS			101
#define SSH_FXP_HANDLE			102
#define SSH_FXP_DATA			103
#define SSH_FXP_NAME			104
#define SSH_FXP_ATTRS			105

/* SFTP attribute presence flags.  When these flags are set, the
   corresponding file attribute value is present */

#define SSH_FILEXFER_ATTR_SIZE			0x01
#define SSH_FILEXFER_ATTR_UIDGID		0x02
#define SSH_FILEXFER_ATTR_PERMISSIONSv3	0x04
#define SSH_FILEXFER_ATTR_ACMODTIME		0x08
#define SSH_FILEXFER_ATTR_ACCESSTIME	0x08
#define SSH_FILEXFER_ATTR_CREATETIME	0x10
#define SSH_FILEXFER_ATTR_MODIFYTIME	0x20
#define SSH_FILEXFER_ATTR_PERMISSIONSv4	0x40
#define SSH_FILEXFER_ATTR_ACL			0x40
#define SSH_FILEXFER_ATTR_OWNERGROUP	0x80
#define SSH_FILEXFER_ATTR_SUBSECOND_TIMES 0x100
#define SSH_FILEXFER_ATTR_EXTENDED		0x80000000

/* SFTP file open/create flags */

#define SSH_FXF_READ			0x01
#define SSH_FXF_WRITE			0x02
#define SSH_FXF_APPEND			0x04
#define SSH_FXF_CREAT			0x08
#define SSH_FXF_TRUNC			0x10
#define SSH_FXF_EXCL			0x20
#define SSH_FXF_TEXT			0x40

/* SFTP file types */

#define SSH_FILETYPE_REGULAR	1
#define SSH_FILETYPE_DIRECTORY	2
#define SSH_FILETYPE_SYMLINK	3
#define SSH_FILETYPE_SPECIAL	4
#define SSH_FILETYPE_UNKNOWN	5

/* SFTP status codes */

#define SSH_FX_OK				0
#define SSH_FX_EOF				1
#define SSH_FX_NO_SUCH_FILE		2
#define SSH_FX_PERMISSION_DENIED 3
#define SSH_FX_FAILURE			4
#define SSH_FX_BAD_MESSAGE		5
#define SSH_FX_NO_CONNECTION	6
#define SSH_FX_CONNECTION_LOST	7
#define SSH_FX_OP_UNSUPPORTED	8
#define SSH_FX_INVALID_HANDLE	9
#define SSH_FX_NO_SUCH_PATH		10
#define SSH_FX_FILE_ALREADY_EXISTS 11
#define SSH_FX_WRITE_PROTECT	12
#define SSH_FX_NO_MEDIA			13

/* A structure to contain SFTP file attributes */

typedef struct {
	BOOLEAN isDirectory;		/* Whether directory or normal file */
	long size;					/* File size */
	int permissions;			/* File permissions */
	time_t ctime, atime, mtime;	/* File create, access, mod times */
	} SFTP_ATTRS;

/* A structure to contain SFTP session information */

#define MAX_HANDLE_SIZE		16

typedef struct {
	int version;				/* SFTP protocol version */
	long id;					/* Session ID */
	BYTE handle[ MAX_HANDLE_SIZE ];	/* File handle */
	int handleSize;
	} SFTP_INFO;

/* Read/write SFTP attributes.  This changed completely from v3 to v4, so we 
   have to treat them as special-cases:

	uint32		flags
	byte		file_type
	uint64		size (present if ATTR_SIZE)
	string		owner (present if ATTR_OWNERGROUP)
	string		group (present if ATTR_OWNERGROUP)
	uint32		permissions (present if ATTR_PERMISSIONS)
	uint64		atime (present if ATTR_ACCESSTIME)
	uint32		atime_nseconds (present if ATTR_SUBSECOND_TIMES)
	uint64		createtime (present if ATTR_CREATETIME)
	uint32		createtime_nseconds (present if ATTR_SUBSECOND_TIMES)
	uint64		mtime (present if ATTR_MODIFYTIME)
	uint32		mtime_nseconds (present if ATTR_SUBSECOND_TIMES)
	string		acl (present if ATTR_ACL)
	uint32		extended_count (present if ATTR_EXTENDED)
		string	extended_type
		string	extended_value
   		[ extended_count type/value pairs ] */

static int sizeofAttributes( SFTP_ATTRS *attributes, const int version )
	{
	int size = UINT32_SIZE;	/* Flags */

	if( version < 4 )
		{
		if( attributes->size != CRYPT_UNUSED )
			size += UINT64_SIZE;
		if( attributes->permissions != CRYPT_UNUSED )
			size += UINT32_SIZE;
		if( attributes->atime )
			size += UINT32_SIZE;
		if( attributes->mtime )
			size += UINT32_SIZE;
		}
	else
		{
		size++;
		if( attributes->size != CRYPT_UNUSED )
			size += UINT64_SIZE;
		if( attributes->permissions != CRYPT_UNUSED )
			size += UINT32_SIZE;
		if( attributes->ctime )
			size += UINT64_SIZE;
		if( attributes->atime )
			size += UINT64_SIZE;
		if( attributes->mtime )
			size += UINT64_SIZE;
		}

	return( size );
	}

static int readAttributes( STREAM *stream, SFTP_ATTRS *attributes, const int version )
	{
	long flags;

	memset( attributes, 0, sizeof( SFTP_ATTRS ) );
	attributes->permissions = CRYPT_UNUSED;
	attributes->size = CRYPT_UNUSED;

	/* Read basic attribute information: File size, and owner, and
	   permissions */
	flags = readUint32( stream );
	if( cryptStatusError( flags ) )
		return( flags );
	if( version < 4 )
		{
		if( flags & SSH_FILEXFER_ATTR_SIZE )
			attributes->size = readUint64( stream );
		if( flags & SSH_FILEXFER_ATTR_UIDGID )
			{
			readUint32( stream );
			readUint32( stream );
			}
		if( flags & SSH_FILEXFER_ATTR_PERMISSIONSv3 )
			attributes->permissions = readUint32( stream );

		/* Read file access and modify times */
		if( flags & SSH_FILEXFER_ATTR_ACMODTIME )
			{
			readUint32Time( stream, &attributes->atime );
			readUint32Time( stream, &attributes->mtime );
			}
		}
	else
		{
		if( flags & SSH_FILEXFER_ATTR_SIZE )
			attributes->size = readUint64( stream );
		if( flags & SSH_FILEXFER_ATTR_OWNERGROUP )
			{
			readString32( stream, NULL, NULL, 0 );
			readString32( stream, NULL, NULL, 0 );
			}
		if( flags & SSH_FILEXFER_ATTR_PERMISSIONSv4 )
			attributes->permissions = readUint32( stream );

		/* Read file create, access, and modify times */
		if( flags & SSH_FILEXFER_ATTR_ACCESSTIME )
			{
			readUint64Time( stream, &attributes->atime );
			if( flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES )
				readUint32( stream );
			}
		if( flags & SSH_FILEXFER_ATTR_CREATETIME )
			{
			readUint64Time( stream, &attributes->ctime );
			if( flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES )
				readUint32( stream );
			}
		if( flags & SSH_FILEXFER_ATTR_MODIFYTIME )
			{
			readUint64Time( stream, &attributes->mtime );
			if( flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES )
				readUint32( stream );
			}
		}

	/* Read ACLs and extended attribute type/value pairs, the one thing that 
	   stayed the same from v3 to v4 */
	if( flags & SSH_FILEXFER_ATTR_ACL )
		readString32( stream, NULL, NULL, 0 );
	if( flags & SSH_FILEXFER_ATTR_EXTENDED )
		{
		int extAttrCount = readUint32( stream );

		if( cryptStatusError( extAttrCount ) )
			return( extAttrCount );
		while( extAttrCount > 0 )
			{
			readString32( stream, NULL, NULL, 0 );
			readString32( stream, NULL, NULL, 0 );
			extAttrCount--;
			}
		}

	return( sGetStatus( stream ) );
	}

static int writeAttributes( STREAM *stream, SFTP_ATTRS *attributes, const int version )
	{
	int flags = 0;

	if( version < 4 )
		{
		/* Indicate which attribute values we're going to write */
		if( attributes->size != CRYPT_UNUSED )
			flags |= SSH_FILEXFER_ATTR_SIZE;
		if( attributes->permissions != CRYPT_UNUSED )
			flags |= SSH_FILEXFER_ATTR_PERMISSIONSv3;
		if( attributes->atime )
			flags |= SSH_FILEXFER_ATTR_ACMODTIME;
		writeUint32( stream, flags );

		/* Write the optional attributes */
		if( attributes->size != CRYPT_UNUSED )
			writeUint64( stream, attributes->size );
		if( attributes->permissions != CRYPT_UNUSED )
			writeUint32( stream, attributes->permissions );
		if( attributes->atime )
			{
			writeUint32Time( stream, attributes->atime );
			writeUint32Time( stream, attributes->mtime );
			}
		}
	else
		{
		/* Indicate which attribute values we're going to write */
		if( attributes->size != CRYPT_UNUSED )
			flags |= SSH_FILEXFER_ATTR_SIZE;
		if( attributes->permissions != CRYPT_UNUSED )
			flags |= SSH_FILEXFER_ATTR_PERMISSIONSv4;
		if( attributes->ctime )
			flags |= SSH_FILEXFER_ATTR_CREATETIME;
		if( attributes->atime )
			flags |= SSH_FILEXFER_ATTR_ACCESSTIME;
		if( attributes->mtime )
			flags |= SSH_FILEXFER_ATTR_MODIFYTIME;
		writeUint32( stream, flags );
		sputc( stream, attributes->isDirectory ? \
					   SSH_FILETYPE_DIRECTORY : SSH_FILETYPE_REGULAR );

		/* Write the optional attributes */
		if( attributes->size != CRYPT_UNUSED )
			writeUint64( stream, attributes->size );
		if( attributes->permissions != CRYPT_UNUSED )
			writeUint32( stream, attributes->permissions );
		if( attributes->ctime )
			writeUint64Time( stream, attributes->ctime );
		if( attributes->atime )
			writeUint64Time( stream, attributes->atime );
		if( attributes->mtime )
			writeUint64Time( stream, attributes->mtime );
		}

	return( sGetStatus( stream ) );
	}

/* Read/write SFTP status:

	uint32		id
	uint32		error/status code
	string		error message (ISO-10646 UTF-8 [RFC-2279])
	string		language tag (as defined in [RFC-1766]) */

static int sizeofStatus( const char *sshStatusString )
	{
	return( UINT32_SIZE + UINT32_SIZE + \
			( UINT32_SIZE + strlen( sshStatusString ) ) + \
			UINT32_SIZE );
	}

static int readStatus( STREAM *stream, SFTP_INFO *info )
	{
	static const struct {
		const int sftpStatus, cryptlibStatus;
		} sftpStatusMap[] = {
		{ SSH_FX_OK, CRYPT_OK },
		{ SSH_FX_EOF, CRYPT_ERROR_COMPLETE },
		{ SSH_FX_NO_SUCH_FILE, CRYPT_ERROR_NOTFOUND },
		{ SSH_FX_PERMISSION_DENIED, CRYPT_ERROR_PERMISSION },
		{ SSH_FX_FAILURE, CRYPT_ERROR_FAILED },
		{ SSH_FX_BAD_MESSAGE, CRYPT_ERROR_BADDATA },
		{ SSH_FX_NO_CONNECTION, CRYPT_ERROR_FAILED },
		{ SSH_FX_CONNECTION_LOST, CRYPT_ERROR_FAILED },
		{ SSH_FX_OP_UNSUPPORTED, CRYPT_ERROR_NOTAVAIL },
		{ SSH_FX_INVALID_HANDLE, CRYPT_ERROR_BADDATA },
		{ SSH_FX_NO_SUCH_PATH, CRYPT_ERROR_NOTFOUND },
		{ SSH_FX_FILE_ALREADY_EXISTS, CRYPT_ERROR_DUPLICATE },
		{ SSH_FX_WRITE_PROTECT, CRYPT_ERROR_PERMISSION },
		{ SSH_FX_NO_MEDIA, CRYPT_ERROR_FAILED },
		{ CRYPT_ERROR, CRYPT_ERROR_FAILED }
		};
	int value, i, status;

	/* Read the status info and make sure it's valid */
	value = readUint32( stream );
	status = readUint32( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( value != info->id )
		return( CRYPT_ERROR_BADDATA );

	/* Translate the SFTP status into a cryptlib status */
	for( i = 0; sftpStatusMap[ i ].sftpStatus != CRYPT_ERROR && \
				sftpStatusMap[ i ].sftpStatus != status; i++ );
	status = sftpStatusMap[ i ].cryptlibStatus;

	return( status );
	}

static int writeStatus( STREAM *stream, SFTP_INFO *info, const int sshStatus,
						const char *sshStatusString )
	{
	writeUint32( stream, info->id );
	writeUint32( stream, sshStatus );
	writeString32( stream, sshStatusString, strlen( sshStatusString ) );
	return( writeString32( stream, "", 0 ) );
	}

static int readSftpPacket( const CRYPT_SESSION cryptSession, void *buffer, 
						   const int bufSize )
	{
	int bytesCopied, status;

	status = cryptPopData( cryptSession, buffer, BUFFER_SIZE, &bytesCopied );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: Couldn't read data from SFTP client, status %d, line "
				"%d.\n", status, __LINE__ );
		return( status );
		}
	return( bytesCopied > 0 ? bytesCopied : CRYPT_ERROR_UNDERFLOW );
	}

static int writeSftpPacket( const CRYPT_SESSION cryptSession, const void *data, 
							const int length )
	{
	int bytesCopied, status;

	status = cryptPushData( cryptSession, data, length, &bytesCopied );
	if( cryptStatusOK( status ) )
		status = cryptFlushData( cryptSession );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: Couldn't write data to SFTP client, status %d, line "
				"%d.\n", status, __LINE__ );
		return( status );
		}
	if( bytesCopied < length )
		{
		printf( "SVR: Only wrote %d of %d bytes of SFTP data, line %d.\n", 
				bytesCopied, length, __LINE__ );
		return( status );
		}
	return( CRYPT_OK );
	}

static int sendAck( const CRYPT_SESSION cryptSession, SFTP_INFO *sftpInfo )
	{
	STREAM stream;
	BYTE buffer[ 128 ];
	int length;

	/* Ack an SFTP packet */
	sMemOpen( &stream, buffer, 128 );
	writeUint32( &stream, 1 + sizeofStatus( "" ) );
	sputc( &stream, SSH_FXP_STATUS );
	writeStatus( &stream, sftpInfo, SSH_FX_OK, "" );
	length = stell( &stream );
	sMemDisconnect( &stream );
	return( writeSftpPacket( cryptSession, buffer, length ) );
	}

int sftpServer( const CRYPT_SESSION cryptSession )
	{
	STREAM stream;
	SFTP_ATTRS sftpAttrs;
	SFTP_INFO sftpInfo;
	BYTE buffer[ BUFFER_SIZE ], nameBuffer[ 128 ];
	time_t xferTime;
	long xferCount = 0, dataLength;
	int length, value, status;

	cryptSetAttribute( cryptSession, CRYPT_OPTION_NET_TIMEOUT, 30 );

	memset( &sftpInfo, 0, sizeof( SFTP_INFO ) );

	/* Read the client's FXP_INIT and send our response */
	status = readSftpPacket( cryptSession, buffer, BUFFER_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, buffer, status );
	length = readUint32( &stream );
	value = sgetc( &stream );
	if( ( length != 1 + 4 ) || ( value != SSH_FXP_INIT ) )
		return( CRYPT_ERROR_BADDATA );
	sftpInfo.version = readUint32( &stream );
	sMemDisconnect( &stream );
	printf( "SVR: Client supports SFTP version %d.\n", sftpInfo.version );
	sMemOpen( &stream, buffer, BUFFER_SIZE );
	writeUint32( &stream, 1 + 4 );
	sputc( &stream, SSH_FXP_VERSION );
	writeUint32( &stream, 3 );
	length = stell( &stream );
	sMemDisconnect( &stream );
	status = writeSftpPacket( cryptSession, buffer, length );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the client's FXP_OPEN and send our response */
	status = readSftpPacket( cryptSession, buffer, BUFFER_SIZE );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptSession, "SVR: Attempt to read data from "
					   "client", status, __LINE__ );
		return( status );
		}
	sMemConnect( &stream, buffer, status );
	length = readUint32( &stream );
	value = sgetc( &stream );
	if( value == SSH_FXP_STAT )
		{
		/* See what the client is after */
		sftpInfo.id = readUint32( &stream );
		length = readUint32( &stream );
		sread( &stream, nameBuffer, length );
		sMemDisconnect( &stream );
		nameBuffer[ length ] = '\0';
		printf( "SVR: Client tried to stat file '%s'.\n", nameBuffer );
		if( strcmp( nameBuffer, "." ) )
			{
			puts( "SVR: Don't know how to respond to stat request for this "
				  "file." );
			return( CRYPT_ERROR_NOTAVAIL );
			}

		/* Send back a dummy response */
		memset( &sftpAttrs, 0, sizeof( SFTP_ATTRS ) );
		sftpAttrs.isDirectory = TRUE;
		sftpAttrs.permissions = 0777;
		sftpAttrs.size = CRYPT_UNUSED;
		sftpAttrs.atime = sftpAttrs.ctime = sftpAttrs.mtime = time( NULL );
		length = sizeofAttributes( &sftpAttrs, sftpInfo.version );
		sMemOpen( &stream, buffer, BUFFER_SIZE );
		writeUint32( &stream, 1 + UINT32_SIZE + length );
		sputc( &stream, SSH_FXP_ATTRS );
		writeUint32( &stream, sftpInfo.id );
		writeAttributes( &stream, &sftpAttrs, sftpInfo.version );
		length = stell( &stream );
		sMemDisconnect( &stream );
		status = writeSftpPacket( cryptSession, buffer, length );
		if( cryptStatusError( status ) )
			return( status );

		/* See what they want next */
		status = readSftpPacket( cryptSession, buffer, BUFFER_SIZE );
		if( cryptStatusError( status ) )
			{
			printExtError( cryptSession, "SVR: Attempt to read data from "
						   "client", status, __LINE__ );
			return( status );
			}
		sMemConnect( &stream, buffer, status );
		length = readUint32( &stream );
		value = sgetc( &stream );
		}
	if( value == SSH_FXP_OPEN )
		{
		/* See what the client is after */
		sftpInfo.id = readUint32( &stream );
		length = readUint32( &stream );
		sread( &stream, nameBuffer, length );
		value = readUint32( &stream );
		readAttributes( &stream, &sftpAttrs, sftpInfo.version );
		sMemDisconnect( &stream );
		nameBuffer[ length ] = '\0';
		printf( "Client tried to open file '%s', mode %02X, length %d.\n", 
				nameBuffer, value, sftpAttrs.size );

		/* Putty for some reason tries to open the current directory for 
		   create (rather than the filename), and bails out when it gets a 
		   permission-denied.  So I guess we tell it to go ahead... */
		sMemOpen( &stream, buffer, BUFFER_SIZE );
		writeUint32( &stream, 1 + UINT32_SIZE + ( UINT32_SIZE + 1 ) );
		sputc( &stream, SSH_FXP_HANDLE );
		writeUint32( &stream, sftpInfo.id );
		writeUint32( &stream, 1 );
		sputc( &stream, 1 );
		length = stell( &stream );
		sMemDisconnect( &stream );
		status = writeSftpPacket( cryptSession, buffer, length );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Now we're in the write loop... */
	xferTime = time( NULL );
	dataLength = 0;
	while( TRUE )
		{
		/* See what they want next */
		status = readSftpPacket( cryptSession, buffer, BUFFER_SIZE );
		if( cryptStatusError( status ) )
			{
			printExtError( cryptSession, "SVR: Attempt to read data from "
						   "client", status, __LINE__ );
			return( status );
			}
		if( status < 1 )
			{
			printf( "SVR: Read 0 bytes from client.\n" );
			return( CRYPT_ERROR_UNDERFLOW );
			}
		if( dataLength > 0 )
			{
			xferCount += status;
			dataLength -= status;
			printf( "SRV: -------- : %d.\r", xferCount );
			if( dataLength <= 0 )
				break;
			continue;
			}
		sMemConnect( &stream, buffer, status );
		length = readUint32( &stream );
		if( status < BUFFER_SIZE && ( length != status - UINT32_SIZE ) )
			{
			printf( "Didn't read complete packet, length = %d, byte count = "
					"%d.\n", length, status - UINT32_SIZE );
			}
		value = sgetc( &stream );
		if( value != SSH_FXP_WRITE )
			break;
		sftpInfo.id = readUint32( &stream );
		readString32( &stream, nameBuffer, &length, 128 );
		value = readUint64( &stream );
		dataLength = readUint32( &stream );
		printf( "SRV: %8d : %d.\r", value, length );
		xferCount += status - stell( &stream );
		dataLength -= status - stell( &stream );
		sMemDisconnect( &stream );

		/* Ack the write */
		if( dataLength <= 0 )
			{
			status = sendAck( cryptSession, &sftpInfo );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	xferTime = time( NULL ) - xferTime;
	printf( "Transfer time = %d seconds, %ld bytes, %d bytes/sec.\n", 
			xferTime, xferCount, xferCount / xferTime );

	/* Clean up */
	if( value != SSH_FXP_CLOSE )
		{
		printf( "SVR: Client sent unexpected packet %d.\n", value );
		return( CRYPT_ERROR_BADDATA );
		}
	sftpInfo.id = readUint32( &stream );
	status = sendAck( cryptSession, &sftpInfo );
	if( cryptStatusError( status ) )
		return( status );
	status = readSftpPacket( cryptSession, buffer, BUFFER_SIZE );
	if( status == CRYPT_ERROR_COMPLETE )
		{
		puts( "SVR: Client has closed the channel." );
		return( CRYPT_OK );
		}
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, buffer, status );
	length = readUint32( &stream );
	value = sgetc( &stream );

	return( CRYPT_OK );
	}

#define SFTP_DATA_AMOUNT	( 1024 * 1024 )

int sftpClient( const CRYPT_SESSION cryptSession )
	{
	STREAM stream;
	SFTP_ATTRS sftpAttrs;
	SFTP_INFO sftpInfo;
	BYTE buffer[ BUFFER_SIZE ];
	long totalLength = SFTP_DATA_AMOUNT;
	int length, value, status;

	cryptSetAttribute( cryptSession, CRYPT_OPTION_NET_TIMEOUT, 30 );

	memset( &sftpInfo, 0, sizeof( SFTP_INFO ) );

	/* Send our FXP_INIT and read back the response */
	sMemOpen( &stream, buffer, BUFFER_SIZE );
	writeUint32( &stream, 1 + 4 );
	sputc( &stream, SSH_FXP_INIT );
	writeUint32( &stream, 3 );
	length = stell( &stream );
	sMemDisconnect( &stream );
	status = writeSftpPacket( cryptSession, buffer, length );
	if( cryptStatusError( status ) )
		return( status );
	status = readSftpPacket( cryptSession, buffer, BUFFER_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, buffer, status );
	length = readUint32( &stream );
	value = sgetc( &stream );
	if( ( length != 1 + 4 ) || ( value != SSH_FXP_VERSION ) )
		return( CRYPT_ERROR_BADDATA );
	sftpInfo.version = readUint32( &stream );
	sMemDisconnect( &stream );
	printf( "Server supports SFTP version %d.\n", sftpInfo.version );

	/* Open the file to transfer */
	memset( &sftpAttrs, 0, sizeof( SFTP_ATTRS ) );
	sftpAttrs.permissions = 0777;
	sftpAttrs.size = CRYPT_UNUSED;
	sftpAttrs.atime = sftpAttrs.ctime = sftpAttrs.mtime = time( NULL );
	length = sizeofAttributes( &sftpAttrs, sftpInfo.version );
	sMemOpen( &stream, buffer, BUFFER_SIZE );
	writeUint32( &stream, 1 + UINT32_SIZE + ( UINT32_SIZE + 8 ) + UINT32_SIZE + length );
	sputc( &stream, SSH_FXP_OPEN );
	writeUint32( &stream, 1 );
	writeString32( &stream, "test.dat", 8 );
	writeUint32( &stream, SSH_FXF_CREAT | SSH_FXF_WRITE	);
	writeAttributes( &stream, &sftpAttrs, sftpInfo.version );
	length = stell( &stream );
	sMemDisconnect( &stream );
	status = writeSftpPacket( cryptSession, buffer, length );
	if( cryptStatusError( status ) )
		return( status );
	status = readSftpPacket( cryptSession, buffer, BUFFER_SIZE );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptSession, "Attempt to read data from server", 
					   status, __LINE__ );
		return( status );
		}
	sMemConnect( &stream, buffer, status );
	length = readUint32( &stream );
	value = sgetc( &stream );
	readUint32( &stream );
	readString32( &stream, sftpInfo.handle, &sftpInfo.handleSize, 
				  MAX_HANDLE_SIZE );
	sMemDisconnect( &stream );
	if( value != SSH_FXP_HANDLE )
		{
		printf( "Server sent packet %d, expected file handle.\n", value );
		return( CRYPT_ERROR_BADDATA );
		}

	/* Send the file (just 1MB of test data) */
	sMemOpen( &stream, buffer, BUFFER_SIZE );
	writeUint32( &stream, 1 + UINT32_SIZE + \
						  ( UINT32_SIZE + sftpInfo.handleSize ) + \
						  UINT64_SIZE + ( UINT32_SIZE + SFTP_DATA_AMOUNT ) );
	sputc( &stream, SSH_FXP_WRITE );
	writeUint32( &stream, sftpInfo.id );
	writeString32( &stream, sftpInfo.handle, sftpInfo.handleSize );
	writeUint64( &stream, 0 );
	writeUint32( &stream, SFTP_DATA_AMOUNT );
	length = stell( &stream );
	memset( buffer + length, '*', BUFFER_SIZE - length );
	status = writeSftpPacket( cryptSession, buffer, BUFFER_SIZE );
	if( cryptStatusError( status ) )
		return( status );
	totalLength -= BUFFER_SIZE - length;
	while( totalLength > 0 )
		{
		memset( buffer, '*', BUFFER_SIZE );
		status = writeSftpPacket( cryptSession, buffer, 
								  min( totalLength, BUFFER_SIZE ) );
		if( cryptStatusError( status ) )
			return( status );
		totalLength -= min( totalLength, BUFFER_SIZE );
		}

	/* Wait for the ack */
	status = readSftpPacket( cryptSession, buffer, BUFFER_SIZE );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptSession, "Attempt to read data from server", 
					   status, __LINE__ );
		return( status );
		}

	return( CRYPT_OK );
	}
#endif /* WINDOWS_THREADS */
