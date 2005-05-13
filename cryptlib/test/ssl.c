/****************************************************************************
*																			*
*							cryptlib SSL/TLS Routines						*
*						Copyright Peter Gutmann 1998-2004					*
*																			*
****************************************************************************/

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

/****************************************************************************
*																			*
*								SSL/TLS Routines Test						*
*																			*
****************************************************************************/

/* If we're using local sockets, we have to pull in the winsock defines */

#if defined( __WINDOWS__ ) && !defined( _WIN32_WCE )
  #include <winsock.h>
#endif /* __WINDOWS__ && !_WIN32_WCE */

/* There are various servers running that we can use for testing, the
   following remapping allows us to switch between them.  Notes:

	Server 1: Local loopback.
	Server 2: Generic test server.
	Server 3: ~40K data returned.
	Server 4: Sends zero-length blocks (actually a POP server).
	Server 5: Novell GroupWise, requires CRYPT_OPTION_CERT_COMPLIANCELEVEL = 
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
	Server 10: Newer IIS (certificate is actually for akamai.net, so the SSL
			   may not be Microsoft's at all).
	Server 11: IBM (Websphere?).
	Server 12: Server is running TLS with SSL disabled, drops connection when
			   it sees an SSL handshake.  MSIE in its default config (TLS
			   disabled) can't connect to this server.
	Server 13: GnuTLS.
	Server 14: GnuTLS test server with TLS 1.1.
	Server 15: Can only do SSLv2, server hangs when sent an SSLv3 handshake.
	Server 16: Can't handle TLS 1.1 handshake (drops connection).
	Server 17: Can't handle TLS 1.1 handshake (drops connection).  Both of
			   these servers are sitting behind NetApp NetCache's (see also
			   server 7), which could be the cause of the problem.
	Server 18: Generic OpenSSL server */

#define SSL_SERVER_NO	2
#define TLS_SERVER_NO	2
#define TLS11_SERVER_NO	2

static const struct {
	const C_STR name;
	const char *path;
	} sslInfo[] = {
	{ NULL, NULL },
	/*  1 */ { TEXT( "localhost" ), "/" },
	/*  2 */ { TEXT( "https://www.amazon.com" ), "/" },
	/*  3 */ { TEXT( "https://www.cs.berkeley.edu" ), "/~daw/people/crypto.html" },
	/*  4 */ { TEXT( "pop.web.de:995" ), "/" },
	/*  5 */ { TEXT( "imap4-gw.uni-regensburg.de:993" ), "/" },
	/*  6 */ { TEXT( "securepop.t-online.de:995" ), "/" },
	/*  7 */ { TEXT( "https://homedir.wlv.ac.uk" ), "/" },
	/*  8 */ { TEXT( "https://www.horaso.com:20443" ), "/" },
	/*  9 */ { TEXT( "https://homedir.wlv.ac.uk" ), "/" },
	/* 10 */ { TEXT( "https://www.microsoft.com" ), "/" },
	/* 11 */ { TEXT( "https://alphaworks.ibm.com/" ), "/" },
	/* 12 */ { TEXT( "https://webmount.turbulent.ca/" ), "/" },
	/* 13 */ { TEXT( "https://www.gnutls.org/" ), "/" },
	/* 14 */ { TEXT( "https://www.gnutls.org:5555/" ), "/" },
	/* 15 */ { TEXT( "https://www.networksolutions.com/" ), "/" },
	/* 16 */ { TEXT( "https://olb.westpac.com.au/" ), "/" },
	/* 17 */ { TEXT( "https://www.hertz.com/" ), "/" },
	/* 18 */ { TEXT( "https://www.openssl.org/" ), "/" },
	{ NULL, NULL }
	};

/* Various servers used for STARTTLS/STLS/AUTH TLS testing.  Notes:

	Server 1: SMTP: mailbox.ucsd.edu:25 (132.239.1.57) requires a client cert.
	Server 2: POP: pop.cae.wisc.edu:1110 (144.92.240.11) OK.
	Server 3: SMTP: smtpauth.cae.wisc.edu:25 (144.92.12.93) requires a client 
			  cert.
	Server 4: SMTP: send.columbia.edu:25 (128.59.59.23) returns invalid cert 
			  (lower compliance level to fix).
	Server 5: POP: pop3.myrealbox.com:110 (192.108.102.201) returns invalid 
			  cert (lower compliance level to fix).
	Server 6: Encrypted POP: securepop.t-online.de:995 (194.25.134.46) direct 
			  SSL connect.
	Server 7: FTP: ftp.windsorchapel.net:21 (68.38.166.195) sends redundant 
			  client cert request with invalid length.
	Server 8: POP: webmail.chm.tu-dresden.de:110 (141.30.198.37), another
			  GroupWise server (see the server comments above) with b0rken
			  certs.

			  To test FTP with SSL/TLS manually: Disable auto-login with FTP, 
			  then send an RFC 2389 FEAT command to check security facilities.  
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
	/* 1 */	{ "132.239.1.57", 25, PROTOCOL_SMTP },
	/* 2 */	{ "144.92.240.11", 1110, PROTOCOL_POP },
	/* 3 */	{ "144.92.12.93", 25, PROTOCOL_SMTP },
	/* 4 */	{ "128.59.59.23", 25, PROTOCOL_SMTP },
	/* 5 */	{ "192.108.102.201", 110, PROTOCOL_POP },
	/* 6 */	{ "194.25.134.46", 995, PROTOCOL_POP_DIRECT },
	/* 7 */	{ "68.38.166.195", 21, PROTOCOL_FTP },
	/* 8 */	{ "141.30.198.37", 110, PROTOCOL_POP },
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

#if defined( __WINDOWS__ ) && !defined( _WIN32_WCE )

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
#endif /* __WINDOWS__ && !_WIN32_WCE */

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
	const C_STR serverName = ( version == 0 ) ? \
								sslInfo[ SSL_SERVER_NO ].name : \
							 ( version == 1 ) ? \
								sslInfo[ TLS_SERVER_NO ].name : \
								sslInfo[ TLS11_SERVER_NO ].name;
	BYTE *bulkBuffer;
	char buffer[ FILEBUFFER_SIZE ];
#if defined( __WINDOWS__ ) && !defined( _WIN32_WCE )
	int netSocket;
#endif /* __WINDOWS__ && !_WIN32_WCE */
	int bytesCopied, protocol = PROTOCOL_SMTP, status;

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
#if defined( __WINDOWS__ ) && !defined( _WIN32_WCE )
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
#elif defined( _WIN32_WCE )
			status = cryptSetAttribute( cryptSession,
							CRYPT_SESSINFO_NETWORKSOCKET, 1 );
#else
			status = cryptSetAttribute( cryptSession,
							CRYPT_SESSINFO_NETWORKSOCKET, fileno( stdin ) );
#endif /* OS-specific local socket handling */
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
								paramStrlen( serverName ) );
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
									paramStrlen( SSL_USER_NAME ) );
		if( cryptStatusOK( status ) )
			status = cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_PASSWORD, SSL_PASSWORD,
									paramStrlen( SSL_PASSWORD ) );
		if( isServer )
			{
#if 0	/* Old PSK mechanism */
			/* If it's a server session, set an additional username/password
			   to test the ability of the session cache to store multiple
			   shared secrets */
			status = cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_USERNAME, TEXT( "0000" ), 
									paramStrlen( TEXT( "0000" ) ) );
			if( cryptStatusOK( status ) )
				status = cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_PASSWORD, TEXT( "0000" ), 
									paramStrlen( TEXT( "0000" ) ) );
			if( cryptStatusOK( status ) && \
				cryptStatusOK( \
					cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_USERNAME, TEXT( "0000" ), 
									paramStrlen( TEXT( "0000" ) ) ) ) )
				{
				printf( "SVR: Addition of duplicate entry to SSL session "
						"cache wasn't detected, line %d.\n", __LINE__ );
				return( FALSE );
				}
#endif /* 0 */

#if 0		/* Check the functioning of the session cache's LRU mechanism */
			{
			int i;

			for( i = 0; i < 1024 + 2000; i++ )
				{
				char userName[ 64 ];

				sprintf( userName, "user%04d", i );
				status = cryptSetAttributeString( cryptSession,
										CRYPT_SESSINFO_USERNAME, userName, 
										paramStrlen( userName ) );
				if( cryptStatusOK( status ) )
					status = cryptSetAttributeString( cryptSession,
										CRYPT_SESSINFO_PASSWORD, userName, 
										paramStrlen( userName ) );
				if( cryptStatusError( status ) )
					{
					printf( "SVR: Error %d during SSL server cache LRU "
							"test, line %d.\n", status, __LINE__ );
					return( FALSE );
					}
				}
			}
#endif /* 0 */
			}
		}
	if( cryptStatusError( status ) )
		{
		if( localSocket )
			{
#if defined( __WINDOWS__ ) && !defined( _WIN32_WCE )
			closesocket( netSocket );
			WSACleanup();
#else
			/* Creating a socket in a portable manner is too difficult so 
			   we've passed in a stdio handle, this should return an error 
			   since it's not a blocking socket */
			return( TRUE );
#endif /* __WINDOWS__ && !_WIN32_WCE */
			}
		printf( "cryptSetAttribute/AttributeString() failed with error code "
				"%d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
#if ( SSL_SERVER_NO == 5 ) || ( STARTTLS_SERVER_NO == 8 )
	cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   &version );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   CRYPT_COMPLIANCELEVEL_OBLIVIOUS );
#endif /* SSL servers with b0rken certs */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
#if ( SSL_SERVER_NO == 5 ) || ( STARTTLS_SERVER_NO == 8 )
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   version );
#endif /* SSL server with b0rken certs */
	if( isServer )
		{
		if( !printConnectInfo( cryptSession ) )
			return( FALSE );
		}
	if( cryptStatusError( status ) )
		{
		char strBuffer[ 128 ];

		if( localSocket )
			{
#if defined( __WINDOWS__ ) && !defined( _WIN32_WCE )
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
#endif /* __WINDOWS__ && !_WIN32_WCE */
			}
		sprintf( strBuffer, "%sAttempt to activate %s%s session",
				 isServer ? "SVR: " : "", localSession ? "local " : "", 
				 versionStr[ version ] );
		printExtError( cryptSession, strBuffer, status, __LINE__ );
		cryptDestroySession( cryptSession );
		if( bulkTransfer )
			free( bulkBuffer );
		if( status == CRYPT_ERROR_OPEN || status == CRYPT_ERROR_NOTFOUND )
			{
			/* These servers are constantly appearing and disappearing so if
			   we get a straight connect error we don't treat it as a serious
			   failure */
			puts( "  (Server could be down, faking it and continuing...)\n" );
			return( CRYPT_ERROR_FAILED );
			}
		return( FALSE );
		}

	/* Report the session security info */
	if( !printSecurityInfo( cryptSession, isServer, !sharedKey ) )
		return( FALSE );
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
		C_CHR userNameBuffer[ CRYPT_MAX_TEXTSIZE + 1 ];
		int length;

		status = cryptGetAttributeString( cryptSession,
										  CRYPT_SESSINFO_USERNAME, 
										  userNameBuffer, &length );
		if( cryptStatusError( status ) )
			{
			printf( "SVR: Couldn't read client user name, status %d, line "
					"%d.\n", status, __LINE__ );
			return( FALSE );
			}
#ifdef UNICODE_STRINGS
		userNameBuffer[ length / sizeof( wchar_t ) ] = TEXT( '\0' );
		printf( "SVR: Client user name = '%S'.\n", userNameBuffer );
#else
		userNameBuffer[ length ] = '\0';
		printf( "SVR: Client user name = '%s'.\n", userNameBuffer );
#endif /* UNICODE_STRINGS */
		}

	/* Send data over the SSL/TLS link.  If we're doing a bulk transfer
	   we use fully asynchronous I/O to verify the timeout handling in
	   the session code */
#if SSL_SERVER_NO == 3
	/* This server has a large amount of data on it, used to test high-
	   latency bulk transfers, so we set a larger timeout for the read */
	status = cryptSetAttribute( cryptSession, CRYPT_OPTION_NET_READTIMEOUT, 
								15 );
#else
	status = cryptSetAttribute( cryptSession, CRYPT_OPTION_NET_READTIMEOUT, 
								bulkTransfer ? 0 : 5 );
#endif /* SSL_SERVER_NO == 3 */
	if( bulkTransfer )
		{
		if( isServer )
			{
			long byteCount = 0;

			do
				{
				status = cryptPushData( cryptSession, bulkBuffer + byteCount,
										BULKDATA_BUFFER_SIZE - byteCount, 
										&bytesCopied );
				byteCount += bytesCopied;
				}
			while( ( cryptStatusOK( status ) || \
					 status == CRYPT_ERROR_TIMEOUT ) && \
				   byteCount < BULKDATA_BUFFER_SIZE );
			if( cryptStatusError( status ) )
				{
				printExtError( cryptSession, 
							   "SVR: Send of bulk data to client", status, 
							   __LINE__ );
				return( FALSE );
				}
			status = cryptFlushData( cryptSession );
			if( cryptStatusError( status ) )
				{
				printExtError( cryptSession, 
							   "SVR: Flush of bulk data to client", status, 
							   __LINE__ );
				return( FALSE );
				}
			if( byteCount != BULKDATA_BUFFER_SIZE )
				{
				printf( "Only sent %ld of %ld bytes.\n", byteCount,
						BULKDATA_BUFFER_SIZE );
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
			while( ( cryptStatusOK( status ) || \
					 status == CRYPT_ERROR_TIMEOUT ) && \
				   byteCount < BULKDATA_BUFFER_SIZE );
			if( cryptStatusError( status ) )
				{
				char strBuffer[ 256 ];

				sprintf( strBuffer, "Read of bulk data from server aborted "
									"after %d of %d bytes were read\n(last "
									"read = %d bytes), transfer", 
									byteCount, BULKDATA_BUFFER_SIZE, 
									bytesCopied );
				printExtError( cryptSession, strBuffer, status, __LINE__ );
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
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 819 )
#endif /* IBM medium iron */
			const char serverReply[] = \
				"HTTP/1.0 200 OK\n"
				"Date: Fri, 7 June 2005 20:02:07 GMT\n"
				"Server: cryptlib SSL/TLS test\n"
				"Content-Type: text/html\n"
				"Connection: Close\n"
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
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */

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

			/* Wait for the data to be flushed through to the client before 
			   we close the session */
			delayThread( 1 );
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
#if defined( __WINDOWS__ ) && !defined( _WIN32_WCE )
	if( localSocket )
		{
		closesocket( netSocket );
		WSACleanup();
		}
#endif /* __WINDOWS__ && !_WIN32_WCE */

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
	   complex to handle easily via a loopback test.  Note that with MSIE
	   this will require three lots of connects rather than two, because it 
	   handles an unknown cert by doing a resume, which consumes two lots of 
	   sessions, and then the third one is the actual session resume */
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
#endif /* WINDOWS_THREADS */
