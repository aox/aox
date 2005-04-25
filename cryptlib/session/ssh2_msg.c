/****************************************************************************
*																			*
*					cryptlib SSHv2 Control Message Management				*
*						Copyright Peter Gutmann 1998-2004					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "ssh.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../misc/misc_rw.h"
  #include "session.h"
  #include "ssh.h"
#else
  #include "crypt.h"
  #include "misc/misc_rw.h"
  #include "session/session.h"
  #include "session/ssh.h"
#endif /* Compiler-specific includes */

#ifdef USE_SSH2

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Read host name/address and port information and format it into string 
   form for the caller */

static int readAddressAndPort( SESSION_INFO *sessionInfoPtr, STREAM *stream, 
							   char *hostInfo, int *hostInfoLen )
	{
	BYTE stringBuffer[ CRYPT_MAX_TEXTSIZE + 8 ];
	char portBuffer[ 16 ];
	int stringLength, port, portLength, status;

	/* Clear return value */
	*hostInfo = '\0';
	*hostInfoLen = 0;

	/* Get the host and port:

		string	host
		uint32	port */
	status = readString32( stream, stringBuffer, &stringLength, 
						   CRYPT_MAX_TEXTSIZE - 4 );
	if( cryptStatusError( status ) || \
		stringLength <= 0 || stringLength > CRYPT_MAX_TEXTSIZE - 4 )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid host name value" );
	status = port = readUint32( stream );
	if( cryptStatusError( status ) || port <= 0 || port >= 65535L )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid port number value" );

	/* Convert the info into string form for the caller to process */
	portLength = sPrintf( portBuffer, ":%ld", port );
	memcpy( hostInfo, stringBuffer, stringLength );
	if( stringLength + portLength <= CRYPT_MAX_TEXTSIZE )
		{
		memcpy( hostInfo + stringLength, portBuffer, portLength );
		stringLength += portLength;
		}
	*hostInfoLen = stringLength;

	return( CRYPT_OK );
	}

/* Add or clear host name/address and port information */

static int getAddressAndPort( SESSION_INFO *sessionInfoPtr, STREAM *stream,
							  char *hostInfo, int *hostInfoLen )
	{
	int status;

	/* Read the address and port info */
	status = readAddressAndPort( sessionInfoPtr, stream, hostInfo, 
								 hostInfoLen );
	if( cryptStatusError( status ) )
		return( status );
	if( getChannelStatusAddr( sessionInfoPtr, hostInfo, \
							  *hostInfoLen ) != CHANNEL_NONE )
		{
		/* We're adding new forwarding info, if it already exists this is
		   an error */
		hostInfo[ *hostInfoLen ] = '\0';
		retExt( sessionInfoPtr, CRYPT_ERROR_DUPLICATE,
				"Received duplicate request for existing host/port %s", 
				hostInfo );
		}

	return( CRYPT_OK );
	}

static int clearAddressAndPort( SESSION_INFO *sessionInfoPtr, STREAM *stream )
	{
#if 0	/* This is a somewhat special-case function in that it does't apply
		   to an open channel but to a past request for forwarding that 
		   exists outside of the normal attribute space.  Until this type of
		   functionality is explicitly requested by users, we don't handle
		   this special-case non-attribute data setting */
	SSH_CHANNEL_INFO *channelInfoPtr;
	char hostInfo[ CRYPT_MAX_TEXTSIZE + 8 ];
	int hostInfoLen, status;

	/* Read the address and port info */
	status = readAddressAndPort( sessionInfoPtr, stream, hostInfo, 
								 &hostInfoLen );
	if( cryptStatusError( status ) )
		return( status );
	return( deleteChannelAddr( sessionInfoPtr, addrInfo, addrInfoLen ) );
#else
	return( CRYPT_OK );
#endif /* 0 */
	}

/****************************************************************************
*																			*
*							Client-side Channel Management					*
*																			*
****************************************************************************/

/* Create a request for the appropriate type of service, either encrypted-
   telnet, SFTP (or more generically a subsystem), or port forwarding.  
   There are several different port-forwarding mechanisms that we can use.  
   A global request of type "tcpip-forward" requests forwarding of a remote 
   port to the local system, specifying the remote port to be forwarded but
   without actually opening a session/channel, it's merely q request for
   future forwarding.  When a connection arrives on the remote port for 
   which forwarding has been requested, the remote system opens a channel of 
   type "forwarded-tcpip" to the local system.  To open a connection from a 
   locally-forwarded port to a port on the remote system, the local system 
   opens a channel of type "direct-tcpip" to the remote system:

	Pkt		Name			Arg1			Arg2		Comment
	---		----			----			----		-------
	open	"session"									Followed by pty-req 
														or subsys
	open	"fded-tcpip"	remote_info (in)			Server -> client in 
														response.to tcpip-fd
	open	"direct-tcpip"	remote_info		local_info	Client -> server, currently
														local_info = 127.0.0.1
	channel	"pty-req"
	channel "subsystem"		name
	global	"tcpip-fd"		remote_info (out)			Request for remote 
														forwarding */

static int createOpenRequest( SESSION_INFO *sessionInfoPtr, STREAM *stream )
	{
	const long channelNo = getCurrentChannelNo( sessionInfoPtr,
												CHANNEL_READ );
	const int maxPacketSize = sessionInfoPtr->sendBufSize - \
							  EXTRA_PACKET_SIZE;
	BYTE typeString[ CRYPT_MAX_TEXTSIZE + 8 ];
	BYTE arg1String[ CRYPT_MAX_TEXTSIZE + 8 ];
	BOOLEAN isPortForward = FALSE, isSubsystem = FALSE;
	int typeLen, arg1Len, packetOffset, status;

	/* Get the information that's needed for the channel we're about to 
	   create */
	status = getChannelAttribute( sessionInfoPtr, 
								  CRYPT_SESSINFO_SSH_CHANNEL_TYPE,
								  typeString, &typeLen );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status,
				"Missing channel type for channel activation" );
	if( !strCompare( typeString, "subsystem", 9 ) )
		isSubsystem = TRUE;
	if( !strCompare( typeString, "direct-tcpip", 12 ) || \
		!strCompare( typeString, "forwarded-tcpip", 15 ) )
		isPortForward = TRUE;
	if( isPortForward || isSubsystem )
		{
		status = getChannelAttribute( sessionInfoPtr, 
									  CRYPT_SESSINFO_SSH_CHANNEL_ARG1,
									  arg1String, &arg1Len );
		if( cryptStatusError( status ) )
			retExt( sessionInfoPtr, status,
					"Missing channel argument (%s) for channel "
					"activation", isPortForward ? \
						"host name/port" : "subsystem name" );

		/* If we know that the argument is a URL (rather than, say, a
		   subsystem name), check its validity */
		if( !isSubsystem )
			{
			URL_INFO urlInfo;

			status = sNetParseURL( &urlInfo, arg1String, arg1Len );
			if( cryptStatusError( status ) )
				retExt( sessionInfoPtr, status,
						"Invalid channel argument (%s) for channel "
						"activation", isPortForward ? \
							"host name/port" : "subsystem name" );
			}
		}

#if 0	/* Request forwarding of a port from the remote system to the local
		   one.  Once a connection arrives on the remote port it'll open a
		   channel to the local system of type "forwarded-tcpip".  Since 
		   this isn't a normal channel open, we return a special status to
		   let the caller know that there's nothing further to do */
	if( "tcpip-forward" )
		{
		URL_INFO urlInfo;

		/*	...
			byte	type = SSH_MSG_GLOBAL_REQUEST
			string	request_name = "tcpip-forward"
			boolean	want_reply = FALSE
			string	remote_address_to_bind (e.g. "0.0.0.0")
			uint32	remote_port_to_bind
		
		   Since this is a special-case request-only message, we let the
		   caller know that they don't have to proceed further with the
		   channel-open */
		sNetParseURL( &urlInfo, arg1String, arg1Len );
		packetOffset = continuePacketStreamSSH( stream, 
												SSH2_MSG_GLOBAL_REQUEST );
		writeString32( stream, "tcpip-forward", 0 );
		sputc( stream, 0 );
		writeString32( stream, urlInfo.host, urlInfo.hostLen );
		writeUint32( stream, urlInfo.port );
		status = wrapPacketSSH2( sessionInfoPtr, stream, packetOffset );
		return( cryptStatusError( status ) ? status : OK_SPECIAL );
		}
#endif /* 0 */

	/* Send a channel open:

		byte	type = SSH2_MSG_CHANNEL_OPEN
		string	channel_type
		uint32	sender_channel
		uint32	initial_window_size = MAX_WINDOW_SIZE
		uint32	max_packet_size = bufSize
		...

	   The use of security protocol-level flow control when there's already
	   a far better, heavily analysed and field-tested network protocol-
	   level flow control mechanism is just stupid.  All it does is create
	   performance handbrake where throughput can be reduced by as much as 
	   an order of magnitude due to SSH's "flow-control" getting in the way 
	   (Putty even has an FAQ entry "Why is SFTP so much slower than scp?", 
	   for which the correct answer should be "It's the SSH-level flow-
	   control braindamage").  For this reason cryptlib always advertises a 
	   maximum window size (effectively disabling the SSH-level flow 
	   control) and lets the network stack and network hardware take care of 
	   flow control, as they should */
	openPacketStreamSSH( stream, sessionInfoPtr, CRYPT_USE_DEFAULT, 
						 SSH2_MSG_CHANNEL_OPEN );
	if( isSubsystem )
		/* A subsystem is an additional layer on top of the standard 
		   channel, so we have to open the channel first and then add the
		   subsystem later via a channel request rather than opening it
		   directly */
		writeString32( stream, "session", 0 );
	else
		writeString32( stream, typeString, typeLen );
	writeUint32( stream, channelNo );
	writeUint32( stream, MAX_WINDOW_SIZE );
	writeUint32( stream, maxPacketSize );
	if( isPortForward )
		{
		URL_INFO urlInfo;

		/* The caller has requested a port-forwarding channel open, continue
		   the basic channel-open packet with port-forwarding info:

			...
			string	remote_host_to_connect
			uint32	rempte_port_to_connect
			string	local_originator_IP_address
			uint32	local_originator_port */
		sNetParseURL( &urlInfo, arg1String, arg1Len );
		writeString32( stream, urlInfo.host, urlInfo.hostLen );
		writeUint32( stream, urlInfo.port );
		writeString32( stream, "127.0.0.1", 0 );
		writeUint32( stream, 22 );
		return( wrapPacketSSH2( sessionInfoPtr, stream, 0 ) );
		}
	status = wrapPacketSSH2( sessionInfoPtr, stream, 0 );
	if( cryptStatusError( status ) )
		return( status );

	/* If the caller has requested the use of a custom subsystem (and at the
	   moment the only one that's likely to be used is SFTP), request this 
	   from the server by modifying the channel that we've just opened to
	   run the subsystem */
	if( isSubsystem )
		{
		/*	...
			byte	type = SSH2_MSG_CHANNEL_REQUEST
			uint32	recipient_channel
			string	request_name = "subsystem"
			boolean	want_reply = FALSE
			string	subsystem_name */
		packetOffset = continuePacketStreamSSH( stream, 
												SSH2_MSG_CHANNEL_REQUEST );
		writeUint32( stream, channelNo );
		writeString32( stream, "subsystem", 0 );
		sputc( stream, 0 );
		writeString32( stream, arg1String, arg1Len );
		return( wrapPacketSSH2( sessionInfoPtr, stream, packetOffset ) );
		}

	/* It's a standard channel open:
		...
		byte	type = SSH2_MSG_CHANNEL_REQUEST
		uint32	recipient_channel
		string	request_name = "pty-req"
		boolean	want_reply = FALSE
		string	TERM_environment_variable = "xterm"
		uint32	cols = 80
		uint32	rows = 48
		uint32	pixel_width = 0
		uint32	pixel_height = 0
		string	tty_mode_info = ""
		... */
	packetOffset = continuePacketStreamSSH( stream, 
											SSH2_MSG_CHANNEL_REQUEST );
	writeUint32( stream, channelNo );
	writeString32( stream, "pty-req", 0 );
	sputc( stream, 0 );					/* No reply */
	writeString32( stream, "xterm", 0 );/* Generic */
	writeUint32( stream, 80 );
	writeUint32( stream, 48 );			/* 48 x 80 (we're past 24 x 80) */
	writeUint32( stream, 0 );
	writeUint32( stream, 0 );			/* No graphics capabilities */
	writeUint32( stream, 0 );			/* No special TTY modes */
	status = wrapPacketSSH2( sessionInfoPtr, stream, packetOffset );
	if( cryptStatusError( status ) )
		return( status );

	/*	...
		byte	type = SSH2_MSG_CHANNEL_REQUEST
		uint32	recipient_channel
		string	request_name = "shell"
		boolean	want_reply = FALSE

	   This final request, once sent, moves the server into interactive 
	   session mode */
	packetOffset = continuePacketStreamSSH( stream, 
											SSH2_MSG_CHANNEL_REQUEST );
	writeUint32( stream, channelNo );
	writeString32( stream, "shell", 0 );
	sputc( stream, 0 );					/* No reply */
	return( wrapPacketSSH2( sessionInfoPtr, stream, packetOffset ) );
	}

/* Send a channel open */

int sendChannelOpen( SESSION_INFO *sessionInfoPtr )
	{
	STREAM stream;
	const long channelNo = getCurrentChannelNo( sessionInfoPtr,
												CHANNEL_READ );
	long currentChannelNo;
	int length, value, status;

	/* Make sure that there's channel data available to activate and
	   that it doesn't correspond to an already-active channel */
	if( channelNo == UNUSED_CHANNEL_NO )
		retExt( sessionInfoPtr, CRYPT_ERROR_NOTINITED,
				"No current channel information available to activate "
				"channel" );
	status = getChannelAttribute( sessionInfoPtr, 
								  CRYPT_SESSINFO_SSH_CHANNEL_ACTIVE,
								  NULL, &value );
	if( cryptStatusError( status ) || value )
		retExt( sessionInfoPtr, CRYPT_ERROR_INITED,
				"Current channel has already been activated" );

	/* Create a request for the appropriate type of service */
	status = createOpenRequest( sessionInfoPtr, &stream );
	if( cryptStatusError( status ) )
		{
		/* If it's a request-only message that doesn't open a channel,
		   send it and exit */
		if( status == OK_SPECIAL )
			status = sendPacketSSH2( sessionInfoPtr, &stream, TRUE );
		sMemDisconnect( &stream );
		return( status );
		}

	/* Send the whole mess to the server.  The SSHv2 spec doesn't really 
	   explain the semantics of the server's response to the channel open 
	   command, in particular whether the returned data size parameters are 
	   merely a confirmation of the client's requested values or whether the 
	   server is allowed to further modify them to suit its own requirements 
	   (or perhaps one is for send and the other for receive?).  In the 
	   absence of any further guidance, we just ignore the returned values, 
	   which seems to work for all deployed servers */
	status = sendPacketSSH2( sessionInfoPtr, &stream, TRUE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Wait for the server's ack of the channel open request:

		byte	SSH_MSG_CHANNEL_OPEN_CONFIRMATION
		uint32	recipient_channel
		uint32	sender_channel
		uint32	initial_window_size
		uint32	maximum_packet_size
		... */
	length = readPacketSSH2( sessionInfoPtr, SSH2_MSG_SPECIAL_CHANNEL,
							 ID_SIZE + UINT32_SIZE + UINT32_SIZE + \
								UINT32_SIZE + UINT32_SIZE );
	if( cryptStatusError( length ) )
		return( length );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	if( sgetc( &stream ) == SSH2_MSG_CHANNEL_OPEN_FAILURE )
		{
		BYTE stringBuffer[ CRYPT_MAX_TEXTSIZE + 8 ];
		int stringLen;

		/* The channel open failed, tell the caller why:

			byte	SSH_MSG_CHANNEL_OPEN_FAILURE
			uint32	recipient_channel
			uint32	reason_code
			string	additional_text */
		readUint32( &stream );		/* Skip channel number */
		sessionInfoPtr->errorCode = readUint32( &stream );
		status = readString32( &stream, stringBuffer, &stringLen, 
							   CRYPT_MAX_TEXTSIZE );
		if( cryptStatusError( status ) || \
			stringLen <= 0 || stringLen > CRYPT_MAX_TEXTSIZE )
			/* No error message, the best that we can do is give the reason
			   code as part of the message */
			retExt( sessionInfoPtr, CRYPT_ERROR_OPEN,
					"Channel open failed, reason code %ld", 
					sessionInfoPtr->errorCode );
		stringBuffer[ stringLen ] = '\0';
		retExt( sessionInfoPtr, CRYPT_ERROR_OPEN,
				"Channel open failed, error message '%s'", stringBuffer );
		}
	currentChannelNo = readUint32( &stream );
	if( currentChannelNo != channelNo )
		{
		sMemDisconnect( &stream );
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid channel number %ld in channel open confirmation, "
				"should be %ld", currentChannelNo, channelNo );
		}
	currentChannelNo = readUint32( &stream );
	sMemDisconnect( &stream );

	/* It's unclear why anyone would use different channel numbers for 
	   different directions, since it's the same channel that the data is 
	   moving across.  All (known) implementations use the same value in 
	   both directions, just in case anyone doesn't we throw an exception in 
	   the debug version */
	assert( currentChannelNo == channelNo );

	/* The channel has been successfully created, mark it as active and 
	   select it for future exchanges */
	setChannelExtAttribute( sessionInfoPtr, SSH_ATTRIBUTE_ACTIVE,
							NULL, TRUE );
	return( selectChannel( sessionInfoPtr, channelNo, CHANNEL_BOTH ) );
	}

/****************************************************************************
*																			*
*							Server-side Channel Management					*
*																			*
****************************************************************************/

/* SSH identifies channel requests using awkward string-based identifiers,
   to make these easier to work with we map them to integer values */

typedef enum { REQUEST_NONE, REQUEST_SUBSYSTEM, REQUEST_SHELL, REQUEST_EXEC, 
			   REQUEST_PORTFORWARD, REQUEST_PORTFORWARD_CANCEL, REQUEST_PTY,
			   REQUEST_NOOP, REQUEST_DISALLOWED } REQUEST_TYPE;

#define REQUEST_FLAG_NONE		0x00/* No request flag */
#define REQUEST_FLAG_TERMINAL	0x01/* Request ends negotiation */

typedef struct { 
	const char *requestName;		/* String form of request type */
	const REQUEST_TYPE requestType;	/* Integer form of request type */
	const int flags;				/* Request flags */
	} REQUEST_TYPE_INFO;

/* Process a global or channel request */

static int sendRequestResponse( SESSION_INFO *sessionInfoPtr,
								const long channelNo,
								const BOOLEAN isChannelRequest,
								const BOOLEAN isSuccessful )
	{
	int status;

	/* Indicate that the request succeeded/was denied:

		byte	type = SSH2_MSG_CHANNEL/GLOBAL_SUCCESS/FAILURE
	  [	uint32	channel_no		- For channel reqs ] */
	if( isChannelRequest )
		status = enqueueResponse( sessionInfoPtr, 
					isSuccessful ? SSH2_MSG_CHANNEL_SUCCESS : \
								   SSH2_MSG_CHANNEL_FAILURE, 1,
					( channelNo == CRYPT_USE_DEFAULT ) ? \
						getCurrentChannelNo( sessionInfoPtr, CHANNEL_READ ) : \
						channelNo,
					CRYPT_UNUSED, CRYPT_UNUSED, CRYPT_UNUSED );
	else
		status = enqueueResponse( sessionInfoPtr, 
					isSuccessful ? SSH2_MSG_GLOBAL_SUCCESS : \
								   SSH2_MSG_GLOBAL_FAILURE, 0,
					CRYPT_UNUSED, CRYPT_UNUSED, CRYPT_UNUSED, 
					CRYPT_UNUSED );
	return( cryptStatusOK( status ) ? \
			sendEnqueuedResponse( sessionInfoPtr, CRYPT_UNUSED ) : status );
	}

static int processChannelRequest( SESSION_INFO *sessionInfoPtr, 
								  STREAM *stream, const long prevChannelNo )
	{
	static const FAR_BSS REQUEST_TYPE_INFO requestInfo[] = {
		/* Channel/session-creation requests, only permitted on the server-
		   side */
		{ "subsystem", REQUEST_SUBSYSTEM, REQUEST_FLAG_TERMINAL },
		{ "tcpip-forward", REQUEST_PORTFORWARD, REQUEST_FLAG_NONE },
		{ "cancel-tcpip-forward", REQUEST_PORTFORWARD_CANCEL, REQUEST_FLAG_NONE },
		{ "shell", REQUEST_SHELL, REQUEST_FLAG_TERMINAL }, 
		{ "exec", REQUEST_EXEC, REQUEST_FLAG_TERMINAL },
		{ "pty-req", REQUEST_PTY, REQUEST_FLAG_NONE },

		/* No-op requests */
		{ "env", REQUEST_NOOP, REQUEST_FLAG_NONE },
		{ "exit-signal", REQUEST_NOOP, REQUEST_FLAG_NONE },
		{ "exit-status", REQUEST_NOOP, REQUEST_FLAG_NONE },
		{ "signal", REQUEST_NOOP, REQUEST_FLAG_NONE },
		{ "xon-xoff", REQUEST_NOOP, REQUEST_FLAG_NONE },
		{ "window-change", REQUEST_NOOP, REQUEST_FLAG_NONE },

		/* Disallowed requests */
		{ "x11-req", REQUEST_DISALLOWED, REQUEST_FLAG_NONE },
		{ NULL, REQUEST_NONE, REQUEST_FLAG_NONE }
		};
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	const BOOLEAN isChannelRequest = \
			( sshInfo->packetType == SSH2_MSG_CHANNEL_REQUEST );
	REQUEST_TYPE requestType = REQUEST_DISALLOWED;
	BYTE stringBuffer[ CRYPT_MAX_TEXTSIZE + 8 ];
	BOOLEAN wantReply, requestOK = FALSE, requestIsTerminal = FALSE;
	int stringLength, i, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Process the channel/global request (the type and channel number
	   have already been read by the caller):

	  [	byte	type = SSH2_MSG_CHANNEL_REQUEST / SSH2_MSG_GLOBAL_REQUEST ]
	  [	uint32	recipient_channel	- For channel reqs ]
		string	request_type
		boolean	want_reply
		[...]

	   If there's an error at this point we can't send back a response 
	   because one or both of the channel number and the want_reply flag
	   aren't available yet.  The consensus among SSH implementors was that
	   not doing anything if the request packet is invalid is preferable to
	   sending back a response with a placeholder channel number, or a 
	   response when want_reply could have been false had it been able to
	   be decoded */
	status = readString32( stream, stringBuffer, &stringLength, 
						   CRYPT_MAX_TEXTSIZE );
	if( cryptStatusError( status ) || \
		stringLength <= 0 || stringLength > CRYPT_MAX_TEXTSIZE  || \
		cryptStatusError( wantReply = sgetc( stream ) ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid %s request packet type",
				isChannelRequest ? "channel" : "global" );

	/* Try and identify the request type */
	for( i = 0; requestInfo[ i ].requestName != NULL; i++ )
		if( stringLength == strlen( requestInfo[ i ].requestName ) && \
			!memcmp( stringBuffer, requestInfo[ i ].requestName, 
					 stringLength ) )
			{
			requestType = requestInfo[ i ].requestType;
			requestOK = ( requestType != REQUEST_DISALLOWED ) ? \
						TRUE : FALSE;
			requestIsTerminal = \
					( requestInfo[ i ].flags & REQUEST_FLAG_TERMINAL ) ? \
					TRUE : FALSE;
			break;
			}

	/* If it's an explicitly disallowed request type or if we're the client 
	   and it's anything other than a no-op request (for example a request 
	   to execute a command or perform port forwarding), it isn't 
	   permitted */
	if( !requestOK || \
		( !( sessionInfoPtr->flags & SESSION_ISSERVER ) && \
		  ( requestType != REQUEST_NOOP ) ) )
		{
		if( wantReply )
			{
			status = sendRequestResponse( sessionInfoPtr, prevChannelNo,
										  isChannelRequest, FALSE );
			if( isChannelRequest )
				/* The request failed, go back to the previous channel */
				selectChannel( sessionInfoPtr, prevChannelNo, CHANNEL_READ );
			}
		return( status );
		}

	assert( requestOK && \
			( ( sessionInfoPtr->flags & SESSION_ISSERVER ) || \
			  ( requestType == REQUEST_NOOP ) ) );

	/* Process the request.  Since these are administrative messages that 
	   aren't visible to the caller, we don't bail out if we encounter a 
	   problem, we just deny the request */
	switch( requestType )
		{
		case REQUEST_SUBSYSTEM:
			/* We're being asked for a subsystem, record the type:

				[...]
				string	subsystem_name */
			status = readString32( stream, stringBuffer, &stringLength, 
								   CRYPT_MAX_TEXTSIZE );
			if( cryptStatusError( status ) || \
				stringLength <= 0 || stringLength > CRYPT_MAX_TEXTSIZE )
				requestOK = FALSE;
			else
				{
				/* The handling of subsystems is somewhat awkward, instead
				   of opening a subsystem channel SSH first opens a standard
				   session channel and then layers a subsystem on top of it.
				   Because of this we have to replace the standard channel 
				   type with a new subsystem channel-type as well as recording
				   the subsystem type */
				setChannelAttribute( sessionInfoPtr, 
									 CRYPT_SESSINFO_SSH_CHANNEL_TYPE,
									 "subsystem", 9 );
				setChannelAttribute( sessionInfoPtr, 
									 CRYPT_SESSINFO_SSH_CHANNEL_ARG1,
									 stringBuffer, stringLength );
				}
			break;

		case REQUEST_SHELL:
		case REQUEST_EXEC:
		case REQUEST_PTY:
		case REQUEST_NOOP:
			/* Generic requests containing extra information that we're not
			   interested in */
			break;

		case REQUEST_PORTFORWARD:
			/* We're being asked for port forwarding, get the address and 
			   port information:
				
				[...]
				string	local_address_to_bind (e.g. "0.0.0.0")
				uint32	local_port_to_bind */
			status = getAddressAndPort( sessionInfoPtr, stream, stringBuffer,
										&stringLength );
			if( cryptStatusError( status ) )
				requestOK = FALSE;
			else
#if 0			/* This is a global request that doesn't apply to any 
				   channel, which makes it rather hard to deal with since
				   we can't associate it with anything that the user can
				   work with.  For now we leave it until there's actual
				   user demand for it */
				setChannelAttribute( sessionInfoPtr, 
									 CRYPT_SESSINFO_SSH_CHANNEL_ARG1,
									 stringBuffer, stringLength );
#endif /* 0 */
			break;

		case REQUEST_PORTFORWARD_CANCEL:
			{
			const int offset = stell( stream );

			/* Check that this is a request to close a port for which 
			   forwarding was actually requested.  Since there could be 
			   multiple channels open on the forwarded port, we keep looking 
			   for other channels open on this port until we've cleared them 
			   all.  The spec is silent about what happens to open channels 
			   when the forwarding is cancelled, but from reading between 
			   the lines (new channel-open requests can be received until 
			   the forwarding is cancelled) it appears that the channels 
			   remain active until the channel itself is closed */
			requestOK = FALSE;
			do
				{
				sseek( stream, offset );
				status = clearAddressAndPort( sessionInfoPtr, stream );
				if( cryptStatusOK( status ) )
					requestOK = TRUE;
				}
			while( cryptStatusOK( status ) );
			break;
			}

		case REQUEST_DISALLOWED:
		default:
			/* Anything else we don't allow.  This should already be handled 
			   via the default status setting of FALSE, but we make it
			   explicit here */
			requestOK = FALSE;
			break;
		}

	/* Acknowledge the request if necessary */
	if( wantReply )
		{
		status = sendRequestResponse( sessionInfoPtr, prevChannelNo,
									  isChannelRequest, requestOK );
		if( isChannelRequest && \
			( cryptStatusError( status ) || !requestOK ) )
			/* The request failed, go back to the previous channel */
			status = selectChannel( sessionInfoPtr, prevChannelNo, 
									CHANNEL_READ );
		if( cryptStatusError( status ) )
			return( status );
		}
	return( requestIsTerminal ? OK_SPECIAL : CRYPT_OK );
	}

/* Process a channel open.  Since these are administrative messages that 
   aren't visible to the caller, we don't bail out if we encounter a 
   problem, we just deny the request */

static int sendOpenResponseFailed( SESSION_INFO *sessionInfoPtr,
								   const long channelNo )
	{
	int status;

	/* Indicate that the request was denied:

		byte	SSH2_MSG_CHANNEL_OPEN_FAILURE
		uint32	recipient_channel
		uint32	reason_code = SSH_OPEN_ADMINISTRATIVELY_PROHIBITED
		string	additional_text = ""
		string	language_tag = ""

	   We always send the same reason code to avoid giving away anything 
	   to an attacker */
	status = enqueueResponse( sessionInfoPtr, 
							  SSH2_MSG_CHANNEL_OPEN_FAILURE, 4, 
							  channelNo, 
							  SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
							  0, 0 );
	if( cryptStatusOK( status ) )
		status = sendEnqueuedResponse( sessionInfoPtr, CRYPT_UNUSED );
	return( status );
	}

int processChannelOpen( SESSION_INFO *sessionInfoPtr, STREAM *stream )
	{
	BYTE typeString[ CRYPT_MAX_TEXTSIZE + 8 ];
	BYTE arg1String[ CRYPT_MAX_TEXTSIZE + 8 ], *arg1Ptr = NULL;
	BOOLEAN isPortForwarding = FALSE;
	long channelNo, maxPacketSize;
	int typeLen, arg1Len = 0, status;

	/* Read the channel open request (the type has already been read by the 
	   caller):

	  [	byte	type = SSH2_MSG_CHANNEL_OPEN ]
		string	channel_type = "session" | "direct-tcpip"
		uint32	sender_channel
		uint32	initial_window_size
		uint32	max_packet_size
	  [ string	host_to_connect		- For port-forwarding
		uint32	port_to_connect
		string	originator_IP_address
		uint32	originator_port ]
	
	   As for global/channel requests in processChannelOpen(), we can't
	   return an error indication if we encounter a problem too early in the
	   packet, see the comment for that function for further details */
	status = readString32( stream, typeString, &typeLen, CRYPT_MAX_TEXTSIZE );
	if( cryptStatusError( status ) || \
		typeLen <= 0 || typeLen > CRYPT_MAX_TEXTSIZE )
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid channel open channel type" );
	if( typeLen != 7 || strCompare( typeString, "session", 7 ) )
		{
		/* It's not a normal channel open, see if the caller is trying to
		   do port forwarding */
		if( typeLen != 12 || strCompare( typeString, "direct-tcpip", 12 ) )
			{
			/* It's something else, report it as an error */
			typeString[ typeLen ] = '\0';
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid channel open channel type '%'", typeString );
			}
		isPortForwarding = TRUE;
		}
	channelNo = readUint32( stream );
	readUint32( stream );			/* Skip window size */
	status = maxPacketSize = readUint32( stream );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status, "Invalid channel open packet" );
	if( maxPacketSize < 1024 || maxPacketSize > 0x100000L )
		{
		/* General sanity check to make sure that the packet size is in the 
		   range 1K ... 16MB.  We've finally got valid packet data so we can
		   send error responses from now on */
		sendOpenResponseFailed( sessionInfoPtr, channelNo );
		retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
				"Invalid channel open maximum packet size %d", 
				maxPacketSize );
		}
	if( isPortForwarding )
		{
		/* Get the source and destination host information */
		status = getAddressAndPort( sessionInfoPtr, stream,
									arg1String, &arg1Len );
		if( cryptStatusError( status ) )
			{
			sendOpenResponseFailed( sessionInfoPtr, channelNo );
			return( status );
			}
		arg1Ptr = arg1String;
		}
	maxPacketSize = min( maxPacketSize, \
						 sessionInfoPtr->receiveBufSize - EXTRA_PACKET_SIZE );

	/* If this is the client, opening a new channel by the server isn't 
	   permitted */
	if( !( sessionInfoPtr->flags & SESSION_ISSERVER ) )
		{
		sendOpenResponseFailed( sessionInfoPtr, channelNo );
		retExt( sessionInfoPtr, CRYPT_ERROR_PERMISSION,
				"Server attempted to a open channel to the client" );
		}

	/* Add the new channel */
	status = addChannel( sessionInfoPtr, channelNo, maxPacketSize, 
						 typeString, typeLen, arg1Ptr, arg1Len );
	if( cryptStatusError( status ) )
		{
		sendOpenResponseFailed( sessionInfoPtr, channelNo );
		retExt( sessionInfoPtr, status,
				"Couldn't add new channel %ld", channelNo );
		}

	/* Send back the open confirmation:

		byte	type = SSH2_MSG_CHANNEL_OPEN_CONFIRMATION
		uint32	recipient_channel = prev. sender_channel
		uint32	sender_channel
		uint32	initial_window_size = MAX_WINDOW_SIZE
		uint32	max_packet_size = bufSize

	   The SSHv2 spec doesn't really explain the semantics of the server's 
	   response to the channel open command, in particular whether the 
	   returned data size parameters are merely a confirmation of the 
	   client's requested values or whether the server is allowed to further 
	   modify them to suit its own requirements (or perhaps one is for send 
	   and the other for receive?).  In the absence of any further guidance, 
	   we try and comply with a client's request for smaller data 
	   quantities, but also return a smaller-than-requested data size value 
	   if they ask for too much data.

	   See the comments in the client-side channel-open code for the reason 
	   for the window size */
	status = enqueueResponse( sessionInfoPtr, 
							  SSH2_MSG_CHANNEL_OPEN_CONFIRMATION, 4, 
							  channelNo, channelNo, 
							  MAX_WINDOW_SIZE, maxPacketSize );
	if( cryptStatusOK( status ) )
		status = sendEnqueuedResponse( sessionInfoPtr, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		deleteChannel( sessionInfoPtr, channelNo, CHANNEL_BOTH, TRUE );
		return( status );
		}

	/* The channel has been successfully created, mark it as active and 
	   select it for future exchanges */
	setChannelExtAttribute( sessionInfoPtr, SSH_ATTRIBUTE_ACTIVE,
							NULL, TRUE );
	return( selectChannel( sessionInfoPtr, channelNo, CHANNEL_BOTH ) );
	}

/****************************************************************************
*																			*
*							General Channel Management						*
*																			*
****************************************************************************/

/* Send a channel close notification */

static int sendChannelClose( SESSION_INFO *sessionInfoPtr,
							 const long channelNo,
							 const CHANNEL_TYPE channelType,
							 const BOOLEAN closeLastChannel )
	{
	BOOLEAN lastChannel = FALSE;
	int status;

	/* Delete the channel */
	status = deleteChannel( sessionInfoPtr, channelNo, channelType,
							closeLastChannel  );
	if( status == OK_SPECIAL )
		lastChannel = TRUE;

	/* Prepare the channel-close notification:

		byte		SSH2_MSG_CHANNEL_CLOSE
		uint32		channel_no */
	status = enqueueResponse( sessionInfoPtr, SSH2_MSG_CHANNEL_CLOSE, 1, 
							  channelNo, CRYPT_UNUSED, CRYPT_UNUSED, 
							  CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's the last channel, don't try and send the close, since this
	   will be sent as part of the session shutdown process */
	if( lastChannel )
		return( OK_SPECIAL );
	
	/* We can't safely use anything that ends up at sendPacketSSH2() at this 
	   point since we may be closing the connection in response to a link 
	   error, in which case the error returned from the packet send would 
	   overwrite the actual error information.  Because of this we send the
	   response with the no-report-error flag set to suppress reporting of
	   network errors during the send */
	sessionInfoPtr->flags |= SESSION_NOREPORTERROR;
	status = sendEnqueuedResponse( sessionInfoPtr, CRYPT_UNUSED );
	sessionInfoPtr->flags &= ~SESSION_NOREPORTERROR;
	return( status );
	}

/* Process a channel control message */

static int clearPacket( SESSION_INFO *sessionInfoPtr )
	{
	/* Reset the send buffer indicators to clear the packet */
	sessionInfoPtr->receiveBufEnd = sessionInfoPtr->receiveBufPos;
	sessionInfoPtr->pendingPacketLength = 0;

	/* Tell the caller to try again */
	return( OK_SPECIAL );
	}

int processChannelControlMessage( SESSION_INFO *sessionInfoPtr, 
								  STREAM *stream )
	{
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	const long prevChannelNo = \
				getCurrentChannelNo( sessionInfoPtr, CHANNEL_READ );
	long channelNo;
	int status;

	/* See what we've got.  SSHv2 has a pile of noop-equivalents that we 
	   have to handle as well as the obvious no-ops.  We can also get global 
	   and channel requests for assorted reasons and a constant stream of 
	   window adjust messages to implement the SSH performance handbrake */
	switch( sshInfo->packetType )
		{
		case SSH2_MSG_GLOBAL_REQUEST:
			status = processChannelRequest( sessionInfoPtr, stream, 
											CRYPT_UNUSED );
			if( cryptStatusError( status ) && status != OK_SPECIAL )
				return( status );
			return( clearPacket( sessionInfoPtr ) );

		case SSH2_MSG_CHANNEL_OPEN:
			status = processChannelOpen( sessionInfoPtr, stream );
			if( cryptStatusError( status ) )
				return( status );
			clearPacket( sessionInfoPtr );

			/* Tell the caller that they have to process the new channel 
			   info before they can continue */
			return( CRYPT_ENVELOPE_RESOURCE );

		case SSH2_MSG_IGNORE:
		case SSH2_MSG_DEBUG:
			/* Nothing to see here, move along, move along:

				byte	SSH2_MSG_IGNORE
				string	data

				byte	SSH2_MSG_DEBUG
				boolean	always_display
				string	message
				string	language_tag */
			return( clearPacket( sessionInfoPtr ) );

		case SSH2_MSG_DISCONNECT:
			/* This only really seems to be used during the handshake phase, 
			   once a channel is open it (and the session as a whole) is 
			   disconnected with a channel EOF/close, but we handle it here
			   just in case */
			status = getDisconnectInfo( sessionInfoPtr, stream );
			clearPacket( sessionInfoPtr );
			return( status );

		case SSH2_MSG_KEXINIT:
			/* The SSH spec is extremely vague about the sequencing of 
			   operations during a rehandshake.  Unlike SSL, there is no 
			   real indication of what happens to the connection-layer 
			   transfers while a transport-layer rehandshake is in progress.  
			   Also unlike SSL, we can't refuse a rehandshake by ignoring 
			   the request, so once we've fallen we can't get up any more.  
			   This is most obvious with ssh.com's server, which starting
			   with version 2.3.0 would do a rehandshake every hour (for a 
			   basic encrypted telnet session, while a high-volume IPsec 
			   link can run for hours before it feels the need to do this).  
			   To make things even messier, neither side can block for too 
			   long waiting for the rehandshake to complete before sending 
			   new data because the lack of WINDOW_ADJUSTs (in an 
			   implementation that sends these with almost every packet, as 
			   most do) will screw up flow control and lead to deadlock.
			   This problem got so bad that as of 2.4.0 the ssh.com 
			   implementation would detect OpenSSH (the other main
			   implementation at the time) and disable the rehandshake when
			   it was talking to it, but it may not do this for other
			   implementations.

			   To avoid falling into this hole, or at least to fail 
			   obviously when the two sides can't agree on how to handle the 
			   layering mismatch problem, we report a rehandshake request as 
			   an error.  Trying to handle it properly results in hard-to-
			   diagnose errors (it depends on what the layers are doing at 
			   the time of the problem), typically some bad-packet error 
			   when the other side tries to interpret a connection-layer 
			   packet as part of the rehandshake, or when the two sides 
			   disagree on when to switch keys and it decrypts with the 
			   wrong keys and gets a garbled packet type */
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Unexpected KEXINIT request received" );

		case SSH2_MSG_CHANNEL_DATA:
		case SSH2_MSG_CHANNEL_EXTENDED_DATA:
		case SSH2_MSG_CHANNEL_REQUEST:
		case SSH2_MSG_CHANNEL_WINDOW_ADJUST:
		case SSH2_MSG_CHANNEL_EOF:
		case SSH2_MSG_CHANNEL_CLOSE:
			/* All channel-specific messages end up here */
			channelNo = readUint32( stream );
			if( cryptStatusError( channelNo ) )
				/* We can't send an error response to a channel request at
				   this point both because we haven't got to the response-
				   required flag yet and because SSH doesn't provide a 
				   mechanism for returning an error response without an
				   accompanying channel number.  The best that we can do is
				   to quietly ignore the packet */
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Invalid channel-specific packet type %d",
						sshInfo->packetType );
			if( channelNo != getCurrentChannelNo( sessionInfoPtr, \
												  CHANNEL_READ ) )
				{
				/* It's a request on something other than the current 
				   channel, try and select the new channel */
				status = selectChannel( sessionInfoPtr, channelNo, 
										CHANNEL_READ );
				if( cryptStatusError( status ) )
					{
					/* As before for error handling */
					retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
							"Invalid channel number %ld in channel-specific "
							"packet type %d, current channel "
							"is %ld", channelNo, 
							sshInfo->packetType, prevChannelNo );
					}
				}
			break;

		default:
			{
			BYTE buffer[ 16 ];

			/* We got something unexpected, throw an exception in the debug 
			   version and let the caller know the details */
			assert( NOTREACHED );
			status = sread( stream, buffer, 8 );
			if( cryptStatusError( status ) )
				/* There's not enough data present to dump the start of the
				   packet, provide a more generic response */
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Unexpected control packet type %d received",
						sshInfo->packetType );
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Unexpected control packet type %d received, beginning "
					"%02X %02X %02X %02X %02X %02X %02X %02X",
					sshInfo->packetType, 
					buffer[ 0 ], buffer[ 1 ], buffer[ 2 ], buffer[ 3 ],
					buffer[ 4 ], buffer[ 5 ], buffer[ 6 ], buffer[ 7 ] );
			}
		}

	/* From here on we're processing a channel-specific message that applies 
	   to the currently selected channel */
	switch( sshInfo->packetType )
		{
		case SSH2_MSG_CHANNEL_DATA:
		case SSH2_MSG_CHANNEL_EXTENDED_DATA:
			{
			const int streamPos = stell( stream );
			const BOOLEAN hasWindowBug = \
				( sessionInfoPtr->protocolFlags & SSH_PFLAG_WINDOWBUG );
			long length;
			int windowCount;

			/* Get the payload length and make sure that it's 
			   (approximately) valid.  More exact checking will be done
			   by the caller (which is why we reset the stream position
			   to allow it to be re-read), all that we're really interested 
			   in here is that the length is approximately valid for window-
			   adjust calculation purposes */
			length = readUint32( stream );
			sseek( stream, streamPos );
			if( length < 0 || length > sessionInfoPtr->receiveBufSize )
				retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
						"Invalid data packet payload length %d, should be "
						"0...%d", length, sessionInfoPtr->receiveBufSize );
			
			/* These are messages that consume window space, adjust the data 
			   window and communicate changes to the other side if necessary.  
			   See the comment in sendChannelOpen() for the reason for the 
			   window size handling */
			getChannelExtAttribute( sessionInfoPtr, 
									SSH_ATTRIBUTE_WINDOWCOUNT,
									NULL, &windowCount );
			windowCount += length;
			if( windowCount > MAX_WINDOW_SIZE - \
							  sessionInfoPtr->sendBufSize || hasWindowBug )
				{
				/* Send the window adjust to the remote system:

					byte	SSH2_MSG_CHANNEL_WINDOW_ADJUST
					uint32	channel
					uint32	bytes_to_add

				   We ignore any possible error code from the packet send 
				   because we're supposed to be processing a read and not a 
				   write at this point, the write is only required by SSH's 
				   braindamaged flow-control handling */
				enqueueChannelData( sessionInfoPtr, 
									SSH2_MSG_CHANNEL_WINDOW_ADJUST, 
									channelNo, hasWindowBug ? \
										length : MAX_WINDOW_SIZE );

				/* We've reset the window, start again from zero */
				windowCount = 0;
				}
			setChannelExtAttribute( sessionInfoPtr, 
									SSH_ATTRIBUTE_WINDOWCOUNT,
									NULL, windowCount );

			/* If it's a standard data packet, we're done */
			if( sshInfo->packetType == SSH2_MSG_CHANNEL_DATA )
				return( CRYPT_OK );

			/* The extended data message is used for out-of-band data sent 
			   over a channel, specifically output sent to stderr from a 
			   shell command.  What to do with this is somewhat uncertain, 
			   the only possible action that we could take apart from just 
			   ignoring it is to convert it back to in-band data.  However, 
			   something running a shell command may not expect to get 
			   anything returned in this manner (see the comment for the 
			   port-forwarding channel open in the client-side channel-open 
			   code for more on this), so for now we just ignore it and 
			   assume that the user will rely on results sent as in-band 
			   data.  This should be fairly safe since this message type 
			   seems to be rarely (if ever) used, so apps will function 
			   without it */
			return( clearPacket( sessionInfoPtr ) );
			}

		case SSH2_MSG_CHANNEL_REQUEST:
			status = processChannelRequest( sessionInfoPtr, stream,
											prevChannelNo );
			if( cryptStatusError( status ) && status != OK_SPECIAL )
				return( status );
			return( clearPacket( sessionInfoPtr ) );

		case SSH2_MSG_CHANNEL_WINDOW_ADJUST:
			/* Another noop-equivalent (but a very performance-affecting 
			   one) */
			return( clearPacket( sessionInfoPtr ) );

		case SSH2_MSG_CHANNEL_EOF:
			/* According to the SSH docs the EOF packet is mostly a courtesy 
			   notification, however many implementations seem to use a 
			   channel EOF in place of a close before sending a disconnect
			   message */
			return( clearPacket( sessionInfoPtr ) );

		case SSH2_MSG_CHANNEL_CLOSE:
			/* The peer has closed their side of the channel, if our side
			   isn't already closed (in other words if this message isn't
			   a response to a close that we sent), close our side as well */
			if( getChannelStatus( sessionInfoPtr, channelNo ) == CHANNEL_BOTH )
				status = sendChannelClose( sessionInfoPtr, channelNo, 
										   CHANNEL_BOTH, TRUE );
			else
				/* We've already closed our side of the channel, delete it */
				status = deleteChannel( sessionInfoPtr, channelNo, 
										CHANNEL_BOTH, TRUE );

			/* If this wasn't the last channel, we're done */
			if( status != OK_SPECIAL )
				return( clearPacket( sessionInfoPtr ) );

			/* We've closed the last channel, indicate that the overall 
			   connection is now closed.  This behaviour isn't mentioned in 
			   the spec, but it seems to be the standard way of handling 
			   things, particularly for the most common case where 
			   channel == session */
			sessionInfoPtr->flags |= SESSION_SENDCLOSED;
			retExt( sessionInfoPtr, CRYPT_ERROR_COMPLETE,
					"Remote system closed last remaining SSH channel" );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/* Close a channel */

int closeChannel( SESSION_INFO *sessionInfoPtr,
				  const BOOLEAN closeLastChannel )
	{
	READSTATE_INFO readInfo;
	const int currWriteChannelNo = \
				getCurrentChannelNo( sessionInfoPtr, CHANNEL_WRITE );
	int status;

	/* If we've already sent the final channel-close message in response to 
	   getting a final close notification from the peer, all that's left 
	   to do is to disconnect the session */
	if( sessionInfoPtr->flags & SESSION_SENDCLOSED )
		{
		sNetDisconnect( &sessionInfoPtr->stream );
		return( CRYPT_OK );
		}

	/* Normally we can keep closing open channels until we hit the last one
	   whereupon we close the overall session, however if we're closing a
	   single identified channel we can't automatically close the whole 
	   session as a side-effect of closing the single channel */
	if( !closeLastChannel && currWriteChannelNo == UNUSED_CHANNEL_NO )
		retExt( sessionInfoPtr, CRYPT_ERROR_NOTINITED,
				"No current channel information available to close "
				"channel" );

	/* If there's no channel open, close the session with a session 
	   disconnect rather than a channel close:

		byte		SSH2_MSG_DISCONNECT
		uint32		reason_code = SSH2_DISCONNECT_CONNECTION_LOST
		string		description = ""
		string		language_tag = ""
		
	   The spec doesn't explain what the reason codes actually mean, but
	   SSH2_DISCONNECT_CONNECTION_LOST seems to be the least inappropriate 
	   disconnect reason at this point */
	if( currWriteChannelNo == UNUSED_CHANNEL_NO )
		{
		status = enqueueResponse( sessionInfoPtr, SSH2_MSG_DISCONNECT, 3, 
								  SSH2_DISCONNECT_CONNECTION_LOST, 0, 0, 
								  CRYPT_UNUSED );
		if( cryptStatusOK( status ) )
			sendEnqueuedResponse( sessionInfoPtr, CRYPT_UNUSED );
		sessionInfoPtr->flags |= SESSION_SENDCLOSED;
		sNetDisconnect( &sessionInfoPtr->stream );
		return( CRYPT_OK );
		}

	/* Close the write side of the channel, the complete close will be done
	   when the other side acknowledges our close.  If this isn't the last
	   open channel, the response to our close will be handled as part of 
	   normal packet processing and we're done */
	status = sendChannelClose( sessionInfoPtr, currWriteChannelNo, 
							   CHANNEL_WRITE, closeLastChannel );
	if( status != OK_SPECIAL )
		{
		/* If this is the last remaining channel, we similarly can't close
		   it */
		if( status == CRYPT_ERROR_PERMISSION )
			retExt( sessionInfoPtr, CRYPT_ERROR_PERMISSION,
					"Cannot close last remaining channel without closing "
					"the overall session" );

		return( CRYPT_OK );
		}

	/* It's the last open channel, close down the session */
	status = sendCloseNotification( sessionInfoPtr, NULL, 0 );
	if( cryptStatusError( status ) || \
		( sessionInfoPtr->protocolFlags & SESSION_SENDCLOSED ) )
		{
		/* There's a problem at the network level or the other side has
		   already closed the session, close the network link and exit */
		sNetDisconnect( &sessionInfoPtr->stream );
		return( CRYPT_OK );
		}

	/* If there's not enough room in the receive buffer to read at least 1K 
	   of packet data, we can't try anything further */
	if( sessionInfoPtr->receiveBufSize - sessionInfoPtr->receiveBufEnd < \
		min( sessionInfoPtr->pendingPacketRemaining, 1024 ) )
		{
		sNetDisconnect( &sessionInfoPtr->stream );
		return( CRYPT_OK );
		}

	/* Read back the other side's channel close.  This is somewhat messy
	   since the other side could decide that it still wants to send us
	   arbitrary amounts of data (the spec is rather vague about how urgent
	   a channel close is, the general idea among implementors seems to be
	   that you should let output drain before you close your side, but
	   if you're in the middle of sending a 2GB file that's a lot of output
	   to drain).  This can also be complicated by implementation-specific
	   quirks, for example OpenSSH may hang more or less indefinitely if
	   there's output coming from a background process on the server.  This
	   is because of a rather obscure race condition that would occur if it
	   exited immediately in which the SSH server gets the SIGCHLD from the 
	   (local) background process exiting before it's written all of its 
	   data to the (local) pipe connecting it to the SSH server, so it 
	   closes the (remote) SSH channel/connection before the last piece of 
	   data comes over the (local) pipe.  Because the server won't close the 
	   (remote) SSH connection until it's certain that the (local) process 
	   has written all of its data, and it'll never get the EOF over the 
	   pipe, it hangs forever.  This is a piece of Unix plumbing arcana that
	   doesn't really concern us, so again just exiting after a short wait
	   is the best response.
	   
	   Since we're about to shut down the session anyway, we try
	   to read a basic channel close ack from the other side, if there's
	   anything more than that we drop it.  This is complicated somewhat by 
	   the fact that what we're doing here is something that's normally 
	   handled by the high-level read code in sess_rw.c.  What we implement 
	   here is the absolute minimum needed to clear the stream 
	   (sendCloseNotification() has set the necessary (small) nonzero 
	   timeout for us) */
	status = sessionInfoPtr->readHeaderFunction( sessionInfoPtr, &readInfo );
	if( !cryptStatusError( status ) )
		{
		/* Adjust the packet info for the packet header data that was just
		   read */
		sessionInfoPtr->receiveBufEnd += status;
		sessionInfoPtr->pendingPacketPartialLength = status;
		sessionInfoPtr->pendingPacketRemaining -= status;
		if( sessionInfoPtr->pendingPacketRemaining <= 512 )
			{
			const int bytesLeft = sessionInfoPtr->receiveBufSize - \
								  sessionInfoPtr->receiveBufEnd;

			/* We got a packet and it's probably the channel close ack, read
			   it */
			status = sread( &sessionInfoPtr->stream,
							sessionInfoPtr->receiveBuffer + \
								sessionInfoPtr->receiveBufEnd,
							min( sessionInfoPtr->pendingPacketRemaining, \
								 bytesLeft ) );
			}
		}
	sNetDisconnect( &sessionInfoPtr->stream );
	return( CRYPT_OK );
	}
#endif /* USE_SSH2 */
