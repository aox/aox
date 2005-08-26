/****************************************************************************
*																			*
*						cryptlib SSHv2 Session Management					*
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

/* Tables mapping SSHv2 algorithm names to cryptlib algorithm IDs, in 
   preferred algorithm order.  See the comment in ssh2_svr.c for the reason
   behind the difference in encryption algorithm tables for client and 
   server */

static const FAR_BSS ALGO_STRING_INFO algoStringKeyexTbl[] = {
	{ "diffie-hellman-group-exchange-sha1", CRYPT_PSEUDOALGO_DHE },
	{ "diffie-hellman-group1-sha1", CRYPT_ALGO_DH },
	{ NULL, CRYPT_ALGO_NONE }
	};

static const FAR_BSS ALGO_STRING_INFO algoStringCoprTbl[] = {
	{ "none", CRYPT_PSEUDOALGO_COPR },
	{ NULL, CRYPT_ALGO_NONE }
	};

static const FAR_BSS ALGO_STRING_INFO algoStringPubkeyTbl[] = {
	{ "ssh-rsa", CRYPT_ALGO_RSA },
	{ "ssh-dss", CRYPT_ALGO_DSA },
	{ NULL, CRYPT_ALGO_NONE }
	};

static const FAR_BSS ALGO_STRING_INFO algoStringEncrTblClient[] = {
	{ "3des-cbc", CRYPT_ALGO_3DES },
	{ "aes128-cbc", CRYPT_ALGO_AES },
	{ "blowfish-cbc", CRYPT_ALGO_BLOWFISH },
	{ "cast128-cbc", CRYPT_ALGO_CAST },
	{ "idea-cbc", CRYPT_ALGO_IDEA },
	{ "arcfour", CRYPT_ALGO_RC4 },
	{ NULL, CRYPT_ALGO_NONE }
	};
static const FAR_BSS ALGO_STRING_INFO algoStringEncrTblServer[] = {
	{ "3des-cbc", CRYPT_ALGO_3DES },
	{ "blowfish-cbc", CRYPT_ALGO_BLOWFISH },
	{ "cast128-cbc", CRYPT_ALGO_CAST },
	{ "idea-cbc", CRYPT_ALGO_IDEA },
	{ "arcfour", CRYPT_ALGO_RC4 },
	{ NULL, CRYPT_ALGO_NONE }
	};

static const FAR_BSS ALGO_STRING_INFO algoStringMACTbl[] = {
	{ "hmac-sha1", CRYPT_ALGO_HMAC_SHA },
	{ "hmac-md5", CRYPT_ALGO_HMAC_MD5 },
	{ NULL, CRYPT_ALGO_NONE }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Convert an SSHv2 algorithm list to a cryptlib ID in preferred-algorithm
   order.  For some bizarre reason the algorithm information is communicated
   as a comma-delimited list (in an otherwise binary protocol), so we have
   to unpack and pack them into this cumbersome format alongside just
   choosing which algorithm to use.  In addition, the algorithm selection
   mechanism differs depending on whether we're the client or server, and 
   what set of algorithms we're matching.  Unlike SSL, which uses the 
   offered-suites/chosen-suites mechanism, in SSHv2 both sides offer a 
   selection of cipher suites and the server chooses the first one that 
   appears on both it and the client's list, with special-case handling for
   the keyex and signature algorithms if the match isn't the first one on 
   the list.  This means that the client can choose as it pleases from the 
   server's list if it waits for the server hello (see the comment in the 
   client/server hello handling code on the annoying nature of this portion 
   of the SSHv2 handshake), but the server has to perform a complex double-
   match of its own vs.the client's list.  The cases that we need to handle 
   are:

	get the first matching algorithm, used by the server to match the client.

	get the first matching algorithm and warn if it isn't the first one on 
		the list of possible algorithms, used by the server to match the 
		client for the keyex and public-key algorithms.

	get the best matching algorithm (that is, the one corresponding to the
		strongest crypto mechanism), used by the client to match the server.

   This is a sufficiently complex and screwball function that we need to 
   define a composite structure to pass all of the control information in 
   and out */

typedef enum {
	GETALGO_NONE,			/* No match action */
	GETALGO_FIRST_MATCH,	/* Get first matching algorithm */
	GETALGO_FIRST_MATCH_WARN,/* Get first matching algo, warn if not first */
	GETALGO_BEST_MATCH,		/* Get best matching algorithm */
	GETALGO_LAST			/* Last possible match action */
	} GETALGO_TYPE;

typedef struct {
	const ALGO_STRING_INFO *algoInfo;/* Algorithm selection info */
	CRYPT_ALGO_TYPE preferredAlgo;	/* Preferred algo for first-match */
	GETALGO_TYPE getAlgoType;		/* Type of match to perform */
	CRYPT_ALGO_TYPE algo;			/* Matched algorithm */
	BOOLEAN prefAlgoMismatch;		/* First match != preferredAlgo */
	} ALGOID_INFO;

#define setAlgoIDInfo( algoIDInfo, algoStrInfo, prefAlgo, getType ) \
	{ \
	memset( ( algoIDInfo ), 0, sizeof( ALGOID_INFO ) ); \
	( algoIDInfo )->algoInfo = ( algoStrInfo ); \
	( algoIDInfo )->preferredAlgo = ( prefAlgo ); \
	( algoIDInfo )->getAlgoType = ( getType ); \
	}

static int readAlgoStringEx( STREAM *stream, ALGOID_INFO *algoIDInfo, 
							 void *errorInfo )
	{
	BOOLEAN foundMatch = FALSE;
	const char *string;
	int stringPos, stringLen, substringLen, algoIndex = 999, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( algoIDInfo, sizeof( ALGOID_INFO ) ) );
	assert( isReadPtr( algoIDInfo->algoInfo, sizeof( ALGO_STRING_INFO ) ) );
	assert( ( algoIDInfo->getAlgoType == GETALGO_BEST_MATCH && \
			  algoIDInfo->preferredAlgo == CRYPT_ALGO_NONE ) || \
			( algoIDInfo->getAlgoType == GETALGO_FIRST_MATCH ) ||
			( algoIDInfo->getAlgoType == GETALGO_FIRST_MATCH_WARN && \
			  ( algoIDInfo->preferredAlgo > CRYPT_ALGO_NONE && \
				algoIDInfo->preferredAlgo < CRYPT_ALGO_LAST ) ) );

	/* Get the string length and make sure that it's valid */
	status = stringLen = readUint32( stream );
	if( !cryptStatusError( status ) )
		{
		string = sMemBufPtr( stream );
		status = sSkip( stream, stringLen );
		if( cryptStatusOK( status  ) && stringLen < SSH2_MIN_ALGOID_SIZE )
			/* Quick-reject for too-short strings */
			status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusError( status ) )
		retExt( errorInfo, CRYPT_ERROR_BADDATA,
				"Invalid algorithm ID string" );

	/* Walk down the string looking for a recognised algorithm.  Since our
	   preference may not match the other side's preferences, we have to walk
	   down the entire list to find our preferred choice:

		"algo1,algo2,algo3,algoN"
			   ^   ^		   ^
			   |substrLen	   |
		  stringPos			stringLen */
	for( stringPos = 0; stringPos < stringLen && !foundMatch; \
		 stringPos += substringLen + 1 )
		{
		int currentAlgoIndex;

		/* Find the length of the next algorithm name */
		for( substringLen = stringPos; \
			 substringLen < stringLen && string[ substringLen ] != ','; \
			 substringLen++ );
		substringLen -= stringPos;
		if( substringLen < SSH2_MIN_ALGOID_SIZE )
			continue;	/* Empty or too-short algorithm name, continue */

		/* Check whether it's something that we can handle */
		for( currentAlgoIndex = 0; \
			 algoIDInfo->algoInfo[ currentAlgoIndex ].name != NULL; \
			 currentAlgoIndex++ )
			if( substringLen == strlen( algoIDInfo->algoInfo[ currentAlgoIndex ].name ) && \
				!memcmp( algoIDInfo->algoInfo[ currentAlgoIndex ].name, 
						 string + stringPos, substringLen ) )
				break;
		if( algoIDInfo->algoInfo[ currentAlgoIndex ].name == NULL || \
			( !isPseudoAlgo( algoIDInfo->algoInfo[ currentAlgoIndex ].algo ) && \
			  !algoAvailable( algoIDInfo->algoInfo[ currentAlgoIndex ].algo ) ) )
			{
			/* No match or the matched algorithm isn't available in this 
			   build, if we have to match the first algorithm on the list
			   remember to warn the caller, then move on to the next name */
			if( algoIDInfo->getAlgoType == GETALGO_FIRST_MATCH_WARN )
				algoIDInfo->prefAlgoMismatch = TRUE;
			continue;
			}

		switch( algoIDInfo->getAlgoType )
			{
			case GETALGO_BEST_MATCH:
				/* If we're looking for the best (highest-ranked algorithm) 
				   match, see whether the current match ranks higher than 
				   the existing one */
				if( currentAlgoIndex < algoIndex )
					{
					algoIndex = currentAlgoIndex;
					if( algoIndex <= 0 )
						foundMatch = TRUE;	/* Gruener werd's net */
					}
				break;

			case GETALGO_FIRST_MATCH:
				/* If we've found an acceptable algorithm, remember it and 
				   exit */
				if( algoIDInfo->preferredAlgo == CRYPT_ALGO_NONE || \
					algoIDInfo->preferredAlgo == \
							algoIDInfo->algoInfo[ currentAlgoIndex ].algo )
					{
					algoIndex = currentAlgoIndex;
					foundMatch = TRUE;
					}
				break;

			case GETALGO_FIRST_MATCH_WARN:
				/* If we found the algorithm that we're after, remember it 
				   and exit */
				if( algoIDInfo->preferredAlgo != \
							algoIDInfo->algoInfo[ currentAlgoIndex ].algo )
					/* We didn't match the first algorithm on the list, warn 
					   the caller */
					algoIDInfo->prefAlgoMismatch = TRUE;
				algoIndex = currentAlgoIndex;
				foundMatch = TRUE;
				break;

			default:
				assert( NOTREACHED );
			}
		}
	if( algoIndex > 50 )
		{
		char algoString[ 256 ];

		/* We couldn't find anything to use, tell the caller what was 
		   available */
		if( stringLen > min( MAX_ERRMSG_SIZE - 80, 255 ) )
			stringLen = min( MAX_ERRMSG_SIZE - 80, 255 );
		memcpy( algoString, string, stringLen );
		algoString[ stringLen ] = '\0';
		retExt( errorInfo, CRYPT_ERROR_NOTAVAIL,
				"No algorithm compatible with the remote system's selection "
				"was found : %s", algoString );
		}

	/* We found a more-preferred algorithm than the default, go with that */
	algoIDInfo->algo = algoIDInfo->algoInfo[ algoIndex ].algo;
	return( CRYPT_OK );
	}

int readAlgoString( STREAM *stream, const ALGO_STRING_INFO *algoInfo, 
					CRYPT_ALGO_TYPE *algo, const BOOLEAN useFirstMatch, 
					void *errorInfo )
	{
	ALGOID_INFO algoIDInfo;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( algoInfo, sizeof( ALGO_STRING_INFO ) ) );
	assert( isWritePtr( algo, sizeof( CRYPT_ALGO_TYPE ) ) );

	/* Clear return value */
	*algo = CRYPT_ALGO_NONE;

	setAlgoIDInfo( &algoIDInfo, algoInfo, CRYPT_ALGO_NONE, 
				   useFirstMatch ? GETALGO_FIRST_MATCH : \
								   GETALGO_BEST_MATCH );
	status = readAlgoStringEx( stream, &algoIDInfo, errorInfo );
	if( cryptStatusOK( status ) )
		*algo = algoIDInfo.algo;
	return( status );
	}

/* Algorithms used to protect data packets are used in pairs, one for 
   incoming and the other for outgoing data.  To keep things simple we 
   always force these to be the same, first reading the algorithm for one 
   direction and then making sure that the one for the other direction 
   matches this.  All implementations seem to do this anyway, many aren't 
   even capable of supporting asymmetric algorithm choices */

static int readAlgoStringPair( STREAM *stream, const ALGO_STRING_INFO *algoInfo, 
							   CRYPT_ALGO_TYPE *algo, const BOOLEAN isServer, 
							   void *errorInfo )
	{
	CRYPT_ALGO_TYPE pairPreferredAlgo;
	ALGOID_INFO algoIDInfo;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( algoInfo, sizeof( ALGO_STRING_INFO ) ) );

	/* Clear return value */
	if( algo != NULL )
		*algo = CRYPT_ALGO_NONE;

	/* Get the first algorithm */
	setAlgoIDInfo( &algoIDInfo, algoInfo, CRYPT_ALGO_NONE,
				   isServer ? GETALGO_FIRST_MATCH : GETALGO_BEST_MATCH );
	status = readAlgoStringEx( stream, &algoIDInfo, errorInfo );
	if( cryptStatusError( status ) )
		return( status );
	pairPreferredAlgo = algoIDInfo.algo;

	/* Get the matched second algorithm */
	setAlgoIDInfo( &algoIDInfo, algoInfo, pairPreferredAlgo, 
				   GETALGO_FIRST_MATCH );
	status = readAlgoStringEx( stream, &algoIDInfo, errorInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( pairPreferredAlgo != algoIDInfo.algo )
		retExt( errorInfo, CRYPT_ERROR_BADDATA,
				"Client algorithm %d doesn't match server algorithm %d in "
				"algorithm pair", pairPreferredAlgo, algoIDInfo.algo );
	if( algo != NULL )
		*algo = algoIDInfo.algo;
	return( status );
	}

/* Convert a cryptlib algorithm ID to an SSHv2 algorithm name */

int writeAlgoString( STREAM *stream, const CRYPT_ALGO_TYPE algo )
	{
	static const FAR_BSS ALGO_STRING_INFO algoStringMapTbl[] = {
		{ "ssh-rsa", CRYPT_ALGO_RSA },
		{ "ssh-dss", CRYPT_ALGO_DSA },
		{ "3des-cbc", CRYPT_ALGO_3DES },
		{ "aes128-cbc", CRYPT_ALGO_AES },
		{ "blowfish-cbc", CRYPT_ALGO_BLOWFISH },
		{ "cast128-cbc", CRYPT_ALGO_CAST },
		{ "idea-cbc", CRYPT_ALGO_IDEA },
		{ "arcfour", CRYPT_ALGO_RC4 },
		{ "diffie-hellman-group-exchange-sha1", CRYPT_PSEUDOALGO_DHE },
		{ "diffie-hellman-group1-sha1", CRYPT_ALGO_DH },
		{ "hmac-sha1", CRYPT_ALGO_HMAC_SHA },
		{ "hmac-md5", CRYPT_ALGO_HMAC_MD5 },
		{ "none", CRYPT_PSEUDOALGO_COPR },
		{ "none", CRYPT_ALGO_LAST }		/* Catch-all */
		};
	int i;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( algo >= CRYPT_ALGO_NONE && algo < CRYPT_ALGO_LAST );

	/* Locate the name for this algorithm and encode it as an SSH string */
	for( i = 0; algoStringMapTbl[ i ].algo != CRYPT_ALGO_LAST && \
				algoStringMapTbl[ i ].algo != algo; i++ );
	assert( algoStringMapTbl[ i ].algo != CRYPT_ALGO_LAST );
	return( writeString32( stream, algoStringMapTbl[ i ].name, 0 ) );
	}

/****************************************************************************
*																			*
*							Miscellaneous Functions							*
*																			*
****************************************************************************/

/* Process a client/server hello packet */

int processHelloSSH( SESSION_INFO *sessionInfoPtr, 
					 SSH_HANDSHAKE_INFO *handshakeInfo, int *keyexLength,
					 const BOOLEAN isServer )
	{
	STREAM stream;
	ALGOID_INFO algoIDInfo;
	BOOLEAN preferredAlgoMismatch = FALSE, guessedKeyex = FALSE;
	int length, status;

	/* Process the client/server hello:

		byte		type = SSH2_MSG_KEXINIT
		byte[16]	cookie
		string		keyex algorithms
		string		pubkey algorithms
		string		client_crypto algorithms
		string		server_crypto algorithms
		string		client_mac algorithms
		string		server_mac algorithms
		string		client_compression algorithms
		string		server_compression algorithms
		string		client_language
		string		server_language
		boolean		first_keyex_packet_follows
		uint32		reserved

	   The cookie isn't explicitly processed as with SSHv1 since SSHv2
	   hashes the entire hello message */
	length = readPacketSSH2( sessionInfoPtr, SSH2_MSG_KEXINIT, 128 );
	if( cryptStatusError( length ) )
		return( length );
	*keyexLength = length;
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	sSkip( &stream, ID_SIZE + SSH2_COOKIE_SIZE );

	/* Read the keyex algorithm info */
	if( isServer )
		{
		setAlgoIDInfo( &algoIDInfo, algoStringKeyexTbl, CRYPT_PSEUDOALGO_DHE, 
					   GETALGO_FIRST_MATCH_WARN );
		}
	else
		{
		setAlgoIDInfo( &algoIDInfo, algoStringKeyexTbl, CRYPT_ALGO_NONE, 
					   GETALGO_BEST_MATCH );
		}
	status = readAlgoStringEx( &stream, &algoIDInfo, sessionInfoPtr );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	if( algoIDInfo.prefAlgoMismatch )
		/* We didn't get a match for our first choice, remember that we have
		   to discard any guessed keyex that may follow */
		preferredAlgoMismatch = TRUE;
	if( algoIDInfo.algo == CRYPT_PSEUDOALGO_DHE )
		/* If we're using ephemeral rather than static DH keys, we need to 
		   negotiate the keyex key before we can perform the exchange */
		handshakeInfo->requestedServerKeySize = SSH2_DEFAULT_KEYSIZE;

	/* Read the pubkey (signature) algorithm info */
	if( isServer )
		{
		setAlgoIDInfo( &algoIDInfo, handshakeInfo->algoStringPubkeyTbl, 
					   handshakeInfo->pubkeyAlgo, GETALGO_FIRST_MATCH_WARN );
		}
	else
		{
		setAlgoIDInfo( &algoIDInfo, handshakeInfo->algoStringPubkeyTbl, 
					   CRYPT_ALGO_NONE, GETALGO_BEST_MATCH );
		}
	status = readAlgoStringEx( &stream, &algoIDInfo, sessionInfoPtr );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	if( !isServer )
		handshakeInfo->pubkeyAlgo = algoIDInfo.algo;
	if( algoIDInfo.prefAlgoMismatch )
		/* We didn't get a match for our first choice, remember that we have
		   to discard any guessed keyex that may follow */
		preferredAlgoMismatch = TRUE;

	/* Read the encryption and MAC algorithm info */
	status = readAlgoStringPair( &stream,
						( sessionInfoPtr->flags & SESSION_ISSERVER ) ? \
						  algoStringEncrTblServer : algoStringEncrTblClient, 
						&sessionInfoPtr->cryptAlgo, isServer, 
						sessionInfoPtr );
	if( cryptStatusOK( status ) )
		status = readAlgoStringPair( &stream, algoStringMACTbl,
									 &sessionInfoPtr->integrityAlgo, 
									 isServer, sessionInfoPtr );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* Read the remaining algorithm info.  The final reserved value should
	   always be zero, but we don't specifically check for this since at 
	   some point in the future it may become non-zero */
	status = readAlgoStringPair( &stream, algoStringCoprTbl, NULL, 
								 isServer, sessionInfoPtr );
	if( cryptStatusOK( status ) )
		status = readUniversal32( &stream );
	if( cryptStatusOK( status ) )
		status = readUniversal32( &stream );
	if( cryptStatusOK( status ) )
		{
		if( sgetc( &stream ) )
			guessedKeyex = TRUE;
		status = readUint32( &stream );	/* Reserved value */
		}
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, status, 
				"Invalid hello packet compression algorithm/language string/"
				"trailer" );

	/* If there's a guessed keyex following this packet and we didn't match 
	   the first-choice keyex/pubkey algorithm, tell the caller to skip it */
	if( guessedKeyex && preferredAlgoMismatch )
		return( OK_SPECIAL );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Get/Put Data Functions						*
*																			*
****************************************************************************/

/* Read data over the SSHv2 link */

static int readHeaderFunction( SESSION_INFO *sessionInfoPtr,
							   READSTATE_INFO *readInfo )
	{
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer + \
				   sessionInfoPtr->receiveBufPos;
	long length;
	int extraLength, removedDataLength = ( ID_SIZE + PADLENGTH_SIZE );
	int status;

	/* Clear return value */
	*readInfo = READINFO_NONE;

	/* Make sure that there's room left to handle the speculative read */
	if( sessionInfoPtr->receiveBufPos >= \
		sessionInfoPtr->receiveBufSize - 128 )
		return( 0 );

	/* Try and read the header data from the remote system */
	assert( sessionInfoPtr->receiveBufPos == sessionInfoPtr->receiveBufEnd );
	status = readPacketHeaderSSH2( sessionInfoPtr, SSH2_MSG_CHANNEL_DATA,
								   &length, &extraLength, readInfo );
	if( cryptStatusError( status ) )
		return( ( status == OK_SPECIAL ) ? CRYPT_OK : status );
	assert( length >= ID_SIZE + PADLENGTH_SIZE + SSH2_MIN_PADLENGTH_SIZE );
	status = macPayload( sessionInfoPtr->iAuthInContext, sshInfo->readSeqNo, 
						 bufPtr, MIN_PACKET_SIZE - LENGTH_SIZE, length, 
						 MAC_START, sessionInfoPtr->authBlocksize, TRUE );
	if( cryptStatusError( status ) )
		/* We don't return an extended status at this point because we 
		   haven't completed message MAC calculation/check yet, so any 
		   errors will be cryptlib-internal ones */
		return( status );

	/* Extract fixed information (the pad length and packet type) */
	sshInfo->padLength = bufPtr[ 0 ];
	sshInfo->packetType = bufPtr[ 1 ];

	/* If it's channel data, strip the encapsulation, which allows us to
	   process the payload directly without having to move it around in
	   the buffer */
	if( sshInfo->packetType == SSH2_MSG_CHANNEL_DATA )
		{
		STREAM stream;
		long payloadLength;

		/* Process the channel header and make sure that the payload length 
		   matches the packet length */
		sMemConnect( &stream, bufPtr, SSH2_HEADER_REMAINDER_SIZE );
		sSkip( &stream, ID_SIZE + PADLENGTH_SIZE );
		status = processChannelControlMessage( sessionInfoPtr, &stream );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		payloadLength = readUint32( &stream );
		removedDataLength = stell( &stream );
		sMemDisconnect( &stream );
		if( payloadLength != length - ( removedDataLength + \
										sshInfo->padLength ) )
			retExt( sessionInfoPtr, CRYPT_ERROR_BADDATA,
					"Invalid data packet payload length %ld, should be %ld",
					payloadLength, 
					length - ( removedDataLength + sshInfo->padLength ) );
		}

	/* Move the remainder down to the start of the buffer.  The general idea 
	   is to remove all of the header data so that only the payload remains 
	   in the buffer, avoiding the need to move it down afterwards.  This is 
	   complicated by the fact that (unlike SSL) all of the data (including 
	   the header) is encrypted and MAC'ed, so we can't just read that 
	   separately but have to process it as part of the payload, remove it, 
	   and remember anything that's left for later */
	assert( SSH2_HEADER_REMAINDER_SIZE - removedDataLength > 0 );
	memmove( bufPtr, bufPtr + removedDataLength, 
			 SSH2_HEADER_REMAINDER_SIZE - removedDataLength );

	/* Determine how much data we'll be expecting, adjusted for the fixed 
	   information that we've removed and the (implicitly present) MAC data */
	sessionInfoPtr->pendingPacketLength = \
			sessionInfoPtr->pendingPacketRemaining = \
					( length + extraLength ) - removedDataLength;

	/* Indicate that we got some payload as part of the header */
	*readInfo = READINFO_HEADERPAYLOAD;
	return( SSH2_HEADER_REMAINDER_SIZE - removedDataLength );
	}

static int processBodyFunction( SESSION_INFO *sessionInfoPtr,
								READSTATE_INFO *readInfo )
	{
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer + \
				   sessionInfoPtr->receiveBufPos;
	long length = ( sessionInfoPtr->pendingPacketLength - \
					sessionInfoPtr->pendingPacketPartialLength ) - \
				  sessionInfoPtr->authBlocksize;
	int status;

	/* All errors processing the payload are fatal */
	*readInfo = READINFO_FATAL;

	/* Decrypt the packet in the buffer and MAC the payload.  The length may
	   be zero if the entire message fits into the fixed-length portion, e.g.
	   for channel-close messages that only contain a channel number */
	if( length > 0 )
		{
		status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
						IMESSAGE_CTX_DECRYPT,
						bufPtr + sessionInfoPtr->pendingPacketPartialLength,
						length );
		if( cryptStatusError( status ) )
			return( status );
		}
	status = macPayload( sessionInfoPtr->iAuthInContext, 0,
						 bufPtr + sessionInfoPtr->pendingPacketPartialLength,
						 length, 0, MAC_END, sessionInfoPtr->authBlocksize,
						 TRUE );
	if( cryptStatusError( status ) )
		retExt( sessionInfoPtr, CRYPT_ERROR_SIGNATURE, 
				"Bad message MAC for packet type %d, length %d",
				sshInfo->packetType, 
				sessionInfoPtr->pendingPacketPartialLength + length );

	/* Strip the padding and MAC and update the state information */
	length = sessionInfoPtr->pendingPacketLength - \
			 ( sshInfo->padLength + sessionInfoPtr->authBlocksize );
	sshInfo->readSeqNo++;

	/* If it's not plain data (which was handled at the readHeaderFunction()
	   stage), handle it as a control message */
	if( sshInfo->packetType != SSH2_MSG_CHANNEL_DATA )
		{
		STREAM stream;

		/* Process the control message and reset the receive buffer 
		   indicators to clear it */
		sMemConnect( &stream, bufPtr, length );
		status = processChannelControlMessage( sessionInfoPtr, &stream );
		sMemDisconnect( &stream );
		sessionInfoPtr->receiveBufEnd = sessionInfoPtr->receiveBufPos;
		sessionInfoPtr->pendingPacketLength = 0;
		if( cryptStatusError( status ) )
			{
			/* If we got an OK_SPECIAL status, the packet was handled 
			   internally and we can try again.  If it was a message that
			   the user has to respond to, it's also not a fatal error
			   condition and they can continue afterwards */
			if( status == OK_SPECIAL || status == CRYPT_ENVELOPE_RESOURCE )
				*readInfo = READINFO_NOOP;
			return( status );
			}
		}

	sessionInfoPtr->receiveBufEnd = sessionInfoPtr->receiveBufPos + length;
	sessionInfoPtr->receiveBufPos = sessionInfoPtr->receiveBufEnd;
	sessionInfoPtr->pendingPacketLength = 0;

	*readInfo = READINFO_NONE;
	return( length );
	}

/* Write data over the SSHv2 link */

static int preparePacketFunction( SESSION_INFO *sessionInfoPtr )
	{
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	STREAM stream;
	const int dataLength = sessionInfoPtr->sendBufPos - \
						   ( SSH2_HEADER_SIZE + SSH2_PAYLOAD_HEADER_SIZE );
	int length, status;

	assert( !( sessionInfoPtr->flags & SESSION_SENDCLOSED ) );

	/* Wrap up the payload ready for sending:

		byte		SSH2_MSG_CHANNEL_DATA
		uint32		channel_no
		string		data

	   Since this is wrapping in-place data, we first open a write stream to
	   add the header, then open a read stream covering the full buffer in
	   preparation for wrapping the packet */
	openPacketStreamSSH( &stream, sessionInfoPtr, SSH2_PAYLOAD_HEADER_SIZE, 
						 SSH2_MSG_CHANNEL_DATA );
	writeUint32( &stream, getCurrentChannelNo( sessionInfoPtr, \
											   CHANNEL_WRITE ) );
	writeUint32( &stream, dataLength );
	assert( sStatusOK( &stream ) );
	sMemDisconnect( &stream );
	sMemConnect( &stream, sessionInfoPtr->sendBuffer, 
				 sessionInfoPtr->sendBufSize );
	sSkip( &stream, SSH2_HEADER_SIZE + SSH2_PAYLOAD_HEADER_SIZE + \
					dataLength );
	status = wrapPacketSSH2( sessionInfoPtr, &stream, 0 );
	length = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* If there's control data enqueued to be written, try and append it to
	   the existing data to be sent */
	if( sshInfo->response.type > 0 )
		{
		int length2;

		length2 = appendChannelData( sessionInfoPtr, length );
		if( !cryptStatusError( length2 ) )
			length += length2;
		}

	return( length );
	}

/* Close a previously-opened SSH session */

static void shutdownFunction( SESSION_INFO *sessionInfoPtr )
	{
	/* If we haven't entered the secure state yet (i.e. we're still in the
	   middle of the handshake), this is an abnormal termination, send a
	   disconnect indication:

		byte		SSH2_MSG_DISCONNECT
		uint32		reason_code = SSH2_DISCONNECT_PROTOCOL_ERROR
		string		description = "Handshake failed"
		string		language_tag = "" */
	if( !( sessionInfoPtr->flags & SESSION_ISSECURE_WRITE ) )
		{
		STREAM stream;
		int status;

		openPacketStreamSSH( &stream, sessionInfoPtr, CRYPT_USE_DEFAULT, 
							 SSH2_MSG_DISCONNECT );
		writeUint32( &stream, SSH2_DISCONNECT_PROTOCOL_ERROR );
		writeString32( &stream, "Handshake failed", 16 );
		writeUint32( &stream, 0 );	/* No language tag */
		status = wrapPacketSSH2( sessionInfoPtr, &stream, 0 );
		if( cryptStatusOK( status ) )
			{
			const int length = stell( &stream );

			sendCloseNotification( sessionInfoPtr, 
								   sMemBufPtr( &stream ) - length,
								   length );
			}
		sMemDisconnect( &stream );
		sNetDisconnect( &sessionInfoPtr->stream );
		return;
		}

	/* Close the channel */
	closeChannel( sessionInfoPtr, TRUE );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

void initSSH2processing( SESSION_INFO *sessionInfoPtr,
						 SSH_HANDSHAKE_INFO *handshakeInfo,
						 const BOOLEAN isServer )
	{
	static const PROTOCOL_INFO protocolInfo = {
		/* General session information */
		FALSE,						/* Request-response protocol */
		SESSION_NONE,				/* Flags */
		SSH_PORT,					/* SSH port */
		SESSION_NEEDS_USERID |		/* Client attributes */
			SESSION_NEEDS_PASSWORD | \
			SESSION_NEEDS_KEYORPASSWORD | \
			SESSION_NEEDS_PRIVKEYSIGN,
				/* The client private key is optional, but if present it has 
				   to be signature-capable */
		SESSION_NEEDS_PRIVATEKEY |	/* Server attributes */
			SESSION_NEEDS_PRIVKEYSIGN,
#ifdef USE_SSH1
		2, 1, 2,					/* Version 2 */
#else
		2, 2, 2,					/* Version 2 */
#endif /* USE_SSH1 */
		NULL, NULL,					/* Content-type */

		/* Protocol-specific information */
		EXTRA_PACKET_SIZE + \
			DEFAULT_PACKET_SIZE,	/* Send/receive buffer size */
		SSH2_HEADER_SIZE + \
			SSH2_PAYLOAD_HEADER_SIZE,/* Payload data start */
		DEFAULT_PACKET_SIZE			/* (Default) maximum packet size */
		};

	sessionInfoPtr->protocolInfo = &protocolInfo;
	sessionInfoPtr->readHeaderFunction = readHeaderFunction;
	sessionInfoPtr->processBodyFunction = processBodyFunction;
	sessionInfoPtr->preparePacketFunction = preparePacketFunction;
	sessionInfoPtr->shutdownFunction = shutdownFunction;
	if( handshakeInfo != NULL )
		{
		if( isServer )
			initSSH2serverProcessing( sessionInfoPtr, handshakeInfo );
		else
			initSSH2clientProcessing( sessionInfoPtr, handshakeInfo );

		handshakeInfo->algoStringPubkeyTbl = algoStringPubkeyTbl;
		}
	}
#endif /* USE_SSH2 */
