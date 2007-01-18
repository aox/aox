/****************************************************************************
*																			*
*								Signature Routines							*
*						Copyright Peter Gutmann 1993-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "mech.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
  #include "pgp.h"
#else
  #include "crypt.h"
  #include "mechs/mech.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
  #include "misc/misc_rw.h"
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*							Extended Create/Check a Signature 				*
*																			*
****************************************************************************/

/* Create/check an extended signature type */

C_RET cryptCreateSignatureEx( C_OUT void C_PTR signature,
							  C_IN int signatureMaxLength,
							  C_OUT int C_PTR signatureLength,
							  C_IN CRYPT_FORMAT_TYPE formatType,
							  C_IN CRYPT_CONTEXT signContext,
							  C_IN CRYPT_CONTEXT hashContext,
							  C_IN CRYPT_HANDLE extraData )
	{
	CRYPT_CERTTYPE_TYPE certType;
	int value, status;

	/* Perform basic error checking.  We have to use an internal message to
	   check for signing capability because the DLP algorithms have
	   specialised data-formatting requirements that can't normally be
	   directly accessed via external messages, and even the non-DLP
	   algorithms may be internal-use-only if there's a cert attached to
	   the context.  If we're performing a sign operation this is OK since
	   they're being used from cryptlib-internal routines, but to make sure
	   that the context is OK we first check its external accessibility by
	   performing a dummy attribute read.  Note that we can't safely use the
	   cert-type read performed later on for this check because some error
	   conditions (e.g. "not a certificate") are valid in this case, but we
	   don't want to have mess with trying to distinguish OK-in-this-instance 
	   vs.not-OK error conditions for the basic accessibility check */
	if( signature != NULL )
		{
		if( signatureMaxLength < MIN_CRYPT_OBJECTSIZE )
			return( CRYPT_ERROR_PARAM2 );
		if( !isWritePtr( signature, signatureMaxLength ) )
			return( CRYPT_ERROR_PARAM1 );
		memset( signature, 0, MIN_CRYPT_OBJECTSIZE );
		}
	else
		if( signatureMaxLength != 0 )
			return( CRYPT_ERROR_PARAM2 );
	if( !isWritePtr( signatureLength, sizeof( int ) ) )
		return( CRYPT_ERROR_PARAM3 );
	*signatureLength = 0;
	if( formatType <= CRYPT_FORMAT_NONE || \
		formatType >= CRYPT_FORMAT_LAST_EXTERNAL )
		return( CRYPT_ERROR_PARAM4 );
	status = krnlSendMessage( signContext, MESSAGE_GETATTRIBUTE,
							  &value, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM5 : status );
	status = krnlSendMessage( signContext, IMESSAGE_CHECK, NULL,
							  MESSAGE_CHECK_PKC_SIGN );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM5 : status );
	status = krnlSendMessage( hashContext, MESSAGE_CHECK, NULL,
							  MESSAGE_CHECK_HASH );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM6 : status );

	/* If the signing context has a cert chain attached, the currently-
	   selected cert may not be the leaf cert.  To ensure that we use the
	   correct cert, we lock the chain (which both protects us from having
	   the user select a different cert while we're using it, and saves the
	   selection state for when we later unlock it) and explicitly select
	   the leaf cert.  Certs are used for formats other than the obvious
	   CRYPT_FORMAT_CMS/CRYPT_FORMAT_SMIME, so we perform this operation
	   unconditionally rather than only for those two formats */
	status = krnlSendMessage( signContext, MESSAGE_GETATTRIBUTE,
							  &certType, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		/* There's no cert of the required type attached */
		certType = CRYPT_CERTTYPE_NONE;
	else
		if( certType == CRYPT_CERTTYPE_CERTCHAIN )
			{
			status = krnlSendMessage( signContext, IMESSAGE_SETATTRIBUTE,
									  MESSAGE_VALUE_TRUE,
									  CRYPT_IATTRIBUTE_LOCKED );
			if( cryptStatusError( status ) )
				return( status );
			krnlSendMessage( signContext, IMESSAGE_SETATTRIBUTE,
							 MESSAGE_VALUE_CURSORFIRST,
							 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
			}

	/* Call the low-level signature create function to create the
	   signature */
	switch( formatType )
		{
		case CRYPT_FORMAT_AUTO:
		case CRYPT_FORMAT_CRYPTLIB:
			/* If it's a cryptlib-format signature, there can't be any extra
			   signing attributes present */
			if( extraData != CRYPT_USE_DEFAULT )
				{
				status = CRYPT_ERROR_PARAM7;
				break;
				}

			status = createSignature( signature, signatureLength,
									  signatureMaxLength, signContext,
									  hashContext, CRYPT_UNUSED,
									  SIGNATURE_CRYPTLIB );
			break;

		case CRYPT_FORMAT_CMS:
		case CRYPT_FORMAT_SMIME:
			/* Make sure that the signing context has a cert attached to
			   it */
			if( certType != CRYPT_CERTTYPE_CERTIFICATE && \
				certType != CRYPT_CERTTYPE_CERTCHAIN )
				{
				status = CRYPT_ERROR_PARAM5;
				break;
				}

			/* Make sure that the extra data object is in order */
			if( extraData != CRYPT_USE_DEFAULT )
				{
				status = krnlSendMessage( extraData, MESSAGE_GETATTRIBUTE,
										  &certType, CRYPT_CERTINFO_CERTTYPE );
				if( cryptStatusError( status ) || \
					certType != CRYPT_CERTTYPE_CMS_ATTRIBUTES )
					{
					status = CRYPT_ERROR_PARAM7;
					break;
					}
				}

			status = createSignatureCMS( signature, signatureLength,
										 signatureMaxLength, signContext,
										 hashContext, extraData,
										 CRYPT_UNUSED, formatType );
			break;

#ifdef USE_PGP
		case CRYPT_FORMAT_PGP:
			status = createSignaturePGP( signature, signatureLength,
										 signatureMaxLength, signContext,
										 hashContext );
			break;
#endif /* USE_PGP */

		default:
			assert( NOTREACHED );
			status = CRYPT_ERROR_PARAM4;
		}
	if( certType == CRYPT_CERTTYPE_CERTCHAIN )
		/* We're signing with a cert chain, restore its state and unlock it
		   to allow others access */
		krnlSendMessage( signContext, IMESSAGE_SETATTRIBUTE,
						 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptArgError( status ) )
		/* Remap the error code to refer to the correct parameter */
		status = ( status == CRYPT_ARGERROR_NUM1 ) ? \
				 CRYPT_ERROR_PARAM5 : CRYPT_ERROR_PARAM6;
	return( status );
	}

C_RET cryptCreateSignature( C_OUT void C_PTR signature,
							C_IN int signatureMaxLength,
							C_OUT int C_PTR signatureLength,
							C_IN CRYPT_CONTEXT signContext,
							C_IN CRYPT_CONTEXT hashContext )
	{
	int status;

	status = cryptCreateSignatureEx( signature, signatureMaxLength,
									 signatureLength, CRYPT_FORMAT_CRYPTLIB,
									 signContext, hashContext,
									 CRYPT_USE_DEFAULT );
	if( cryptStatusError( status ) )
		{
		/* Remap parameter errors to the correct position */
		if( status == CRYPT_ERROR_PARAM5 )
			status = CRYPT_ERROR_PARAM4;
		if( status == CRYPT_ERROR_PARAM6 )
			status = CRYPT_ERROR_PARAM5;
		}
	return( status );
	}

static CRYPT_FORMAT_TYPE getFormatType( const void *data, 
										const int dataLength )
	{
	CRYPT_FORMAT_TYPE formatType = CRYPT_FORMAT_NONE;
	STREAM stream;
	const int dataReadLength = min( dataLength, 16 );
	long value;
	int status;

	assert( isReadPtr( data, MIN_CRYPT_OBJECTSIZE ) );
	assert( dataLength >= MIN_CRYPT_OBJECTSIZE );

	sMemConnect( &stream, data, dataReadLength );

	/* Figure out what we've got.  A PKCS #7/CMS/SMIME signature begins:

		cryptlibSignature ::= SEQUENCE {
			version		INTEGER (3),
			keyID [ 0 ]	OCTET STRING

	   while a CMS signature begins:

		cmsSignature ::= SEQUENCE {
			version		INTEGER (1),
			digestAlgo	SET OF {

	   which allows us to determine which type of object we have */
	if( sPeek( &stream ) == BER_SEQUENCE )
		{
		readSequence( &stream, NULL );
		status = readShortInteger( &stream, &value );
		if( cryptStatusOK( status ) )
			{
			switch( value )
				{
				case SIGNATURE_VERSION:
					formatType = CRYPT_FORMAT_CMS;
					break;

				case SIGNATURE_EX_VERSION:
					formatType = CRYPT_FORMAT_CRYPTLIB;
					break;

				default:
					formatType = CRYPT_FORMAT_NONE;
				}
			}
		sMemDisconnect( &stream );

		return( formatType );
		}

#ifdef USE_PGP
	/* It's not ASN.1 data, check for PGP data */
	status = pgpReadPacketHeader( &stream, NULL, &value, 30 );
	if( cryptStatusOK( status ) && value > 30 && value < 8192 )
		{
		sMemDisconnect( &stream );
		return( CRYPT_FORMAT_PGP );
		}
#endif /* USE_PGP */

	sMemDisconnect( &stream );

	return( CRYPT_FORMAT_NONE );
	}

C_RET cryptCheckSignatureEx( C_IN void C_PTR signature,
							 C_IN int signatureLength,
							 C_IN CRYPT_HANDLE sigCheckKey,
							 C_IN CRYPT_CONTEXT hashContext,
							 C_OUT CRYPT_HANDLE C_PTR extraData )
	{
	CRYPT_FORMAT_TYPE formatType;
	CRYPT_CONTEXT sigCheckContext;
	int status;

	/* Perform basic error checking */
	if( signatureLength < MIN_CRYPT_OBJECTSIZE )
		return( CRYPT_ERROR_PARAM2 );
	if( !isReadPtr( signature, signatureLength ) )
		return( CRYPT_ERROR_PARAM1 );
	if( ( formatType = getFormatType( signature, \
									  signatureLength ) ) == CRYPT_FORMAT_NONE )
		return( CRYPT_ERROR_BADDATA );
	status = krnlSendMessage( sigCheckKey, MESSAGE_GETDEPENDENT,
							  &sigCheckContext, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( sigCheckContext, IMESSAGE_CHECK,
								  NULL, MESSAGE_CHECK_PKC_SIGCHECK );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( hashContext, MESSAGE_CHECK, NULL,
								  MESSAGE_CHECK_HASH );
		if( status == CRYPT_ARGERROR_OBJECT )
			status = CRYPT_ERROR_PARAM4;
		}
	else
		if( status == CRYPT_ARGERROR_OBJECT )
			status = CRYPT_ERROR_PARAM3;
	if( cryptStatusError( status ) )
		return( status );
	if( formatType == CRYPT_FORMAT_CMS || \
		formatType == CRYPT_FORMAT_SMIME )
		{
		int certType;

		/* Make sure that the sig check key includes a cert */
		status = krnlSendMessage( sigCheckKey, MESSAGE_GETATTRIBUTE,
								  &certType, CRYPT_CERTINFO_CERTTYPE );
		if( cryptStatusError( status ) ||
			( certType != CRYPT_CERTTYPE_CERTIFICATE && \
			  certType != CRYPT_CERTTYPE_CERTCHAIN ) )
			return( CRYPT_ERROR_PARAM3 );
		}

	/* Call the low-level signature check function to check the signature */
	switch( formatType )
		{
		case CRYPT_FORMAT_CRYPTLIB:
			/* If it's a cryptlib-format signature, there can't be any extra
			   signing attributes present */
			if( extraData != NULL )
				return( CRYPT_ERROR_PARAM5 );
			status = checkSignature( signature, signatureLength,
									 sigCheckContext, hashContext,
									 CRYPT_UNUSED, SIGNATURE_CRYPTLIB );
			break;

		case CRYPT_FORMAT_CMS:
		case CRYPT_FORMAT_SMIME:
			if( extraData != NULL )
				{
				if( !isWritePtr( extraData, sizeof( int ) ) )
					return( CRYPT_ERROR_PARAM6 );
				*extraData = CRYPT_ERROR;
				}
			status = checkSignatureCMS( signature, signatureLength,
										sigCheckContext, hashContext,
										extraData, sigCheckKey );
			if( cryptStatusOK( status ) && extraData != NULL )
				/* Make the recovered signing attributes externally
				   visible */
				krnlSendMessage( *extraData, IMESSAGE_SETATTRIBUTE,
								 MESSAGE_VALUE_FALSE,
								 CRYPT_IATTRIBUTE_INTERNAL );
			break;

#ifdef USE_PGP
		case CRYPT_FORMAT_PGP:
			/* PGP doesn't have signing attributes */
			if( extraData != NULL )
				return( CRYPT_ERROR_PARAM5 );
			status = checkSignaturePGP( signature, signatureLength,
										sigCheckContext, hashContext );
			break;
#endif /* USE_PGP */

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_PARAM4 );
		}

	if( cryptArgError( status ) )
		/* Remap the error code to refer to the correct parameter */
		status = ( status == CRYPT_ARGERROR_NUM1 ) ? \
				 CRYPT_ERROR_PARAM3 : CRYPT_ERROR_PARAM4;
	return( status );
	}

C_RET cryptCheckSignature( C_IN void C_PTR signature,
						   C_IN int signatureLength,
						   C_IN CRYPT_HANDLE sigCheckKey,
						   C_IN CRYPT_CONTEXT hashContext )
	{
	return( cryptCheckSignatureEx( signature, signatureLength, sigCheckKey,
								   hashContext, NULL ) );
	}

/* Internal versions of the above.  These skip a lot of the checking done by
   the external versions since they're only called by cryptlib internal
   functions that have already checked the parameters for validity.  In
   addition the iExtraData value can take an extra value CRYPT_UNUSED
   (don't use any signing attributes) */

int iCryptCreateSignatureEx( void *signature, int *signatureLength,
							 const int sigMaxLength,
							 const CRYPT_FORMAT_TYPE formatType,
							 const CRYPT_CONTEXT iSignContext,
							 const CRYPT_CONTEXT iHashContext,
							 const CRYPT_HANDLE iExtraData,
							 const CRYPT_SESSION iTspSession )
	{
	BOOLEAN isCertChain = FALSE;
	int certType, status;

	/* Clear return value */
	*signatureLength = 0;

	assert( ( signature == NULL && sigMaxLength == 0 ) || \
			( signature != NULL && \
			  sigMaxLength > 64 && sigMaxLength < 32768L ) );
	assert( signature == NULL || isWritePtr( signature, sigMaxLength ) );
	assert( isWritePtr( signatureLength, sizeof( int ) ) );
	assert( formatType > CRYPT_FORMAT_NONE && \
			formatType < CRYPT_FORMAT_LAST );
	assert( isHandleRangeValid( iSignContext ) );
	assert( isHandleRangeValid( iHashContext ) );

	/* If the signing context has a cert chain attached, the currently-
	   selected cert may not be the leaf cert.  To ensure that we use the
	   correct cert, we lock the chain (which both protects us from having
	   the user select a different cert while we're using it, and saves the
	   selection state for when we later unlock it) and explicitly select
	   the leaf cert */
	status = krnlSendMessage( iSignContext, IMESSAGE_GETATTRIBUTE,
							  &certType, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusOK( status ) && certType == CRYPT_CERTTYPE_CERTCHAIN )
		{
		status = krnlSendMessage( iSignContext, IMESSAGE_SETATTRIBUTE,
								  MESSAGE_VALUE_TRUE,
								  CRYPT_IATTRIBUTE_LOCKED );
		if( cryptStatusError( status ) )
			return( status );
		krnlSendMessage( iSignContext, IMESSAGE_SETATTRIBUTE,
						 MESSAGE_VALUE_CURSORFIRST,
						 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
		isCertChain = TRUE;
		}

	/* Call the low-level signature create function to create the signature */
	switch( formatType )
		{
		case CRYPT_FORMAT_CRYPTLIB:
			status = createSignature( signature, signatureLength,
									  sigMaxLength, iSignContext,
									  iHashContext, CRYPT_UNUSED,
									  SIGNATURE_CRYPTLIB );
			break;

#ifdef USE_PGP
		case CRYPT_FORMAT_PGP:
			status = createSignaturePGP( signature, signatureLength,
										 sigMaxLength, iSignContext,
										 iHashContext );
			break;
#endif /* USE_PGP */

#ifdef USE_SSL
		case CRYPT_IFORMAT_SSL:
			status = createSignature( signature, signatureLength,
									  sigMaxLength, iSignContext,
									  iHashContext, iExtraData,
									  SIGNATURE_SSL );
			break;
#endif /* USE_SSL */

#ifdef USE_SSH
		case CRYPT_IFORMAT_SSH:
			status = createSignature( signature, signatureLength,
									  sigMaxLength, iSignContext,
									  iHashContext, CRYPT_UNUSED,
									  SIGNATURE_SSH );
			break;
#endif /* USE_SSH */

		case CRYPT_FORMAT_CMS:
		case CRYPT_FORMAT_SMIME:
			status = createSignatureCMS( signature, signatureLength,
										 sigMaxLength, iSignContext,
										 iHashContext, iExtraData,
										 iTspSession, formatType );
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
		}
	if( cryptArgError( status ) )
		{
		/* Catch any parameter errors that slip through */
		assert( NOTREACHED );
		status = CRYPT_ERROR_FAILED;
		}
	if( isCertChain )
		/* If we're signing with a cert chain, restore its state and unlock
		   it to allow others access */
		krnlSendMessage( iSignContext, IMESSAGE_SETATTRIBUTE,
						 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );

	return( status );
	}

int iCryptCheckSignatureEx( const void *signature, const int signatureLength,
							const CRYPT_FORMAT_TYPE formatType,
							const CRYPT_HANDLE iSigCheckKey,
							const CRYPT_CONTEXT iHashContext,
							CRYPT_HANDLE *extraData )
	{
	CRYPT_CONTEXT sigCheckContext;
	int status;

	assert( isReadPtr( signature, signatureLength ) );
	assert( formatType > CRYPT_FORMAT_NONE && \
			formatType < CRYPT_FORMAT_LAST );
	assert( isHandleRangeValid( iSigCheckKey ) );
	assert( isHandleRangeValid( iHashContext ) );

	/* Perform basic error checking */
	status = krnlSendMessage( iSigCheckKey, IMESSAGE_GETDEPENDENT,
							  &sigCheckContext, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );

	/* Call the low-level signature check function to check the signature */
	switch( formatType )
		{
		case CRYPT_FORMAT_CRYPTLIB:
			status = checkSignature( signature, signatureLength,
									 sigCheckContext, iHashContext,
									 CRYPT_UNUSED, SIGNATURE_CRYPTLIB );
			break;

#ifdef USE_PGP
		case CRYPT_FORMAT_PGP:
			status = checkSignaturePGP( signature, signatureLength,
										sigCheckContext, iHashContext );
			break;
#endif /* USE_PGP */

#ifdef USE_SSL
		case CRYPT_IFORMAT_SSL:
			status = checkSignature( signature, signatureLength,
									 sigCheckContext, iHashContext,
									 *extraData, SIGNATURE_SSL );
			break;
#endif /* USE_SSL */

#ifdef USE_SSH
		case CRYPT_IFORMAT_SSH:
			status = checkSignature( signature, signatureLength,
									 sigCheckContext, iHashContext,
									 CRYPT_UNUSED, SIGNATURE_SSH );
			break;
#endif /* USE_SSH */

		case CRYPT_FORMAT_CMS:
		case CRYPT_FORMAT_SMIME:
			if( extraData != NULL )
				*extraData = CRYPT_ERROR;
			status = checkSignatureCMS( signature, signatureLength, 
										sigCheckContext, iHashContext, 
										extraData, iSigCheckKey );
			break;

		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
		}
	if( cryptArgError( status ) )
		{
		/* Catch any parameter errors that slip through */
		assert( NOTREACHED );
		status = CRYPT_ERROR_SIGNATURE;
		}
	return( status );
	}
