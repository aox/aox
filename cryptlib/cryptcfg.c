/****************************************************************************
*																			*
*						 cryptlib Configuration Routines					*
*						Copyright Peter Gutmann 1994-2005					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "asn1.h"
#else
  #include "misc/asn1.h"
#endif /* Compiler-specific includes */

/* Prototypes for cert trust management functions */

int addTrustEntry( void *trustInfoPtr, const CRYPT_CERTIFICATE cryptCert,
				   const void *certObject, const int certObjectLength );
int enumTrustedCerts( void *trustInfoPtr, const CRYPT_CERTIFICATE iCryptCtl,
					  const CRYPT_KEYSET iCryptKeyset );

/****************************************************************************
*																			*
*							Configuration Options							*
*																			*
****************************************************************************/

/* Configuration option types */

typedef enum {
	OPTION_NONE,					/* Non-option */
	OPTION_STRING,					/* Literal string */
	OPTION_NUMERIC,					/* Numeric value */
	OPTION_BOOLEAN					/* Boolean flag */
	} OPTION_TYPE;

/* The configuration options.  These are broken up into two parts, the fixed
   default values that are shared across all cryptlib operations and the
   variable values that are variable for each user object.

   Alongside the CRYPT_ATTRIBUTE_TYPE we store a persistant index value for
   the option that always stays the same even if the attribute type changes.
   This avoids the need to change the config file every time an attribute is
   added or deleted.  Some options can't be made persistent, for these the
   index value is set to CRYPT_UNUSED */

typedef struct {
	const CRYPT_ATTRIBUTE_TYPE option;/* Attribute ID */
	const OPTION_TYPE type;			/* Option type */
	const int index;				/* Index value for this option */
	const char FAR_BSS *strDefault;	/* Default if it's a string option */
	const int intDefault;			/* Default if it's a numeric/boolean */
	} FIXED_OPTION_INFO;

typedef struct {
	char *strValue;					/* Value if it's a string option */
	int intValue;					/* Value if it's a numeric/boolean */
	BOOLEAN dirty;					/* Whether option has been changed */
	} OPTION_INFO;

#define MK_OPTION( option, value, index ) \
	{ option, OPTION_NUMERIC, index, NULL, value }
#define MK_OPTION_B( option, value, index ) \
	{ option, OPTION_BOOLEAN, index, NULL, value }
#define MK_OPTION_S( option, value, index ) \
	{ option, OPTION_STRING, index, value, 0 }
#define MK_OPTION_NONE() \
	{ CRYPT_ATTRIBUTE_NONE, OPTION_NONE, CRYPT_UNUSED, NULL, 0 }

static const FAR_BSS FIXED_OPTION_INFO fixedOptionInfo[] = {
	/* Dummy entry for CRYPT_ATTRIBUTE_NONE */
	MK_OPTION_NONE(),

	/* cryptlib information (read-only) */
	MK_OPTION_S( CRYPT_OPTION_INFO_DESCRIPTION, "cryptlib security toolkit", CRYPT_UNUSED ),
	MK_OPTION_S( CRYPT_OPTION_INFO_COPYRIGHT, "Copyright Peter Gutmann, Eric Young, OpenSSL, 1994-2005", CRYPT_UNUSED ),
	MK_OPTION( CRYPT_OPTION_INFO_MAJORVERSION, 3, CRYPT_UNUSED ),
	MK_OPTION( CRYPT_OPTION_INFO_MINORVERSION, 2, CRYPT_UNUSED ),
	MK_OPTION( CRYPT_OPTION_INFO_STEPPING, 0, CRYPT_UNUSED ),

	/* Context options, base = 0 */
	/* Algorithm = Conventional encryption/hash/MAC options */
	MK_OPTION( CRYPT_OPTION_ENCR_ALGO, CRYPT_ALGO_3DES, 0 ),
	MK_OPTION( CRYPT_OPTION_ENCR_HASH, CRYPT_ALGO_SHA, 1 ),
	MK_OPTION( CRYPT_OPTION_ENCR_MAC, CRYPT_ALGO_HMAC_SHA, 2 ),

	/* Algorithm = PKC options */
	MK_OPTION( CRYPT_OPTION_PKC_ALGO, CRYPT_ALGO_RSA, 3 ),
	MK_OPTION( CRYPT_OPTION_PKC_KEYSIZE, bitsToBytes( 1024 ), 4 ),

	/* Algorithm = Signature options */
	MK_OPTION( CRYPT_OPTION_SIG_ALGO, CRYPT_ALGO_RSA, 5 ),
	MK_OPTION( CRYPT_OPTION_SIG_KEYSIZE, bitsToBytes( 1024 ), 6 ),

	/* Algorithm = Key derivation options */
	MK_OPTION( CRYPT_OPTION_KEYING_ALGO, CRYPT_ALGO_SHA, 7 ),
	MK_OPTION( CRYPT_OPTION_KEYING_ITERATIONS, 500, 8 ),

	/* Certificate options, base = 100 */
	MK_OPTION_B( CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, FALSE, 100 ),
	MK_OPTION( CRYPT_OPTION_CERT_VALIDITY, 365, 101 ),
	MK_OPTION( CRYPT_OPTION_CERT_UPDATEINTERVAL, 90, 102 ),
	MK_OPTION( CRYPT_OPTION_CERT_COMPLIANCELEVEL, CRYPT_COMPLIANCELEVEL_STANDARD, 103 ),
	MK_OPTION_B( CRYPT_OPTION_CERT_REQUIREPOLICY, TRUE, 104 ),

	/* CMS options */
	MK_OPTION_B( CRYPT_OPTION_CMS_DEFAULTATTRIBUTES, TRUE, 105 ),

	/* Keyset options, base = 200 */
	/* Keyset = LDAP options */
	MK_OPTION_S( CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS, "inetOrgPerson", 200 ),
	MK_OPTION( CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE, CRYPT_CERTTYPE_NONE, 201 ),
	MK_OPTION_S( CRYPT_OPTION_KEYS_LDAP_FILTER, "(objectclass=*)", 202 ),
	MK_OPTION_S( CRYPT_OPTION_KEYS_LDAP_CACERTNAME, "cACertificate;binary", 203 ),
	MK_OPTION_S( CRYPT_OPTION_KEYS_LDAP_CERTNAME, "userCertificate;binary", 204 ),
	MK_OPTION_S( CRYPT_OPTION_KEYS_LDAP_CRLNAME, "certificateRevocationList;binary", 205 ),
	MK_OPTION_S( CRYPT_OPTION_KEYS_LDAP_EMAILNAME, "mail", 206 ),

	/* Device options, base = 300 */
	/* Device = PKCS #11 token options */
	MK_OPTION_S( CRYPT_OPTION_DEVICE_PKCS11_DVR01, NULL, 300 ),
	MK_OPTION_S( CRYPT_OPTION_DEVICE_PKCS11_DVR02, NULL, 301 ),
	MK_OPTION_S( CRYPT_OPTION_DEVICE_PKCS11_DVR03, NULL, 302 ),
	MK_OPTION_S( CRYPT_OPTION_DEVICE_PKCS11_DVR04, NULL, 303 ),
	MK_OPTION_S( CRYPT_OPTION_DEVICE_PKCS11_DVR05, NULL, 304 ),
	MK_OPTION_B( CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY, FALSE, 305 ),

	/* Session options, base = 400 */

	/* Miscellaneous options, base = 500.  The network options are mostly
	   used by sessions, but also apply to other object types like network
	   keysets, so they're classed as miscellaneous options */
	MK_OPTION_S( CRYPT_OPTION_NET_SOCKS_SERVER, NULL, 500 ),
	MK_OPTION_S( CRYPT_OPTION_NET_SOCKS_USERNAME, NULL, 501 ),
	MK_OPTION_S( CRYPT_OPTION_NET_HTTP_PROXY, NULL, 502 ),
	MK_OPTION( CRYPT_OPTION_NET_CONNECTTIMEOUT, 30, 503 ),
	MK_OPTION( CRYPT_OPTION_NET_READTIMEOUT, 0, 504 ),
	MK_OPTION( CRYPT_OPTION_NET_WRITETIMEOUT, 2, 505 ),
	MK_OPTION_B( CRYPT_OPTION_MISC_ASYNCINIT, TRUE, 506 ),
	MK_OPTION_B( CRYPT_OPTION_MISC_SIDECHANNELPROTECTION, FALSE, 507 ),

	/* All options beyond this point are ephemeral and aren't stored to disk.
	   Remember to update the LAST_STORED_OPTION define below when adding
	   new options here */

	/* cryptlib state information.  These are special-case options that
	   record state information rather than a static config value.  The
	   config-option-changed status value is updated dynamically, being set
	   to TRUE if any config option is changed.  Writing it to FALSE commits
	   the changes to disk.  The self-test status value is initially set to
	   FALSE, writing it to TRUE triggers a self-test for which the value
	   remains at TRUE if the test succeeds.  Writing it to a particular
	   algorithm value tests only that algorithm */
	MK_OPTION_B( CRYPT_OPTION_CONFIGCHANGED, FALSE, CRYPT_UNUSED ),
	MK_OPTION( CRYPT_OPTION_SELFTESTOK, FALSE, CRYPT_UNUSED ),

	/* End-of-list marker */
	MK_OPTION_NONE()
	};

/* The last option that's written to disk.  Further options beyond this one
   are ephemeral and are never written to disk */

#define LAST_STORED_OPTION	CRYPT_OPTION_MISC_SIDECHANNELPROTECTION

/* The size of the variable-length config data */

#define OPTION_INFO_SIZE	( sizeof( OPTION_INFO ) * \
							  CRYPT_OPTION_CONFIGCHANGED - CRYPT_OPTION_FIRST )

/****************************************************************************
*																			*
*						Set/Query Library-wide Config Options				*
*																			*
****************************************************************************/

/* Set the value of a numeric or string option */

int setOption( OPTION_INFO *optionList, const CRYPT_ATTRIBUTE_TYPE option,
			   const int value )
	{
	const FIXED_OPTION_INFO *fixedOptionInfoPtr;
	OPTION_INFO *optionInfoPtr;

	/* The update of the selt-test status is performed in two phases, when we
	   begin the self-test it's set to an undefined value, once the self-test
	   completes it's set to the test result.  Since there's no direct way to
	   differentiate an internal status update from an external attempt to do
	   the same thing, we disallow any attempt to update the value when it's
	   in the undefined state (see the comment for CRYPT_OPTION_SELFTESTOK
	   below), and use a write of CRYPT_OPTION_LAST to indicate an update of
	   the self-test status */
	if( option == CRYPT_OPTION_LAST )
		{
		assert( optionList[ CRYPT_OPTION_SELFTESTOK - \
							CRYPT_OPTION_FIRST ].intValue == CRYPT_ERROR );
		optionList[ CRYPT_OPTION_SELFTESTOK - \
					CRYPT_OPTION_FIRST ].intValue = value;
		return( CRYPT_OK );
		}

	/* Get a pointer to the option information and make sure that everything
	   is OK */
	assert( option > CRYPT_OPTION_FIRST && option < CRYPT_OPTION_LAST );
	optionInfoPtr = &optionList[ option - CRYPT_OPTION_FIRST ];
	fixedOptionInfoPtr = &fixedOptionInfo[ option - CRYPT_OPTION_FIRST ];
	assert( fixedOptionInfoPtr->type == OPTION_NUMERIC || \
			fixedOptionInfoPtr->type == OPTION_BOOLEAN );

	/* If the value is the same as the current one, there's nothing to do */
	if( optionInfoPtr->intValue == value )
		return( CRYPT_OK );

	/* If we're forcing a commit by returning the config.changed flag to its
	   ground state, write any changed options to backing store */
	if( option == CRYPT_OPTION_CONFIGCHANGED )
		{
		/* When a non-config option (for example a cert trust option) is
		   changed, then we need to write the updated config data to backing
		   store, but there's no way to tell that this is required because
		   the config options are unchanged.  To allow the caller to signal
		   this change, they can explicitly set the config-changed setting
		   to TRUE (normally this is done implicitly by when another config
		   setting is changed).  This explicit setting can only be done by
		   the higher-level config-update code, because the kernel blocks
		   any attempts to set it to a value other than FALSE */
		if( value )
			{
			optionInfoPtr->intValue = TRUE;
			return( CRYPT_OK );
			}

		/* Make sure that there's something to write.  We do this to avoid
		   problems with programs that always try to update the config
		   (whether it's necessary or not), which can cause problems with
		   media with limited writeability */
		if( !optionInfoPtr->intValue )
			return( CRYPT_OK );

		/* We don't do anything to write the config data at this level since
		   we currently have the user object locked and don't want to stall
		   all operations that depend on it while we're updating the config
		   data, so all we do is tell the user object to perform the
		   necessary operations */
		return( OK_SPECIAL );
		}

	/* If we're forcing a self-test by changing the value of the self-test
	   status, perform an algorithm test */
	if( option == CRYPT_OPTION_SELFTESTOK )
		{
		/* The self-test can take some time to complete.  While it's running
		   we don't want to leave the user object locked since this will
		   block most other threads, which all eventually read some sort of
		   config option.  To get around this problem we set the result
		   value to an undefined status and unlock the user object around the
		   call, then re-lock it and set its actual value via an update of
		   the pseudo-option CRYPT_OPTION_LAST once the self-test is done */
		if( optionInfoPtr->intValue == CRYPT_ERROR )
			return( CRYPT_ERROR_TIMEOUT );
		optionInfoPtr->intValue = CRYPT_ERROR;
		return( OK_SPECIAL );
		}

	/* Set the value and remember that the config options have been changed */
	if( fixedOptionInfoPtr->type == OPTION_BOOLEAN )
		/* Turn a generic zero/nonzero boolean into TRUE or FALSE */
		optionInfoPtr->intValue = ( value ) ? TRUE : FALSE;
	else
		optionInfoPtr->intValue = value;
	optionInfoPtr->dirty = TRUE;
	optionList[ CRYPT_OPTION_CONFIGCHANGED - \
				CRYPT_OPTION_FIRST ].intValue = TRUE;
	return( CRYPT_OK );
	}

int setOptionString( OPTION_INFO *optionList,
					 const CRYPT_ATTRIBUTE_TYPE option, const char *value,
					 const int valueLength )
	{
	const FIXED_OPTION_INFO *fixedOptionInfoPtr;
	OPTION_INFO *optionInfoPtr;
	char *valuePtr;

	/* Get a pointer to the option information and make sure that everything
	   is OK */
	assert( option > CRYPT_OPTION_FIRST && option < CRYPT_OPTION_LAST );
	optionInfoPtr = &optionList[ option - CRYPT_OPTION_FIRST ];
	fixedOptionInfoPtr = &fixedOptionInfo[ option - CRYPT_OPTION_FIRST ];
	assert( fixedOptionInfoPtr->type == OPTION_STRING );

	/* If there's no value given, we're deleting the option rather than
	   setting it.  These options don't have default values so we check for
	   a setting of NULL rather than equivalence to a default string value */
	if( value == NULL )
		{
		assert( fixedOptionInfoPtr->strDefault == NULL );
		if( optionInfoPtr->strValue == NULL )
			return( CRYPT_ERROR_NOTFOUND );
		zeroise( optionInfoPtr->strValue, strlen( optionInfoPtr->strValue ) );
		clFree( "setOptionString", optionInfoPtr->strValue );
		optionInfoPtr->strValue = NULL;
		optionInfoPtr->dirty = TRUE;
		optionList[ CRYPT_OPTION_CONFIGCHANGED - \
					CRYPT_OPTION_FIRST ].intValue = TRUE;
		return( CRYPT_OK );
		}
	assert( value != NULL && valueLength > 0 );

	/* If the value is the same as the current one, there's nothing to do */
	if( optionInfoPtr->strValue != NULL && \
		strlen( optionInfoPtr->strValue ) == valueLength && \
		!memcmp( optionInfoPtr->strValue, value, valueLength ) )
		return( CRYPT_OK );

	/* If we're resetting a value to its default setting, just reset the
	   string pointers rather than storing the value */
	if( fixedOptionInfoPtr->strDefault != NULL && \
		strlen( fixedOptionInfoPtr->strDefault ) == valueLength && \
		!memcmp( fixedOptionInfoPtr->strDefault, value, valueLength ) )
		{
		if( optionInfoPtr->strValue != fixedOptionInfoPtr->strDefault )
			{
			zeroise( optionInfoPtr->strValue,
					 strlen( optionInfoPtr->strValue ) );
			clFree( "setOptionString", optionInfoPtr->strValue );
			}
		optionInfoPtr->strValue = ( char * ) fixedOptionInfoPtr->strDefault;
		optionInfoPtr->dirty = TRUE;
		optionList[ CRYPT_OPTION_CONFIGCHANGED - \
					CRYPT_OPTION_FIRST ].intValue = TRUE;
		return( CRYPT_OK );
		}

	/* Try and allocate room for the new option */
	if( ( valuePtr = clAlloc( "setOptionString", valueLength + 1 ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memcpy( valuePtr, value, valueLength );
	valuePtr[ valueLength ] = '\0';

	/* If the string value that's currently set isn't the default setting,
	   clear and free it */
	if( optionInfoPtr->strValue != fixedOptionInfoPtr->strDefault )
		{
		zeroise( optionInfoPtr->strValue, strlen( optionInfoPtr->strValue ) );
		clFree( "setOptionString", optionInfoPtr->strValue );
		}

	/* Set the value and remember that the config options have been changed */
	optionInfoPtr->strValue = valuePtr;
	optionInfoPtr->dirty = TRUE;
	optionList[ CRYPT_OPTION_CONFIGCHANGED - \
				CRYPT_OPTION_FIRST ].intValue = TRUE;
	return( CRYPT_OK );
	}

/* Query the value of a numeric or string option */

int getOption( OPTION_INFO *optionList, const CRYPT_ATTRIBUTE_TYPE option )
	{
	assert( option > CRYPT_OPTION_FIRST && option < CRYPT_OPTION_LAST );
	assert( fixedOptionInfo[ option - \
							 CRYPT_OPTION_FIRST ].type == OPTION_NUMERIC || \
			fixedOptionInfo[ option - \
							 CRYPT_OPTION_FIRST ].type == OPTION_BOOLEAN );

	return( optionList[ option - CRYPT_OPTION_FIRST ].intValue );
	}

char *getOptionString( OPTION_INFO *optionList,
					   const CRYPT_ATTRIBUTE_TYPE option )
	{
	assert( option > CRYPT_OPTION_FIRST && option < CRYPT_OPTION_LAST );
	assert( fixedOptionInfo[ option - \
							 CRYPT_OPTION_FIRST ].type == OPTION_STRING );

	return( optionList[ option - CRYPT_OPTION_FIRST ].strValue );
	}

/* Initialise/shut down the config option handling */

int initOptions( OPTION_INFO **optionListPtr )
	{
	OPTION_INFO *optionList;
	int i;

	/* Perform a consistency check on the options */
	FORALL( i, 1, CRYPT_OPTION_LAST - CRYPT_OPTION_FIRST,
			fixedOptionInfo[ i ].option == i + CRYPT_OPTION_FIRST );

	/* Allocate storage for the variable config data */
	if( ( optionList = clAlloc( "initOptions", OPTION_INFO_SIZE ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( optionList, 0, OPTION_INFO_SIZE );

	/* Walk through the config table setting up each option to contain
	   its default value */
	for( i = 1; fixedOptionInfo[ i ].option != CRYPT_ATTRIBUTE_NONE; i++ )
		if( fixedOptionInfo[ i ].type == OPTION_STRING )
			optionList[ i ].strValue = \
						( char * ) fixedOptionInfo[ i ].strDefault;
		else
			optionList[ i ].intValue = fixedOptionInfo[ i ].intDefault;
	*optionListPtr = optionList;

	return( CRYPT_OK );
	}

void endOptions( OPTION_INFO *optionList )
	{
	int i;

	/* Walk through the config table clearing and freeing each option */
	for( i = 1; fixedOptionInfo[ i ].option != CRYPT_ATTRIBUTE_NONE; i++ )
		{
		const FIXED_OPTION_INFO *fixedOptionInfoPtr = &fixedOptionInfo[ i ];
		OPTION_INFO *optionInfoPtr = &optionList[ i ];

		if( fixedOptionInfoPtr->type == OPTION_STRING )
			{
			/* If the string value that's currently set isn't the default
			   setting, clear and free it */
			if( optionInfoPtr->strValue != fixedOptionInfoPtr->strDefault )
				{
				zeroise( optionInfoPtr->strValue,
						 strlen( optionInfoPtr->strValue ) );
				clFree( "endOptions", optionInfoPtr->strValue );
				}
			}
		}

	/* Clear and free the config table */
	memset( optionList, 0, OPTION_INFO_SIZE );
	clFree( "endOptions", optionList );
	}

/****************************************************************************
*																			*
*						Read and Write the Config Options 					*
*																			*
****************************************************************************/

/* Read any user-defined configuration options.  Since the config file is an
   untrusted source, we set the values in it via external messages rather than
   manipulating the config info directly, which means that everything read is
   subject to the usual ACL checks */

static int readTrustedCerts( const CRYPT_KEYSET iCryptKeyset,
							 void *trustInfoPtr )
	{
	RESOURCE_DATA msgData;
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 1536 ];
	int status;

	/* Read each trusted cert from the keyset */
	setMessageData( &msgData, buffer, CRYPT_MAX_PKCSIZE + 1536 );
	status = krnlSendMessage( iCryptKeyset, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_TRUSTEDCERT );
	while( cryptStatusOK( status ) )
		{
		/* Add the cert data as a trusted cert item and look for the next
		   one */
		addTrustEntry( trustInfoPtr, CRYPT_UNUSED, msgData.data,
					   msgData.length );
		setMessageData( &msgData, buffer, CRYPT_MAX_PKCSIZE + 1536 );
		status = krnlSendMessage( iCryptKeyset, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_TRUSTEDCERT_NEXT );
		}

	return( ( status == CRYPT_ERROR_NOTFOUND ) ? CRYPT_OK : status );
	}

int readConfig( const CRYPT_USER iCryptUser, const char *fileName,
				void *trustInfoPtr )
	{
	CRYPT_KEYSET iCryptKeyset;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	STREAM stream;
	DYNBUF configDB;
	char configFilePath[ MAX_PATH_LENGTH + 128 ];	/* Protection for Windows */
	int status;

	/* Try and open the config file.  If we can't open it, it means the that
	   file doesn't exist, which isn't an error */
	fileBuildCryptlibPath( configFilePath, fileName, BUILDPATH_GETPATH );
	setMessageCreateObjectInfo( &createInfo, CRYPT_KEYSET_FILE );
	createInfo.arg2 = CRYPT_KEYOPT_READONLY;
	createInfo.strArg1 = configFilePath;
	createInfo.strArgLen1 = strlen( configFilePath );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_KEYSET );
	if( cryptStatusError( status ) )
		return( CRYPT_OK );		/* No config data present */
	iCryptKeyset = createInfo.cryptHandle;

	/* Get the config info from the keyset */
	status = dynCreate( &configDB, iCryptKeyset,
						CRYPT_IATTRIBUTE_CONFIGDATA );
	if( status == CRYPT_ERROR_NOTFOUND )
		{
		/* No config options present, there may still be trusted certs */
		status = readTrustedCerts( iCryptKeyset, trustInfoPtr );
		krnlSendNotifier( iCryptKeyset, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	if( cryptStatusOK( status ) )
		status = readTrustedCerts( iCryptKeyset, trustInfoPtr );
	krnlSendNotifier( iCryptKeyset, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		dynDestroy( &configDB );
		return( status );
		}

	/* Read each config option */
	sMemConnect( &stream, dynData( configDB ), dynLength( configDB ) );
	while( cryptStatusOK( status ) && \
		   stell( &stream ) < dynLength( configDB ) )
		{
		CRYPT_ATTRIBUTE_TYPE attributeType;
		long option;
		int value, tag, i;

		/* Read the wrapper and option index and map it to the actual option.
		   If we find an unknown index or one that shouldn't be writeable to
		   persistent storage, we skip it and continue.  This is done to
		   handle new options that may have been added after this version of
		   cryptlib was built (for unknown indices) and because the stored
		   config options are an untrusted source so we have to check for
		   attempts to feed in bogus values (for non-writeable options) */
		readSequence( &stream, NULL );
		status = readShortInteger( &stream, &option );
		if( cryptStatusError( status ) )
			continue;
		for( i = 1; fixedOptionInfo[ i ].option <= LAST_STORED_OPTION; i++ )
			if( fixedOptionInfo[ i ].index == option )
				break;
		if( fixedOptionInfo[ i ].option > LAST_STORED_OPTION || \
			fixedOptionInfo[ i ].index == CRYPT_UNUSED )
			{
			readUniversal( &stream );
			continue;
			}
		attributeType = fixedOptionInfo[ i ].option;

		/* Read the option value and set the option.  We don't treat a failure
		   to set the option as a problem since the user probably doesn't want
		   the entire system to fail because of a bad config option, and in any
		   case we'll fall back to a safe default value */
		tag = peekTag( &stream );
		if( tag == BER_BOOLEAN || tag == BER_INTEGER )
			{
			/* It's a numeric value, read the appropriate type and try and set
			   the option */
			if( tag == BER_BOOLEAN )
				status = readBoolean( &stream, &value );
			else
				{
				long integer;

				status = readShortInteger( &stream, &integer );
				value = ( int ) integer;
				}
			if( cryptStatusOK( status ) )
				krnlSendMessage( iCryptUser, IMESSAGE_SETATTRIBUTE, &value,
								 attributeType );
			}
		else
			{
			int length;

			/* It's a string value, set the option straight from the encoded
			   data */
			status = readGenericHole( &stream, &length, BER_STRING_UTF8 );
			if( cryptStatusError( status ) )
				continue;
			setMessageData( &msgData, sMemBufPtr( &stream ), length );
			krnlSendMessage( iCryptUser, IMESSAGE_SETATTRIBUTE_S, &msgData,
							 attributeType );
			status = sSkip( &stream, length );
			}
		}
	sMemDisconnect( &stream );

	/* Clean up */
	dynDestroy( &configDB );
	return( status );
	}

/* Write any user-defined configuration options.  This is performed in two
   phases, a first phase that encodes the config data and a second phase
   that writes the data to disk.  The reason for the split is that the
   second phase doesn't require the use of the user object data any more
   and can be a somewhat lengthy process due to disk accesses and other bits
   and pieces.  Because of this the caller is expected to unlock the user
   object between the two phases to ensure that the second phase doesn't
   stall all other operations that require it */

int encodeConfigData( OPTION_INFO *optionList, const char *fileName,
					  void *trustInfoPtr, void **data, int *length )
	{
	STREAM stream;
	const BOOLEAN trustedCertsPresent = \
						cryptStatusOK( \
							enumTrustedCerts( trustInfoPtr, CRYPT_UNUSED,
											  CRYPT_UNUSED ) ) ? \
					TRUE : FALSE;
	int i;

	/* Clear the return values */
	*data = NULL;
	*length = 0;

	/* If neither the config options nor any cert trust settings have
	   changed, there's nothing to do */
	for( i = 1; fixedOptionInfo[ i ].option <= LAST_STORED_OPTION; i++ )
		if( optionList[ i ].dirty )
			break;
	if( fixedOptionInfo[ i ].option >= LAST_STORED_OPTION && \
		!trustedCertsPresent )
		return( CRYPT_OK );

	/* Make a first pass through the config options to determine the total
	   encoded length of the ones that don't match the default setting.  We
	   can't just check the isDirty flag because if a value is reset to its
	   default setting the encoded size will be zero even though the isDirty
	   flag is set */
	for( i = 1; fixedOptionInfo[ i ].option <= LAST_STORED_OPTION; i++ )
		{
		const FIXED_OPTION_INFO *fixedOptionInfoPtr = &fixedOptionInfo[ i ];
		const OPTION_INFO *optionInfoPtr = &optionList[ i ];

		/* If it's an option that can't be written to disk, skip it */
		if( fixedOptionInfoPtr->index == CRYPT_UNUSED )
			continue;

		if( fixedOptionInfoPtr->type == OPTION_STRING )
			{
			/* If the string value is the same as the default, there's
			   nothing to do */
			if( optionInfoPtr->strValue == NULL || \
				optionInfoPtr->strValue == fixedOptionInfoPtr->strDefault )
				continue;
			*length += ( int ) sizeofObject( \
						sizeofShortInteger( fixedOptionInfoPtr->index ) + \
						sizeofObject( strlen( optionInfoPtr->strValue ) ) );
			}
		else
			{
			/* If the integer/boolean value that's currently set isn't the
			   default setting, update it */
			if( optionInfoPtr->intValue == fixedOptionInfoPtr->intDefault )
				continue;
			*length += ( int ) sizeofObject( \
						sizeofShortInteger( fixedOptionInfoPtr->index ) + \
						( fixedOptionInfoPtr->type == OPTION_NUMERIC ? \
						  sizeofShortInteger( optionInfoPtr->intValue ) : \
						  sizeofBoolean() ) );
			}
		}

	/* If we've gone back to all default values from having non-default ones
	   stored, we either have to write only trusted certs or nothing at all */
	if( *length <= 0 )
		{
		char configFilePath[ MAX_PATH_LENGTH + 128 ];	/* Protection for Windows */

		/* There's no data to write, if there are trusted certs present
		   notify the caller */
		if( trustedCertsPresent )
			return( OK_SPECIAL );

		/* There's nothing to write, delete the config file */
		fileBuildCryptlibPath( configFilePath, fileName, BUILDPATH_GETPATH );
		fileErase( configFilePath );
		return( CRYPT_OK );
		}

	assert( *length > 0 );

	/* Allocate a buffer to hold the encoded values */
	if( ( *data = clAlloc( "encodeConfigData", *length ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Write the config options */
	sMemOpen( &stream, *data, *length );
	for( i = 1; fixedOptionInfo[ i ].option <= LAST_STORED_OPTION; i++ )
		{
		const FIXED_OPTION_INFO *fixedOptionInfoPtr = &fixedOptionInfo[ i ];
		const OPTION_INFO *optionInfoPtr = &optionList[ i ];

		/* If it's an option that can't be written to disk, skip it */
		if( fixedOptionInfoPtr->index == CRYPT_UNUSED )
			continue;

		if( fixedOptionInfoPtr->type == OPTION_STRING )
			{
			if( optionInfoPtr->strValue == NULL || \
				optionInfoPtr->strValue == fixedOptionInfoPtr->strDefault )
				continue;
			writeSequence( &stream,
						   sizeofShortInteger( fixedOptionInfoPtr->index ) + \
						   sizeofObject( strlen( optionInfoPtr->strValue ) ) );
			writeShortInteger( &stream, fixedOptionInfoPtr->index,
							   DEFAULT_TAG );
			writeCharacterString( &stream, optionInfoPtr->strValue,
								  strlen( optionInfoPtr->strValue ),
								  BER_STRING_UTF8 );
			continue;
			}

		if( optionInfoPtr->intValue == fixedOptionInfoPtr->intDefault )
			continue;
		if( fixedOptionInfoPtr->type == OPTION_NUMERIC )
			{
			writeSequence( &stream,
						   sizeofShortInteger( fixedOptionInfoPtr->index ) + \
						   sizeofShortInteger( optionInfoPtr->intValue ) );
			writeShortInteger( &stream, fixedOptionInfoPtr->index,
							   DEFAULT_TAG );
			writeShortInteger( &stream, optionInfoPtr->intValue,
							   DEFAULT_TAG );
			}
		else
			{
			writeSequence( &stream,
						   sizeofShortInteger( fixedOptionInfoPtr->index ) + \
						   sizeofBoolean() );
			writeShortInteger( &stream, fixedOptionInfoPtr->index,
							   DEFAULT_TAG );
			writeBoolean( &stream, optionInfoPtr->intValue, DEFAULT_TAG );
			}
		}
	assert( sGetStatus( &stream ) == CRYPT_OK );
	sMemDisconnect( &stream );

	/* We've written the config data to the memory buffer, let the caller
	   know that they can unlock it and commit it to permanent storage */
	return( OK_SPECIAL );
	}

int commitConfigData( const CRYPT_USER cryptUser, const char *fileName,
					  const void *data, const int length )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	char configFilePath[ MAX_PATH_LENGTH + 128 ];	/* Protection for Windows */
	int status;

	/* Build the path to the config file and try and create it */
	fileBuildCryptlibPath( configFilePath, fileName, BUILDPATH_CREATEPATH );
	setMessageCreateObjectInfo( &createInfo, CRYPT_KEYSET_FILE );
	createInfo.arg2 = CRYPT_KEYOPT_CREATE;
	createInfo.strArg1 = configFilePath;
	createInfo.strArgLen1 = strlen( configFilePath );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_KEYSET );
	if( cryptStatusError( status ) )
		/* Map the lower-level keyset-specific error into a more meaningful
		   generic error */
		return( CRYPT_ERROR_OPEN );

	/* Send the config data (if there is any) and any trusted certs to the
	   keyset */
	if( length > 0 )
		{
		setMessageData( &msgData, ( void * ) data, length );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_CONFIGDATA );
		}
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( cryptUser, IMESSAGE_SETATTRIBUTE,
								  &createInfo.cryptHandle,
								  CRYPT_IATTRUBUTE_CERTKEYSET );
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		fileErase( configFilePath );
		return( CRYPT_ERROR_WRITE );
		}
	return( CRYPT_OK );
	}
