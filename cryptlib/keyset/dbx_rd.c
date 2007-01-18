/****************************************************************************
*																			*
*							cryptlib DBMS Interface							*
*						Copyright Peter Gutmann 1996-2004					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "dbms.h"
  #include "asn1.h"
  #include "rpc.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
  #include "keyset/dbms.h"
  #include "misc/asn1.h"
  #include "misc/rpc.h"
#endif /* Compiler-specific includes */

#ifdef USE_DBMS

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* The most common query types can be performed using cached access plans 
   and query data.  The following function determines whether a particular
   query can be performed using one of these cached queries, returning the
   cache entry for the query if so */

DBMS_CACHEDQUERY_TYPE getCachedQueryType( const KEYMGMT_ITEM_TYPE itemType,
										  const CRYPT_KEYID_TYPE keyIDtype )
	{
	/* If we're not reading from the standard certs table, the query won't
	   be cached */
	if( itemType != KEYMGMT_ITEM_PUBLICKEY )
		return( DBMS_CACHEDQUERY_NONE );

	/* Check whether we're querying on a cacheable key value type.  An ID 
	   type of CRYPT_KEYID_LAST is a special case which denotes that we're
	   doing a query on name ID, this is used for getNext() and is very 
	   common (it follows most cert reads and is used to see if we can build 
	   a chain), so we make it cacheable */
	switch( keyIDtype )
		{
		case CRYPT_KEYID_URI:
			return( DBMS_CACHEDQUERY_URI );

		case CRYPT_IKEYID_ISSUERID:
			return( DBMS_CACHEDQUERY_ISSUERID );

		case CRYPT_IKEYID_CERTID:
			return( DBMS_CACHEDQUERY_CERTID );

		case CRYPT_KEYID_LAST:
			return( DBMS_CACHEDQUERY_NAMEID );
		}

	return( DBMS_CACHEDQUERY_NONE );
	}

/* Check an encoded cert for a matching key usage.  The semantics of key
   usage flags are vague in the sense that the query "Is this key valid for
   X" is easily resolved, but the query "Which key is appropriate for X" is
   NP-hard due to the potential existence of unbounded numbers of
   certificates with usage semantics expressed in an arbitrary number of
   ways.  For now we distinguish between signing and encryption keys (this,
   at least, is feasible) by doing a quick check for keyUsage if we get
   multiple certs with the same DN and choosing the one with the appropriate
   key usage.

   Rather than performing a relatively expensive cert import for each cert,
   we find the keyUsage by doing an optimised search through the cert data
   for its encoded form.  The pattern that we look for is:

	OID				06 03 55 1D 0F
	BOOLEAN			(optional)
	OCTET STRING {	04 (4 or 5)
		BIT STRING	03 (2 or 3) nn (value) */

static BOOLEAN checkCertUsage( const BYTE *certificate, const int length,
							   const int requestedUsage )
	{
	int i;

	assert( requestedUsage & KEYMGMT_MASK_USAGEOPTIONS );

	/* Scan the payload portion of the cert for the keyUsage extension */
	for( i = 256; i < length - 64; i++ )
		{
		int keyUsage;

		/* Look for the OID.  This potentially skips two bytes at a
		   time, but this is safe since the preceding bytes can never
		   contain either of these two values (they're 0x30 + 11...15) */
		if( certificate[ i++ ] != BER_OBJECT_IDENTIFIER || \
			certificate[ i++ ] != 3 )
			continue;
		if( memcmp( certificate + i, "\x55\x1D\x0F", 3 ) )
			continue;
		i += 3;

		/* We've found the OID (with 1.1e-12 error probability), skip
		   the critical flag if necessary */
		if( certificate[ i ] == BER_BOOLEAN )
			i += 3;

		/* Check for the OCTET STRING wrapper and BIT STRING */
		if( certificate[ i++ ] != BER_OCTETSTRING || \
			( certificate[ i ] != 4 && certificate[ i ] != 5 ) || \
			certificate[ ++i ] != BER_BITSTRING )
			continue;
		keyUsage = certificate[ i + 3 ];

		/* We've got to the BIT STRING payload, check whether the requested
		   usage is allowed.  This is somewhat ugly since it hardcodes in
		   the bit values, but it's difficult to handle otherwise without
		   resorting to interpresting the encoded ASN.1 */
		if( requestedUsage & KEYMGMT_FLAG_USAGE_CRYPT )
			{
			if( keyUsage & 0x20 )
				return( TRUE );
			}
		else
			if( keyUsage & 0x80 )
				return( TRUE );

		/* The requested usage isn't permitted by this cert */
		return( FALSE );
		}

	/* No key usage found, assume that any usage is OK */
	return( TRUE );
	}

/****************************************************************************
*																			*
*							Database Access Functions						*
*																			*
****************************************************************************/

/* Fetch a sequence of certs from a data source.  This is called in one of
   two ways, either indirectly by the certificate code to fetch the first and
   subsequent certs in a chain or directly by the user after submitting a
   query to the keyset (which doesn't return any data) to read the results of
   the query.  The schema for calls is:

	state = NULL:		query( NULL, &data, CONTINUE );
	state, point query:	query( SQL, &data, NORMAL );
	state, multi-cert:	query( SQL, &data, START );
						query( NULL, &data, CONTINUE ); */

int getItemData( DBMS_INFO *dbmsInfo, CRYPT_CERTIFICATE *iCertificate,
				 int *stateInfo, const CRYPT_KEYID_TYPE keyIDtype, 
				 const char *keyValue, const int keyValueLength,
				 const KEYMGMT_ITEM_TYPE itemType, const int options )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	const DBMS_CACHEDQUERY_TYPE cachedQueryType = \
								getCachedQueryType( itemType, keyIDtype );
	BYTE certificate[ MAX_CERT_SIZE + BASE64_OVFL_SIZE + 8 ];
	char certDataBuffer[ MAX_QUERY_RESULT_SIZE + 8 ];
	void *certDataPtr = certDataBuffer;
	char sqlBuffer[ STANDARD_SQL_QUERY_SIZE + 8 ], *sqlBufPtr;
	DBMS_QUERY_TYPE queryType;
	BOOLEAN multiCertQuery = ( options & KEYMGMT_MASK_USAGEOPTIONS ) ? \
							 TRUE : FALSE;
	BOOLEAN continueFetch = TRUE;
	int certDataLength, iterationCount = 0, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( isWritePtr( iCertificate, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( ( keyValueLength > 2 && \
			  isReadPtr( keyValue, keyValueLength ) && \
			  ( keyIDtype > CRYPT_KEYID_NONE && \
				keyIDtype <= CRYPT_KEYID_LAST ) ) || \
			( keyValueLength == 0 && keyValue == NULL && \
			  keyIDtype == CRYPT_KEYID_NONE ) );
	assert( itemType == KEYMGMT_ITEM_NONE || \
			itemType == KEYMGMT_ITEM_PUBLICKEY || \
			itemType == KEYMGMT_ITEM_REQUEST || \
			itemType == KEYMGMT_ITEM_PKIUSER || \
			itemType == KEYMGMT_ITEM_REVOCATIONINFO );

	/* Make sure that we can never explicitly fetch anything with an ID that
	   indicates that it's physically but not logically present, for example
	   certificates that have been created but not fully issued yet, cert
	   items that are on hold, and similar items */
	if( keyValue != NULL && \
		( !memcmp( keyValue, KEYID_ESC1, KEYID_ESC_SIZE ) || \
		  !memcmp( keyValue, KEYID_ESC2, KEYID_ESC_SIZE ) ) )
		/* Eheu, litteras istas reperire non possum */
		return( CRYPT_ERROR_NOTFOUND );

	/* Perform a slight optimisation to eliminate unnecessary multi-cert 
	   queries: If we're querying by certID or issuerID only one cert can 
	   ever match, so there's no need to perform a multi-cert query even if
	   key usage options are specified */
	if( keyIDtype == CRYPT_IKEYID_ISSUERID || \
		keyIDtype == CRYPT_IKEYID_CERTID )
		multiCertQuery = FALSE;

	/* If we have binary blob support, fetch the data directly into the
	   certificate buffer */
	if( hasBinaryBlobs( dbmsInfo ) )
		certDataPtr = certificate;

	/* Set the query to begin the fetch */
	if( stateInfo != NULL )
		{
		dbmsFormatSQL( sqlBuffer, STANDARD_SQL_QUERY_SIZE,
			"SELECT certData FROM $ WHERE $ = ?",
					   getTableName( itemType ), 
					   ( keyIDtype == CRYPT_KEYID_LAST ) ? \
							"nameID" : getKeyName( keyIDtype ) );
		sqlBufPtr = sqlBuffer;
		queryType = multiCertQuery ? DBMS_QUERY_START : DBMS_QUERY_NORMAL;
		}
	else
		{
		/* It's an ongoing query, just fetch the next set of results */
		sqlBufPtr = NULL;
		queryType = DBMS_QUERY_CONTINUE;
		}

	/* Retrieve the results from the query */
	while( continueFetch && iterationCount++ < FAILSAFE_ITERATIONS_MED )
		{
		/* Retrieve the record and base64-decode the binary cert data if
		   necessary */
		status = dbmsQuery( sqlBufPtr, certDataPtr, &certDataLength, 
							keyValue, keyValueLength, 0, cachedQueryType, 
							queryType );
		if( cryptStatusOK( status ) && !hasBinaryBlobs( dbmsInfo ) )
			{
			certDataLength = base64decode( certificate, MAX_CERT_SIZE,
										   certDataBuffer, certDataLength,
										   CRYPT_CERTFORMAT_NONE );
			if( cryptStatusError( certDataLength ) )
				status = certDataLength;
			}
		if( cryptStatusError( status ) )
			/* Convert the error code to a more appropriate value if
			   appropriate */
			return( ( multiCertQuery && ( status == CRYPT_ERROR_COMPLETE ) ) ? \
					CRYPT_ERROR_NOTFOUND : status );

		/* We've started the fetch, from now on we're only fetching further
		   results */
		sqlBufPtr = NULL;
		if( queryType == DBMS_QUERY_START )
			queryType = DBMS_QUERY_CONTINUE;

		assert( certDataLength > 16 );
		assert( ( ( stateInfo != NULL ) && \
				  ( queryType == DBMS_QUERY_NORMAL || \
					queryType == DBMS_QUERY_CONTINUE ) ) || \
				( ( stateInfo == NULL ) && \
				  ( queryType == DBMS_QUERY_CONTINUE ) ) );

		/* If the first byte of the cert data is 0xFF, this is an item which
		   is physically but not logically present (see the comment above in
		   the check for the keyValue), which means that we can't explicitly 
		   fetch it (te audire non possum, musa sapientum fixa est in aure).  
		   If it's a point query this means we didn't find anything, 
		   otherwise we try again with the next result */
		if( certificate[ 0 ] == 0xFF )
			{
			/* If it's a multi-cert query, try again with the next result */
			if( multiCertQuery )
				continue;
			
			/* It's a point query, we found something but it isn't there.
			   "Can't you understand English you arse, we're not at home"
			   -- Jeremy Black, "The Boys from Brazil" */
			return( CRYPT_ERROR_NOTFOUND );
			}

		/* If more than one cert is present and the requested key usage
		   doesn't match the one indicated in the cert, try again */
		if( multiCertQuery && \
			!checkCertUsage( certificate, certDataLength, options ) )
			continue;

		/* We got what we wanted, exit */
		continueFetch = FALSE;
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MED )
		return( CRYPT_ERROR_NOTFOUND );

	/* If we've been looking through multiple certs, cancel the outstanding
	   query, which will still be in progress */
	if( multiCertQuery )
		dbmsStaticQuery( NULL, cachedQueryType, DBMS_QUERY_CANCEL );

	/* Create a certificate object from the encoded cert.  If we're reading 
	   revocation information the data is a single CRL entry so we have to 
	   tell the cert import code to treat it as a special case of a CRL.  If
	   we're reading a request, it could be one of several types so we have
	   to use auto-detection rather than specifying an exact format */
	setMessageCreateObjectIndirectInfo( &createInfo, certificate, 
										certDataLength,
		( itemType == KEYMGMT_ITEM_PUBLICKEY || \
		  itemType == KEYMGMT_ITEM_NONE ) ? CRYPT_CERTTYPE_CERTIFICATE : \
		( itemType == KEYMGMT_ITEM_REQUEST ) ? CRYPT_CERTTYPE_NONE : \
		( itemType == KEYMGMT_ITEM_PKIUSER ) ? CRYPT_CERTTYPE_PKIUSER : \
		( itemType == KEYMGMT_ITEM_REVOCATIONINFO ) ? CERTFORMAT_REVINFO : \
		CRYPT_CERTTYPE_NONE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	*iCertificate = createInfo.cryptHandle;

	/* If this was a read with state held externally, remember where we got
	   to so that we can fetch the next cert in the sequence */
	if( stateInfo != NULL )
		*stateInfo = *iCertificate;
	return( CRYPT_OK );
	}

static int getFirstItemFunction( KEYSET_INFO *keysetInfo,
								 CRYPT_CERTIFICATE *iCertificate,
								 int *stateInfo,
								 const CRYPT_KEYID_TYPE keyIDtype,
								 const void *keyID, const int keyIDlength,
								 const KEYMGMT_ITEM_TYPE itemType,
								 const int options )
	{
	DBMS_INFO *dbmsInfo = keysetInfo->keysetDBMS;
	char keyIDbuffer[ ( CRYPT_MAX_TEXTSIZE * 2 ) + 8 ];
	int length, status;

	/* If it's a general query, submit the query to the database */
	if( stateInfo == NULL )
		{
		char sqlBuffer[ MAX_SQL_QUERY_SIZE + 8 ];
		int sqlLength;

		assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
				itemType == KEYMGMT_ITEM_REQUEST );
		assert( options == KEYMGMT_FLAG_NONE );

		if( keyIDlength > MAX_SQL_QUERY_SIZE - 64 )
			return( CRYPT_ARGERROR_STR1 );

		/* If we're cancelling an existing query, pass it on down */
		if( keyIDlength == 6 && !strCompare( keyID, "cancel", keyIDlength ) )
			{
			status = dbmsStaticQuery( NULL, DBMS_CACHEDQUERY_NONE,
									  DBMS_QUERY_CANCEL );
			return( status );
			}

		assert( !keysetInfo->isBusyFunction( keysetInfo ) );

		/* Rewrite the user-supplied portion of the query using the actual
		   column names and append it to the SELECT statement.  This is a 
		   special case free-format query where we can't use bound 
		   parameters because the query data must be interpreted as SQL, 
		   unlike standard queries where we definitely don't want it (mis-)
		   interpreted as SQL */
		dbmsFormatSQL( sqlBuffer, MAX_SQL_QUERY_SIZE,
			"SELECT certData FROM $ WHERE ",
					   getTableName( itemType ) );
		sqlLength = strlen( sqlBuffer );
		dbmsFormatQuery( sqlBuffer + sqlLength, 
						 ( MAX_SQL_QUERY_SIZE - 1 ) - sqlLength, 
						 keyID, keyIDlength );
		return( dbmsStaticQuery( sqlBuffer, DBMS_CACHEDQUERY_NONE, 
								 DBMS_QUERY_START ) );
		}

	/* Fetch the first data item */
	status = length = makeKeyID( keyIDbuffer, CRYPT_MAX_TEXTSIZE * 2, 
								 keyIDtype, keyID, keyIDlength );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_STR1 );
	return( getItemData( dbmsInfo, iCertificate, stateInfo, keyIDtype, 
						 keyIDbuffer, length, itemType, options ) );
	}

static int getNextItemFunction( KEYSET_INFO *keysetInfo,
								CRYPT_CERTIFICATE *iCertificate,
								int *stateInfo, const int options )
	{
	DBMS_INFO *dbmsInfo = keysetInfo->keysetDBMS;

	/* If we're fetching the next cert in a sequence based on externally-held
	   state information, set the key ID to the nameID of the previous cert's
	   issuer.  This is a special-case ID that isn't used outside the database
	   keysets, so we use the non-ID type CRYPT_KEYID_LAST to signify its use */
	if( stateInfo != NULL )
		{
		char keyIDbuffer[ ( CRYPT_MAX_TEXTSIZE * 2 ) + 8 ];
		int length, status;

		status = length = getKeyID( keyIDbuffer, *stateInfo,
									CRYPT_IATTRIBUTE_ISSUER );
		if( cryptStatusError( status ) )
			return( status );
		return( getItemData( dbmsInfo, iCertificate, stateInfo, 
							 CRYPT_KEYID_LAST, keyIDbuffer, length, 
							 KEYMGMT_ITEM_PUBLICKEY, options ) );
		}

	/* Fetch the next data item in an ongoing query */
	return( getItemData( dbmsInfo, iCertificate, NULL, CRYPT_KEYID_NONE,
						 NULL, 0, KEYMGMT_ITEM_NONE, options ) );
	}

/* Retrieve a key record from the database */

static int getItemFunction( KEYSET_INFO *keysetInfo,
							CRYPT_HANDLE *iCryptHandle,
							const KEYMGMT_ITEM_TYPE itemType,
							const CRYPT_KEYID_TYPE keyIDtype,
							const void *keyID,  const int keyIDlength,
							void *auxInfo, int *auxInfoLength,
							const int flags )
	{
	DBMS_INFO *dbmsInfo = keysetInfo->keysetDBMS;
	int status;

	assert( auxInfo == NULL ); assert( *auxInfoLength == 0 );

	/* There are some query types that can only be satisfied by a cert store
	   since a standard database doesn't contain the necessary fields.
	   Before we do anything else we make sure that we can resolve the query 
	   using the current database type */
	if( !( dbmsInfo->flags & DBMS_FLAG_CERTSTORE_FIELDS ) )
		{
		/* A standard database doesn't contain a cert ID in the revocation
		   information since the CRL it's populated from only contains an
		   issuerAndSerialNumber, so we can't resolve queries for revocation
		   info using a cert ID */
		if( itemType == KEYMGMT_ITEM_REVOCATIONINFO && \
			keyIDtype == CRYPT_IKEYID_CERTID )
			return( CRYPT_ERROR_NOTFOUND );
		}

	/* If this is a CA management item fetch, fetch the data from the CA cert
	   store */
	if( itemType == KEYMGMT_ITEM_REQUEST || \
		itemType == KEYMGMT_ITEM_PKIUSER || \
		( itemType == KEYMGMT_ITEM_REVOCATIONINFO && \
		  !( flags & KEYMGMT_FLAG_CHECK_ONLY ) ) )
		{
		int dummy;

		/* If we're getting the issuing PKI user, which means that the key ID
		   that's being queried on is that of an issued cert that the user 
		   owns rather than that of the user themselves, fetch the user info 
		   via a special function */
		if( itemType == KEYMGMT_ITEM_PKIUSER && \
			( flags & KEYMGMT_FLAG_GETISSUER ) )
			{
			char certID[ DBXKEYID_BUFFER_SIZE + 8 ];
			int certIDlength;

			assert( keyIDtype == CRYPT_IKEYID_CERTID );
			assert( isCertStore( dbmsInfo ) );

			/* The information required to locate the PKI user from one of 
			   their certs is only present in a cert store */
			if( !isCertStore( dbmsInfo ) )
				return( CRYPT_ERROR_NOTFOUND );

			/* Get the PKI user based on the cert */
			status = certIDlength = \
				makeKeyID( certID, DBXKEYID_BUFFER_SIZE, 
						   CRYPT_IKEYID_CERTID, keyID, keyIDlength );
			if( cryptStatusError( status ) )
				return( CRYPT_ARGERROR_STR1 );
			return( caGetIssuingUser( dbmsInfo, iCryptHandle, 
									  certID, certIDlength ) );
			}

		/* This is just a standard read from a non-certificate table rather
		   than the cert table so we call the get first cert function directly
		   (rather than going via the indirect-cert-import code).  Since it's
		   a direct call, we need to provide a dummy return variable for the
		   state information which is normally handled by the indirect-cert-
		   import code */
		return( getFirstItemFunction( keysetInfo, iCryptHandle, &dummy,
									  keyIDtype, keyID, keyIDlength,
									  itemType, KEYMGMT_FLAG_NONE ) );
		}

	/* If we're doing a check only, just check whether the item is present
	   without fetching any data */
	if( flags & KEYMGMT_FLAG_CHECK_ONLY )
		{
		char keyIDbuffer[ DBXKEYID_BUFFER_SIZE + 8 ];
		char sqlBuffer[ STANDARD_SQL_QUERY_SIZE + 8 ];
		int length;

		assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
				itemType == KEYMGMT_ITEM_REVOCATIONINFO );
		assert( keyIDlength == KEYID_SIZE );
		assert( keyIDtype == CRYPT_IKEYID_ISSUERID || \
				keyIDtype == CRYPT_IKEYID_CERTID );

		/* Check whether this item is present.  We don't care about the
		   result, all we want to know is whether it's there or not, so we
		   just do a check rather than a fetch of any data */
		status = length = makeKeyID( keyIDbuffer, DBXKEYID_BUFFER_SIZE, 
									 keyIDtype, keyID, KEYID_SIZE );
		if( cryptStatusError( status ) )
			return( CRYPT_ARGERROR_STR1 );
		dbmsFormatSQL( sqlBuffer, STANDARD_SQL_QUERY_SIZE,
			"SELECT certData FROM $ WHERE $ = ?",
					   getTableName( itemType ), getKeyName( keyIDtype ) );
		return( dbmsQuery( sqlBuffer, NULL, 0, keyIDbuffer, length, 0,
						   getCachedQueryType( itemType, keyIDtype ),
						   DBMS_QUERY_CHECK ) );
		}

	/* Import the cert by doing an indirect read, which fetches either a
	   single cert or an entire chain if it's present */
	status = iCryptImportCertIndirect( iCryptHandle, keysetInfo->objectHandle,
									   keyIDtype, keyID, keyIDlength,
									   flags & KEYMGMT_MASK_CERTOPTIONS );
	return( status );
	}

/****************************************************************************
*																			*
*							Database Access Routines						*
*																			*
****************************************************************************/

void initDBMSread( KEYSET_INFO *keysetInfo )
	{
	keysetInfo->getItemFunction = getItemFunction;
	keysetInfo->getFirstItemFunction = getFirstItemFunction;
	keysetInfo->getNextItemFunction = getNextItemFunction;
	}
#endif /* USE_DBMS */
