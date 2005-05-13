/****************************************************************************
*																			*
*							cryptlib DBMS Interface							*
*						Copyright Peter Gutmann 1996-2004					*
*																			*
****************************************************************************/

#include <stdarg.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "dbms.h"
  #include "asn1.h"
  #include "rpc.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../keyset/keyset.h"
  #include "../keyset/dbms.h"
  #include "../misc/asn1.h"
  #include "../misc/rpc.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
  #include "keyset/dbms.h"
  #include "misc/asn1.h"
  #include "misc/rpc.h"
#endif /* Compiler-specific includes */

#ifdef USE_DBMS

/* Get a commonName or commonName-equivalent from a certificate */

static int getCommonName( CRYPT_CERTIFICATE iCryptCert, char *CN,
						  const char *OU, const char *O )
	{
	RESOURCE_DATA msgData;
	char buffer[ MAX_ATTRIBUTE_SIZE ], *strPtr;
	int status;

	/* First, we try for a CN */
	setMessageData( &msgData, CN, CRYPT_MAX_TEXTSIZE );
	status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_COMMONNAME );
	if( cryptStatusOK( status ) )
		{
		CN[ msgData.length ] = '\0';
		return( CRYPT_OK );
		}

	/* If that fails, we try for either a pseudonym or givenName + surname.
	   Since these are part of the vast collection of oddball DN attributes
	   that aren't handled directly, we have to get the encoded DN form and
	   look for them by OID */
	setMessageData( &msgData, buffer, MAX_ATTRIBUTE_SIZE - 1 );
	status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_DN );
	if( cryptStatusError( status ) )
		return( status );
	buffer[ msgData.length ] = '\0';

	/* Look for a pseudonym */
	strPtr = strstr( buffer, "oid.2.5.4.65=" );
	if( strPtr != NULL )
		{
		int length;

		strPtr += 13;	/* Skip type indicator */
		for( length = 0; strPtr[ length ] != '\0' && \
						 strPtr[ length ] != ',' && \
						 strPtr[ length ] != '+'; length++ );
		if( length > 0 && strPtr[ length ] == '+' && \
						  strPtr[ length - 1 ] == ' ' )
			length--;	/* Strip trailing space */
		if( length <= CRYPT_MAX_TEXTSIZE )
			{
			memcpy( CN, strPtr, length );
			CN[ length ] = '\0';
			return( CRYPT_OK );
			}
		}

	/* Look for givenName + surname */
	strPtr = strstr( buffer, "G=" );
	if( strPtr != NULL )
		{
		char *surnameStrPtr;
		int length, surnameLength;

		strPtr += 2;	/* Skip type indicator */
		for( length = 0; \
			 strPtr[ length ] != '\0' && \
				strPtr[ length ] != ',' && \
				strPtr[ length ] != '+'; \
			 length++ );
		if( length > 0 && strPtr[ length ] == '+' && \
						  strPtr[ length - 1 ] == ' ' )
			length--;	/* Strip trailing space */
		surnameStrPtr = strstr( buffer, "S=" );
		if( surnameStrPtr != NULL )
			{
			surnameStrPtr += 2;	/* Skip type indicator */
			for( surnameLength = 0; \
				 surnameStrPtr[ surnameLength ] != '\0' && \
					surnameStrPtr[ surnameLength ] != ',' && \
					surnameStrPtr[ length ] != '+'; \
				 surnameLength++ );
			if( surnameLength > 0 && \
				surnameStrPtr[ surnameLength ] == '+' && \
				surnameStrPtr[ surnameLength - 1 ] == ' ' )
				surnameLength--;	/* Strip trailing space */
			if( length + surnameLength <= CRYPT_MAX_TEXTSIZE )
				{
				memcpy( CN, strPtr, length );
				memcpy( CN + length, surnameStrPtr, surnameLength );
				CN[ length + surnameLength ] = '\0';
				return( CRYPT_OK );
				}
			}
		}

	/* It's possible (although highly unlikely) that a certificate won't 
	   have a usable CN-equivalent in some form, in which case we use the OU
	   instead.  If that also fails, we use the O.  This gets a bit messy, 
	   but duplicating the OU / O into the CN seems to be the best way to 
	   handle this */
	strcpy( CN, *OU ? OU : O );

	return( CRYPT_OK );
	}

/* Add a certificate object (cert, cert request, PKI user) to a database.  
   Normally existing rows would be overwritten if we added duplicate entries, 
   but the UNIQUE constraint on the indices will catch this */

int addCert( DBMS_INFO *dbmsInfo, const CRYPT_HANDLE iCryptHandle,
			 const CRYPT_CERTTYPE_TYPE certType, const CERTADD_TYPE addType,
			 const DBMS_UPDATE_TYPE updateType )
	{
	RESOURCE_DATA msgData;
	BYTE certData[ MAX_CERT_SIZE ];
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	char nameID[ DBXKEYID_BUFFER_SIZE ], issuerID[ DBXKEYID_BUFFER_SIZE ];
	char keyID[ DBXKEYID_BUFFER_SIZE ], certID[ DBXKEYID_BUFFER_SIZE ];
	char C[ CRYPT_MAX_TEXTSIZE + 1 ], SP[ CRYPT_MAX_TEXTSIZE + 1 ],
		 L[ CRYPT_MAX_TEXTSIZE + 1 ], O[ CRYPT_MAX_TEXTSIZE + 1 ],
		 OU[ CRYPT_MAX_TEXTSIZE + 1 ], CN[ CRYPT_MAX_TEXTSIZE + 1 ],
		 uri[ CRYPT_MAX_TEXTSIZE + 1 ];
	time_t boundDate = 0;
	int certDataLength, status;

	assert( certType == CRYPT_CERTTYPE_CERTIFICATE || \
			certType == CRYPT_CERTTYPE_REQUEST_CERT || \
			certType == CRYPT_CERTTYPE_PKIUSER );

	*C = *SP = *L = *O = *OU = *CN = *uri = '\0';

	/* Extract the DN and altName (URI) components.  This changes the 
	   currently selected DN components, but this is OK since we've got 
	   the cert locked and the prior state will be restored when we unlock 
	   it */
	krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_UNUSED, CRYPT_CERTINFO_SUBJECTNAME );
	setMessageData( &msgData, C, CRYPT_MAX_TEXTSIZE );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_COUNTRYNAME );
	if( cryptStatusOK( status ) )
		C[ msgData.length ] = '\0';
	if( cryptStatusOK( status ) || status == CRYPT_ERROR_NOTFOUND )
		{
		setMessageData( &msgData, SP, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							&msgData, CRYPT_CERTINFO_STATEORPROVINCENAME );
		if( cryptStatusOK( status ) )
			SP[ msgData.length ] = '\0';
		}
	if( cryptStatusOK( status ) || status == CRYPT_ERROR_NOTFOUND )
		{
		setMessageData( &msgData, L, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							&msgData, CRYPT_CERTINFO_LOCALITYNAME );
		if( cryptStatusOK( status ) )
			L[ msgData.length ] = '\0';
		}
	if( cryptStatusOK( status ) || status == CRYPT_ERROR_NOTFOUND )
		{
		setMessageData( &msgData, O, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							&msgData, CRYPT_CERTINFO_ORGANIZATIONNAME );
		if( cryptStatusOK( status ) )
			O[ msgData.length ] = '\0';
		}
	if( cryptStatusOK( status ) || status == CRYPT_ERROR_NOTFOUND )
		{
		setMessageData( &msgData, OU, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							&msgData, CRYPT_CERTINFO_ORGANIZATIONALUNITNAME );
		if( cryptStatusOK( status ) )
			OU[ msgData.length ] = '\0';
		}
	if( cryptStatusOK( status ) || status == CRYPT_ERROR_NOTFOUND )
		{
		/* The handling of the CN (or CN-equivalent) is somewhat complex so 
		   we use a separate function for this */
		status = getCommonName( iCryptHandle, CN, OU, O );
		}
	if( ( cryptStatusOK( status ) || status == CRYPT_ERROR_NOTFOUND ) && \
		( certType != CRYPT_CERTTYPE_PKIUSER ) )
		{
		static const int value = CRYPT_CERTINFO_SUBJECTALTNAME;

		/* Get the URI for this cert, in order of likelihood of occurrence */
		setMessageData( &msgData, uri, CRYPT_MAX_TEXTSIZE );
		krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
						 ( void * ) &value, CRYPT_ATTRIBUTE_CURRENT );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_RFC822NAME );
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			setMessageData( &msgData, uri, CRYPT_MAX_TEXTSIZE );
			status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
									  &msgData, 
									  CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER );
			}
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			setMessageData( &msgData, uri, CRYPT_MAX_TEXTSIZE );
			status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
									  &msgData, CRYPT_CERTINFO_DNSNAME );
			}
		if( cryptStatusOK( status ) )
			{
			int i;

			/* Force the URI (as stored) to lowercase to make case-
			   insensitive matching easier.  In most cases we could ask the 
			   back-end to do this, but this complicates indexing and 
			   there's no reason why we can't do it here */
			for( i = 0; i < msgData.length; i++ )
				uri[ i ] = toLower( uri[ i ] );
			uri[ msgData.length ] = '\0';
			}
		}
	if( ( cryptStatusOK( status ) || status == CRYPT_ERROR_NOTFOUND ) && \
		( certType == CRYPT_CERTTYPE_CERTIFICATE ) )
		{
		setMessageData( &msgData, &boundDate, sizeof( time_t ) );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
							&msgData, CRYPT_CERTINFO_VALIDTO );
		}
	else
		if( status == CRYPT_ERROR_NOTFOUND )
			status = CRYPT_OK;
	if( cryptStatusError( status ) )
		/* Convert any low-level cert-specific error into something generic
		   that makes a bit more sense to the caller */
		return( CRYPT_ARGERROR_NUM1 );

	/* Get the ID information and cert data for the cert */
	if( certType == CRYPT_CERTTYPE_CERTIFICATE )
		{
		status = getKeyID( nameID, iCryptHandle, CRYPT_IATTRIBUTE_SUBJECT );
		if( !cryptStatusError( status ) )
			status = getKeyID( issuerID, iCryptHandle,
							   CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
		if( !cryptStatusError( status ) )
			{
			status = getCertKeyID( keyID, iCryptHandle );
			if( !cryptStatusError( status ) )
				status = CRYPT_OK;	/* getCertKeyID() returns a length */
			}
		}
	if( certType == CRYPT_CERTTYPE_PKIUSER )
		{
		char encKeyID[ 128 ];

		/* Get the PKI user ID.  We can't read this directly since it's
		   returned in text form for use by end users so we have to read the
		   encoded form, decode it, and then turn the decoded binary value
		   into a key ID.  We identify the result as a keyID,
		   (== subjectKeyIdentifier, which it isn't really) but we need to
		   use this to ensure that it's hashed/expanded out to the correct
		   size */
		setMessageData( &msgData, encKeyID, 128 );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_PKIUSER_ID );
		if( cryptStatusOK( status ) )
			{
			BYTE binaryKeyID[ 128 ];
			int length;

			status = length = decodePKIUserValue( binaryKeyID, encKeyID, 
												  msgData.length );
			if( !cryptStatusError( status ) )
				{
				status = CRYPT_OK;	/* decodePKIUserValue() returns a length */
				makeKeyID( keyID, DBXKEYID_BUFFER_SIZE, CRYPT_IKEYID_KEYID,
						   binaryKeyID, length );
				}
			}
		if( cryptStatusOK( status ) )
			{
			status = getKeyID( nameID, iCryptHandle, CRYPT_IATTRIBUTE_SUBJECT );
			if( !cryptStatusError( status ) )
				status = CRYPT_OK;	/* getKeyID() returns a length */
			}
		}
	if( cryptStatusOK( status ) )
		{
		status = getKeyID( certID, iCryptHandle,
						   CRYPT_CERTINFO_FINGERPRINT_SHA );
		if( !cryptStatusError( status ) )
			status = CRYPT_OK;	/* getKeyID() returns a length */
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, certData, MAX_CERT_SIZE );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_CRT_EXPORT,
					&msgData, ( certType == CRYPT_CERTTYPE_PKIUSER ) ? \
					CRYPT_ICERTFORMAT_DATA : CRYPT_CERTFORMAT_CERTIFICATE );
		certDataLength = msgData.length;
		}
	if( cryptStatusError( status ) )
		/* Convert any low-level cert-specific error into something generic
		   that makes a bit more sense to the caller */
		return( CRYPT_ARGERROR_NUM1 );

	/* If this is a partial add (in which we add a cert item which is in the
	   initial stages of the creation process where, although the item may
	   be physically present in the store it can't be accessed directly), we
	   set the first byte to 0xFF to indicate this.  In addition we set the
	   first two bytes of the IDs that have uniqueness constraints to an
	   out-of-band value to prevent a clash with the finished entry when we
	   complete the issue process and replace the partial version with the
	   full version */
	if( addType == CERTADD_PARTIAL || addType == CERTADD_PARTIAL_RENEWAL )
		{
		const char *escapeStr = ( addType == CERTADD_PARTIAL ) ? \
								KEYID_ESC1 : KEYID_ESC2;

		certData[ 0 ] = 0xFF;
		memcpy( issuerID, escapeStr, KEYID_ESC_SIZE );
		memcpy( keyID, escapeStr, KEYID_ESC_SIZE );
		memcpy( certID, escapeStr, KEYID_ESC_SIZE );
		}

	/* Set up the cert object data to write */
	if( !hasBinaryBlobs( dbmsInfo ) )
		{
		char encodedCertData[ MAX_ENCODED_CERT_SIZE ];
		int length;

		length = base64encode( encodedCertData, MAX_ENCODED_CERT_SIZE,
							   certData, certDataLength,
							   CRYPT_CERTTYPE_NONE );
		encodedCertData[ length ] = '\0';
		if( certType == CRYPT_CERTTYPE_CERTIFICATE )
			dbmsFormatSQL( sqlBuffer,
			"INSERT INTO certificates VALUES ('$', '$', '$', '$', '$', '$', "
											 "'$', ?, '$', '$', '$', '$', '$')",
						   C, SP, L, O, OU, CN, uri, nameID, issuerID,
						   keyID, certID, encodedCertData );
		else
			if( certType == CRYPT_CERTTYPE_REQUEST_CERT )
				dbmsFormatSQL( sqlBuffer,
			"INSERT INTO certRequests VALUES ('" TEXT_CERTTYPE_REQUEST_CERT "', "
											 "'$', '$', '$', '$', '$', '$', "
											 "'$', '$', '$')",
							   C, SP, L, O, OU, CN, uri, certID,
							   encodedCertData );
			else
				dbmsFormatSQL( sqlBuffer,
			"INSERT INTO pkiUsers VALUES ('$', '$', '$', '$', '$', '$', "
										 "'$', '$', '$', '$')",
							   C, SP, L, O, OU, CN, nameID, keyID, certID,
							   encodedCertData );
		}
	else
		{
		if( certType == CRYPT_CERTTYPE_CERTIFICATE )
			dbmsFormatSQL( sqlBuffer,
			"INSERT INTO certificates VALUES ('$', '$', '$', '$', '$', '$', "
											 "'$', ?, '$', '$', '$', '$', ?)",
						   C, SP, L, O, OU, CN, uri, nameID, issuerID,
						   keyID, certID );
		else
			if( certType == CRYPT_CERTTYPE_REQUEST_CERT )
				dbmsFormatSQL( sqlBuffer,
			"INSERT INTO certRequests VALUES ('" TEXT_CERTTYPE_REQUEST_CERT "', "
											 "'$', '$', '$', '$', '$', '$', "
											 "'$', '$', ?)",
							   C, SP, L, O, OU, CN, uri, certID );
			else
				dbmsFormatSQL( sqlBuffer,
			"INSERT INTO pkiUsers VALUES ('$', '$', '$', '$', '$', '$', "
										 "'$', '$', '$', ?)",
							   C, SP, L, O, OU, CN, nameID, keyID, certID );
		}

	/* Insert the cert object information */
	return( dbmsUpdate( sqlBuffer, hasBinaryBlobs( dbmsInfo ) ? \
						certData : NULL, certDataLength, boundDate,
						updateType ) );
	}

/* Add a CRL to a database */

int addCRL( DBMS_INFO *dbmsInfo, const CRYPT_CERTIFICATE iCryptCRL,
			const CRYPT_CERTIFICATE iCryptRevokeCert,
			const DBMS_UPDATE_TYPE updateType )
	{
	BYTE certData[ MAX_CERT_SIZE ];
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	char nameID[ DBXKEYID_BUFFER_SIZE ], issuerID[ DBXKEYID_BUFFER_SIZE ];
	char certID[ DBXKEYID_BUFFER_SIZE ];
	time_t expiryDate = 0;
	int certDataLength, status;

	assert( ( isCertStore( dbmsInfo ) && \
			  checkHandleRange( iCryptRevokeCert ) ) || \
			( !isCertStore( dbmsInfo ) && \
			  iCryptRevokeCert == CRYPT_UNUSED ) );

	/* Get the ID information for the current CRL entry */
	status = getKeyID( issuerID, iCryptCRL,
					   CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( !cryptStatusError( status ) )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, certData, MAX_CERT_SIZE );
		status = krnlSendMessage( iCryptCRL, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_CRLENTRY );
		certDataLength = msgData.length;
		}
	if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
		{
		/* If it's a cert store we also need to obtain the cert ID, the name
		   ID of the issuer, and the cert expiry date from the cert being
		   revoked */
		status = getKeyID( certID, iCryptRevokeCert,
						   CRYPT_CERTINFO_FINGERPRINT_SHA );
		if( !cryptStatusError( status ) )
			status = getKeyID( nameID, iCryptRevokeCert,
							   CRYPT_IATTRIBUTE_ISSUER );
		if( !cryptStatusError( status ) )
			{
			RESOURCE_DATA msgData;

			setMessageData( &msgData, &expiryDate, sizeof( time_t ) );
			status = krnlSendMessage( iCryptRevokeCert,
									  IMESSAGE_GETATTRIBUTE_S,
									  &msgData, CRYPT_CERTINFO_VALIDTO );
			}
		}
	if( cryptStatusError( status ) )
		/* Convert any low-level cert-specific error into something generic
		   that makes a bit more sense to the caller */
		return( CRYPT_ARGERROR_NUM1 );

	/* Set up the cert object data to write.  Cert stores contain extra info
	   which is needed to build a CRL so we have to vary the SQL string
	   depending on the keyset type */
	if( !hasBinaryBlobs( dbmsInfo ) )
		{
		char encodedCertData[ MAX_ENCODED_CERT_SIZE ];
		int length;

		length = base64encode( encodedCertData, MAX_ENCODED_CERT_SIZE,
							   certData, certDataLength,
							   CRYPT_CERTTYPE_NONE );
		encodedCertData[ length ] = '\0';
		if( isCertStore( dbmsInfo ) )
			dbmsFormatSQL( sqlBuffer,
			"INSERT INTO CRLs VALUES (?, '$', '$', '$', '$')",
						   nameID, issuerID, certID, encodedCertData );
		else
			dbmsFormatSQL( sqlBuffer,
			"INSERT INTO CRLs VALUES ('$', '$')",
						   issuerID, encodedCertData );
		certDataLength = 0;	/* It's encoded in the SQL string */
		}
	else
		{
		if( isCertStore( dbmsInfo ) )
			dbmsFormatSQL( sqlBuffer,
			"INSERT INTO CRLs VALUES (?, '$', '$', '$', ?)",
						   nameID, issuerID, certID );
		else
			dbmsFormatSQL( sqlBuffer,
			"INSERT INTO CRLs VALUES ('$', ?)",
						   issuerID );
		}

	/* Insert the entry */
	return( dbmsUpdate( sqlBuffer, hasBinaryBlobs( dbmsInfo ) ? \
						certData : NULL, certDataLength, expiryDate,
						updateType ) );
	}

/* Add an item to the database */

static int setItemFunction( KEYSET_INFO *keysetInfo,
							const CRYPT_HANDLE iCryptHandle,
							const KEYMGMT_ITEM_TYPE itemType,
							const char *password, const int passwordLength,
							const int flags )
	{
	DBMS_INFO *dbmsInfo = keysetInfo->keysetDBMS;
	BOOLEAN seenNonDuplicate = FALSE;
	int type, status;

	assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			itemType == KEYMGMT_ITEM_REVOCATIONINFO || \
			itemType == KEYMGMT_ITEM_REQUEST || \
			itemType == KEYMGMT_ITEM_PKIUSER );
	assert( password == NULL ); assert( passwordLength == 0 );

	/* Make sure that we've been given a cert, cert chain, or CRL.  We can't
	   do any more specific checking against the itemType because if it's
	   coming from outside cryptlib it'll just be passed in as a generic cert
	   object with no distinction between object subtypes */
	status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE,
							  &type, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( isCertStore( dbmsInfo ) )
		{
		/* The only item that can be inserted directly into a CA cert
		   store is a CA request or PKI user info */
		if( type != CRYPT_CERTTYPE_CERTREQUEST && \
			type != CRYPT_CERTTYPE_REQUEST_CERT && \
			type != CRYPT_CERTTYPE_REQUEST_REVOCATION && \
			type != CRYPT_CERTTYPE_PKIUSER )
			return( CRYPT_ARGERROR_NUM1 );

		if( itemType == KEYMGMT_ITEM_PKIUSER )
			return( caAddPKIUser( dbmsInfo, iCryptHandle ) );

		/* It's a cert request being added to a CA certificate store */
		assert( itemType == KEYMGMT_ITEM_REQUEST );
		return( caAddCertRequest( dbmsInfo, iCryptHandle, type,
								  ( flags & KEYMGMT_FLAG_UPDATE ) ? \
									TRUE : FALSE ) );
		}
	if( type != CRYPT_CERTTYPE_CERTIFICATE && \
		type != CRYPT_CERTTYPE_CERTCHAIN && \
		type != CRYPT_CERTTYPE_CRL )
		return( CRYPT_ARGERROR_NUM1 );

	assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			itemType == KEYMGMT_ITEM_REVOCATIONINFO );

	/* Lock the cert or CRL for our exclusive use and select the first
	   sub-item (cert in a cert chain, entry in a CRL), update the keyset
	   with the cert(s)/CRL entries, and unlock it to allow others access */
	status = krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_CURSORFIRST,
					 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	do
		{
		/* Add the certificate or CRL */
		if( type == CRYPT_CERTTYPE_CRL )
			status = addCRL( dbmsInfo, iCryptHandle, CRYPT_UNUSED,
							 DBMS_UPDATE_NORMAL );
		else
			status = addCert( dbmsInfo, iCryptHandle,
							  CRYPT_CERTTYPE_CERTIFICATE, CERTADD_NORMAL,
							  DBMS_UPDATE_NORMAL );

		/* An item being added may already be present, however we can't fail
		   immediately because what's being added may be a chain containing
		   further certs or a CRL containing further entries, so we keep
		   track of whether we've successfully added at least one item and
		   clear data duplicate errors */
		if( status == CRYPT_OK )
			seenNonDuplicate = TRUE;
		else
			if( status == CRYPT_ERROR_DUPLICATE )
				status = CRYPT_OK;
		}
	while( cryptStatusOK( status ) && \
		   krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
							MESSAGE_VALUE_CURSORNEXT,
							CRYPT_CERTINFO_CURRENT_CERTIFICATE ) == CRYPT_OK );
	krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusOK( status ) && !seenNonDuplicate )
		/* We reached the end of the chain/CRL without finding anything that 
		   we could add, return a data duplicate error */
		status = CRYPT_ERROR_DUPLICATE;

	return( status );
	}

/* Delete an item from the database */

static int deleteItemFunction( KEYSET_INFO *keysetInfo,
							   const KEYMGMT_ITEM_TYPE itemType,
							   const CRYPT_KEYID_TYPE keyIDtype,
							   const void *keyID, const int keyIDlength )
	{
	DBMS_INFO *dbmsInfo = keysetInfo->keysetDBMS;
	char keyIDbuffer[ CRYPT_MAX_TEXTSIZE * 2 ];
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	int status;

	assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			itemType == KEYMGMT_ITEM_PKIUSER );
	assert( ( !isCertStore( dbmsInfo ) && itemType == KEYMGMT_ITEM_PUBLICKEY ) || \
			( isCertStore( dbmsInfo ) && itemType == KEYMGMT_ITEM_PKIUSER ) );

	/* Delete the item from the database */
	status = makeKeyID( keyIDbuffer, CRYPT_MAX_TEXTSIZE * 2, keyIDtype,
						keyID, keyIDlength );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_STR1 );
	if( isCertStore( dbmsInfo ) )
		{
		/* The only item that can be deleted from a CA cert store is PKI 
		   user info */
		if( itemType != KEYMGMT_ITEM_PKIUSER )
			return( CRYPT_ARGERROR_NUM1 );

		return( caDeletePKIUser( dbmsInfo, keyIDtype, keyID, keyIDlength ) );
		}
	dbmsFormatSQL( sqlBuffer,
			"DELETE FROM $ WHERE $ = '$'",
				   getTableName( itemType ), getKeyName( keyIDtype ), 
				   keyIDbuffer );
	return( dbmsStaticUpdate( sqlBuffer ) );
	}

/****************************************************************************
*																			*
*							Database Access Routines						*
*																			*
****************************************************************************/

void initDBMSwrite( KEYSET_INFO *keysetInfo )
	{
	keysetInfo->setItemFunction = setItemFunction;
	keysetInfo->deleteItemFunction = deleteItemFunction;
	}
#endif /* USE_DBMS */
