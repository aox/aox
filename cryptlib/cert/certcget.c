/****************************************************************************
*																			*
*						Get/Delete Certificate Components					*
*						Copyright Peter Gutmann 1997-2003					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "cert.h"
  #include "certattr.h"
  #include "../misc/asn1_rw.h"
  #include "../misc/asn1s_rw.h"
#else
  #include "cert/cert.h"
  #include "cert/certattr.h"
  #include "misc/asn1_rw.h"
  #include "misc/asn1s_rw.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Convert a binary OID to its text form */

int oidToText( const BYTE *binaryOID, char *oid )
	{
	char *outputPtr = oid;
	int i, j, length = binaryOID[ 1 ];
	long value;
#ifdef sun
	BOOLEAN brokenSprintf = FALSE;
#endif /* sun */

	/* Pick apart the OID.  This assumes that no OID component will be
	   larger than LONG_MAX */
	i = binaryOID[ 2 ] / 40;
	j = binaryOID[ 2 ] % 40;
	if( i > 2 )
		{
		/* Handle special case for large j if i = 2 */
		j += ( i - 2 ) * 40;
		i = 2;
		}
#ifdef sun
	if( sprintf( outputPtr, "X" ) != 1 )
		{
		/* SunOS/Slowaris has broken sprintf() handling.  In SunOS 4.x this
		   was documented as returning a pointer to the output data as per
		   the Berkeley original.  Under Slowaris the manpage was changed so
		   that it looks like any other sprintf(), but it still returns the
		   pointer to the output buffer in some versions so we have to check
		   at runtime to see what we've got and adjust our behaviour
		   accordingly.  In addition the standard sprintf()s require casts
		   of the return value to avoid compile errors when building on SunOS
		   systems, these are safe because that code path is never taken on
		   these systems */
		assert( sprintf( outputPtr, "123" ) >= 4 );	/* Double-check */
		brokenSprintf = TRUE;
		outputPtr += strlen( ( void * ) sprintf( outputPtr, "%d %d", i, j ) );
		}
	else
#endif /* Sun braindamage */
	outputPtr += ( int ) sPrintf( outputPtr, "%d %d", i, j );
	value = 0;
	for( i = 3; i < length + 2; i++ )
		{
		value = ( value << 7 ) | ( binaryOID[ i ] & 0x7F );
		if( !( binaryOID[ i ] & 0x80 ) )
			{
#ifdef sun
			if( brokenSprintf )
				outputPtr += strlen( ( void * ) sprintf( outputPtr, " %ld", value ) );
			else
#endif /* Sun braindamage */
			outputPtr += ( int ) sPrintf( outputPtr, " %ld", value );
			value = 0;
			}

		/* Make sure that we don't overflow the buffer (the value 20 is the
		   maximum magnitude of a 64-bit int plus space plus '\0') */
		if( outputPtr - oid > ( CRYPT_MAX_TEXTSIZE * 2 ) - 20 )
			return( CRYPT_ERROR_BADDATA );
		}
	length = strlen( oid );
	oid[ length ] = '\0';		/* Not really necessary, but nice */

	return( length );
	}

/* Copy string data from a cert */

static int copyCertInfo( void *certInfo, int *certInfoLength,
						 const void *data, const int dataLength )
	{
	const int maxLength = *certInfoLength;

	if( dataLength <= 0 )
		return( CRYPT_ERROR_NOTFOUND );
	*certInfoLength = dataLength;
	if( certInfo == NULL )
		return( CRYPT_OK );
	if( dataLength > maxLength )
		return( CRYPT_ERROR_OVERFLOW );
	memcpy( certInfo, data, dataLength );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							DN/GeneralName Routines							*
*																			*
****************************************************************************/

/* GeneralNames and DNs are handled via indirect selection.  There are four
   classes of field type that cover these names:

	GNSelection	= EXCLUDEDSUBTREES | ...
	GNValue		= OTHERNAME | ... | DIRECTORYNAME
	DNSelection	= SUBJECTNAME | ISSUERNAME | DIRECTORYNAME
	DNValue		= C | O | OU | CN | ...

   Note that DIRECTORYNAME is present twice since it's both a component of a
   GeneralName and a DN in its own right.  GNSelection and DNSelection
   components merely select a composite component, the primitive elements are
   read and written via the GN and DN values.  The selection process is as
   follows:

	GNSelection --+	(default = subjectAltName)
				  |
				  v
				 GN -+----------------> non-DirectoryName field
					 |
				  +--+ DirectoryName
				  |
	DNSelection --+	(default = subjectName)
				  |
				  v
				 DN ------------------> DN field

   Selecting a component can therefore lead through a complex heirarchy of
   explicit and implicit selections, in the worst case being something like
   subjectAltName -> directoryName -> DN field.  DN and GeneralName
   components may be absent (if we're selecting it in order to create it),
   or present (if we're about to read it), or can be created when accessed
   (if we're about to write to it).  The handling is selected by the
   SELECTION_OPTION type, if a cert is in the high state then MAY/CREATE 
   options are implicitly converted to MUST_BE_PRESENT during the selection 
   process.

   The selection is performed as follows:

	set attribute:

	  selectionComponent:
		selectDN	subject | issuer			| MAY_BE_ABSENT
		selectGN	attributeID					| MAY_BE_ABSENT
			- Select prior to use

	  valueComponent:
		selectDN	-							| CREATE_IF_ABSENT
		selectGN	-							| CREATE_IF_ABSENT
			- To create DN/GeneralName before adding DN/GN
			  component/setting DN string

	get attribute:

	  selectionComponent:
		check		subject | issuer | other	| Presence check only
		check		attributeID
			- Return T/F if present

	  valueComponent:
		selectDN	none						| MUST_BE_PRESENT
		selectGN	none						| MUST_BE_PRESENT
			- To get DN/GeneralName component

	delete attribute:

		selectDN	subject | issuers			| MUST_BE_PRESENT
		selectGN	attributeID					| MUST_BE_PRESENT
			- To delete DN/GeneralName component

   This code is cursed */

/* Check whether the currently selected extension is a GeneralName.  We do
   this both for simplicity and because isGeneralNameSelectionComponent() is
   a complex macro that we want to avoid expanding as much as possible */

static BOOLEAN isGeneralNameSelected( const CERT_INFO *certInfoPtr )
	{
	return( certInfoPtr->attributeCursor != NULL && \
			isGeneralNameSelectionComponent( certInfoPtr->attributeCursor->fieldID ) ? \
			TRUE : FALSE );
	}

#ifndef NDEBUG

static BOOLEAN selectionInfoConsistent( const CERT_INFO *certInfoPtr )
	{
	/* If the DN-in-extension flag is set, there must be a DN selected */
	if( certInfoPtr->currentSelection.dnPtr == NULL && \
		certInfoPtr->currentSelection.dnInExtension )
		return( FALSE );

	/* If there's a DN selected and it's not in in an extension, it must be
	   the subject or issuer DN */
	if( certInfoPtr->currentSelection.dnPtr != NULL && \
		!certInfoPtr->currentSelection.dnInExtension && \
		certInfoPtr->currentSelection.dnPtr != &certInfoPtr->subjectName && \
		certInfoPtr->currentSelection.dnPtr != &certInfoPtr->issuerName )
		return( FALSE );

	/* If there's a GeneralName selected, there can't also be a saved
	   GeneralName present */
	if( isGeneralNameSelected( certInfoPtr ) && \
		certInfoPtr->currentSelection.generalName != CRYPT_ATTRIBUTE_NONE )
		return( FALSE );

	return( TRUE );
	}
#endif /* NDEBUG */

/* Check whether there's a DN in the currently-selected extension, and update
   the various selection values if we find one */

static int findDnInExtension( CERT_INFO *certInfoPtr,
							  const BOOLEAN updateCursor )
	{
	const CRYPT_ATTRIBUTE_TYPE attributeID = certInfoPtr->attributeCursor->attributeID;
	const CRYPT_ATTRIBUTE_TYPE fieldID = certInfoPtr->attributeCursor->fieldID;
	ATTRIBUTE_LIST *attributeListPtr;

	/* We're inside a GeneralName, clear any possible saved selection */
	certInfoPtr->currentSelection.generalName = CRYPT_ATTRIBUTE_NONE;

	assert( selectionInfoConsistent( certInfoPtr ) );

	/* Search for a DN in the current GeneralName */
	for( attributeListPtr = certInfoPtr->attributeCursor; \
		 attributeListPtr != NULL && \
			attributeListPtr->attributeID == attributeID && \
			attributeListPtr->fieldID == fieldID; \
		 attributeListPtr = attributeListPtr->next )
		if( attributeListPtr->fieldType == FIELDTYPE_DN )
			{
			/* We found a DN, select it */
			certInfoPtr->currentSelection.dnPtr = &attributeListPtr->value;
			if( updateCursor )
				certInfoPtr->attributeCursor = attributeListPtr;
			certInfoPtr->currentSelection.dnInExtension = TRUE;
			assert( selectionInfoConsistent( certInfoPtr ) );
			return( CRYPT_OK );
			}

	return( CRYPT_ERROR_NOTFOUND );
	}

/* Find a GeneralName field in a GeneralName */

#if 0

/* Currently handled with:

	attributeListPtr = findAttributeField( certInfoPtr->attributeCursor,
										   certInfoPtr->attributeCursor->fieldID,
										   certInfoType ); */

static const ATTRIBUTE_LIST *findGeneralNameField( const ATTRIBUTE_LIST *attributeListPtr,
												   const CRYPT_ATTRIBUTE_TYPE certInfoType )
	{
	const CRYPT_ATTRIBUTE_TYPE attributeID = attributeListPtr->attributeID;
	const CRYPT_ATTRIBUTE_TYPE fieldID = attributeListPtr->fieldID;

	assert( isGeneralNameSelectionComponent( attributeListPtr->fieldID ) );

	/* Search for the GeneralName component in the current GeneralName */
	while( attributeListPtr != NULL && \
		   attributeListPtr->attributeID == attributeID && \
		   attributeListPtr->fieldID == fieldID )
		{
		if( attributeListPtr->subFieldID == certInfoType )
			return( attributeListPtr );
		attributeListPtr = attributeListPtr->next;
		}

	return( NULL );
	}
#endif /* 0 */

/* Move the extension cursor to the given extension field */

int moveCursorToField( CERT_INFO *certInfoPtr,
					   const CRYPT_ATTRIBUTE_TYPE certInfoType )
	{
	const ATTRIBUTE_LIST *attributeListPtr;

	assert( selectionInfoConsistent( certInfoPtr ) );
	assert( certInfoType >= CRYPT_CERTINFO_FIRST_EXTENSION && \
			certInfoType <= CRYPT_CERTINFO_LAST );

	/* Try and locate the given field in the extension */
	attributeListPtr = findAttributeField( certInfoPtr->attributes,
										   certInfoType,
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr == NULL )
		return( CRYPT_ERROR_NOTFOUND );

	/* We found the given field, update the cursor and select the DN within
	   it if it's present */
	certInfoPtr->currentSelection.updateCursor = FALSE;
	certInfoPtr->attributeCursor = ( ATTRIBUTE_LIST * ) attributeListPtr;
	if( isGeneralNameSelectionComponent( certInfoType ) )
		/* If this is a GeneralName, select the DN within it if there's one
		   present */
		findDnInExtension( certInfoPtr, FALSE );
	assert( selectionInfoConsistent( certInfoPtr ) );
	return( CRYPT_OK );
	}

/* Synchronise DN/GeneralName selection information after moving the
   extension cursor */

void syncSelection( CERT_INFO *certInfoPtr )
	{
	/* We've moved the cursor, clear any saved GeneralName selection */
	certInfoPtr->currentSelection.generalName = CRYPT_ATTRIBUTE_NONE;

	/* I've we've moved the cursor off the GeneralName or there's no DN in
	   the GeneralName, deselect the DN */
	if( !isGeneralNameSelected( certInfoPtr ) || \
		cryptStatusError( findDnInExtension( certInfoPtr, FALSE ) ) )
		{
		certInfoPtr->currentSelection.dnPtr = NULL;
		certInfoPtr->currentSelection.dnInExtension = FALSE;
		}
	}

/* Handle selection of a GeneralName in a cert extension */

int selectGeneralName( CERT_INFO *certInfoPtr,
					   const CRYPT_ATTRIBUTE_TYPE certInfoType,
					   const SELECTION_OPTION option )
	{
	assert( ( option == MAY_BE_ABSENT && \
			  isGeneralNameSelectionComponent( certInfoType ) ) || \
			( ( option == MUST_BE_PRESENT || option == CREATE_IF_ABSENT ) && \
			  certInfoType == CRYPT_ATTRIBUTE_NONE ) );
	assert( selectionInfoConsistent( certInfoPtr ) );

	certInfoPtr->currentSelection.updateCursor = FALSE;

	if( option == MAY_BE_ABSENT )
		{
		/* If the selection is present, update the extension cursor and
		   exit */
		if( cryptStatusOK( moveCursorToField( certInfoPtr, certInfoType ) ) )
			return( CRYPT_OK );

		/* If the certificate is in the high state, the MAY is treated as
		   a MUST, since we can't be selecting something so that we can
		   create it later */
		if( certInfoPtr->certificate != NULL )
			return( CRYPT_ERROR_NOTFOUND );

		/* The selection isn't present, remember it for later, without
		   changing any other selection info */
		certInfoPtr->currentSelection.generalName = certInfoType;
		certInfoPtr->attributeCursor = NULL;
		assert( selectionInfoConsistent( certInfoPtr ) );
		return( CRYPT_OK );
		}

	assert( option == MUST_BE_PRESENT || option == CREATE_IF_ABSENT );

	/* If there's no saved GeneralName selection present, the extension
	   cursor must be pointing to a GeneralName */
	if( certInfoPtr->currentSelection.generalName == CRYPT_ATTRIBUTE_NONE )
		return( isGeneralNameSelected( certInfoPtr ) ? \
				CRYPT_OK : CRYPT_ERROR_NOTFOUND );

	/* Try and move the cursor to the saved GeneralName selection */
	if( cryptStatusOK( \
			moveCursorToField( certInfoPtr,
							   certInfoPtr->currentSelection.generalName ) ) )
		return( CRYPT_OK );
	if( option == MUST_BE_PRESENT )
		return( CRYPT_ERROR_NOTFOUND );

	/* We're creating the GeneralName extension, deselect the current DN and
	   remember that we have to update the extension cursor when we've done
	   it */
	certInfoPtr->currentSelection.dnPtr = NULL;
	certInfoPtr->currentSelection.dnInExtension = FALSE;
	certInfoPtr->currentSelection.updateCursor = TRUE;
	assert( selectionInfoConsistent( certInfoPtr ) );
	return( CRYPT_OK );
	}

/* Handle selection of DNs */

int selectDN( CERT_INFO *certInfoPtr, const CRYPT_ATTRIBUTE_TYPE certInfoType,
			  const SELECTION_OPTION option )
	{
	CRYPT_ATTRIBUTE_TYPE generalName = \
							certInfoPtr->currentSelection.generalName;
	static const int value = CRYPT_UNUSED;
	int status;

	assert( ( option == MAY_BE_ABSENT && \
			  isDNSelectionComponent( certInfoType ) ) || \
			( ( option == MUST_BE_PRESENT || option == CREATE_IF_ABSENT ) && \
			  certInfoType == CRYPT_ATTRIBUTE_NONE ) );
	assert( selectionInfoConsistent( certInfoPtr ) );

	if( option == MAY_BE_ABSENT )
		{
		/* Try and select a DN based on the supplied attribute ID */
		switch( certInfoType )
			{
			case CRYPT_CERTINFO_SUBJECTNAME:
				certInfoPtr->currentSelection.dnPtr = &certInfoPtr->subjectName;
				break;

			case CRYPT_CERTINFO_ISSUERNAME:
				certInfoPtr->currentSelection.dnPtr = &certInfoPtr->issuerName;

				/* If it's a self-signed cert and the issuer name isn't
				   explicitly present then it must be implicitly present as
				   the subject name */
				if( certInfoPtr->issuerName == NULL && \
					( certInfoPtr->flags & CERT_FLAG_SELFSIGNED ) )
					certInfoPtr->currentSelection.dnPtr = &certInfoPtr->subjectName;
				break;

			default:
				assert( NOTREACHED );
				return( CRYPT_ARGERROR_VALUE );
			}

		/* We've selected a built-in DN, remember that this isn't one in an
		   (optional) extension */
		certInfoPtr->currentSelection.dnInExtension = FALSE;
		assert( selectionInfoConsistent( certInfoPtr ) );
		return( CRYPT_OK );
		}

	/* If there's a DN already selected, we're done */
	if( certInfoPtr->currentSelection.dnPtr != NULL )
		return( CRYPT_OK );

	assert( option == MUST_BE_PRESENT || option == CREATE_IF_ABSENT );

	/* To select a DN in a GeneralName, we first need to have a GeneralName
	   selected */
	status = selectGeneralName( certInfoPtr, CRYPT_ATTRIBUTE_NONE, option );
	if( cryptStatusError( status ) )
		return( status );

	/* If we've now got a GeneralName selected, try and find a DN in it */
	if( isGeneralNameSelected( certInfoPtr ) )
		{
		/* If there's a DN currently selected, we're done */
		if( certInfoPtr->attributeCursor->fieldType == FIELDTYPE_DN )
			{
			certInfoPtr->currentSelection.dnPtr = \
							&certInfoPtr->attributeCursor->value;
			certInfoPtr->currentSelection.dnInExtension = TRUE;
			assert( selectionInfoConsistent( certInfoPtr ) );
			return( CRYPT_OK );
			}

		/* There's no DN selected, see if there's one present somewhere in
		   the extension */
		if( cryptStatusOK( findDnInExtension( certInfoPtr, TRUE ) ) )
			return( CRYPT_OK );

		/* If there's no DN present and we're not about to create one,
		   exit */
		if( option == MUST_BE_PRESENT )
			return( CRYPT_ERROR_NOTFOUND );

		/* Create the DN in the currently selected GeneralName */
		generalName = certInfoPtr->attributeCursor->fieldID;
		}

	/* We're being asked to instantiate the DN, create the attribute field
	   that contains it */
	status = addAttributeField( &certInfoPtr->attributes, generalName,
						CRYPT_CERTINFO_DIRECTORYNAME, &value, CRYPT_UNUSED,
						ATTR_FLAG_NONE, &certInfoPtr->errorLocus,
						&certInfoPtr->errorType );
	if( cryptStatusError( status ) )
		return( status );

	/* Find the field that we just created.  This is a newly-created
	   attribute, so it's the only one present (i.e we don't have to worry
	   about finding one added at the end of the sequence of identical
	   attributes), and we also know that it must be present since we've
	   just created it */
	return( selectGeneralName( certInfoPtr, generalName, MAY_BE_ABSENT ) );
	}

/****************************************************************************
*																			*
*									Get Cert Info							*
*																			*
****************************************************************************/

/* Get a certificate component */

static int getCertAttributeComponentData( const ATTRIBUTE_LIST *attributeListPtr,
										  void *certInfo, int *certInfoLength )
	{
	const int maxLength = ( certInfoLength != NULL ) ? *certInfoLength : 0;

	/* If the data type is an OID, we have to convert it to a human-readable
	   form before we return it */
	if( attributeListPtr->fieldType == BER_OBJECT_IDENTIFIER )
		{
		char textOID[ CRYPT_MAX_TEXTSIZE * 2 ];
		int length;

		assert( certInfoLength != NULL );

		length = oidToText( attributeListPtr->value, textOID );
		*certInfoLength = length;
		if( certInfo == NULL )
			return( CRYPT_OK );
		if( length > maxLength )
			return( CRYPT_ERROR_OVERFLOW );
		memcpy( certInfo, textOID, length );
		return( CRYPT_OK );
		}

	/* If it's a basic data value, copy it over as an integer */
	if( attributeListPtr->valueLength <= 0 )
		{
		*( ( int * ) certInfo ) = ( int ) attributeListPtr->intValue;
		return( CRYPT_OK );
		}
	assert( certInfoLength != NULL );

	/* It's a more complex data type, copy it across */
	*certInfoLength = attributeListPtr->valueLength;
	if( certInfo == NULL )
		return( CRYPT_OK );
	if( attributeListPtr->valueLength > maxLength )
		return( CRYPT_ERROR_OVERFLOW );
	memcpy( certInfo, attributeListPtr->value, attributeListPtr->valueLength );
	return( CRYPT_OK );
	}

static int getCertAttributeComponent( CERT_INFO *certInfoPtr,
									  const CRYPT_ATTRIBUTE_TYPE certInfoType,
									  void *certInfo, int *certInfoLength )
	{
	ATTRIBUTE_LIST *attributeListPtr;

	assert( ( certInfo == NULL && *certInfoLength == 0 ) || \
			( certInfoLength == NULL ) || \
			( *certInfoLength > 1 && *certInfoLength <= 32768 ) );

	/* Try and find this attribute in the attribute list */
	if( isRevocationEntryComponent( certInfoType ) )
		{
		/* If it's an RTCS per-entry attribute, get the attribute from the
		   currently selected entry */
		if( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST || \
			certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE )
			{
			if( certInfoPtr->currentValidity == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			attributeListPtr = findAttributeFieldEx( \
					certInfoPtr->currentValidity->attributes, certInfoType );
			}
		else
			{
			/* It's a CRL or OCSP per-entry attribute, get the attribute 
			   from the currently selected entry */
			if( certInfoPtr->currentRevocation == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			attributeListPtr = findAttributeFieldEx( \
				certInfoPtr->currentRevocation->attributes, certInfoType );
			if( attributeListPtr == NULL && \
				certInfoType == CRYPT_CERTINFO_CRLREASON )
				/* Revocation reason codes are actually a single range of 
				   values spread across two different extensions, so if we 
				   don't find the value as a straight cRLReason we try 
				   again for a cRLExtReason.  If we've been specifically 
				   asked for a cRLExtReason we don't go the other way 
				   because the caller (presumably) specifically wants the 
				   extended reason code */
				attributeListPtr = findAttributeFieldEx( \
								certInfoPtr->currentRevocation->attributes,
								CRYPT_CERTINFO_CRLEXTREASON );
			}
		}
	else
		attributeListPtr = findAttributeFieldEx( certInfoPtr->attributes,
												 certInfoType );
	if( attributeListPtr == NULL )
		return( CRYPT_ERROR_NOTFOUND );

	/* If this is a non-present field in a present attribute with a default
	   value for the field, return that */
	if( isDefaultFieldValue( attributeListPtr ) )
		{
		*( ( int * ) certInfo ) = getDefaultFieldValue( certInfoType );
		return( CRYPT_OK );
		}

	/* If this is a non-present field in a present attribute which denotes
	   an entire (constructed) attribute, return a boolean indicating its
	   presence */
	if( isCompleteAttribute( attributeListPtr ) )
		{
		*( ( int * ) certInfo ) = TRUE;
		return( CRYPT_OK );
		}

	return( getCertAttributeComponentData( attributeListPtr, certInfo,
										   certInfoLength ) );
	}

/* Get the hash of a certificate */

static int getCertHash( CERT_INFO *certInfoPtr,
						const CRYPT_ATTRIBUTE_TYPE certInfoType, 
						void *certInfo, int *certInfoLength )
	{
	const CRYPT_ALGO_TYPE cryptAlgo = \
				( certInfoType == CRYPT_CERTINFO_FINGERPRINT_MD5 ) ? \
				CRYPT_ALGO_MD5 : CRYPT_ALGO_SHA;
	HASHFUNCTION hashFunction;
	BYTE hash[ CRYPT_MAX_HASHSIZE ];
	const int maxLength = *certInfoLength;
	int hashSize;

	/* Get the hash algorithm information */
	getHashParameters( cryptAlgo, &hashFunction, &hashSize );
	*certInfoLength = hashSize;
	if( certInfo == NULL )
		return( CRYPT_OK );
	if( hashSize > maxLength )
		return( CRYPT_ERROR_OVERFLOW );
	assert( certInfoPtr->certificate != NULL );

	/* Write the hash (fingerprint) to the output */
	if( cryptAlgo == CRYPT_ALGO_SHA && certInfoPtr->certHashSet )
		{
		/* If we've got a cached hash present, return that instead of re-
		   hashing the cert */
		memcpy( certInfo, certInfoPtr->certHash, KEYID_SIZE );
		return( CRYPT_OK );
		}
	hashFunction( NULL, hash, certInfoPtr->certificate,
				  certInfoPtr->certificateSize, HASH_ALL );
	memcpy( certInfo, hash, hashSize );
	if( cryptAlgo == CRYPT_ALGO_SHA )
		{
		/* Remember the hash/fingerprint/oobCertID/certHash/thumbprint/
		   whatever for later, since this is reused frequently */
		memcpy( certInfoPtr->certHash, hash, hashSize );
		certInfoPtr->certHashSet = TRUE;
		}
	return( CRYPT_OK );
	}

/* Get a single CRL entry */

static int getCrlEntry( CERT_INFO *certInfoPtr, void *certInfo, 
						int *certInfoLength )
	{
	STREAM stream;
	const int maxLength = *certInfoLength;
	int crlEntrySize, i, status;

	assert( certInfoPtr->type == CRYPT_CERTTYPE_CRL );

	if( certInfoPtr->currentRevocation == NULL )
		return( CRYPT_ERROR_NOTFOUND );

	/* Determine how big the encoded CRL entry will be.  This is somewhat 
	   ugly since we have to pick the necessary function out of the cert 
	   write-function table, but the only other way to do it would be to 
	   pseudo-sign the cert object in order to write the data, which 
	   doesn't work for CRL entries where we could end up pseudo-singing it 
	   multiple times */
	for( i = 0; certWriteTable[ i ].type != CRYPT_CERTTYPE_CRL && \
				certWriteTable[ i ].type != CRYPT_CERTTYPE_NONE; i++ );
	if( certWriteTable[ i ].type == CRYPT_CERTTYPE_NONE )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	sMemOpen( &stream, NULL, 0 );
	status = certWriteTable[ i ].writeFunction( &stream, certInfoPtr,
												NULL, CRYPT_UNUSED );
	crlEntrySize = stell( &stream );
	sMemClose( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the encoded single CRL entry */
	*certInfoLength = crlEntrySize;
	if( certInfo == NULL )
		return( CRYPT_OK );
	if( crlEntrySize > maxLength )
		return( CRYPT_ERROR_OVERFLOW );
	sMemOpen( &stream, certInfo, crlEntrySize );
	status = certWriteTable[ i ].writeFunction( &stream, certInfoPtr,
												NULL, CRYPT_UNUSED );
	sMemDisconnect( &stream );

	return( status );
	}

/* Get the issuerAndSerialNumber for a certificate */

static int getIAndS( CERT_INFO *certInfoPtr, void *certInfo, 
					 int *certInfoLength )
	{
	STREAM stream;
	void *serialNumber;
	const int maxLength = *certInfoLength;
	int serialNumberLength, status;

	if( certInfoPtr->type == CRYPT_CERTTYPE_CRL )
		{
		REVOCATION_INFO *crlInfoPtr = certInfoPtr->currentRevocation;

		/* If it's a CRL, use the serial number of the currently selected 
		   CRL entry */
		assert( crlInfoPtr != NULL );

		serialNumber = crlInfoPtr->dataPtr;
		serialNumberLength = crlInfoPtr->dataLength;
		}
	else
		{
		serialNumber = certInfoPtr->serialNumber;
		serialNumberLength = certInfoPtr->serialNumberLength;
		}
	assert( serialNumber != NULL );
	*certInfoLength = ( int ) \
		sizeofObject( certInfoPtr->issuerDNsize + \
					  sizeofInteger( serialNumber, serialNumberLength ) );
	if( certInfo == NULL )
		return( CRYPT_OK );
	if( *certInfoLength > maxLength )
		return( CRYPT_ERROR_OVERFLOW );
	sMemOpen( &stream, certInfo, *certInfoLength );
	writeSequence( &stream, certInfoPtr->issuerDNsize + \
				   sizeofInteger( serialNumber, serialNumberLength ) );
	swrite( &stream, certInfoPtr->issuerDNptr, certInfoPtr->issuerDNsize );
	status = writeInteger( &stream, serialNumber, serialNumberLength,
						   DEFAULT_TAG );
	sMemDisconnect( &stream );

	return( status );
	}

/* Get the ESSCertID for a certificate */

static int getESSCertID( CERT_INFO *certInfoPtr, void *certInfo, 
						 int *certInfoLength )
	{
	STREAM stream;
	HASHFUNCTION hashFunction;
	const int maxLength = *certInfoLength;
	int hashSize, issuerSerialDataSize, status;

	/* Get the hash algorithm information and hash the cert to get the cert 
	   ID if necessary */
	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
	if( !certInfoPtr->certHashSet )
		{
		hashFunction( NULL, certInfoPtr->certHash, certInfoPtr->certificate,
					  certInfoPtr->certificateSize, HASH_ALL );
		certInfoPtr->certHashSet = TRUE;
		}
	assert( certInfoPtr->serialNumber != NULL );

	/* Write the ESSCertID:

		ESSCertID ::= SEQUENCE {
			certHash		OCTET STRING SIZE(20),
			issuerSerial	SEQUENCE {
				issuer		SEQUENCE { [4] EXPLICIT Name },
				serial		INTEGER
				}
			} */
	issuerSerialDataSize = ( int ) \
			sizeofObject( sizeofObject( certInfoPtr->issuerDNsize ) ) + \
			sizeofInteger( certInfoPtr->serialNumber,
						   certInfoPtr->serialNumberLength );
	*certInfoLength = ( int ) \
			sizeofObject( sizeofObject( hashSize ) + \
						  sizeofObject( issuerSerialDataSize ) );
	if( certInfo == NULL )
		return( CRYPT_OK );
	if( *certInfoLength > maxLength )
		return( CRYPT_ERROR_OVERFLOW );
	sMemOpen( &stream, certInfo, *certInfoLength );
	writeSequence( &stream, sizeofObject( hashSize ) + \
							sizeofObject( issuerSerialDataSize ) );
	writeOctetString( &stream, certInfoPtr->certHash, hashSize, DEFAULT_TAG );
	writeSequence( &stream, issuerSerialDataSize );
	writeSequence( &stream, sizeofObject( certInfoPtr->issuerDNsize ) );
	writeConstructed( &stream, certInfoPtr->issuerDNsize, 4 );
	swrite( &stream, certInfoPtr->issuerDNptr, certInfoPtr->issuerDNsize );
	status = writeInteger( &stream, certInfoPtr->serialNumber,
						   certInfoPtr->serialNumberLength, DEFAULT_TAG );
	sMemDisconnect( &stream );
	assert( cryptStatusOK( status ) );

	return( status );
	}

/* Encode PKI user information into the external format and return it */

static int getPkiUserInfo( CERT_INFO *certInfoPtr, 
						   const CRYPT_ATTRIBUTE_TYPE certInfoType, 
						   void *certInfo, int *certInfoLength )
	{
	char encUserInfo[ 128 ];
	BYTE userInfo[ 128 ], *userInfoPtr = userInfo;
	const int maxLength = *certInfoLength;
	int userInfoLength = 128, status;

	if( certInfoType == CRYPT_CERTINFO_PKIUSER_ID )
		{
		status = getCertAttributeComponent( certInfoPtr,
											CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER,
											userInfo, &userInfoLength );
		assert( cryptStatusOK( status ) );
		if( cryptStatusError( status ) )
			return( status );	/* Should never happen */
		}
	else
		userInfoPtr = ( certInfoType == CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD ) ? \
					  certInfoPtr->pkiIssuePW : certInfoPtr->pkiRevPW;
	*certInfoLength = encodePKIUserValue( encUserInfo, userInfoPtr,
				( certInfoType == CRYPT_CERTINFO_PKIUSER_ID ) ? 3 : 4 );
	zeroise( userInfo, 128 );
	if( certInfo == NULL )
		return( CRYPT_OK );
	if( *certInfoLength > maxLength )
		return( CRYPT_ERROR_OVERFLOW );
	memcpy( certInfo, encUserInfo, *certInfoLength );
	zeroise( encUserInfo, 128 );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*									Get a Component							*
*																			*
****************************************************************************/

/* Get a certificate component */

int getCertComponent( CERT_INFO *certInfoPtr,
					  const CRYPT_ATTRIBUTE_TYPE certInfoType,
					  void *certInfo, int *certInfoLength )
	{
	const int maxLength = ( certInfoLength != NULL ) ? *certInfoLength : 0;
	void *data = NULL;
	int *valuePtr = ( int * ) certInfo;
	int dataLength = 0;

	assert( ( certInfo == NULL && *certInfoLength == 0 ) || \
			( certInfoLength == NULL ) || \
			( *certInfoLength > 1 && *certInfoLength <= 32768 ) );

	/* If it's a GeneralName or DN component, return it.  These are 
	   special-case attribute values, so they have to come before the 
	   general attribute-handling code */
	if( isGeneralNameSelectionComponent( certInfoType ) )
		{
		SELECTION_STATE savedState;
		int status;

		/* Determine whether the given component is present or not.  This
		   has a somewhat odd status return since it returns the found/
		   notfound status in the return code as well as the returned value,
		   this mirrors the behaviour when reading extension-present
		   pseudo-attributes */
		saveSelectionState( savedState, certInfoPtr );
		status = selectGeneralName( certInfoPtr, certInfoType, 
									MAY_BE_ABSENT );
		if( cryptStatusOK( status ) )
			status = selectGeneralName( certInfoPtr, CRYPT_ATTRIBUTE_NONE, 
										MUST_BE_PRESENT );
		*valuePtr = cryptStatusOK( status ) ? TRUE : FALSE;
		restoreSelectionState( savedState, certInfoPtr );

		return( status );
		}
	if( isGeneralNameComponent( certInfoType ) )
		{
		ATTRIBUTE_LIST *attributeListPtr;
		int status;

		/* Find the requested GeneralName component and return it to the
		   caller */
		status = selectGeneralName( certInfoPtr, CRYPT_ATTRIBUTE_NONE,
									MUST_BE_PRESENT );
		if( cryptStatusError( status ) )
			return( status );
		attributeListPtr = findAttributeField( certInfoPtr->attributeCursor,
											   certInfoPtr->attributeCursor->fieldID,
											   certInfoType );
		if( attributeListPtr == NULL )
			return( CRYPT_ERROR_NOTFOUND );
		return( getCertAttributeComponentData( attributeListPtr, certInfo,
											   certInfoLength ) );
		}
	if( isDNComponent( certInfoType ) )
		{
		int status;

		/* Find the requested DN component and return it to the caller */
		status = selectDN( certInfoPtr, CRYPT_ATTRIBUTE_NONE,
						   MUST_BE_PRESENT );
		if( cryptStatusError( status ) )
			return( status );
		return( getDNComponentValue( *certInfoPtr->currentSelection.dnPtr,
									 certInfoType, certInfo, certInfoLength,
									 maxLength ) );
		}

	/* If it's standard cert or CMS attribute, return it */
	if( ( certInfoType >= CRYPT_CERTINFO_FIRST_EXTENSION && \
		  certInfoType <= CRYPT_CERTINFO_LAST_EXTENSION ) || \
		( certInfoType >= CRYPT_CERTINFO_FIRST_CMS && \
		  certInfoType <= CRYPT_CERTINFO_LAST_CMS ) )
		return( getCertAttributeComponent( certInfoPtr, certInfoType,
										   certInfo, certInfoLength ) );

	/* If it's anything else, handle it specially */
	switch( certInfoType )
		{
		case CRYPT_CERTINFO_SELFSIGNED:
			*valuePtr = ( certInfoPtr->flags & CERT_FLAG_SELFSIGNED ) ? \
						TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_IMMUTABLE:
			*valuePtr = ( certInfoPtr->certificate != NULL ) ? TRUE: FALSE;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_XYZZY:
			{
			BYTE policyOID[ MAX_OID_SIZE ];
			int policyOIDLength = MAX_OID_SIZE;

			/* Check for the presence of the XYZZY policy OID */
			if( cryptStatusOK( \
				getCertAttributeComponent( certInfoPtr,
									CRYPT_CERTINFO_CERTPOLICYID,
									policyOID, &policyOIDLength ) ) && \
				policyOIDLength == sizeofOID( OID_CRYPTLIB_XYZZYCERT ) && \
				!memcmp( policyOID, OID_CRYPTLIB_XYZZYCERT, policyOIDLength ) )
				*valuePtr = TRUE;
			else
				*valuePtr = FALSE;
			return( CRYPT_OK );
			}
		case CRYPT_CERTINFO_CERTTYPE:
			*valuePtr = certInfoPtr->type;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_FINGERPRINT_MD5:
		case CRYPT_CERTINFO_FINGERPRINT_SHA:
			return( getCertHash( certInfoPtr, certInfoType, certInfo, 
								 certInfoLength ) );

		case CRYPT_CERTINFO_CURRENT_CERTIFICATE:
		case CRYPT_CERTINFO_CURRENT_EXTENSION:
		case CRYPT_CERTINFO_CURRENT_FIELD:
		case CRYPT_CERTINFO_CURRENT_COMPONENT:
			/* The current component and field are essentially the same 
			   thing since a component is one of a set of entries in a 
			   multivalued field, thus we only distinguish between 
			   extensions and everything else */
			if( certInfoPtr->attributeCursor == NULL )
				return( CRYPT_ERROR_NOTINITED );
			*valuePtr = ( certInfoType == CRYPT_CERTINFO_CURRENT_EXTENSION ) ? \
						certInfoPtr->attributeCursor->attributeID :
						certInfoPtr->attributeCursor->fieldID;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_TRUSTED_USAGE:
			if( certInfoPtr->trustedUsage == CRYPT_ERROR )
				return( CRYPT_ERROR_NOTFOUND );
			*valuePtr = certInfoPtr->trustedUsage;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_TRUSTED_IMPLICIT:
			*valuePtr = cryptStatusOK( \
							krnlSendMessage( certInfoPtr->ownerHandle,
											 IMESSAGE_SETATTRIBUTE,
											 &certInfoPtr->objectHandle,
											 CRYPT_IATTRIBUTE_CERT_CHECKTRUST ) ) ? \
						TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_SIGNATURELEVEL:
			*valuePtr = certInfoPtr->signatureLevel;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_VERSION:
			*valuePtr = certInfoPtr->version;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_SERIALNUMBER:
			if( certInfoPtr->type == CRYPT_CERTTYPE_CRL )
				{
				const REVOCATION_INFO *revInfoPtr = \
					( certInfoPtr->currentRevocation != NULL ) ? \
					certInfoPtr->currentRevocation : certInfoPtr->revocations;

				if( revInfoPtr != NULL )
					{
					data = revInfoPtr->dataPtr;
					dataLength = revInfoPtr->dataLength;
					}
				}
			else
				{
				data = certInfoPtr->serialNumber;
				dataLength = certInfoPtr->serialNumberLength;
				}
			return( copyCertInfo( certInfo, certInfoLength, data, 
								  dataLength ) );

		case CRYPT_CERTINFO_ISSUERNAME:
			*valuePtr = ( certInfoPtr->issuerName != NULL ) ? TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_VALIDFROM:
		case CRYPT_CERTINFO_THISUPDATE:
			if( certInfoPtr->startTime > 0 )
				{
				data = &certInfoPtr->startTime;
				dataLength = sizeof( time_t );
				}
			return( copyCertInfo( certInfo, certInfoLength, data, 
								  dataLength ) );

		case CRYPT_CERTINFO_VALIDTO:
		case CRYPT_CERTINFO_NEXTUPDATE:
			if( certInfoPtr->endTime > 0 )
				{
				data = &certInfoPtr->endTime;
				dataLength = sizeof( time_t );
				}
			return( copyCertInfo( certInfo, certInfoLength, data, 
								  dataLength ) );

		case CRYPT_CERTINFO_SUBJECTNAME:
			*valuePtr = ( certInfoPtr->subjectName != NULL ) ? TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_ISSUERUNIQUEID:
			return( copyCertInfo( certInfo, certInfoLength, 
								  certInfoPtr->issuerUniqueID, 
								  certInfoPtr->issuerUniqueIDlength ) );

		case CRYPT_CERTINFO_SUBJECTUNIQUEID:
			return( copyCertInfo( certInfo, certInfoLength, 
								  certInfoPtr->subjectUniqueID, 
								  certInfoPtr->subjectUniqueIDlength ) );

		case CRYPT_CERTINFO_REVOCATIONDATE:
			/* If there's a specific validity/revocation entry selected, get 
			   its invalidity/revocation time, otherwise if there are 
			   invalid/revoked certs present get the first cert's invalidity/
			   revocation time, otherwise get the default invalidity/
			   revocation time */
			if( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE )
				data = ( certInfoPtr->currentValidity != NULL ) ? \
						   &certInfoPtr->currentValidity->invalidityTime : \
					   ( certInfoPtr->validityInfo != NULL ) ? \
						   &certInfoPtr->validityInfo->invalidityTime : \
					   ( certInfoPtr->revocationTime ) ? \
						   &certInfoPtr->revocationTime : NULL;
			else
				data = ( certInfoPtr->currentRevocation != NULL ) ? \
						   &certInfoPtr->currentRevocation->revocationTime : \
					   ( certInfoPtr->revocations != NULL ) ? \
						   &certInfoPtr->revocations->revocationTime : \
					   ( certInfoPtr->revocationTime ) ? \
						   &certInfoPtr->revocationTime : NULL;
			if( data != NULL )
				dataLength = sizeof( time_t );
			return( copyCertInfo( certInfo, certInfoLength, data, 
								  dataLength ) );

		case CRYPT_CERTINFO_CERTSTATUS:
			{
			const VALIDITY_INFO *valInfoPtr = \
					( certInfoPtr->currentValidity != NULL ) ? \
					certInfoPtr->currentValidity : certInfoPtr->validityInfo;

			if( valInfoPtr == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			*valuePtr = valInfoPtr->extStatus;

			return( CRYPT_OK );
			}

		case CRYPT_CERTINFO_REVOCATIONSTATUS:
			{
			const REVOCATION_INFO *revInfoPtr = \
					( certInfoPtr->currentRevocation != NULL ) ? \
					certInfoPtr->currentRevocation : certInfoPtr->revocations;

			if( revInfoPtr == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			*valuePtr = revInfoPtr->status;

			return( CRYPT_OK );
			}

		case CRYPT_CERTINFO_DN:
			{
			STREAM stream;
			int status;

			/* Export the entire DN in string form */
			status = selectDN( certInfoPtr, CRYPT_ATTRIBUTE_NONE,
							   MUST_BE_PRESENT );
			if( cryptStatusError( status ) )
				return( status );
			sMemOpen( &stream, certInfo, *certInfoLength );
			status = writeDNstring( &stream, 
									*certInfoPtr->currentSelection.dnPtr );
			if( cryptStatusOK( status ) )
				*certInfoLength = stell( &stream );
			sMemDisconnect( &stream );
			return( status );
			}

		case CRYPT_CERTINFO_PKIUSER_ID:
		case CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD:
		case CRYPT_CERTINFO_PKIUSER_REVPASSWORD:
			return( getPkiUserInfo( certInfoPtr, certInfoType, certInfo, 
									certInfoLength ) );

		case CRYPT_IATTRIBUTE_CRLENTRY:
			return( getCrlEntry( certInfoPtr, certInfo, certInfoLength ) );

		case CRYPT_IATTRIBUTE_SUBJECT:
#if 0
			/* Normally these attributes are only present for signed objects
			   (i.e. ones that are in the high state), however CRMF requests
			   acting as CMP revocation requests aren't signed so we have to
			   set the ACLs to allow the attribute to be read in the low state
			   as well.  Since this only represents a programming error rather
			   than a real access violation, we catch it here with an
			   assertion */
			assert( ( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_REVOCATION && \
					  certInfoPtr->certificate == NULL ) || \
					certInfoPtr->certificate != NULL  );
#else
			assert( certInfoPtr->certificate != NULL  );
#endif /* 0 */
			return( copyCertInfo( certInfo, certInfoLength, 
								  certInfoPtr->subjectDNptr, 
								  certInfoPtr->subjectDNsize ) );

		case CRYPT_IATTRIBUTE_ISSUER:
			return( copyCertInfo( certInfo, certInfoLength, 
								  certInfoPtr->issuerDNptr, 
								  certInfoPtr->issuerDNsize ) );

		case CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER:
			return( getIAndS( certInfoPtr, certInfo, certInfoLength ) );

		case CRYPT_IATTRIBUTE_SPKI:
			{
			BYTE *dataStartPtr = certInfo;
			int status;

			status = copyCertInfo( certInfo, certInfoLength, 
								   certInfoPtr->publicKeyInfo, 
								   certInfoPtr->publicKeyInfoSize );
			if( cryptStatusOK( status ) && \
				dataStartPtr != NULL && *dataStartPtr == MAKE_CTAG( 6 ) )
				/* Fix up CRMF braindamage */
				*dataStartPtr = BER_SEQUENCE;
			return( status );
			}

		case CRYPT_IATTRIBUTE_RESPONDERURL:
			/* An RTCS/OCSP URL may be present if it was copied over from a 
			   cert that's being checked, however if there wasn't any
			   authorityInfoAccess information present the URL won't have
			   been initialised.  Since this attribute isn't accessed via
			   the normal cert attribute mechanisms, we have to explictly
			   check for its non-presence */
			if( certInfoPtr->responderUrl == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			return( copyCertInfo( certInfo, certInfoLength, 
								  certInfoPtr->responderUrl, 
								  certInfoPtr->responderUrlSize ) );

		case CRYPT_IATTRIBUTE_AUTHCERTID:
			/* An authorising certificate identifier will be present if
			   the request was handled by cryptlib but not if it came from
			   an external source, so we have to make sure there's something
			   actually present before we try to return it */
			if( !memcmp( certInfoPtr->authCertID,
						 "\x00\x00\x00\x00\x00\x00\x00\x00", 8 ) )
				return( CRYPT_ERROR_NOTFOUND );
			return( copyCertInfo( certInfo, certInfoLength, 
								  certInfoPtr->authCertID, KEYID_SIZE ) );

		case CRYPT_IATTRIBUTE_ESSCERTID:
			return( getESSCertID( certInfoPtr, certInfo, certInfoLength ) );
		}

	/* Everything else isn't available */
	assert( NOTREACHED );
	return( CRYPT_ARGERROR_VALUE );
	}

/****************************************************************************
*																			*
*								Delete a Component							*
*																			*
****************************************************************************/

/* Delete a cert attribute */

static int deleteCertattribute( CERT_INFO *certInfoPtr,
								const CRYPT_ATTRIBUTE_TYPE certInfoType )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	const BOOLEAN isRevocationEntry = \
				isRevocationEntryComponent( certInfoType ) ? TRUE : FALSE;
	int status;

	if( isRevocationEntry )
		{
		/* If it's an RTCS per-entry attribute, look for the attribute in 
		   the currently selected entry */
		if( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST || \
			certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE )
			{
			if( certInfoPtr->currentValidity == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			attributeListPtr = findAttributeFieldEx( \
				certInfoPtr->currentValidity->attributes, certInfoType );
			}
		else
			{
			/* It's a CRL/OCSP per-entry attribute, look for the attribute 
			   in the currently selected entry */
			if( certInfoPtr->currentRevocation == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			attributeListPtr = findAttributeFieldEx( \
				certInfoPtr->currentRevocation->attributes, certInfoType );
			}
		}
	else
		attributeListPtr = findAttributeFieldEx( certInfoPtr->attributes,
												 certInfoType );
	if( attributeListPtr == NULL )
		return( CRYPT_ERROR_NOTFOUND );
	if( isDefaultFieldValue( attributeListPtr ) )
		/* This is a non-present field in a present attribute with a default 
		   value for the field.  There isn't really any satisfactory return 
		   code for this case, returning CRYPT_OK is wrong because the caller 
		   can keep deleting the same field, and return CRYPT_NOTFOUND is 
		   wrong because the caller may have added the attribute at an 
		   earlier date but it was never written because it had the default 
		   value, so that to the caller it appears that the field they added 
		   has been lost.  The least unexpected action is to return 
		   CRYPT_OK */
		return( CRYPT_OK );
	if( isCompleteAttribute( attributeListPtr ) )
		{
		ATTRIBUTE_LIST *fieldAttributeListPtr;
		ATTRIBUTE_LIST attributeListItem;

		/* If the cert has a fleur de lis, make sure that it can't be scraped 
		   off */
		fieldAttributeListPtr = findAttribute( certInfoPtr->attributes,
											   certInfoType, TRUE );
		if( fieldAttributeListPtr != NULL && \
			fieldAttributeListPtr->flags & ATTR_FLAG_LOCKED )
			return( CRYPT_ERROR_PERMISSION );

		/* This is a non-present field in a present attribute that denotes an 
		   entire (constructed) attribute, create a special list pseudo-entry 
		   to convey this and delete the entire attribute */
		memcpy( &attributeListItem, attributeListPtr, sizeof( ATTRIBUTE_LIST ) );
		attributeListItem.intValue = certInfoType;
		if( isRevocationEntry )
			{
			if( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST || \
				certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE )
				status = deleteAttribute( &certInfoPtr->currentValidity->attributes,
										  &certInfoPtr->attributeCursor,
										  &attributeListItem,
										  certInfoPtr->currentSelection.dnPtr );
			else
				status = deleteAttribute( &certInfoPtr->currentRevocation->attributes,
										  &certInfoPtr->attributeCursor,
										  &attributeListItem,
										  certInfoPtr->currentSelection.dnPtr );
			}
		else
			status = deleteAttribute( &certInfoPtr->attributes,
									  &certInfoPtr->attributeCursor,
									  &attributeListItem,
									  certInfoPtr->currentSelection.dnPtr );
		}
	else
		{
		/* If the cert has a fleur de lis, make sure that it can't be scraped 
		   off */
		if( attributeListPtr->flags & ATTR_FLAG_LOCKED )
			return( CRYPT_ERROR_PERMISSION );

		/* It's a single field, delete that */
		if( isRevocationEntry )
			{
			if( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST || \
				certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE )
				status = deleteAttributeField( &certInfoPtr->currentValidity->attributes,
											   &certInfoPtr->attributeCursor,
											   attributeListPtr,
											   certInfoPtr->currentSelection.dnPtr );
			else
				status = deleteAttributeField( &certInfoPtr->currentRevocation->attributes,
											   &certInfoPtr->attributeCursor,
											   attributeListPtr,
											   certInfoPtr->currentSelection.dnPtr );
			}
		else
			status = deleteAttributeField( &certInfoPtr->attributes,
										   &certInfoPtr->attributeCursor,
										   attributeListPtr,
										   certInfoPtr->currentSelection.dnPtr );
		if( status == OK_SPECIAL )
			/* We've deleted the attribute containing the currently selected 
			   DN, deselect it */
			certInfoPtr->currentSelection.dnPtr = NULL;
		}
	return( CRYPT_OK );
	}

/* Delete a certificate component */

int deleteCertComponent( CERT_INFO *certInfoPtr,
						 const CRYPT_ATTRIBUTE_TYPE certInfoType )
	{
	int status;

	/* If it's a GeneralName or DN component, delete it.  These are 
	   special-case attribute values, so they have to come before the 
	   general attribute-handling code */
	if( isGeneralNameSelectionComponent( certInfoType ) )
		{
		CRYPT_ATTRIBUTE_TYPE attributeID, fieldID;
		ATTRIBUTE_LIST *attributeListPtr;

		/* Check whether this GeneralName is present */
		status = selectGeneralName( certInfoPtr, certInfoType,
									MUST_BE_PRESENT );
		if( cryptStatusError( status ) )
			return( status );
		attributeID = certInfoPtr->attributeCursor->attributeID;
		fieldID = certInfoPtr->attributeCursor->fieldID;

		/* Delete each field in the GeneralName */
		for( attributeListPtr = certInfoPtr->attributeCursor; \
			 attributeListPtr != NULL && \
				attributeListPtr->attributeID == attributeID && \
				attributeListPtr->fieldID == fieldID; \
			 attributeListPtr = attributeListPtr->next )
			if( deleteAttributeField( &certInfoPtr->attributes,
						&certInfoPtr->attributeCursor, attributeListPtr,
						certInfoPtr->currentSelection.dnPtr ) == OK_SPECIAL )
				/* We've deleted the attribute containing the currently
				   selected DN, deselect it */
				certInfoPtr->currentSelection.dnPtr = NULL;
		return( CRYPT_OK );
		}
	if( isGeneralNameComponent( certInfoType ) )
		{
		ATTRIBUTE_LIST *attributeListPtr;

		/* Check whether this GeneralName is present */
		status = selectGeneralName( certInfoPtr, CRYPT_ATTRIBUTE_NONE,
									MUST_BE_PRESENT );
		if( cryptStatusError( status ) )
			return( status );

		/* Delete the field within the GeneralName */
		attributeListPtr = findAttributeField( certInfoPtr->attributeCursor,
											   certInfoPtr->attributeCursor->fieldID,
											   certInfoType );
		if( attributeListPtr == NULL )
			return( CRYPT_ERROR_NOTFOUND );
		if( deleteAttributeField( &certInfoPtr->attributes,
						&certInfoPtr->attributeCursor, attributeListPtr,
						certInfoPtr->currentSelection.dnPtr ) == OK_SPECIAL )
			/* We've deleted the attribute containing the currently selected
			   DN, deselect it */
			certInfoPtr->currentSelection.dnPtr = NULL;
		return( CRYPT_OK );
		}
	if( isDNComponent( certInfoType ) )
		{
		status = selectDN( certInfoPtr, CRYPT_ATTRIBUTE_NONE,
						   MUST_BE_PRESENT );
		if( cryptStatusOK( status ) )
			status = deleteDNComponent( certInfoPtr->currentSelection.dnPtr,
										certInfoType, NULL, 0 );
		return( status );
		}

	/* If it's standard cert or CMS attribute, delete it */
	if( ( certInfoType >= CRYPT_CERTINFO_FIRST_EXTENSION && \
		  certInfoType <= CRYPT_CERTINFO_LAST_EXTENSION ) || \
		( certInfoType >= CRYPT_CERTINFO_FIRST_CMS && \
		  certInfoType <= CRYPT_CERTINFO_LAST_CMS ) )
		return( deleteCertattribute( certInfoPtr, certInfoType ) );

	/* If it's anything else, handle it specially */
	switch( certInfoType )
		{
		case CRYPT_CERTINFO_SELFSIGNED:
			if( !( certInfoPtr->flags & CERT_FLAG_SELFSIGNED ) )
				return( CRYPT_ERROR_NOTFOUND );
			certInfoPtr->flags &= ~CERT_FLAG_SELFSIGNED;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_CURRENT_CERTIFICATE:
		case CRYPT_CERTINFO_CURRENT_EXTENSION:
		case CRYPT_CERTINFO_CURRENT_FIELD:
		case CRYPT_CERTINFO_CURRENT_COMPONENT:
			if( certInfoPtr->attributeCursor == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			if( certInfoType == CRYPT_CERTINFO_CURRENT_EXTENSION )
				status = deleteAttribute( &certInfoPtr->attributes,
									&certInfoPtr->attributeCursor,
									certInfoPtr->attributeCursor,
									certInfoPtr->currentSelection.dnPtr );
			else
				/* The current component and field are essentially the
				   same thing since a component is one of a set of
				   entries in a multivalued field, thus they're handled
				   identically */
				status = deleteAttributeField( &certInfoPtr->attributes,
									&certInfoPtr->attributeCursor,
									certInfoPtr->attributeCursor,
									certInfoPtr->currentSelection.dnPtr );
			if( status == OK_SPECIAL )
				/* We've deleted the attribute containing the currently 
				   selected DN, deselect it */
				certInfoPtr->currentSelection.dnPtr = NULL;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_TRUSTED_USAGE:
			if( certInfoPtr->trustedUsage == CRYPT_ERROR )
				return( CRYPT_ERROR_NOTFOUND );
			certInfoPtr->trustedUsage = CRYPT_ERROR;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_TRUSTED_IMPLICIT:
			return( krnlSendMessage( certInfoPtr->ownerHandle,
									 IMESSAGE_SETATTRIBUTE,
									 &certInfoPtr->objectHandle,
									 CRYPT_IATTRIBUTE_CERT_UNTRUSTED ) );

		case CRYPT_CERTINFO_VALIDFROM:
		case CRYPT_CERTINFO_THISUPDATE:
			if( certInfoPtr->startTime <= 0 )
				return( CRYPT_ERROR_NOTFOUND );
			certInfoPtr->startTime = 0;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_VALIDTO:
		case CRYPT_CERTINFO_NEXTUPDATE:
			if( certInfoPtr->endTime <= 0 )
				return( CRYPT_ERROR_NOTFOUND );
			certInfoPtr->endTime = 0;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_SUBJECTNAME:
			if( certInfoPtr->currentSelection.dnPtr == &certInfoPtr->subjectName )
				/* If the DN we're about to delete is currently selected,
				   deselect it */
				certInfoPtr->currentSelection.dnPtr = NULL;
			deleteDN( &certInfoPtr->subjectName );
			return( CRYPT_OK );

		case CRYPT_CERTINFO_REVOCATIONDATE:
			{
			time_t *revocationTimePtr;

			/* If there's a specific invalid/revoked cert selected, delete 
			   its invalidity/revocation time, otherwise if there are 
			   invalid/revoked certs present delete the first cert's 
			   invalidity/revocation time, otherwise delete the default 
			   invalidity/revocation time */
			if( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST || \
				certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE )
				revocationTimePtr = ( certInfoPtr->currentValidity != NULL ) ? \
										&certInfoPtr->currentValidity->invalidityTime : \
									( certInfoPtr->validityInfo != NULL ) ? \
										&certInfoPtr->validityInfo->invalidityTime : \
									( certInfoPtr->revocationTime ) ? \
										&certInfoPtr->revocationTime : NULL;
			else
				revocationTimePtr = ( certInfoPtr->currentRevocation != NULL ) ? \
										&certInfoPtr->currentRevocation->revocationTime : \
									( certInfoPtr->revocations != NULL ) ? \
										&certInfoPtr->revocations->revocationTime : \
									( certInfoPtr->revocationTime ) ? \
										&certInfoPtr->revocationTime : NULL;
			if( revocationTimePtr == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			*revocationTimePtr = 0;
			return( CRYPT_OK );
			}
		}

	/* Everything else is an error */
	assert( NOTREACHED );
	return( CRYPT_ARGERROR_VALUE );
	}
