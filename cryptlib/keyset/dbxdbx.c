/****************************************************************************
*																			*
*							cryptlib DBMS Interface							*
*						Copyright Peter Gutmann 1996-2003					*
*																			*
****************************************************************************/

#include <stdarg.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "dbxdbx.h"
  #include "asn1_rw.h"
  #include "rpc.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../keyset/keyset.h"
  #include "../keyset/dbxdbx.h"
  #include "../misc/asn1_rw.h"
  #include "../misc/rpc.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
  #include "keyset/dbxdbx.h"
  #include "misc/asn1_rw.h"
  #include "misc/rpc.h"
#endif /* Compiler-specific includes */

#ifdef USE_DBMS

/* The table structure for the various DBMS tables is (* = unique, + = cert
   store only):

	CertReq: type, C, SP, L, O, OU, CN, email, certID, certData
	Cert: C, SP, L, O, OU, CN, email, validTo, nameID, issuerID*, keyID*, certID*, certData
	CRL: expiryDate+, nameID+, issuerID*, certID+, certData
	PKIUsers: C, SP, L, O, OU, CN, nameID*, keyID*, certID, certData
	CertLog: action, date, certID*, reqCertID, subjCertID, certData

   Note that in the CRL table the certID is the ID of the cert being
   revoked, not of the per-entry CRL data, and in the  PKIUsers table the
   keyID isn't for a public key but a nonce used to identify the PKI user
   and the nameID is used purely to ensure uniqueness of users.

   The cert store contains a table for logging cert management operations (e.g.
   when issued, when revoked, etc etc).  The operations are tied together by
   the certID of each object, associated with this in the log are optional
   certIDs of the request that caused the action to be taken and the subject
   that was affected by the request.  This allows a complete history of each
   item to be built via the log.  The certLog has a UNIQUE INDEX on the
   certID that detects attempts to add duplicates, although this
   unfortunately requires the addition of dummy nonce certIDs to handle
   certain types of actions that don't produce objects with certIDs.

   The handling for each type of CA management operation is:

	CERTACTION_REQUEST_CERT/CERTACTION_REQUEST_RENEWAL/
	CERTACTION_REQUEST_REVOCATION: Stores the incoming requests and generates
	a log entry.  Duplicate issue requests are detected by the certLog.certID
	uniqueness constraint.  Available: request with certID:

	  INSERT INTO certRequests VALUES ( <type>, <DN components>, <certID>, <request> );
	  INSERT INTO certLog VALUES
		(ACTION_REQUEST_CERT/RENEWAL/REVOCATION, $date, <certID>, NULL, NULL,
		  <request>);

	CERTACTION_ISSUE_CERT/CERTACTION_CERT_CREATION: Add the cert and remove
	the issue request.  Duplicate cert issuance is detected by the
	certLog.certID uniqueness constraint.  Available: request with
	req.certID, certificate with certID

	  INSERT INTO certificates VALUES (<DN components>, <IDs>, <cert>);
	  INSERT INTO certLog VALUES
		(ACTION_ISSUE_CERT/CERT_CREATION, $date, <certID>, <req.certID>, NULL,
		  <cert>);
	  DELETE FROM certRequests WHERE certID = <req.certID>;

	CERTACTION_ISSUE_CRL: Read each CRL entry with caCert.nameID and assemble
	the full CRL.  Requires an ongoing query:

	  SELECT FROM CRLs WHERE nameID = <caCert.nameID>

	CERTACTION_REVOKE_CERT: Add the CRL entry that causes the revocation,
	delete the cert and the request that caused the action.  Available:
	request with req.certID, certificate with cert.certID, CRL entry with
	certID

	  INSERT INTO CRLs VALUES (<IDs>, <crlData>);
	  INSERT INTO certLog VALUES
		(ACTION_REVOKE_CERT, $date, <nonce>, <req.certID>, <cert.certID>, <crlData>);
	  DELETE FROM certRequests WHERE certID = <req.certID>;
	  DELETE FROM certificates WHERE certID = <cert.certID>;

	CERTACTION_EXPIRE_CERT/CERTACTION_RESTART_CLEANUP: Delete each expired
	entry or clean up leftover cert requests after a restart.  The logging
	for these is a bit tricky, ideally we'd want to "INSERT INTO certLog
	VALUES (ACTION_CERT_EXPIRE, $date, SELECT certID FROM certificates WHERE
	validTo <= $date)" or the cleanup equivalent, however this isn't
	possible both because it's not possible to mix static values and a
	select result in an INSERT and because the certID is already present
	from when the cert/request was originally added.  We can fix the former
	by making the static values part of the select result, i.e."INSERT INTO
	certLog VALUES SELECT ACTION_CERT_EXPIRE, $date, certID FROM
	certificates WHERE validTo <= $date" but this still doesn't fix the
	problem with the duplicate IDs.  In fact there isn't really a certID
	present since it's an implicit action, but we can't make the certID
	column null since it's not possible to index nullable columns.  As a
	result the only way we can do it is to repetitively perform 'SELECT
	certID FROM certificates WHERE validTo <= $date' (or the equivalent
	cleanup select) and for each time it succeeds follow it with:

	  INSERT INTO certLog VALUES
		(ACTION_EXPIRE_CERT, $date, <nonce>, NULL, <certID>);
	  DELETE FROM certificates WHERE certID = <certID>

	or

	  INSERT INTO certLog VALUES
		(ACTION_RESTART_CLEANUP, $date, <nonce>, NULL, <certID>);
	  DELETE FROM certRequests WHERE certID = <certID>

	This has the unfortunate side-effect that the update isn't atomic, we
	could enforce this with "LOCK TABLE <name> IN EXCLUSIVE MODE", however
	the MS databases don't support this and either require the use of
	baroque mechanisms such as a "(TABLOCKX HOLDLOCK)" as a locking hint
	after the table name in the first statement after the transaction is
	begun or don't support this type of locking at all.  Because of this it
	isn't really possible to make the update atomic, in particular for the
	cleanup operation we rely on the caller to perform it at startup before
	anyone else accesses the cert store.  The fact that the update isn't
	quite atomic isn't really a major problem, at worst it'll result in
	either an expired cert being visible or a leftover request blocking a
	new request for a split second longer than they should */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Set up key ID information for a query.  There are two variations of
   this, makeKeyID() encodes an existing keyID value and getKeyID() reads an
   attribute from an object and encodes it */

static void makeKeyID( char *keyIDbuffer, const CRYPT_KEYID_TYPE keyIDtype,
					   const void *keyID, const int keyIDlength )
	{
	BYTE hashBuffer[ CRYPT_MAX_HASHSIZE ];
	int idLength = keyIDlength;

	assert( ( keyIDtype == CRYPT_KEYID_NAME || \
			  keyIDtype == CRYPT_KEYID_EMAIL ) || \
			( keyIDtype == CRYPT_IKEYID_KEYID || \
			  keyIDtype == CRYPT_IKEYID_ISSUERID || \
			  keyIDtype == CRYPT_IKEYID_CERTID ) );

	/* Name and email address are used as is */
	if( keyIDtype == CRYPT_KEYID_NAME || \
		keyIDtype == CRYPT_KEYID_EMAIL )
		{
		idLength = min( idLength, ( CRYPT_MAX_TEXTSIZE * 2 ) - 1 );
		memcpy( keyIDbuffer, keyID, idLength );
		keyIDbuffer[ idLength ] = '\0';
		return;
		}

	/* A keyID is just a subjectKeyIdentifier, which is supposed to be an
	   SHA-1 hash anyway but which in practice can be almost anything so we
	   always hash it to a fixed-length value */
	if( keyIDtype == CRYPT_IKEYID_KEYID )
		{
		HASHFUNCTION hashFunction;

		/* Get the hash algorithm information and hash the keyID to get
		   the fixed-length keyID */
		getHashParameters( CRYPT_ALGO_SHA, &hashFunction, NULL );
		hashFunction( NULL, hashBuffer, ( void * ) keyID, keyIDlength,
					  HASH_ALL );
		keyID = hashBuffer;
		idLength = DBXKEYID_SIZE;
		}

	assert( idLength >= DBXKEYID_SIZE );

	/* base64-encode the key ID so that we can use it with database queries.
	   Since we only store 128 bits of a (usually 160 bit) ID to save space
	   (particularly where it's used in indices) and speed lookups, this
	   encoding step has the side-effect of truncating the ID down to the
	   correct size */
	base64encode( keyIDbuffer, keyID, DBXKEYID_SIZE, CRYPT_CERTTYPE_NONE );
	keyIDbuffer[ MAX_ENCODED_DBXKEYID_SIZE ] = '\0';
	}

int getKeyID( char *keyIDbuffer, const CRYPT_HANDLE cryptHandle,
			  const CRYPT_ATTRIBUTE_TYPE keyIDtype )
	{
	BYTE hashBuffer[ CRYPT_MAX_HASHSIZE ];
	int status;

	assert( ( keyIDtype == CRYPT_CERTINFO_FINGERPRINT_SHA || \
			  keyIDtype == CRYPT_IATTRIBUTE_AUTHCERTID ) || \
			( keyIDtype == CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER || \
			  keyIDtype == CRYPT_IATTRIBUTE_ISSUER || \
			  keyIDtype == CRYPT_IATTRIBUTE_SUBJECT || \
			  keyIDtype == CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER || \
			  keyIDtype == CRYPT_IATTRIBUTE_SPKI ) );

	/* Get the attribute from the cert and hash it, unless it's already a
	   hash */
	if( keyIDtype == CRYPT_CERTINFO_FINGERPRINT_SHA || \
		keyIDtype == CRYPT_IATTRIBUTE_AUTHCERTID )
		{
		RESOURCE_DATA msgData;

		setMessageData( &msgData, hashBuffer, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, keyIDtype );
		if( cryptStatusError( status ) )
			return( status );
		assert( msgData.length == KEYID_SIZE );
		}
	else
		{
		DYNBUF idDB;
		HASHFUNCTION hashFunction;
		int hashSize;

		/* Get the attribute data and hash it to get the ID */
		status = dynCreate( &idDB, cryptHandle, keyIDtype );
		if( cryptStatusError( status ) )
			return( status );
		getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
		hashFunction( NULL, hashBuffer, dynData( idDB ), dynLength( idDB ), 
					  HASH_ALL );
		assert( hashSize == KEYID_SIZE );
		dynDestroy( &idDB );
		}

	makeKeyID( keyIDbuffer, CRYPT_IKEYID_CERTID, hashBuffer, KEYID_SIZE );
	return( CRYPT_OK );
	}

/* Get a keyID for a certificate */

int getCertKeyID( char *keyID, const CRYPT_CERTIFICATE iCryptCert )
	{
	int status;

	/* Certificate keyID handling isn't quite as simple as just reading an
	   attribute from the certificate since the subjectKeyIdentifier (if
	   present) may not be the same as the keyID if the cert has come from
	   a CA that does strange things with the sKID.  To resolve this we try
	   and build the key ID from the sKID, if this isn't present we use the
	   keyID (the sKID may have a nonstandard length since it's possible to
	   stuff anything in there, getKeyID() will hash it to the standard size
	   if the length is wrong) */
	status = getKeyID( keyID, iCryptCert,
					   CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );

	/* There's no subjectKeyIdentifier, use the keyID.  Note that we can't
	   just read the CRYPT_IATTRIBUTE_KEYID attribute directly since this
	   may be a data-only cert (either a standalone cert or one from the
	   middle of a chain), so we have to generate it indirectly by hashing
	   the SubjectPublicKeyInfo, which is equivalent to the keyID and is
	   always present in a cert */
	return( getKeyID( keyID, iCryptCert, CRYPT_IATTRIBUTE_SPKI ) );
	}

/* Get names for various items */

char *getKeyName( const CRYPT_KEYID_TYPE keyIDtype )
	{
	switch( keyIDtype )
		{
		case CRYPT_KEYID_NAME:
			return( "CN" );

		case CRYPT_KEYID_EMAIL:
			return( "email" );

		case CRYPT_IKEYID_KEYID:
			return( "keyID" );

		case CRYPT_IKEYID_ISSUERID:
			return( "issuerID" );

		case CRYPT_IKEYID_CERTID:
			return( "certID" );
		}

	assert( NOTREACHED );
	return( "XXXX" );		/* Get rid of compiler warning */
	}

static char *getTableName( const KEYMGMT_ITEM_TYPE itemType )
	{
	switch( itemType )
		{
		case KEYMGMT_ITEM_REQUEST:
			return( "certRequests" );

		case KEYMGMT_ITEM_PKIUSER:
			return( "pkiUsers" );

		case KEYMGMT_ITEM_PUBLICKEY:
			return( "certificates" );

		case KEYMGMT_ITEM_REVOCATIONINFO:
			return( "CRLs" );
		}

	assert( NOTREACHED );
	return( "XXXX" );		/* Get rid of compiler warning */
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

/* Create a new key database */

static int createDatabase( DBMS_INFO *dbmsInfo )
	{
	int updateProgress = 0, status;

	/* Create tables for certs, CRLs, cert requests, PKI users, and CA logs.
	   We use CHAR rather than VARCHAR for the ID fields since these always
	   have a fixed length and CHAR is faster than VARCHAR.  In addition we
	   make as many columns as possible NOT NULL since these fields should
	   always be present, and because this is faster for most databases.  The
	   BLOB type is nonstandard, this is rewritten by the database interface
	   layer to the type which is appropriate for the database */
	status = dbmsStaticUpdate(
			"CREATE TABLE certificates ("
				"C CHAR(2), "
				"SP VARCHAR(64), "
				"L VARCHAR(64), "
				"O VARCHAR(64), "
				"OU VARCHAR(64), "
				"CN VARCHAR(64), "
				"email VARCHAR(64), "
				"validTo DATETIME NOT NULL, "
				"nameID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"issuerID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"keyID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"certID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"certData BLOB NOT NULL)" );
	if( cryptStatusError( status ) )
		return( status );
	if( isCertStore( dbmsInfo ) )
		/* The cert store contains in addition to the other CRL fields the
		   certificate expiry time which is used to remove the entry from
		   the CRL table once the certificate has expired anyway, the nameID
		   which is used to force clustering of entries for each CA, and the
		   ID of the cert being revoked, which isn't available if we're
		   creating it from a raw CRL */
		status = dbmsStaticUpdate(
			"CREATE TABLE CRLs ("
				"expiryDate DATETIME NOT NULL, "
				"nameID CHAR(" TEXT_DBXKEYID_SIZE ") PRIMARY KEY NOT NULL, "
				"issuerID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL,"
				"certID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"certData BLOB NOT NULL)" );
	else
		status = dbmsStaticUpdate(
			"CREATE TABLE CRLs ("
				"issuerID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL,"
				"certData BLOB NOT NULL)" );
	if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
		{
		updateProgress++;
		status = dbmsStaticUpdate(
			"CREATE TABLE pkiUsers ("
				"C CHAR(2), "
				"SP VARCHAR(64), "
				"L VARCHAR(64), "
				"O VARCHAR(64), "
				"OU VARCHAR(64), "
				"CN VARCHAR(64), "
				"nameID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"keyID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"certID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"certData BLOB NOT NULL)" );
		}
	if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
		{
		updateProgress++;
		status = dbmsStaticUpdate(
			"CREATE TABLE certRequests ("
				"type SMALLINT NOT NULL, "
				"C CHAR(2), "
				"SP VARCHAR(64), "
				"L VARCHAR(64), "
				"O VARCHAR(64), "
				"OU VARCHAR(64), "
				"CN VARCHAR(64), "
				"email VARCHAR(64), "
				"certID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"certData BLOB NOT NULL)" );
		}
	if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
		{
		updateProgress++;
		status = dbmsStaticUpdate(
			"CREATE TABLE certLog ("
				"action SMALLINT NOT NULL, "
				"actionTime DATETIME NOT NULL, "
				"certID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
				"reqCertID CHAR(" TEXT_DBXKEYID_SIZE "), "
				"subjCertID CHAR(" TEXT_DBXKEYID_SIZE "), "
				"certData BLOB)" );
		}
	if( cryptStatusError( status ) )
		{
		/* Undo the previous table creations */
		dbmsStaticUpdate( "DROP TABLE certificates" );
		if( updateProgress > 0 )
			dbmsStaticUpdate( "DROP TABLE CRLs" );
		if( updateProgress > 1 )
			dbmsStaticUpdate( "DROP TABLE pkiUsers" );
		if( updateProgress > 2 )
			dbmsStaticUpdate( "DROP TABLE certRequests" );
		return( status );
		}

	/* Create an index for the email address, nameID, issuerID, keyID, and
	   certID in the certificates table, the issuerID and certID in the CRLs
	   table (the CRL nameID isn't indexed since we only use it for linear
	   scans, however it's designated the primary key to ensure that rows are
	   clustered around it), the nameID and keyID in the PKI users table (the
	   former isn't used but is made a UNIQUE INDEX to ensure that the same 
	   entry can't be added more than once) and the certID in the cert log 
	   (this also isn't used but is made a UNIQUE INDEX to ensure that the 
	   same entry can't be added more than once).  We have to give these 
	   unique names since some databases don't allow two indexes to have the 
	   same name, even if they're in a different table.  Since most of the 
	   fields in the tables are supposed to be unique, we can specify this 
	   for the indexes we're creating, however we can't do it for the email 
	   address or the nameID in the certs table since there could be multiple 
	   certs present that differ only in key usage.  We don't index the other 
	   tables since indexes consume space and we don't expect to access any 
	   of these much */
	status = dbmsStaticUpdate(
			"CREATE INDEX emailIdx ON certificates(email)" );
	if( cryptStatusOK( status ) )
		status = dbmsStaticUpdate(
			"CREATE INDEX nameIDIdx ON certificates(nameID)" );
	if( cryptStatusOK( status ) )
		status = dbmsStaticUpdate(
			"CREATE UNIQUE INDEX issuerIDIdx ON certificates(issuerID)" );
	if( cryptStatusOK( status ) )
		status = dbmsStaticUpdate(
			"CREATE UNIQUE INDEX keyIDIdx ON certificates(keyID)" );
	if( cryptStatusOK( status ) )
		status = dbmsStaticUpdate(
			"CREATE UNIQUE INDEX certIDIdx ON certificates(certID)" );
	if( cryptStatusOK( status ) )
		status = dbmsStaticUpdate(
			"CREATE UNIQUE INDEX crlIssuerIDIdx ON CRLs (issuerID)" );
	if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
		status = dbmsStaticUpdate(
			"CREATE UNIQUE INDEX crlCertIDIdx ON CRLs (certID)" );
	if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
		status = dbmsStaticUpdate(
			"CREATE UNIQUE INDEX userKeyIDIdx ON pkiUsers (keyID)" );
	if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
		status = dbmsStaticUpdate(
			"CREATE UNIQUE INDEX userNameIDIdx ON pkiUsers (nameID)" );
	if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
		status = dbmsStaticUpdate(
			"CREATE UNIQUE INDEX logCertIDIdx ON certLog (certID)" );
	if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
		{
		char dummyCertID[ DBXKEYID_BUFFER_SIZE ];

		/* Create a special dummy certID with an out-of-band value to mark
		   the first entry in the log */
		memset( dummyCertID, '-', MAX_ENCODED_DBXKEYID_SIZE );
		dummyCertID[ MAX_ENCODED_DBXKEYID_SIZE - 1 ] = '\0';

		/* Add the initial log entry recording the creation of the log */
		status = updateCertLog( dbmsInfo, CRYPT_CERTACTION_CREATE,
								dummyCertID, NULL, NULL, NULL, 0,
								DBMS_UPDATE_NORMAL );
		}
	if( cryptStatusError( status ) )
		{
		/* Undo the creation of the various tables */
		dbmsStaticUpdate( "DROP TABLE certificates" );
		dbmsStaticUpdate( "DROP TABLE CRLs" );
		if( isCertStore( dbmsInfo ) )
			{
			dbmsStaticUpdate( "DROP TABLE pkiUsers" );
			dbmsStaticUpdate( "DROP TABLE certRequests" );
			dbmsStaticUpdate( "DROP TABLE certLog" );
			}
		return( CRYPT_ERROR_WRITE );
		}

	return( CRYPT_OK );
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
   the query */

int getItemData( DBMS_INFO *dbmsInfo, CRYPT_CERTIFICATE *iCertificate,
				 int *stateInfo, const char *keyName, const char *keyValue,
				 const KEYMGMT_ITEM_TYPE itemType, const int options )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	const BOOLEAN multiCertQuery = ( options & KEYMGMT_MASK_USAGEOPTIONS ) ? \
								   TRUE : FALSE;
	const DBMS_QUERY_TYPE queryType = \
					( stateInfo == NULL || multiCertQuery ) ? \
					DBMS_QUERY_CONTINUE : DBMS_QUERY_NORMAL;
	BYTE certificate[ MAX_CERT_SIZE ];
	BOOLEAN continueFetch;
	char keyBuffer[ MAX_QUERY_RESULT_SIZE ], *keyPtr = keyBuffer;
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ], *sqlBufPtr = NULL;
	int keyLength, status;

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
		( !memcmp( keyValue, "--", 2 ) || !memcmp( keyValue, "++", 2 ) ) )
		/* Eheu, litteras istas reperire non possum */
		return( CRYPT_ERROR_NOTFOUND );

	/* If we have binary blob support, fetch the data directly into the
	   certificate buffer */
	if( hasBinaryBlobs( dbmsInfo ) )
		keyPtr = ( char * ) certificate;

	/* If this isn't an ongoing fetch from a query submitted earlier, prepare
	   and submit the query to fetch the data */
	if( stateInfo != NULL )
		{
		dbmsFormatSQL( sqlBuffer,
			"SELECT certData FROM $ WHERE $ = '$'",
					   getTableName( itemType ), keyName, keyValue );
		if( multiCertQuery )
			{
			/* We're fetching a collection of certs in order to pick out the
			   one that we want, submit the query to start the fetch */
			status = dbmsQuery( sqlBuffer, NULL, NULL, 0, DBMS_QUERY_START );
			if( cryptStatusError( status ) )
				return( status );
			}
		else
			/* It's a point query, submit it as we do the fetch */
			sqlBufPtr = sqlBuffer;
		}

	do
		{
		/* Retrieve the record and base64-decode the binary cert data if
		   necessary */
		status = dbmsQuery( sqlBufPtr, keyPtr, &keyLength, 0, queryType );
		if( cryptStatusOK( status ) && !hasBinaryBlobs( dbmsInfo ) )
			{
			keyLength = base64decode( certificate, keyBuffer, keyLength,
									  CRYPT_CERTFORMAT_NONE );
			if( !keyLength )
				status = CRYPT_ERROR_BADDATA;
			}
		if( cryptStatusError( status ) )
			/* Convert the error code to a more appropriate value if
			   appropriate */
			return( ( multiCertQuery && ( status == CRYPT_ERROR_COMPLETE ) ) ? \
					CRYPT_ERROR_NOTFOUND : status );

		/* If the first byte of the cert data is 0xFF, this is an item which
		   is physically but not logically present (see the comment above in
		   the check for the keyValue), which means we can't explicitly fetch
		   it.  If it's a point query this means we didn't find anything,
		   otherwise we try again with the next result */
		if( certificate[ 0 ] == 0xFF )
			{
			if( sqlBufPtr == sqlBuffer )
				/* Point query, we found something but it isn't there.
				   "Can't you understand English you arse, we're not at home"
				   -- Jeremy Black, "The Boys from Brazil" */
				return( CRYPT_ERROR_NOTFOUND );
			continueFetch = TRUE;
			}
		else
			/* If more than one cert is present and the requested key usage
			   doesn't match the one indicated in the cert, try again */
			if( multiCertQuery && \
				!checkCertUsage( certificate, keyLength, options ) )
				continueFetch = TRUE;
			else
				/* We got what we wanted, exit */
				continueFetch = FALSE;
		}
	while( continueFetch );

	/* If we've been looking through multiple certs, cancel the outstanding
	   query, which is still in progress */
	if( multiCertQuery )
		dbmsStaticQuery( NULL, DBMS_QUERY_CANCEL );

	/* Create a certificate object from the encoded cert.  If we're reading 
	   revocation information the data is a single CRL entry so we have to 
	   tell the cert import code to treat it as a special case of a CRL.  If
	   we're reading a request, it could be one of several types so we have
	   to use autodetection rather than specifying an exact format */
	setMessageCreateObjectIndirectInfo( &createInfo, certificate, keyLength,
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
	   to so we can fetch the next cert in the sequence */
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
	char keyIDbuffer[ CRYPT_MAX_TEXTSIZE * 2 ];
	int status;

	/* If it's a general query, submit the query to the database */
	if( stateInfo == NULL )
		{
		char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
		int sqlLength;

		assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
				itemType == KEYMGMT_ITEM_REQUEST );
		assert( options == KEYMGMT_FLAG_NONE );

		if( keyIDlength > MAX_SQL_QUERY_SIZE - 64 )
			return( CRYPT_ARGERROR_STR1 );

		/* If we're cancelling an existing query, pass it on down */
		if( keyIDlength == 6 && !strCompare( keyID, "cancel", keyIDlength ) )
			{
			status = dbmsStaticQuery( NULL, DBMS_QUERY_CANCEL );
			return( status );
			}

		assert( !keysetInfo->isBusyFunction( keysetInfo ) );

		/* Rewrite the user-supplied portion of the query using the actual
		   column names and append it to the SELECT statement */
		dbmsFormatSQL( sqlBuffer,
			"SELECT certData FROM $ WHERE ",
					   getTableName( itemType ) );
		sqlLength = strlen( sqlBuffer );
		dbmsFormatQuery( sqlBuffer + sqlLength, keyID, keyIDlength,
						 ( MAX_SQL_QUERY_SIZE - 1 ) - sqlLength );
		return( dbmsStaticQuery( sqlBuffer, DBMS_QUERY_START ) );
		}

	/* Fetch the first data item */
	makeKeyID( keyIDbuffer, keyIDtype, keyID, keyIDlength );
	return( getItemData( dbmsInfo, iCertificate, stateInfo,
						 getKeyName( keyIDtype ), keyIDbuffer, itemType,
						 options ) );
	}

static int getNextItemFunction( KEYSET_INFO *keysetInfo,
								CRYPT_CERTIFICATE *iCertificate,
								int *stateInfo, const int options )
	{
	DBMS_INFO *dbmsInfo = keysetInfo->keysetDBMS;

	/* If we're fetching the next cert in a sequence based on externally-held
	   state information, set the key ID to the nameID of the previous cert's
	   issuer */
	if( stateInfo != NULL )
		{
		char keyIDbuffer[ CRYPT_MAX_TEXTSIZE * 2 ];
		const int status = getKeyID( keyIDbuffer, *stateInfo,
									 CRYPT_IATTRIBUTE_ISSUER );
		if( cryptStatusError( status ) )
			return( status );
		return( getItemData( dbmsInfo, iCertificate, stateInfo, "nameID",
							 keyIDbuffer, KEYMGMT_ITEM_PUBLICKEY, options ) );
		}

	/* Fetch the next data item in an ongoing query */
	return( getItemData( dbmsInfo, iCertificate, NULL, NULL,
						 NULL, KEYMGMT_ITEM_NONE, options ) );
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
			char keyIDbuffer[ DBXKEYID_BUFFER_SIZE ];

			assert( keyIDtype == CRYPT_IKEYID_CERTID );
			assert( isCertStore( dbmsInfo ) );

			/* The information required to locate the PKI user from one of 
			   their certs is only present in a cert store */
			if( !isCertStore( dbmsInfo ) )
				return( CRYPT_ERROR_NOTFOUND );

			/* Get the PKI user based on the cert */
			makeKeyID( keyIDbuffer, CRYPT_IKEYID_CERTID, keyID, 
					   keyIDlength );
			return( caGetIssuingUser( dbmsInfo, iCryptHandle, 
									  keyIDbuffer ) );
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
		char keyIDbuffer[ DBXKEYID_BUFFER_SIZE ];
		char sqlBuffer[ MAX_SQL_QUERY_SIZE ];

		assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
				itemType == KEYMGMT_ITEM_REVOCATIONINFO );
		assert( keyIDlength == KEYID_SIZE );
		assert( keyIDtype == CRYPT_IKEYID_ISSUERID || \
				keyIDtype == CRYPT_IKEYID_CERTID );

		/* Check whether this item is present.  We don't care about the
		   result, all we want to know is whether it's there or not, so we
		   just do a check rather than a fetch of any data */
		makeKeyID( keyIDbuffer, keyIDtype, keyID, KEYID_SIZE );
		dbmsFormatSQL( sqlBuffer,
			"SELECT certData FROM $ WHERE $ = '$'",
					   getTableName( itemType ), getKeyName( keyIDtype ),
					   keyIDbuffer );
		return( dbmsStaticQuery( sqlBuffer, DBMS_QUERY_CHECK ) );
		}

	/* Import the cert by doing an indirect read, which fetches either a
	   single cert or an entire chain if it's present */
	status = iCryptImportCertIndirect( iCryptHandle, keysetInfo->objectHandle,
									   keyIDtype, keyID, keyIDlength,
									   flags & KEYMGMT_MASK_CERTOPTIONS );
	return( status );
	}

/* Add a certificate object to a database.  Normally RDBMS' would allow
   existing rows to be overwritten, but the UNIQUE constraint on the indices
   will catch this */

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
		 email[ CRYPT_MAX_TEXTSIZE + 1 ];
	time_t boundDate = 0;
	int certDataLength, status;

	assert( certType == CRYPT_CERTTYPE_CERTIFICATE || \
			certType == CRYPT_CERTTYPE_REQUEST_CERT || \
			certType == CRYPT_CERTTYPE_PKIUSER );

	*C = *SP = *L = *O = *OU = *CN = *email = '\0';

	/* Extract the DN and altName components.  This changes the currently
	   selected DN components, but this is OK since we've got the cert
	   locked and the prior state will be restored when we unlock it */
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
		setMessageData( &msgData, CN, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S, 
							&msgData, CRYPT_CERTINFO_COMMONNAME );
		if( cryptStatusOK( status ) )
			CN[ msgData.length ] = '\0';
		else
			if( status == CRYPT_ERROR_NOTFOUND )
				/* It's possible (although highly unlikely) that a
				   certificate won't have a CN, in which case we use the OU
				   instead.  If that also fails, we use the O.  This gets a
				   bit messy, but duplicating the OU/O into the CN seems to
				   be the best way to handle this */
				strcpy( CN, *OU ? OU : O );
		}
	if( ( cryptStatusOK( status ) || status == CRYPT_ERROR_NOTFOUND ) && \
		( certType != CRYPT_CERTTYPE_PKIUSER ) )
		{
		static const int value = CRYPT_CERTINFO_SUBJECTALTNAME;

		setMessageData( &msgData, email, CRYPT_MAX_TEXTSIZE );
		krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE, 
						 ( void * ) &value, CRYPT_CERTINFO_CURRENT_FIELD );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S, 
							&msgData, CRYPT_CERTINFO_RFC822NAME );
		if( cryptStatusOK( status ) )
			email[ msgData.length ] = '\0';
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
		if( cryptStatusOK( status ) )
			status = getKeyID( issuerID, iCryptHandle,
							   CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
		if( cryptStatusOK( status ) )
			status = getCertKeyID( keyID, iCryptHandle );
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

			length = decodePKIUserValue( binaryKeyID, encKeyID, msgData.length );
			makeKeyID( keyID, CRYPT_IKEYID_KEYID, binaryKeyID, length );
			}
		if( cryptStatusOK( status ) )
			status = getKeyID( nameID, iCryptHandle, CRYPT_IATTRIBUTE_SUBJECT );
		}
	if( cryptStatusOK( status ) )
		status = getKeyID( certID, iCryptHandle, 
						   CRYPT_CERTINFO_FINGERPRINT_SHA );
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
		const char ch = ( addType == CERTADD_PARTIAL ) ? '-' : '+';

		certData[ 0 ] = 0xFF;
		issuerID[ 0 ] = issuerID[ 1 ] = ch;
		keyID[ 0 ] = keyID[ 1 ] = ch;
		certID[ 0 ] = certID[ 1 ] = ch;
		}

	/* Set up the cert object data to write */
	if( !hasBinaryBlobs( dbmsInfo ) )
		{
		char encodedCertData[ MAX_ENCODED_CERT_SIZE ];

		base64encode( encodedCertData, certData, certDataLength,
					  CRYPT_CERTTYPE_NONE );
		if( certType == CRYPT_CERTTYPE_CERTIFICATE )
			dbmsFormatSQL( sqlBuffer,
			"INSERT INTO certificates VALUES ('$', '$', '$', '$', '$', '$', "
											 "'$', ?, '$', '$', '$', '$', '$')",
						   C, SP, L, O, OU, CN, email, nameID, issuerID,
						   keyID, certID, encodedCertData );
		else
			if( certType == CRYPT_CERTTYPE_REQUEST_CERT )
				dbmsFormatSQL( sqlBuffer,
			"INSERT INTO certRequests VALUES ('" TEXT_CERTTYPE_REQUEST_CERT "', "
											 "'$', '$', '$', '$', '$', '$', "
											 "'$', '$', '$')",
							   C, SP, L, O, OU, CN, email, certID,
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
						   C, SP, L, O, OU, CN, email, nameID, issuerID,
						   keyID, certID );
		else
			if( certType == CRYPT_CERTTYPE_REQUEST_CERT )
				dbmsFormatSQL( sqlBuffer,
			"INSERT INTO certRequests VALUES ('" TEXT_CERTTYPE_REQUEST_CERT "', "
											 "'$', '$', '$', '$', '$', '$', "
											 "'$', '$', ?)",
							   C, SP, L, O, OU, CN, email, certID );
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
	if( cryptStatusOK( status ) )
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
		if( cryptStatusOK( status ) )
			status = getKeyID( nameID, iCryptRevokeCert,
							   CRYPT_IATTRIBUTE_ISSUER );
		if( cryptStatusOK( status ) )
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

		base64encode( encodedCertData, certData, certDataLength,
					  CRYPT_CERTTYPE_NONE );
		if( isCertStore( dbmsInfo ) )
			dbmsFormatSQL( sqlBuffer,
			"INSERT INTO CRLs VALUES (?, '$', '$', '$', '$')",
						   nameID, issuerID, certID, encodedCertData );
		else
			dbmsFormatSQL( sqlBuffer,
			"INSERT INTO CRLs VALUES ('$', '$')",
						   issuerID, encodedCertData );
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
		/* We reached the end of the chain/CRL without finding anything we
		   could add, return a data duplicate error */
		status = CRYPT_ERROR_DUPLICATE;

	return( status );
	}

/* Delete a record from the database */

static int deleteItemFunction( KEYSET_INFO *keysetInfo,
							   const KEYMGMT_ITEM_TYPE itemType,
							   const CRYPT_KEYID_TYPE keyIDtype,
							   const void *keyID, const int keyIDlength )
	{
	DBMS_INFO *dbmsInfo = keysetInfo->keysetDBMS;
	char keyIDbuffer[ CRYPT_MAX_TEXTSIZE * 2 ];
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];

	assert( itemType == KEYMGMT_ITEM_PUBLICKEY );
	assert( !isCertStore( dbmsInfo ) );

	/* Delete the key from the database */
	makeKeyID( keyIDbuffer, keyIDtype, keyID, keyIDlength );
	dbmsFormatSQL( sqlBuffer,
			"DELETE FROM certificates WHERE $ = '$'",
				   getKeyName( keyIDtype ), keyIDbuffer );
	return( dbmsStaticUpdate( sqlBuffer ) );
	}

/* Return status info for the keyset */

static BOOLEAN isBusyFunction( KEYSET_INFO *keysetInfo )
	{
	return( ( keysetInfo->keysetDBMS->flags & \
			  ( DBMS_FLAG_UPDATEACTIVE | DBMS_FLAG_QUERYACTIVE ) ) ? \
			  TRUE : FALSE );
	}

/* Open a connection to a database */

static int initFunction( KEYSET_INFO *keysetInfo, const char *name,
						 const CRYPT_KEYOPT_TYPE options )
	{
	DBMS_INFO *dbmsInfo = keysetInfo->keysetDBMS;
	int status;

	/* Perform a database back-end specific open */
	status = dbmsOpen( name, ( options == CRYPT_KEYOPT_READONLY ) ? \
					   options : CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		endDbxSession( keysetInfo );
		return( status );
		}

	/* If we're being asked to create a new database, create it and exit */
	if( options == CRYPT_KEYOPT_CREATE )
		{
		status = createDatabase( dbmsInfo );
		if( cryptStatusOK( status ) && isCertStore( dbmsInfo ) )
			status = updateCertLog( dbmsInfo, CRYPT_CERTACTION_CONNECT,
									NULL, NULL, NULL, NULL, 0,
									DBMS_UPDATE_NORMAL );
		if( cryptStatusError( status ) )
			{
			dbmsClose();
			endDbxSession( keysetInfo );
			}
		return( status );
		}

	/* Check to see whether it's a cert store.  We do this by checking for
	   the presence of the cert store creation entry in the log, this is
	   always present with an action value of CRYPT_CERTACTION_CREATE */
	status = dbmsStaticQuery(
			"SELECT certData FROM certLog WHERE action = "
				TEXT_CERTACTION_CREATE,
							  DBMS_QUERY_CHECK );
	if( cryptStatusOK( status ) )
		{
		/* It's a cert store, if we're opening it as a non-cert-store it has
		   to be in read-only mode.  We return an error rather than quietly
		   changing the access mode to read-only both to make it explicit to
		   the user at open time that they can't make changes and because we
		   need to have the read-only flag set when we open the database to
		   optimise the buffering and locking strategy, setting it at this
		   point is too late */
		if( !isCertStore( dbmsInfo ) )
			{
			if( options != CRYPT_KEYOPT_READONLY )
				{
				dbmsClose();
				endDbxSession( keysetInfo );
				status = CRYPT_ERROR_PERMISSION;
				}

			/* Remember that even though it's not functioning as a cert
			   store, we can still perform some extended queries on it based
			   on fields that are only present in cert stores */
			dbmsInfo->flags |= DBMS_FLAG_CERTSTORE_FIELDS;

			return( status );
			}

		/* If this isn't a read-only open then record a connection to the
		   store */
		if( options != CRYPT_KEYOPT_READONLY )
			{
			status = updateCertLog( dbmsInfo, CRYPT_CERTACTION_CONNECT,
									NULL, NULL, NULL, NULL, 0,
									DBMS_UPDATE_NORMAL );
			if( cryptStatusError( status ) )
				{
				dbmsClose();
				endDbxSession( keysetInfo );
				}
			}

		return( status );
		}

	/* It's not a cert store, if we're expecting to open it as one tell the
	   caller */
	if( isCertStore( dbmsInfo ) )
		{
		dbmsClose();
		endDbxSession( keysetInfo );
		return( CRYPT_ARGERROR_NUM1 );
		}

	/* Since the failure of the query above will set the extended error
	   information, we have to explicitly clear it here to avoid making the
	   (invisible) query side-effects visible to the user */
	dbmsInfo->errorCode = 0;
	memset( dbmsInfo->errorMessage, 0, MAX_ERRMSG_SIZE );

	return( CRYPT_OK );
	}

/* Close the connection to a database */

static void shutdownFunction( KEYSET_INFO *keysetInfo )
	{
	DBMS_INFO *dbmsInfo = keysetInfo->keysetDBMS;

	/* If it's a cert store opened in read/write mode, record a closed
	   connection to the store */
	if( isCertStore( dbmsInfo ) && \
		keysetInfo->options != CRYPT_KEYOPT_READONLY )
		updateCertLog( dbmsInfo, CRYPT_CERTACTION_DISCONNECT, NULL, NULL,
					   NULL, NULL, 0, DBMS_UPDATE_NORMAL );

	/* If we're in the middle of a query, cancel it */
	if( dbmsInfo->flags & DBMS_FLAG_QUERYACTIVE )
		dbmsStaticQuery( NULL, DBMS_QUERY_CANCEL );

	dbmsClose();
	endDbxSession( keysetInfo );
	}

/* Set up the function pointers to the keyset methods */

int setAccessMethodDBMS( KEYSET_INFO *keysetInfo,
						 const CRYPT_KEYSET_TYPE type )
	{
	int status = CRYPT_ERROR;

	/* Set up the lower-level interface functions */
	status = initDbxSession( keysetInfo, type );
	if( cryptStatusError( status ) )
		return( status );

	/* Set the access method pointers */
	keysetInfo->initFunction = initFunction;
	keysetInfo->shutdownFunction = shutdownFunction;
	keysetInfo->getItemFunction = getItemFunction;
	keysetInfo->setItemFunction = setItemFunction;
	keysetInfo->deleteItemFunction = deleteItemFunction;
	keysetInfo->getFirstItemFunction = getFirstItemFunction;
	keysetInfo->getNextItemFunction = getNextItemFunction;
	if( type == CRYPT_KEYSET_ODBC_STORE || \
		type == CRYPT_KEYSET_DATABASE_STORE || \
		type == CRYPT_KEYSET_PLUGIN_STORE )
		initDBMSCA( keysetInfo );
	keysetInfo->isBusyFunction = isBusyFunction;

	return( CRYPT_OK );
	}
#endif /* USE_DBMS */
