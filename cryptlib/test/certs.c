/****************************************************************************
*																			*
*					cryptlib Certificate Handling Test Routines				*
*						Copyright Peter Gutmann 1997-2004					*
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

/* Certificate times.  Unlike every other system on the planet, the Mac
   takes the time_t epoch as 1904 rather than 1970 (even VMS, MVS, VM/CMS,
   the AS/400, Tandem NSK, and God knows what other sort of strangeness
   stick to 1970 as the time_t epoch).  ANSI and ISO C are very careful to
   avoid specifying what the epoch actually is, so it's legal to do this in
   the same way that it's legal for Microsoft to break Kerberos because the
   standard doesn't say they can't */

#if defined( __MWERKS__ ) || defined( SYMANTEC_C ) || defined( __MRC__ )
  #define CERTTIME_DATETEST	( 0x38000000L + 2082844800L )
  #define CERTTIME_Y2KTEST	( 0x46300C01L + 2082844800L )
#else
  #define CERTTIME_DATETEST	0x38000000L
  #define CERTTIME_Y2KTEST	0x46300C01L
#endif /* Macintosh-specific weird epoch */

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Set the trust setting for the root CA in a cert chain.  This is required
   for the self-test in order to allow signature checks for chains signed by
   arbitrary CAs to work */

static int setRootTrust( const CRYPT_CERTIFICATE cryptCertChain,
						 BOOLEAN *oldTrustValue, 
						 const BOOLEAN newTrustValue )
	{
	int status;

	status = cryptSetAttribute( cryptCertChain, 
								CRYPT_CERTINFO_CURRENT_CERTIFICATE,
								CRYPT_CURSOR_LAST );
	if( cryptStatusError( status ) )
		return( status );
	if( oldTrustValue != NULL )
		cryptGetAttribute( cryptCertChain, CRYPT_CERTINFO_TRUSTED_IMPLICIT, 
						   oldTrustValue );
	return( cryptSetAttribute( cryptCertChain, 
							   CRYPT_CERTINFO_TRUSTED_IMPLICIT, 
							   newTrustValue ) );
	}

/****************************************************************************
*																			*
*						Certificate Creation Routines Test					*
*																			*
****************************************************************************/

BYTE FAR_BSS certBuffer[ BUFFER_SIZE ];
int certificateLength;

/* Create a series of self-signed certs */

static const CERT_DATA certData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Smith" ) },

	/* Self-signed X.509v3 certificate (technically it'd be an X.509v1, but
	   cryptlib automatically adds some required standard attributes so it
	   becomes an X.509v3 cert) */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testCert( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int value, status;

#if defined( _MSC_VER ) && ( _MSC_VER <= 800 )
	time_t testTime = time( NULL ), newTime;

	newTime = mktime( localtime( &testTime ) );
	if( newTime == testTime )
		{
		puts( "Illogical local/GMT time detected.  VC++ 1.5x occasionally "
			  "exhibits a bug in\nits time zone handling in which it thinks "
			  "that the local time zone is GMT and\nGMT itself is some "
			  "negative offset from the current time.  This upsets\n"
			  "cryptlibs certificate date validity checking, since "
			  "certificates appear to\nhave inconsistent dates.  Deleting "
			  "all the temporary files and rebuilding\ncryptlib after "
			  "restarting your machine may fix this.\n" );
		return( FALSE );
		}
#endif /* VC++ 1.5 bug check */

	puts( "Testing certificate creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certificate components */
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSetAttribute()", status,
							   __LINE__ ) );
	if( !addCertFields( cryptCert, certData ) )
		return( FALSE );

	/* Delete a component and replace it with something else */
	status = cryptDeleteAttribute( cryptCert, CRYPT_CERTINFO_COMMONNAME );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptDeleteAttribute()", status,
							   __LINE__ ) );
	cryptSetAttributeString( cryptCert,
				CRYPT_CERTINFO_COMMONNAME, TEXT( "Dave Taylor" ), 
				paramStrlen( TEXT( "Dave Taylor" ) ) );

	/* Sign the certificate and print information on what we got */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSignCert()", status,
							   __LINE__ ) );
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Check the signature.  Since it's self-signed, we don't need to pass in
	   a signature check key */
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );

	/* Set the cert usage to untrusted for any purpose, which should result
	   in the signature check failing */
	cryptSetAttribute( cryptCert, CRYPT_CERTINFO_TRUSTED_USAGE,
					   CRYPT_KEYUSAGE_NONE );
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		{
		puts( "Untrusted cert signature check succeeded, should have "
			  "failed." );
		return( FALSE );
		}
	cryptDeleteAttribute( cryptCert, CRYPT_CERTINFO_TRUSTED_USAGE );

	/* Export the cert.  We perform a length check using a null buffer to
	   make sure that this facility is working as required */
	status = cryptExportCert( NULL, 0, &value, CRYPT_CERTFORMAT_CERTIFICATE,
							  cryptCert );
	if( cryptStatusOK( status ) )
		status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
								  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptExportCert()", status,
							   __LINE__ ) );
	if( value != certificateLength )
		{
		puts( "Exported certificate size != actual data size." );
		return( FALSE );
		}
	printf( "Exported certificate is %d bytes long.\n", certificateLength );
	debugDump( "cert", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	puts( "Certificate creation succeeded.\n" );
	return( TRUE );
	}

static const CERT_DATA cACertData[] = {
	/* Identification information.  Note the non-heirarchical order of the
	   components to test the automatic arranging of the DN */
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers and CA" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Himself" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Certification Division" ) },
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },

	/* Self-signed X.509v3 certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	/* Start date set to a fixed value to check for problems in date/time
	   conversion routines, expiry date set to > Y2K (with the start date set
	   to before Y2K) to test for Y2K problems */
	{ CRYPT_CERTINFO_VALIDFROM, IS_TIME, 0, NULL, CERTTIME_DATETEST },
	{ CRYPT_CERTINFO_VALIDTO, IS_TIME, 0, NULL, CERTTIME_Y2KTEST },

	/* CA extensions.  Policies are very much CA-specific and currently
	   undefined, so we use a dummy OID for a nonexistant private org for
	   now */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_CERTPOLICYID, IS_STRING, 0, TEXT( "1 3 6 1 4 1 9999 1" ) },
		/* Blank line needed due to bug in Borland C++ parser */
	{ CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT, IS_STRING, 0, TEXT( "This policy isn't worth the paper it's not printed on." ) },
	{ CRYPT_CERTINFO_CERTPOLICY_ORGANIZATION, IS_STRING, 0, TEXT( "Honest Joe's used cars and certification authority" ) },
	{ CRYPT_CERTINFO_CERTPOLICY_NOTICENUMBERS, IS_NUMERIC, 1 },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testCACert( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	time_t startTime, endTime;
	int value, status;

	puts( "Testing CA certificate creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certificate components */
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSetAttribute()", status,
							   __LINE__ ) );
	if( !addCertFields( cryptCert, cACertData ) )
		return( FALSE );

	/* Sign the certificate and print information on what we got */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSignCert()", status,
							   __LINE__ ) );
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Export the cert, this time with base64 encoding to make sure that 
	   this works.  As before, we perform a length check using a null 
	   buffer to make sure that this facility is working as required */
	status = cryptExportCert( NULL, 0, &value,
							  CRYPT_CERTFORMAT_TEXT_CERTIFICATE, cryptCert );
	if( cryptStatusOK( status ) )
		status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
								  CRYPT_CERTFORMAT_TEXT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptExportCert()", status,
							   __LINE__ ) );
	if( value != certificateLength )
		{
		puts( "Exported certificate size != actual data size." );
		return( FALSE );
		}
	printf( "Exported certificate is %d bytes long.\n", certificateLength );
	debugDump( "cacert", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created.  We make the second 
	   parameter to the check function the cert (rather than CRYPT_UNUSED as 
	   done for the basic self-signed cert) to check that this option works 
	   as required */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, cryptCert );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );
	status = cryptGetAttributeString( cryptCert, CRYPT_CERTINFO_VALIDFROM,
									  &startTime, &value );
	if( cryptStatusOK( status ) )
		status = cryptGetAttributeString( cryptCert, CRYPT_CERTINFO_VALIDTO,
										  &endTime, &value );
	if( cryptStatusError( status ) )
		{
		printf( "Cert time read failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	if( startTime != CERTTIME_DATETEST )
		{
		printf( "Warning: cert start time is wrong, got %lX, should be "
				"%lX.\n         This is probably due to problems in the "
				"system time handling routines.\n",
				startTime, CERTTIME_DATETEST );
		}
	if( endTime != CERTTIME_Y2KTEST )
		printf( "Warning: cert end time is wrong, got %lX, should be "
				"%lX.\n         This is probably due to problems in the "
				"system time handling routines.\n",
				endTime, CERTTIME_Y2KTEST );
	cryptDestroyCert( cryptCert );
#if defined( __WINDOWS__ ) || defined( __linux__ ) || defined( sun )
	if( ( startTime != CERTTIME_DATETEST && \
		  ( startTime - CERTTIME_DATETEST != 3600 && \
			startTime - CERTTIME_DATETEST != -3600 ) ) || \
		( endTime != CERTTIME_Y2KTEST && \
		  ( endTime - CERTTIME_Y2KTEST != 3600 && \
			endTime - CERTTIME_Y2KTEST != -3600 ) ) )
		/* If the time is off by exactly one hour this isn't a problem
		   because the best we can do is get the time adjusted for DST
		   now rather than DST when the cert was created, a problem that
		   is more or less undecidable.  In addition we don't automatically
		   abort for arbitrary systems since date problems usually arise
		   from incorrectly configured time zone info or bugs in the system
		   date-handling routines or who knows what, aborting on every
		   random broken system would lead to a flood of unnecessary "bug"
		   reports */
		return( FALSE );
#endif /* System with known-good time handling */

	/* Clean up */
	puts( "CA certificate creation succeeded.\n" );
	return( TRUE );
	}

static const CERT_DATA xyzzyCertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Smith" ) },

	/* XYZZY certificate */
	{ CRYPT_CERTINFO_XYZZY, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testXyzzyCert( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int status;

	puts( "Testing XYZZY certificate creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certificate components */
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSetAttribute()", status,
							   __LINE__ ) );
	if( !addCertFields( cryptCert, xyzzyCertData ) )
		return( FALSE );

	/* Sign the certificate and print information on what we got */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSignCert()", status,
							   __LINE__ ) );
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Check the signature.  Since it's self-signed, we don't need to pass in
	   a signature check key */
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );

	/* Export the cert */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptExportCert()", status,
							   __LINE__ ) );
	printf( "Exported certificate is %d bytes long.\n", certificateLength );
	debugDump( "certxy", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	puts( "XYZZY certificate creation succeeded.\n" );
	return( TRUE );
	}

#ifdef HAS_WIDECHAR

static const wchar_t unicodeStr[] = {
	0x0414, 0x043E, 0x0432, 0x0435, 0x0440, 0x044F, 0x0439, 0x002C, 
	0x0020, 0x043D, 0x043E, 0x0020, 0x043F, 0x0440, 0x043E, 0x0432, 
	0x0435, 0x0440, 0x044F, 0x0439, 0x0000 };

static const CERT_DATA textStringCertData[] = {
	/* Identification information: A latin-1 string, a Unicode string, 
	   an ASCII-in-Unicode string, and an ASCII string */
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Hörr Østerix" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_WCSTRING, 0, unicodeStr },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_WCSTRING, 0, L"Dave's Unicode-aware CA with very long string" },
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "GB" ) },

	/* Another XYZZY certificate */
	{ CRYPT_CERTINFO_XYZZY, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testTextStringCert( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int status;

	puts( "Testing complex string type certificate creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certificate components */
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSetAttribute()", status,
							   __LINE__ ) );
	if( !addCertFields( cryptCert, textStringCertData ) )
		return( FALSE );

	/* Sign the certificate and print information on what we got */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSignCert()", status,
							   __LINE__ ) );
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Check the signature.  Since it's self-signed, we don't need to pass in
	   a signature check key */
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );

	/* Export the cert */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptExportCert()", status,
							   __LINE__ ) );
	printf( "Exported certificate is %d bytes long.\n", certificateLength );
	debugDump( "certstr", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	puts( "Complex string type certificate creation succeeded.\n" );
	return( TRUE );
	}
#else

int testTextStringCert( void )
	{
	return( TRUE );
	}
#endif /* Unicode-aware systems */

static const CERT_DATA complexCertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "US" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers and Netscape CA" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "SSL Certificates" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Himself" ) },

	/* Self-signed X.509v3 certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, TEXT( "dave@wetas-r-us.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.wetas-r-us.com" ) },

	/* Oddball altName components.  Note that the otherName.value must be a
	   DER-encoded ASN.1 object */
	{ CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER, IS_STRING, 0, TEXT( "EDI Name Assigner" ) },
	{ CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME, IS_STRING, 0, TEXT( "EDI Party Name" ) },
	{ CRYPT_CERTINFO_OTHERNAME_TYPEID, IS_STRING, 0, TEXT( "1 3 6 1 4 1 9999 2" ) },
	{ CRYPT_CERTINFO_OTHERNAME_VALUE, IS_STRING, 10, "\x04\x08" "12345678" },

	/* Path constraint */
	{ CRYPT_ATTRIBUTE_CURRENT, IS_NUMERIC, CRYPT_CERTINFO_EXCLUDEDSUBTREES },
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "CZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Brother's CA" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "SSL Certificates" ) },

	/* CRL distribution points */
	{ CRYPT_ATTRIBUTE_CURRENT, IS_NUMERIC, CRYPT_CERTINFO_CRLDIST_FULLNAME },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.revocations.com/crls/" ) },

	/* Add a vendor-specific extension, in this case a Thawte strong extranet
	   extension */
	{ CRYPT_CERTINFO_STRONGEXTRANET_ZONE, IS_NUMERIC, 0x99 },
	{ CRYPT_CERTINFO_STRONGEXTRANET_ID, IS_STRING, 0, TEXT( "EXTRA1" ) },

	/* Misc funnies */
	{ CRYPT_CERTINFO_OCSP_NOCHECK, IS_NUMERIC, CRYPT_UNUSED },

	/* Re-select the subject name after poking around in the altName */
	{ CRYPT_CERTINFO_SUBJECTNAME, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testComplexCert( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	C_CHR buffer1[ 64 ], buffer2[ 64 ];
	int length1, length2, status;

	puts( "Testing complex certificate creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certificate components */
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSetAttribute()", status,
							   __LINE__ ) );
	if( !addCertFields( cryptCert, complexCertData ) )
		return( FALSE );

	/* Add a non-CA basicConstraint, delete it, and re-add it as CA
	   constraint */
	status = cryptSetAttribute( cryptCert, CRYPT_CERTINFO_CA, FALSE );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSetAttribute()", status,
							   __LINE__ ) );
	status = cryptDeleteAttribute( cryptCert,
								   CRYPT_CERTINFO_BASICCONSTRAINTS );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptDeleteAttribute()", status,
							   __LINE__ ) );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptCert, CRYPT_CERTINFO_CA, TRUE );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSetAttribute()", status,
							   __LINE__ ) );

	/* Sign the certificate and print information on what we got */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSignCert()", status,
							   __LINE__ ) );
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Make sure that GeneralName component selection is working properly */
	cryptSetAttribute( cryptCert, CRYPT_ATTRIBUTE_CURRENT,
					   CRYPT_CERTINFO_SUBJECTALTNAME );
	status = cryptGetAttributeString( cryptCert,
						CRYPT_CERTINFO_RFC822NAME, buffer1, &length1 );
	if( cryptStatusOK( status ) )
		status = cryptGetAttributeString( cryptCert,
						CRYPT_CERTINFO_RFC822NAME, buffer2, &length2 );
	if( cryptStatusError( status ) )
		{
		printf( "Attempt to read and re-read email address failed, line "
				"%d.\n", __LINE__ );
		return( FALSE );
		}
#ifdef UNICODE_STRINGS
	buffer1[ length1 / sizeof( wchar_t ) ] = TEXT( '\0' );
	buffer2[ length2 / sizeof( wchar_t ) ] = TEXT( '\0' );
#else
	buffer1[ length1 ] = '\0';
	buffer2[ length2 ] = '\0';
#endif /* UNICODE_STRINGS */
	if( ( length1 != ( int ) paramStrlen( TEXT( "dave@wetas-r-us.com" ) ) ) || \
		( length1 != length2 ) || \
		memcmp( buffer1, TEXT( "dave@wetas-r-us.com" ), length1 ) || \
		memcmp( buffer2, TEXT( "dave@wetas-r-us.com" ), length2 ) )
		{
		printf( "Email address on read #1 = '%s',\n  read #2 = '%s', should "
				"have been '%s'.\n", buffer1, buffer2, 
				"dave@wetas-r-us.com" );
		return( FALSE );
		}

	/* Export the cert */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptExportCert()", status,
							   __LINE__ ) );
	printf( "Exported certificate is %d bytes long.\n", certificateLength );
	debugDump( "certc", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	puts( "Complex certificate creation succeeded.\n" );
	return( TRUE );
	}

int testCertExtension( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	BYTE buffer[ 16 ];
	const char *extensionData = "\x0C\x04Test";
	int value, length, status;

	puts( "Testing certificate with nonstd.extension creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptCert, CRYPT_CERTINFO_CA, TRUE );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSetAttribute()", status,
							   __LINE__ ) );
	if( !addCertFields( cryptCert, certData ) )
		return( FALSE );

	/* Add a nonstandard critical extension */
	status = cryptAddCertExtension( cryptCert, "1.2.3.4.5", TRUE, extensionData, 6 );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptAddCertExtension()", status,
							   __LINE__ ) );

	/* Sign the certificate.  Since we're adding a nonstandard extension we
	   have to set the CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES flag to
	   make sure that cryptlib will sign it */
	cryptGetAttribute( CRYPT_UNUSED,
					   CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, &value );
	cryptSetAttribute( CRYPT_UNUSED,
					   CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, TRUE );
	status = cryptSignCert( cryptCert, privKeyContext );
	cryptSetAttribute( CRYPT_UNUSED,
					   CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, value );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSignCert()", status,
							   __LINE__ ) );
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );

	/* Print information on what we've got */
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Export the cert and make sure that we can read what we created */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptExportCert()", status,
							   __LINE__ ) );
	printf( "Exported certificate is %d bytes long.\n", certificateLength );
	debugDump( "certext", certBuffer, certificateLength );
	cryptDestroyCert( cryptCert );
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Check the cert.  Since it contains an unrecognised critical extension
	   it should be rejected, but accepted at a lowered compliance level */
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		{
		printf( "Certificate with unrecognised critical extension was "
				"accepted when it should\nhave been rejected, line %d.\n",
				__LINE__ );
		return( FALSE );
		}
	cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   &value );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   CRYPT_COMPLIANCELEVEL_REDUCED );
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   value );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );

	/* Read back the nonstandard extension and make sure that it's what we
	   originally wrote */
	status = cryptGetCertExtension( cryptCert, "1.2.3.4.5", &value, buffer,
									16, &length );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptGetCertExtension()", status,
							   __LINE__ ) );
	if( value != TRUE || length != 6 || memcmp( extensionData, buffer, 6 ) )
		{
		printf( "Recovered nonstandard extension data differs from what was "
				"written, line %d.\n", __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyCert( cryptCert );
	puts( "Certificate with nonstd.extension creation succeeded.\n" );
	return( TRUE );
	}

int testCustomDNCert( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	const C_STR customDN = \
				TEXT( "cn=Dave Taylor + sn=12345, ou=Org.Unit 2\\=1, ou=Org.Unit 2, ou=Org.Unit 1, o=Dave's Big Organisation, c=PT" );
	char buffer[ BUFFER_SIZE ];
	int length, status;

	puts( "Testing certificate with custom DN creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptCert, CRYPT_CERTINFO_CA, TRUE );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptCert, CRYPT_CERTINFO_SELFSIGNED, TRUE );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSetAttribute()", status,
							   __LINE__ ) );

	/* Add the custom DN in string form */
	status = cryptSetAttributeString( cryptCert, CRYPT_CERTINFO_DN,
									  customDN, paramStrlen( customDN ) );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSetAttributeString()", status,
							   __LINE__ ) );

	/* Sign the certificate and print information on what we got */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSignCert()", status,
							   __LINE__ ) );
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Export the cert and make sure that we can read what we created */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptExportCert()", status,
							   __LINE__ ) );
	printf( "Exported certificate is %d bytes long.\n", certificateLength );
	debugDump( "certext", certBuffer, certificateLength );
	cryptDestroyCert( cryptCert );
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );

	/* Read back the custom DN and make sure that it's what we originally 
	   wrote */
	status = cryptGetAttributeString( cryptCert, CRYPT_CERTINFO_DN,
									  buffer, &length );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptGetAttributeString()", status,
							   __LINE__ ) );
	if( length != ( int ) paramStrlen( customDN ) || \
		memcmp( customDN, buffer, length ) )
		{
		printf( "Recovered custom DN differs from what was written, line "
				"%d.\n", __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyCert( cryptCert );
	puts( "Certificate with custom DN creation succeeded.\n" );
	return( TRUE );
	}

static const CERT_DATA setCertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers and Temple of SET" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "SET Commerce Division" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave's Cousin Bob" ) },

	/* Self-signed X.509v3 certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	/* Add the SET extensions */
	{ CRYPT_CERTINFO_SET_CERTIFICATETYPE, IS_NUMERIC, CRYPT_SET_CERTTYPE_RCA },
	{ CRYPT_CERTINFO_SET_CERTCARDREQUIRED, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_SET_ROOTKEYTHUMBPRINT, IS_STRING, 20, TEXT( "12345678900987654321" ) },
	{ CRYPT_CERTINFO_SET_MERID, IS_STRING, 0, TEXT( "Wetaburger Vendor" ) },
	{ CRYPT_CERTINFO_SET_MERACQUIRERBIN, IS_STRING, 0, TEXT( "123456" ) },
	{ CRYPT_CERTINFO_SET_MERCHANTLANGUAGE, IS_STRING, 0, TEXT( "English" ) },
	{ CRYPT_CERTINFO_SET_MERCHANTNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers and SET Merchant" ) },
	{ CRYPT_CERTINFO_SET_MERCHANTCITY, IS_STRING, 0, TEXT( "Eketahuna" ) },
	{ CRYPT_CERTINFO_SET_MERCHANTCOUNTRYNAME, IS_STRING, 0, TEXT( "New Zealand" ) },
	{ CRYPT_CERTINFO_SET_MERCOUNTRY, IS_NUMERIC, 554 },		/* ISO 3166 */

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

int testSETCert( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int status;

	puts( "Testing SET certificate creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certificate components */
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSetAttribute()", status,
							   __LINE__ ) );
	if( !addCertFields( cryptCert, setCertData ) )
		return( FALSE );

	/* Sign the certificate and print information on what we got */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSignCert()", status,
							   __LINE__ ) );
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Export the cert */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptExportCert()", status,
							   __LINE__ ) );
	printf( "Exported certificate is %d bytes long.\n", certificateLength );
	debugDump( "certset", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	puts( "SET certificate creation succeeded.\n" );
	return( TRUE );
	}

static const CERT_DATA attributeCertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NI" ) },		/* Ni! Ni! Ni! */
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers and Attributes" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Attribute Management" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave's Mum" ) },

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

int testAttributeCert( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT cryptAuthorityKey;
	int status;

	puts( "Testing attribute certificate creation/export..." );

	/* Get the authority's private key */
	status = getPrivateKey( &cryptAuthorityKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "Authority private key read failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_ATTRIBUTE_CERT );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certificate components.  Note that we don't add any
	   attributes because these hadn't been defined yet (at least not as of
	   the JTC1 SC21/ITU-T Q.17/7 draft of July 1997) */
	if( !addCertFields( cryptCert, attributeCertData ) )
		return( FALSE );

	/* Sign the certificate and print information on what we got */
	status = cryptSignCert( cryptCert, cryptAuthorityKey );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSignCert()", status,
							   __LINE__ ) );
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Export the cert */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptExportCert()", status,
							   __LINE__ ) );
	printf( "Exported certificate is %d bytes long.\n", certificateLength );
	debugDump( "certattr", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, cryptAuthorityKey );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	cryptDestroyContext( cryptAuthorityKey );
	puts( "Attribute certificate creation succeeded.\n" );
	return( TRUE );
	}

/* Test certification request code. Note the similarity with the certificate
   creation code, only the call to cryptCreateCert() differs */

static const CERT_DATA certRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "PT" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Smith" ) },

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

int testCertRequest( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int status;

	puts( "Testing certification request creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate object */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTREQUEST );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certification request components */
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSetAttribute()", status,
							   __LINE__ ) );
	if( !addCertFields( cryptCert, certRequestData ) )
		return( FALSE );

	/* Sign the certification request and print information on what we got */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSignCert()", status,
							   __LINE__ ) );
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Check the signature.  Since it's self-signed, we don't need to pass in
	   a signature check key */
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );

	/* Export the cert */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptExportCert()", status,
							   __LINE__ ) );
	printf( "Exported certification request is %d bytes long.\n",
			certificateLength );
	debugDump( "certreq", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	puts( "Certification request creation succeeded.\n" );
	return( TRUE );
	}

/* Test complex certification request code */

static const CERT_DATA complexCertRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Smith" ) },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, TEXT( "dave@wetas-r-us.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.wetas-r-us.com" ) },

	/* Re-select the subject name after poking around in the altName */
	{ CRYPT_CERTINFO_SUBJECTNAME, IS_NUMERIC, CRYPT_UNUSED },

	/* SSL server and client authentication */
	{ CRYPT_CERTINFO_EXTKEY_SERVERAUTH, IS_NUMERIC, CRYPT_UNUSED },
	{ CRYPT_CERTINFO_EXTKEY_CLIENTAUTH, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testComplexCertRequest( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int status;

	puts( "Testing complex certification request creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate object */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTREQUEST );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certification request components */
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSetAttribute()", status,
							   __LINE__ ) );
	if( !addCertFields( cryptCert, complexCertRequestData ) )
		return( FALSE );

	/* Sign the certification request and print information on what we got */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSignCert()", status,
							   __LINE__ ) );
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Check the signature.  Since it's self-signed, we don't need to pass in
	   a signature check key */
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );

	/* Export the cert */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptExportCert()", status,
							   __LINE__ ) );
	printf( "Exported certification request is %d bytes long.\n",
			certificateLength );
	debugDump( "certreqc", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	puts( "Complex certification request creation succeeded.\n" );
	return( TRUE );
	}

/* Test CRMF certification request code */

int testCRMFRequest( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int status;

	puts( "Testing CRMF certification request creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate object */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_REQUEST_CERT );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certification request components */
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSetAttribute()", status,
							   __LINE__ ) );
	if( !addCertFields( cryptCert, certRequestData ) )
		return( FALSE );

	/* Sign the certification request and print information on what we got */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSignCert()", status,
							   __LINE__ ) );
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Check the signature.  Since it's self-signed, we don't need to pass in
	   a signature check key */
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );

	/* Export the cert */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptExportCert()", status,
							   __LINE__ ) );
	printf( "Exported certification request is %d bytes long.\n",
			certificateLength );
	debugDump( "req_crmf", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	puts( "CRMF certification request creation succeeded.\n" );
	return( TRUE );
	}

int testComplexCRMFRequest( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int status;

	puts( "Testing complex CRMF certification request creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate object */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_REQUEST_CERT );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certification request components */
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSetAttribute()", status,
							   __LINE__ ) );
	if( !addCertFields( cryptCert, complexCertRequestData ) )
		return( FALSE );

	/* Sign the certification request and print information on what we got */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptSignCert()", status,
							   __LINE__ ) );
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Check the signature.  Since it's self-signed, we don't need to pass in
	   a signature check key */
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );

	/* Export the cert */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptExportCert()", status,
							   __LINE__ ) );
	printf( "Exported certification request is %d bytes long.\n",
			certificateLength );
	debugDump( "req_crmfc", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	puts( "Complex CRMF certification request creation succeeded.\n" );
	return( TRUE );
	}

/* Test CRL code.  This one represents a bit of a chicken-and-egg problem
   since we need a CA cert to create the CRL, but we can't read this until
   the private key file read has been tested, and that requires testing of
   the cert management.  At the moment we just assume that private key file
   reads work for this test */

int testCRL( void )
	{
	CRYPT_CERTIFICATE cryptCRL;
	CRYPT_CONTEXT cryptCAKey;
	int status;

	puts( "Testing CRL creation/export..." );

	/* Get the CA's private key */
	status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "CA private key read failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Create the CRL */
	status = cryptCreateCert( &cryptCRL, CRYPT_UNUSED, CRYPT_CERTTYPE_CRL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some CRL components.  In this case the CA is revoking its own
	   key */
	status = cryptSetAttribute( cryptCRL, CRYPT_CERTINFO_CERTIFICATE, 
								cryptCAKey );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCRL, "cryptSetAttribute()", status,
							   __LINE__ ) );

	/* Sign the CRL */
	status = cryptSignCert( cryptCRL, cryptCAKey );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCRL, "cryptSignCert()", status,
							   __LINE__ ) );

	/* Print information on what we've got */
	if( !printCertInfo( cryptCRL ) )
		return( FALSE );

	/* Check the signature.  Since we have the CA private key handy, we
	   use that to check the signature */
	status = cryptCheckCert( cryptCRL, cryptCAKey );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCRL, "cryptCheckCert()", status,
							   __LINE__ ) );

	/* Export the CRL */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCRL );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCRL, "cryptExportCert()", status,
							   __LINE__ ) );
	printf( "Exported CRL is %d bytes long.\n", certificateLength );
	debugDump( "crl", certBuffer, certificateLength );

	/* Destroy the CRL */
	status = cryptDestroyCert( cryptCRL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCRL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCRL, cryptCAKey );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCRL, "cryptCheckCert()", status,
							   __LINE__ ) );
	cryptDestroyCert( cryptCRL );
	cryptDestroyContext( cryptCAKey );

	/* Clean up */
	puts( "CRL creation succeeded.\n" );
	return( TRUE );
	}

/* Test complex CRL code */

static const CERT_DATA complexCRLData[] = {
	/* Next update time */
	{ CRYPT_CERTINFO_NEXTUPDATE, IS_TIME, 0, NULL, 0x42000000L },

	/* CRL number and delta CRL indicator */
	{ CRYPT_CERTINFO_CRLNUMBER, IS_NUMERIC, 1 },
	{ CRYPT_CERTINFO_DELTACRLINDICATOR, IS_NUMERIC, 2 },

	/* Issuing distribution points */
	{ CRYPT_ATTRIBUTE_CURRENT, IS_NUMERIC, CRYPT_CERTINFO_ISSUINGDIST_FULLNAME },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.wetas-r-us.com" ) },
	{ CRYPT_CERTINFO_ISSUINGDIST_USERCERTSONLY, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testComplexCRL( void )
	{
	CRYPT_CERTIFICATE cryptCRL, cryptRevokeCert;
	CRYPT_CONTEXT cryptCAKey;
	time_t revocationTime;
	int revocationReason, dummy, status;

	puts( "Testing complex CRL creation/export..." );

	/* Get the CA's private key */
	status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "CA private key read failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Create the CRL */
	status = cryptCreateCert( &cryptCRL, CRYPT_UNUSED, CRYPT_CERTTYPE_CRL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some CRL components with per-entry attributes.  In this case the
	   CA is revoking its own key because it was compromised (would you trust
	   this CRL?) and some keys from test certs */
	if( !addCertFields( cryptCRL, complexCRLData ) )
		return( FALSE );
	status = cryptSetAttribute( cryptCRL, CRYPT_CERTINFO_CERTIFICATE,
								cryptCAKey );
	if( cryptStatusOK( status ) )
		/* The CA key was compromised */
		status = cryptSetAttribute( cryptCRL,
									CRYPT_CERTINFO_CRLREASON,
									CRYPT_CRLREASON_CACOMPROMISE );
	if( cryptStatusOK( status ) )
		status = importCertFromTemplate( &cryptRevokeCert,
										 CRLCERT_FILE_TEMPLATE, 1 );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptCRL, CRYPT_CERTINFO_CERTIFICATE,
									cryptRevokeCert );
		cryptDestroyCert( cryptRevokeCert );
		}
	if( cryptStatusOK( status ) )
		{
		/* Hold cert, call issuer for details */
		status = cryptSetAttribute( cryptCRL,
									CRYPT_CERTINFO_CRLREASON,
									CRYPT_CRLREASON_CERTIFICATEHOLD );
		if( cryptStatusOK( status ) )
			status = cryptSetAttribute( cryptCRL,
										CRYPT_CERTINFO_HOLDINSTRUCTIONCODE,
										CRYPT_HOLDINSTRUCTION_CALLISSUER );
		}
	if( cryptStatusOK( status ) )
		status = importCertFromTemplate( &cryptRevokeCert,
										 CRLCERT_FILE_TEMPLATE, 2 );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptCRL, CRYPT_CERTINFO_CERTIFICATE, 
									cryptRevokeCert );
		cryptDestroyCert( cryptRevokeCert );
		}
	if( cryptStatusOK( status ) )
		{
		const time_t invalidityDate = 0x37000000L;

		/* The private key was invalid quite some time ago (1999).  We can't
		   go back too far because the cryptlib kernel won't allow
		   suspiciously old dates */
		status = cryptSetAttributeString( cryptCRL,
					CRYPT_CERTINFO_INVALIDITYDATE, &invalidityDate,
					sizeof( time_t ) );
		}
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCRL, "cryptSetAttribute()", status,
							   __LINE__ ) );

	/* Sign the CRL */
	status = cryptSignCert( cryptCRL, cryptCAKey );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCRL, "cryptSignCert()", status,
							   __LINE__ ) );

	/* Print information on what we've got */
	if( !printCertInfo( cryptCRL ) )
		return( FALSE );

	/* Check the signature.  Since we have the CA private key handy, we
	   use that to check the signature */
	status = cryptCheckCert( cryptCRL, cryptCAKey );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCRL, "cryptCheckCert()", status,
							   __LINE__ ) );

	/* Export the CRL */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCRL );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCRL, "cryptExportCert()", status,
							   __LINE__ ) );
	printf( "Exported CRL is %d bytes long.\n", certificateLength );
	debugDump( "crlc", certBuffer, certificateLength );

	/* Destroy the CRL */
	status = cryptDestroyCert( cryptCRL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCRL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCRL, cryptCAKey );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCRL, "cryptCheckCert()", status,
							   __LINE__ ) );

	/* Check the newly-revoked CA key agains the CRL */
	status = cryptCheckCert( cryptCAKey, cryptCRL );
	if( status != CRYPT_ERROR_INVALID )
		{
		printf( "Revoked cert wasn't reported as being revoked, line %d.\n",
				__LINE__ );
		return( FALSE );
		}
	status = cryptGetAttributeString( cryptCRL, CRYPT_CERTINFO_REVOCATIONDATE,
									  &revocationTime, &dummy );
	if( cryptStatusOK( status ) )
		status = cryptGetAttribute( cryptCRL, CRYPT_CERTINFO_CRLREASON,
									&revocationReason );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCRL, "cryptGetAttribute()", status,
							   __LINE__ ) );
	if( revocationReason != CRYPT_CRLREASON_CACOMPROMISE )
		{
		printf( "Revocation reason was %d, should have been %d.\n",
				revocationReason, CRYPT_CRLREASON_CACOMPROMISE );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyCert( cryptCRL );
	cryptDestroyContext( cryptCAKey );
	puts( "CRL creation succeeded.\n" );
	return( TRUE );
	}

/* Test revocation request code */

static const CERT_DATA revRequestData[] = {
	/* Revocation reason */
	{ CRYPT_CERTINFO_CRLREASON, IS_NUMERIC, CRYPT_CRLREASON_SUPERSEDED },

	/* Invalidity date */
	{ CRYPT_CERTINFO_INVALIDITYDATE, IS_TIME, 0, NULL, 0x42000000L },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testRevRequest( void )
	{
	CRYPT_CERTIFICATE cryptCert, cryptRequest;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, status;

	puts( "Testing revocation request creation/export..." );

	filenameFromTemplate( buffer, CERT_FILE_TEMPLATE, 1 );
	if( ( filePtr = fopen( buffer, "rb" ) ) == NULL )
		{
		puts( "Couldn't find certificate file for revocation request test." );
		return( FALSE );
		}
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	status = cryptImportCert( buffer, count, CRYPT_UNUSED, &cryptCert );
	if( cryptStatusError( status ) )
		{
		puts( "Cert import failed, skipping test of revocation request..." );
		return( TRUE );
		}

	/* Create the certificate object and add the certificate details and
	   revocation info */
	status = cryptCreateCert( &cryptRequest, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_REQUEST_REVOCATION );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptRequest, CRYPT_CERTINFO_CERTIFICATE,
								cryptCert );
	cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptRequest, "cryptSetAttribute()", status,
							   __LINE__ ) );
	if( !addCertFields( cryptRequest, revRequestData ) )
		return( FALSE );

	/* Print information on what we've got */
	if( !printCertInfo( cryptRequest ) )
		return( FALSE );

#if 0	/* CMP doesn't currently allow revocation requests to be signed, so
		   it's treated like CMS attributes as a series of uninitialised
		   attributes */
	/* Export the cert */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptRequest );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptRequest, "cryptExportCert()", status,
							   __LINE__ ) );
	printf( "Exported revocation request is %d bytes long.\n",
			certificateLength );
	debugDump( "req_rev", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptRequest );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptRequest );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
#endif /* 0 */
	cryptDestroyCert( cryptRequest );

	/* Clean up */
	puts( "Revocation request creation succeeded.\n" );
	return( TRUE );
	}

/* Test cert chain creation */

static const CERT_DATA certRequestNoDNData[] = {
	/* Identification information.  There's no DN, only a subject altName.  
	   This type of identifier is only possible with a CA-signed cert, since
	   it contains an empty DN */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, TEXT( "dave@wetas-r-us.com" ) },

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

static int createChain( CRYPT_CERTIFICATE *cryptCertChain,
						const CRYPT_CONTEXT cryptCAKey,
						const BOOLEAN useEmptyDN )
	{
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int status;

	/* Create the cert chain */
	status = cryptCreateCert( cryptCertChain, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTCHAIN );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Create a simple cert request to turn into the end-user cert */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );
	status = cryptSetAttribute( *cryptCertChain,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( *cryptCertChain, useEmptyDN ? certRequestNoDNData : \
													  certRequestData ) )
		return( FALSE );
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate creation failed with status %d, line %d.\n", 
				status, __LINE__ );
		return( FALSE );
		}

	/* Sign the leaf of the cert chain */
	status = cryptSignCert( *cryptCertChain, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		cryptDestroyCert( *cryptCertChain );
		if( useEmptyDN )
			return( -1 );
		return( attrErrorExit( *cryptCertChain, "cryptSignCert()", status,
							   __LINE__ ) );
		}

	return( TRUE );
	}

int testCertChain( void )
	{
	CRYPT_CERTIFICATE cryptCertChain;
	CRYPT_CONTEXT cryptCAKey;
	int value, status;

	puts( "Testing certificate chain creation/export..." );

	/* Get the CA's private key */
	status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "CA private key read failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Create a new cert chain */
	if( !createChain( &cryptCertChain, cryptCAKey, FALSE ) )
		return( FALSE );

	/* Check the signature.  Since the chain counts as self-signed, we don't
	   have to supply a sig.check key.  Since the DIY CA cert isn't trusted,
	   we have to force cryptlib to treat it as explicitly trusted when we
	   try to verify the chain */
	status = setRootTrust( cryptCertChain, &value, 1 );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCertChain, "Setting cert chain trusted", 
							   status, __LINE__ ) );
	status = cryptCheckCert( cryptCertChain, CRYPT_UNUSED );
	setRootTrust( cryptCertChain, NULL, value );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCertChain, "cryptCheckCert()", status,
							   __LINE__ ) );

	/* Try the other way of verifying the chain, by making the signing key
	   implicitly trusted */
	status = cryptSetAttribute( cryptCAKey, CRYPT_CERTINFO_TRUSTED_IMPLICIT, 
								TRUE );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCertChain, "Setting chain signing key "
							   "trusted", status, __LINE__ ) );
	status = cryptCheckCert( cryptCertChain, CRYPT_UNUSED );
	cryptSetAttribute( cryptCAKey, CRYPT_CERTINFO_TRUSTED_IMPLICIT, FALSE );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCertChain, "cryptCheckCert()", status,
							   __LINE__ ) );

	/* Finally, make sure that the non-trusted chain doesn't verify */
	status = cryptCheckCert( cryptCertChain, CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		{
		printf( "Cert chain verified OK even though it wasn't trusted, "
				"line %d.\n", __LINE__ );
		return( FALSE );
		}

	/* Export the cert chain */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTCHAIN, cryptCertChain );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCertChain, "cryptExportCert()", status,
							   __LINE__ ) );
	printf( "Exported cert chain is %d bytes long.\n", certificateLength );
	debugDump( "certchn", certBuffer, certificateLength );

	/* Destroy the cert chain */
	status = cryptDestroyCert( cryptCertChain );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCertChain );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "Checking signatures... " );
	status = setRootTrust( cryptCertChain, &value, 1 );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCertChain, "Setting cert chain trusted", 
							   status, __LINE__ ) );
	status = cryptCheckCert( cryptCertChain, CRYPT_UNUSED );
	setRootTrust( cryptCertChain, NULL, value );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCertChain, "cryptCheckCert()", status,
							   __LINE__ ) );
	puts( "signatures verified." );

	/* Display info on each cert in the chain */
	if( !printCertChainInfo( cryptCertChain ) )
		return( FALSE );

	/* Create a second cert chain with a null DN */
	cryptDestroyCert( cryptCertChain );
	status = createChain( &cryptCertChain, cryptCAKey, TRUE );
	if( status != -1 )
		{
		printf( "Attempt to create cert with null DN %s, line %d.\n", 
				( status == FALSE ) ? \
					"failed" : "succeeded when it should have failed", 
				__LINE__ );
		return( FALSE );
		}
	cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   &value );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   CRYPT_COMPLIANCELEVEL_PKIX_FULL );
	status = createChain( &cryptCertChain, cryptCAKey, TRUE );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   value );
	if( status != TRUE )
		return( FALSE );
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &certificateLength,
							  CRYPT_CERTFORMAT_CERTCHAIN, cryptCertChain );
	cryptDestroyCert( cryptCertChain );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCertChain, "cryptExportCert()", status,
							   __LINE__ ) );
	debugDump( "certchndn", certBuffer, certificateLength );
	status = cryptImportCert( certBuffer, certificateLength, CRYPT_UNUSED,
							  &cryptCertChain );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyCert( cryptCertChain );
	cryptDestroyContext( cryptCAKey );
	puts( "Certificate chain creation succeeded.\n" );
	return( TRUE );
	}

/* Test CMS attribute code.  This doesn't actually test much since this
   object type is just a basic data container used for the extended signing
   functions */

static const CERT_DATA cmsAttributeData[] = {
	/* Content type and an S/MIME capability */
	{ CRYPT_CERTINFO_CMS_CONTENTTYPE, IS_NUMERIC, CRYPT_CONTENT_SIGNEDDATA },
	{ CRYPT_CERTINFO_CMS_SMIMECAP_PREFERSIGNEDDATA, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testCMSAttributes( void )
	{
	CRYPT_CERTIFICATE cryptAttributes;
	int status;

	puts( "Testing CMS attribute creation..." );

	/* Create the CMS attribute container */
	status = cryptCreateCert( &cryptAttributes, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CMS_ATTRIBUTES );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some CMS attribute components */
	if( !addCertFields( cryptAttributes, cmsAttributeData ) )
		return( FALSE );

	/* Print information on what we've got */
	if( !printCertInfo( cryptAttributes ) )
		return( FALSE );

	/* Destroy the attributes.  We can't do much more than this at this
	   stage since the attributes are only used internally by other
	   functions */
	status = cryptDestroyCert( cryptAttributes );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	puts( "CMS attribute creation succeeded.\n" );
	return( TRUE );
	}

/* Test RTCS request/response code.  This test routine itself doesn't
   actually test much since this object type is just a basic data container
   used for RTCS sessions, however the shared initRTCS() routine is used by
   the RTCS session code to test the rest of the functionality */

int initRTCS( CRYPT_CERTIFICATE *cryptRTCSRequest, const int number,
			  const BOOLEAN multipleCerts )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CERTIFICATE cryptErrorObject = *cryptRTCSRequest;
	C_CHR rtcsURL[ 512 ];
	int count, status;

	/* Import the EE certs */
	status = importCertFromTemplate( &cryptCert, RTCS_FILE_TEMPLATE,
									 number );
	if( cryptStatusError( status ) )
		{
		printf( "EE cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Select the RTCS responder location from the EE cert and read the URL/
	   FQDN value (this isn't used but is purely for display to the user) */
	status = cryptSetAttribute( cryptCert, CRYPT_ATTRIBUTE_CURRENT,
								CRYPT_CERTINFO_AUTHORITYINFO_RTCS );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptCert,
								CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER,
								rtcsURL, &count );
		if( status == CRYPT_ERROR_NOTFOUND )
			status = cryptGetAttributeString( cryptCert,
								CRYPT_CERTINFO_DNSNAME, rtcsURL, &count );
		}
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_NOTFOUND )
			puts( "RTCS responder URL not present in cert, server name must "
				  "be provided\n  externally." );
		else
			{
			printf( "Attempt to read RTCS responder URL failed with error "
					"code %d, line %d.\n", status, __LINE__ );
			printErrorAttributeInfo( cryptCert );
			return( FALSE );
			}
		}
	else
		{
#ifdef UNICODE_STRINGS
		rtcsURL[ count / sizeof( wchar_t ) ] = TEXT( '\0' );
		printf( "RTCS responder URL = %sS.\n", rtcsURL );
#else
		rtcsURL[ count ] = '\0';
		printf( "RTCS responder URL = %s.\n", rtcsURL );
#endif /* UNICODE_STRINGS */
		}

	/* Create the RTCS request container */
	status = cryptCreateCert( cryptRTCSRequest, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_RTCS_REQUEST );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add the request components */
	status = cryptSetAttribute( *cryptRTCSRequest, 
								CRYPT_CERTINFO_CERTIFICATE, cryptCert );
	if( status == CRYPT_ERROR_PARAM3 )
		cryptErrorObject = cryptCert;
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptErrorObject, "cryptSetAttribute()",
							   status, __LINE__ ) );

	/* If we're doing a query with multiple certs, add another cert.  To
	   keep things simple and avoid having to stockpile a whole collection
	   of certs for each responder we just use a random cert for which we
	   expect an 'unknown' response */
	if( multipleCerts )
		{
		cryptDestroyCert( cryptCert );
		status = importCertFromTemplate( &cryptCert, CERT_FILE_TEMPLATE, 1 );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttribute( *cryptRTCSRequest,
										CRYPT_CERTINFO_CERTIFICATE, cryptCert );
			if( status == CRYPT_ERROR_PARAM3 )
				cryptErrorObject = cryptCert;
			}
		if( cryptStatusError( status ) )
			return( attrErrorExit( *cryptRTCSRequest, "cryptSetAttribute()",
								   status, __LINE__ ) );
		}

	/* Clean up */
	cryptDestroyCert( cryptCert );

	return( TRUE );
	}

int testRTCSReqResp( void )
	{
	CRYPT_CERTIFICATE cryptRTCSRequest;
	int status;

	puts( "Testing RTCS request creation..." );

	/* Create the RTCS request using the certs and print information on what
	   we've got */
	if( !initRTCS( &cryptRTCSRequest, 1, FALSE ) )
		return( FALSE );
	if( !printCertInfo( cryptRTCSRequest ) )
		return( FALSE );

	/* Destroy the request.  We can't do much more than this at this stage
	   since the request is only used internally by the RTCS session code */
	status = cryptDestroyCert( cryptRTCSRequest );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "RTCS request creation succeeded.\n" );
	return( TRUE );
	}

/* Test OCSP request/response code.  This test routine itself doesn't
   actually test much since this object type is just a basic data container
   used for OCSP sessions, however the shared initOCSP() routine is used by
   the OCSP session code to test the rest of the functionality */

int initOCSP( CRYPT_CERTIFICATE *cryptOCSPRequest, const int number,
			  const BOOLEAN ocspv2, const BOOLEAN revokedCert,
			  const BOOLEAN multipleCerts, 
			  const CRYPT_SIGNATURELEVEL_TYPE sigLevel,
			  const CRYPT_CONTEXT privKeyContext )
	{
	CRYPT_CERTIFICATE cryptOCSPCA, cryptOCSPEE;
	CRYPT_CERTIFICATE cryptErrorObject = *cryptOCSPRequest;
	C_CHR ocspURL[ 512 ];
	int count, status;

	assert( !ocspv2 );

	/* Import the OCSP CA (if required) and EE certs */
	if( !ocspv2 )
		{
		status = importCertFromTemplate( &cryptOCSPCA,
										 OCSP_CA_FILE_TEMPLATE, number );
		if( cryptStatusError( status ) )
			{
			printf( "CA cryptImportCert() failed with error code %d, line "
					"%d.\n", status, __LINE__ );
			return( FALSE );
			}
		}
	status = importCertFromTemplate( &cryptOCSPEE, revokedCert ? \
						OCSP_EEREV_FILE_TEMPLATE: OCSP_EEOK_FILE_TEMPLATE,
						number );
	if( cryptStatusError( status ) )
		{
		printf( "EE cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Select the OCSP responder location from the EE cert and read the URL/
	   FQDN value (this isn't used but is purely for display to the user) */
	status = cryptSetAttribute( cryptOCSPEE, CRYPT_ATTRIBUTE_CURRENT,
								CRYPT_CERTINFO_AUTHORITYINFO_OCSP );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetAttributeString( cryptOCSPEE,
							CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER,
							ocspURL, &count );
		if( status == CRYPT_ERROR_NOTFOUND )
			status = cryptGetAttributeString( cryptOCSPEE,
							CRYPT_CERTINFO_DNSNAME, ocspURL, &count );
		}
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_NOTFOUND )
			puts( "OCSP responder URL not present in cert, server name must "
				  "be provided\n  externally." );
		else
			{
			printf( "Attempt to read OCSP responder URL failed with error "
					"code %d, line %d.\n", status, __LINE__ );
			printErrorAttributeInfo( cryptOCSPEE );
			return( FALSE );
			}
		}
	else
		{
#ifdef UNICODE_STRINGS
		ocspURL[ count / sizeof( wchar_t ) ] = TEXT( '\0' );
		printf( "OCSP responder URL = %S.\n", ocspURL );
#else
		ocspURL[ count ] = '\0';
		printf( "OCSP responder URL = %s.\n", ocspURL );
#endif /* UNICODE_STRINGS */
		}

	/* Create the OCSP request container */
	status = cryptCreateCert( cryptOCSPRequest, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_OCSP_REQUEST );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add the request components.  Note that if we're using v1 we have to
	   add the CA cert first since it's needed to generate the request ID
	   for the EE cert */
	if( !ocspv2 )
		{
		status = cryptSetAttribute( *cryptOCSPRequest,
							CRYPT_CERTINFO_CACERTIFICATE, cryptOCSPCA );
		if( status == CRYPT_ERROR_PARAM3 )
			cryptErrorObject = cryptOCSPCA;
		}
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( *cryptOCSPRequest, 
									CRYPT_CERTINFO_CERTIFICATE, cryptOCSPEE );
		if( status == CRYPT_ERROR_PARAM3 )
			cryptErrorObject = cryptOCSPEE;
		}
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptErrorObject, "cryptSetAttribute()",
							   status, __LINE__ ) );

	/* If we're doing a query with multiple certs, add another cert.  To
	   keep things simple and avoid having to stockpile a whole collection
	   of certs for each responder we just use a random cert for which we
	   expect an 'unknown' response */
	if( multipleCerts )
		{
		cryptDestroyCert( cryptOCSPEE );
		status = importCertFromTemplate( &cryptOCSPEE, CERT_FILE_TEMPLATE, 1 );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttribute( *cryptOCSPRequest,
										CRYPT_CERTINFO_CERTIFICATE, cryptOCSPEE );
			if( status == CRYPT_ERROR_PARAM3 )
				cryptErrorObject = cryptOCSPEE;
			}
		if( cryptStatusError( status ) )
			return( attrErrorExit( *cryptOCSPRequest, "cryptSetAttribute()",
								   status, __LINE__ ) );
		}

	/* If we have a signing key, create a signed request */
	if( privKeyContext != CRYPT_UNUSED )
		{
		status = cryptSetAttribute( *cryptOCSPRequest, 
							CRYPT_CERTINFO_SIGNATURELEVEL, sigLevel );
		if( cryptStatusError( status ) )
			return( attrErrorExit( *cryptOCSPRequest, "cryptSetAttribute()", 
								   status, __LINE__ ) );
		status = cryptSignCert( *cryptOCSPRequest, privKeyContext );
		if( status == CRYPT_ERROR_PARAM3 )
			cryptErrorObject = privKeyContext;
		if( cryptStatusError( status ) )
			return( attrErrorExit( cryptErrorObject, "cryptSignCert()",
								   status, __LINE__ ) );
		}

	/* Clean up */
	if( !ocspv2 )
		cryptDestroyCert( cryptOCSPCA );
	cryptDestroyCert( cryptOCSPEE );

	return( TRUE );
	}

int testOCSPReqResp( void )
	{
	CRYPT_CERTIFICATE cryptOCSPRequest;
	CRYPT_CONTEXT cryptPrivateKey;
	int status;

	puts( "Testing OCSP request creation..." );

	/* Create the OCSP request using the certs and print information on what
	   we've got */
	if( !initOCSP( &cryptOCSPRequest, 1, FALSE, FALSE, FALSE, 
				   CRYPT_SIGNATURELEVEL_NONE, CRYPT_UNUSED ) )
		return( FALSE );
	puts( "OCSPv1 succeeded." );
	if( !printCertInfo( cryptOCSPRequest ) )
		return( FALSE );

	/* Destroy the request.  We can't do much more than this at this stage
	   since the request is only used internally by the OCSP session code */
	status = cryptDestroyCert( cryptOCSPRequest );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

#if 0	/* OCSPv2 is still in too much of a state of flux to implement this */
	/* Try again with a v2 request.  This only differs from the v1 request in
	   the way the ID generation is handled so we don't bother printing any
	   information on the request */
	if( !initOCSP( &cryptOCSPRequest, 1, TRUE, FALSE, FALSE, 
				   CRYPT_SIGNATURELEVEL_NONE, CRYPT_UNUSED ) )
		return( FALSE );
	puts( "OCSPv2 succeeded." );
	cryptDestroyCert( cryptOCSPRequest );
#endif

	/* Finally, create a signed request, first without and then with signing 
	   certs */
	status = getPrivateKey( &cryptPrivateKey, USER_PRIVKEY_FILE,
							USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "User private key read failed with error code %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}
	if( !initOCSP( &cryptOCSPRequest, 1, FALSE, FALSE, FALSE, 
				   CRYPT_SIGNATURELEVEL_NONE, cryptPrivateKey ) )
		return( FALSE );
	cryptDestroyCert( cryptOCSPRequest );
	puts( "Signed OCSP request succeeded." );
	if( !initOCSP( &cryptOCSPRequest, 1, FALSE, FALSE, FALSE, 
				   CRYPT_SIGNATURELEVEL_SIGNERCERT, cryptPrivateKey ) )
		return( FALSE );
	cryptDestroyCert( cryptOCSPRequest );
	puts( "Signed OCSP request with single signing cert succeeded." );
	if( !initOCSP( &cryptOCSPRequest, 1, FALSE, FALSE, FALSE, 
				   CRYPT_SIGNATURELEVEL_ALL, cryptPrivateKey ) )
		return( FALSE );
	cryptDestroyCert( cryptOCSPRequest );
	puts( "Signed OCSP request with signing cert chain succeeded." );
	cryptDestroyContext( cryptPrivateKey );

	puts( "OCSP request creation succeeded.\n" );
	return( TRUE );
	}

/* Test PKI user information creation.  This doesn't actually test much
   since this object type is just a basic data container used to hold user
   information in a cert store */

static const CERT_DATA pkiUserData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Test PKI user" ) },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};
static const CERT_DATA pkiUserExtData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Test extended PKI user" ) },

	/* SSL server and client authentication */
	{ CRYPT_CERTINFO_EXTKEY_SERVERAUTH, IS_NUMERIC, CRYPT_UNUSED },
	{ CRYPT_CERTINFO_EXTKEY_CLIENTAUTH, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};
static const CERT_DATA pkiUserCAData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Test CA PKI user" ) },

	/* CA extensions */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

#define PKIUSER_NAME_INDEX	3	/* Index of name in CERT_DATA info */

static int testPKIUserCreate( const CERT_DATA *pkiUserInfo )
	{
	CRYPT_CERTIFICATE cryptPKIUser;
	int status;

	/* Create the PKI user object and add the user's identification
	   information */
	status = cryptCreateCert( &cryptPKIUser, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_PKIUSER );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	if( !addCertFields( cryptPKIUser, pkiUserInfo ) )
		{
		printf( "Couldn't create PKI user info for user '%s'.\n",
				pkiUserInfo[ PKIUSER_NAME_INDEX ].stringValue );
		return( FALSE );
		}
	cryptDestroyCert( cryptPKIUser );

	return( TRUE );
	}

int testPKIUser( void )
	{
	puts( "Testing PKI user information creation..." );
	if( !testPKIUserCreate( pkiUserData ) )
		return( FALSE );
	if( !testPKIUserCreate( pkiUserExtData ) )
		return( FALSE );
	if( !testPKIUserCreate( pkiUserCAData ) )
		return( FALSE );
	puts( "PKI user information creation succeeded.\n" );
	return( TRUE );
	}

/****************************************************************************
*																			*
*							Certificate Import Routines Test				*
*																			*
****************************************************************************/

/* Test certificate import code */

static int certImport( const int certNo, const BOOLEAN isBase64 )
	{
	CRYPT_CERTIFICATE cryptCert;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, value, status;

	printf( "Testing %scertificate #%d import...\n",
			isBase64 ? "base64 " : "", certNo );
	filenameFromTemplate( buffer, isBase64 ? BASE64CERT_FILE_TEMPLATE : \
											 CERT_FILE_TEMPLATE, certNo );
	if( ( filePtr = fopen( buffer, "rb" ) ) == NULL )
		{
		puts( "Couldn't find certificate file for import test." );
		return( FALSE );
		}
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );

	/* Import the certificate */
	status = cryptImportCert( buffer, count, CRYPT_UNUSED,
							  &cryptCert );
#ifdef __UNIX__
	if( status == CRYPT_ERROR_NOTAVAIL || status == CRYPT_ERROR_BADDATA )
		{
		puts( "The certificate import failed, probably because you're "
			  "using an\nolder version of unzip that corrupts "
			  "certain types of files when it\nextracts them.  To fix this, "
			  "you need to re-extract test/*.der without\nusing the -a "
			  "option to convert text files.\n" );
		return( TRUE );		/* Skip this test and continue */
		}
#endif /* __UNIX__ */
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() for cert #%d failed with error code %d, "
				"line %d.\n", certNo, status, __LINE__ );
		return( FALSE );
		}
	status = cryptGetAttribute( cryptCert, CRYPT_CERTINFO_SELFSIGNED,
								&value );
	if( cryptStatusError( status ) )
		{
		/* Sanity check to make sure that the cert internal state is 
		   consistent - this should never happen */
		printf( "Couldn't get cert.self-signed status, status %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}
	if( value )
		{
		printf( "Certificate is self-signed, checking signature... " );
		status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
		if( cryptStatusError( status ) )
			{
			int errorLocus;

			printf( "\n" );
			cryptGetAttribute( cryptCert, CRYPT_ATTRIBUTE_ERRORLOCUS,
							   &errorLocus );
			if( errorLocus == CRYPT_CERTINFO_VALIDTO )
				/* Make sure that we don't fail just because the cert we're 
				   using as a test has expired */
				puts( "Validity check failed because the certificate has "
					  "expired." );
			else
				/* RegTP CA certs are marked as non-CA certs, report the
				   problem and continue */
				if( ( certNo == 4 ) && \
					( errorLocus == CRYPT_CERTINFO_CA ) )
					puts( "Validity check failed due to RegTP CA certificate "
						  "incorrectly marked as non-\n  CA certificate." );
				else
					return( attrErrorExit( cryptCert, "cryptCheckCert()",
										   status, __LINE__ ) );
			}
		else
			puts( "signature verified." );
		}
	else
		puts( "Certificate is signed, signature key unknown." );

	/* Print information on what we've got */
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Clean up */
	cryptDestroyCert( cryptCert );
	puts( "Certificate import succeeded.\n" );
	return( TRUE );
	}

#if 0	/* Test rig for NISCC cert data */

static void importTestData( void )
	{
	int i;

	for( i = 1; i <= 110000; i++ )
		{
		CRYPT_CERTIFICATE cryptCert;
		FILE *filePtr;
		BYTE buffer[ BUFFER_SIZE ];
		int count, status;

		if( !( i % 100 ) )
			printf( "%06d\r", i );
/*		filenameFromTemplate( buffer, "/tmp/simple_client/%08d", i ); */
/*		filenameFromTemplate( buffer, "/tmp/simple_server/%08d", i ); */
		filenameFromTemplate( buffer, "/tmp/simple_rootca/%08d", i );
		if( ( filePtr = fopen( buffer, "rb" ) ) == NULL )
			break;
		count = fread( buffer, 1, BUFFER_SIZE, filePtr );
		fclose( filePtr );
		status = cryptImportCert( buffer, count, CRYPT_UNUSED,
								  &cryptCert );
		if( cryptStatusOK( status ) )
			cryptDestroyCert( cryptCert );
		}
	}
#endif /* 0 */

int testCertImport( void )
	{
	int i;

	for( i = 1; i <= 21; i++ )
		if( !certImport( i, FALSE ) )
			return( FALSE );
	return( TRUE );
	}

static int certReqImport( const int certNo )
	{
	CRYPT_CERTIFICATE cryptCert;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, status;

	printf( "Testing certificate request #%d import...\n", certNo );
	filenameFromTemplate( buffer, CERTREQ_FILE_TEMPLATE, certNo );
	if( ( filePtr = fopen( buffer, "rb" ) ) == NULL )
		{
		puts( "Couldn't find certificate file for import test." );
		return( FALSE );
		}
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );

	/* Import the certificate request and check that the signature is valid */
	status = cryptImportCert( buffer, count, CRYPT_UNUSED,
							  &cryptCert );
#ifdef __UNIX__
	if( status == CRYPT_ERROR_NOTAVAIL || status == CRYPT_ERROR_BADDATA )
		{
		puts( "The certificate request import failed, probably because "
			  "you're using an\nolder version of unzip that corrupts "
			  "certain types of files when it\nextracts them.  To fix this, "
			  "you need to re-extract test/*.der without\nusing the -a "
			  "option to convert text files.\n" );
		return( TRUE );		/* Skip this test and continue */
		}
#endif /* __UNIX__ */
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "Checking signature... " );
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );
	puts( "signature verified." );

	/* Print information on what we've got */
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Clean up */
	cryptDestroyCert( cryptCert );
	puts( "Certificate request import succeeded.\n" );
	return( TRUE );
	}

int testCertReqImport( void )
	{
	int i;

	for( i = 1; i <= 2; i++ )
		if( !certReqImport( i ) )
			return( FALSE );
	return( TRUE );
	}

#define LARGE_CRL_SIZE	32767	/* Large CRL is too big for std.buffer */

static int crlImport( const int crlNo, BYTE *buffer )
	{
	CRYPT_CERTIFICATE cryptCert;
	FILE *filePtr;
	int count, status;

	filenameFromTemplate( buffer, CRL_FILE_TEMPLATE, crlNo );
	if( ( filePtr = fopen( buffer, "rb" ) ) == NULL )
		{
		printf( "Couldn't find CRL file for CRL #%d import test.\n", crlNo );
		return( FALSE );
		}
	count = fread( buffer, 1, LARGE_CRL_SIZE, filePtr );
	fclose( filePtr );
	printf( "CRL #%d has size %d bytes.\n", crlNo, count );

	/* Import the CRL.  Since CRL's don't include the signing cert, we can't
	   (easily) check the signature on it */
	status = cryptImportCert( buffer, count, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Print information on what we've got and clean up */
	if( !printCertInfo( cryptCert ) )
		return( FALSE );
	cryptDestroyCert( cryptCert );

	return( TRUE );
	}

int testCRLImport( void )
	{
	BYTE *bufPtr;
	int i;

	puts( "Testing CRL import..." );

	/* Since we're working with an unusually large cert object we have to
	   dynamically allocate the buffer for it */
	if( ( bufPtr = malloc( LARGE_CRL_SIZE ) ) == NULL )
		{
		puts( "Out of memory." );
		return( FALSE );
		}

	for( i = 1; i <= 3; i++ )
		if( !crlImport( i, bufPtr ) )
			return( FALSE );

	/* Clean up */
	free( bufPtr );
	puts( "CRL import succeeded.\n" );
	return( TRUE );
	}

static int certChainImport( const int certNo, const BOOLEAN isBase64 )
	{
	CRYPT_CERTIFICATE cryptCertChain;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, status;

	printf( "Testing %scert chain #%d import...\n",
			isBase64 ? "base64 " : "", certNo );
	filenameFromTemplate( buffer, isBase64 ? BASE64CERTCHAIN_FILE_TEMPLATE : \
											 CERTCHAIN_FILE_TEMPLATE, certNo );
	if( ( filePtr = fopen( buffer, "rb" ) ) == NULL )
		{
		puts( "Couldn't find certificate chain file for import test." );
		return( FALSE );
		}
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	if( count == BUFFER_SIZE )
		{
		puts( "The certificate buffer size is too small for the certificate "
			  "chain.  To fix\nthis, increase the BUFFER_SIZE value in "
			  "test/testcert.c and recompile the code." );
		return( TRUE );		/* Skip this test and continue */
		}
	printf( "Certificate chain has size %d bytes.\n", count );

	/* Import the certificate chain.  This assumes that the default certs are
	   installed as trusted certs, which is required for cryptCheckCert() */
	status = cryptImportCert( buffer, count, CRYPT_UNUSED,
							  &cryptCertChain );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "Checking signatures... " );
	status = cryptCheckCert( cryptCertChain, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
		int trustValue = CRYPT_UNUSED, complianceValue = CRYPT_UNUSED;
		int errorLocus;

		/* If the chain contains a single non-CA cert, we'll get a parameter
		   error since we haven't supplied a signing cert */
		if( status == CRYPT_ERROR_PARAM2 )
			{
			cryptSetAttribute( cryptCertChain, 
							   CRYPT_CERTINFO_CURRENT_CERTIFICATE, 
							   CRYPT_CURSOR_FIRST );
			if( cryptSetAttribute( cryptCertChain, 
								   CRYPT_CERTINFO_CURRENT_CERTIFICATE, 
								   CRYPT_CURSOR_NEXT ) == CRYPT_ERROR_NOTFOUND )
				{
				/* There's only a single cert present, we can't do much with 
				   it, display the info on it and exit */
				puts( "\nCertificate chain contains only a single standalone "
					  "cert, skipping\nsignature check..." );
				if( !printCertChainInfo( cryptCertChain ) )
					return( FALSE );
				cryptDestroyCert( cryptCertChain );
				puts( "Certificate chain import succeeded.\n" );
				return( TRUE );
				}
			}

		/* If it's not a problem with validity, we can't go any further */
		if( status != CRYPT_ERROR_INVALID )
			return( attrErrorExit( cryptCertChain, "cryptCheckCert()", 
								   status, __LINE__ ) );

		/* Check whether the problem is due to an expired cert */
		status = cryptGetAttribute( cryptCertChain, 
									CRYPT_ATTRIBUTE_ERRORLOCUS, 
									&errorLocus );
		if( cryptStatusOK( status ) && \
			errorLocus == CRYPT_CERTINFO_TRUSTED_IMPLICIT )
			{
			/* The error occured because the default certs weren't installed.  
			   Try again with an implicitly-trusted root */
			puts( "\nThe certificate chain didn't verify because you "
				  "haven't installed the\ndefault CA certificates using "
				  "the 'certinst' utility as described in the\nmanual.  "
				  "Checking using implicitly trusted root..." );
			status = setRootTrust( cryptCertChain, &trustValue, 1 );
			if( cryptStatusError( status ) )
				{
				printf( "Attempt to make chain root implicitly trusted "
						"failed, status = %d, line %d.\n", status, 
						__LINE__ );
				return( FALSE );
				}
			status = cryptCheckCert( cryptCertChain, CRYPT_UNUSED );
			if( status == CRYPT_ERROR_INVALID )
				status = cryptGetAttribute( cryptCertChain, 
											CRYPT_ATTRIBUTE_ERRORLOCUS, 
											&errorLocus );
			}
		if( cryptStatusOK( status ) && \
			errorLocus == CRYPT_CERTINFO_VALIDTO )
			{
			/* One (or more) certs in the chain have expired, try again with
			   the compliance level wound down to nothing */
			puts( "The certificate chain didn't verify because one or more "
				  "certificates in it\nhave expired.  Trying again in "
				  "oblivious mode..." );
			cryptGetAttribute( CRYPT_UNUSED, 
							   CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
							   &complianceValue );
			cryptSetAttribute( CRYPT_UNUSED, 
							   CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
							   CRYPT_COMPLIANCELEVEL_OBLIVIOUS );
			status = cryptCheckCert( cryptCertChain, CRYPT_UNUSED );
			}
		if( trustValue != CRYPT_UNUSED )
			setRootTrust( cryptCertChain, NULL, trustValue );
		if( complianceValue != CRYPT_UNUSED )
			cryptSetAttribute( CRYPT_UNUSED, 
							   CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
							   complianceValue );
		if( cryptStatusError( status ) )
			return( attrErrorExit( cryptCertChain, "cryptCheckCert()", status,
								   __LINE__ ) );
		puts( "signatures verified." );
		}
	else
		puts( "signatures verified." );

	/* Display info on each cert in the chain */
	if( !printCertChainInfo( cryptCertChain ) )
		return( FALSE );

	/* Clean up */
	cryptDestroyCert( cryptCertChain );
	puts( "Certificate chain import succeeded.\n" );
	return( TRUE );
	}

int testCertChainImport( void )
	{
	int i;

	for( i = 1; i <= 3; i++ )
		if( !certChainImport( i, FALSE ) )
			return( FALSE );
	return( TRUE );
	}

int testOCSPImport( void )
	{
	CRYPT_CERTIFICATE cryptCert, cryptResponderCert;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, status;

	if( ( filePtr = fopen( convertFileName( OCSP_OK_FILE ), "rb" ) ) == NULL )
		{
		puts( "Couldn't find OCSP OK response file for import test." );
		return( FALSE );
		}
	puts( "Testing OCSP OK response import..." );
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	printf( "OCSP OK response has size %d bytes.\n", count );

	/* Import the OCSP OK response.  Because of the choose-your-own-trust-
	   model status of the OCSP RFC we have to supply our own signature
	   check cert to verify the response */
	status = cryptImportCert( buffer, count, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "Checking signature... " );
	status = importCertFile( &cryptResponderCert, OCSP_CA_FILE );
	if( cryptStatusOK( status ) )
		{
		status = cryptCheckCert( cryptCert, cryptResponderCert );
		cryptDestroyCert( cryptResponderCert );
		}
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );
	puts( "signatures verified." );

	/* Print information on what we've got */
	if( !printCertInfo( cryptCert ) )
		return( FALSE );
	cryptDestroyCert( cryptCert );

	/* Now import the OCSP revoked response.  This has a different CA cert
	   than the OK response, to keep things simple we don't bother with a
	   sig check for this one */
	puts( "Testing OCSP revoked response import..." );
	if( ( filePtr = fopen( convertFileName( OCSP_REV_FILE ), "rb" ) ) == NULL )
		{
		puts( "Couldn't find OCSP revoked response file for import test." );
		return( FALSE );
		}
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	printf( "OCSP revoked response has size %d bytes.\n", count );
	status = cryptImportCert( buffer, count, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Print information on what we've got */
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Clean up */
	cryptDestroyCert( cryptCert );
	puts( "OCSP import succeeded.\n" );
	return( TRUE );
	}

int testBase64CertImport( void )
	{
	int i;

	/* If this is an EBCDIC system, we can't (easily) import the base64-
	   encoded cert without complex calisthenics to handle the different
	   character sets */
#if 'A' == 0xC1
	puts( "Skipping import of base64-encoded data on EBCDIC system.\n" );
	return( TRUE );
#endif /* EBCDIC system */

	for( i = 1; i <= 1; i++ )
		if( !certImport( i, TRUE ) )
			return( FALSE );
	return( TRUE );
	}

int testBase64CertChainImport( void )
	{
	int i;

	/* If this is an EBCDIC system, we can't (easily) import the base64-
	   encoded cert without complex calisthenics to handle the different
	   character sets */
#if 'A' == 0xC1
	puts( "Skipping import of base64-encoded data on EBCDIC system.\n" );
	return( TRUE );
#endif /* EBCDIC system */

	for( i = 1; i <= 1; i++ )
		if( !certChainImport( i, TRUE ) )
			return( FALSE );
	return( TRUE );
	}

static int miscImport( const char *fileName, const char *description )
	{
	CRYPT_CERTIFICATE cryptCert;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, status;

	if( ( filePtr = fopen( fileName, "rb" ) ) == NULL )
		{
		printf( "Couldn't find file for %s key import test.\n", 
				description );
		return( FALSE );
		}
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );

	/* Import the object.  Since this isn't a certificate we can't do much
	   more with it than this - this is only used to test the low-level
	   code and needs to be run inside a debugger, since the call always
	   fails (the data being imported isn't a certificate) */
	status = cryptImportCert( buffer, count, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) && status != CRYPT_ERROR_BADDATA )
		{
		printf( "cryptImportCert() for %s key failed with error code %d, "
				"line %d.\n", description, status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyCert( cryptCert );
	return( TRUE );
	}

int testMiscImport( void )
	{
	BYTE buffer[ BUFFER_SIZE ];
	int i;

	puts( "Testing base64-encoded SSH/PGP key import..." );
	for( i = 1; i <= 2; i++ )
		{
		filenameFromTemplate( buffer, SSHKEY_FILE_TEMPLATE, i );
		if( !miscImport( buffer, "SSH" ) )
			return( FALSE );
		}
	for( i = 1; i <= 3; i++ )
		{
		filenameFromTemplate( buffer, PGPKEY_FILE_TEMPLATE, i );
		if( !miscImport( buffer, "PGP" ) )
			return( FALSE );
		}
	puts( "Import succeeded.\n" );
	return( TRUE );
	}

/* Test cert handling at various levels of compliance */

int testCertComplianceLevel( void )
	{
	CRYPT_CERTIFICATE cryptCert, cryptCaCert;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, value, status;

	cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   &value );

	/* Test import of a broken cert.  First we try it in normal mode, then
	   again in oblivious mode */
	printf( "Testing cert handling at various compliance levels "
			"(current = %d)...\n", value );
	if( ( filePtr = fopen( convertFileName( BROKEN_CERT_FILE ), "rb" ) ) == NULL )
		{
		puts( "Couldn't certificate for import test." );
		return( FALSE );
		}
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	if( value < CRYPT_COMPLIANCELEVEL_PKIX_FULL )
		cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
						   CRYPT_COMPLIANCELEVEL_PKIX_FULL );
	status = cryptImportCert( buffer, count, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusOK( status ) )
		{
		/* Import in normal mode should fail */
		cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
						   value );
		printf( "cryptImportCert() of broken cert succeeded when it should "
				"have failed, line %d.\n", __LINE__ );
		return( FALSE );
		}
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   CRYPT_COMPLIANCELEVEL_STANDARD );
	status = cryptImportCert( buffer, count, CRYPT_UNUSED,
							  &cryptCert );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   value );
	if( cryptStatusError( status ) )
		{
		/* Import in reduced-compliance mode should succeed */
		printf( "cryptImportCert() failed with error code %d, line %d.\n", 
				status, __LINE__ );
		return( FALSE );
		}

	/* Print information on what we've got.  This should only print info for
	   the two basic extensions that are handled in oblivious mode  */
	if( !printCertInfo( cryptCert ) )
		return( FALSE );
	cryptDestroyCert( cryptCert );

	/* Test checking of an expired cert using a broken CA cert in oblivious
	   mode (this checks chaining and the signature, but little else) */
	status = importCertFile( &cryptCert, BROKEN_USER_CERT_FILE );
	if( cryptStatusOK( status ) )
		status = importCertFile( &cryptCaCert, BROKEN_CA_CERT_FILE );
	if( cryptStatusError( status ) )
		{
		printf( "Cert import failed with error code %d, line %d.\n", 
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, cryptCaCert );
	if( cryptStatusOK( status ) )
		{
		/* Checking in normal mode should fail */
		printf( "cryptCheckCert() of broken cert succeeded when it should "
				"have failed, line %d.\n", __LINE__ );
		return( FALSE );
		}
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   CRYPT_COMPLIANCELEVEL_OBLIVIOUS );
	status = cryptCheckCert( cryptCert, cryptCaCert );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   value );
	if( cryptStatusError( status ) )
		{
		/* Checking in oblivious mode should succeed */
		printf( "cryptCheckCert() of broken cert failed when it should "
				"have succeeded, line %d.\n", __LINE__ );
		return( FALSE );
		}
	cryptDestroyCert( cryptCaCert );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	puts( "Certificate handling at different compliance levels succeeded.\n" );
	return( TRUE );
	}

/* Test path processing using the NIST PKI test suite.  This doesn't run all 
   of the tests since some are somewhat redundant (e.g. path length 
   constraints ending at cert n in a chain vs.cert n+1 in a chain where
   both are well short of the constraint length), or require complex 
   additional processing (e.g. CRL fetches) which it's difficult to 
   automate */

typedef struct {
	const int fileMajor, fileMinor;	/* Major and minor number of file */
	const BOOLEAN isValid;			/* Whether path is valid */
	const BOOLEAN policyOptional;	/* Whether explicit policy optional */
	} PATH_TEST_INFO;

static const PATH_TEST_INFO pathTestInfo[] = {
	/* Signature verification */
	/*  0 */ { 1, 1, TRUE },
	/*  1 */ { 1, 2, FALSE },
	/*  2 */ { 1, 3, FALSE },
	/*  3 */ { 1, 4, TRUE },
	/*  4 */ { 1, 6, FALSE },

	/* Validity periods */
	/*  5 */ { 2, 1, FALSE },
	/*  6 */ { 2, 2, FALSE },
	/* The second cert in test 4.2.3 has a validFrom date of 1950, which 
	   cryptlib rejects on import as being not even remotely valid (it can't
	   even be represented in the ANSI/ISO C date format).  Supposedly half-
	   century-old certs are symptomatic of severely broken software, so
	   rejecting this cert is justified */
/*	{ 2, 3, TRUE }, */
	/*  7 */ { 2, 4, TRUE },
	/*  8 */ { 2, 5, FALSE },
	/*  9 */ { 2, 6, FALSE },
	/* 10 */ { 2, 7, FALSE },
	/* 11 */ { 2, 8, TRUE },

	/* Name chaining */
	/* 12 */ { 3, 1, FALSE },
	/* 13 */ { 3, 6, TRUE },
	/* 14 */ { 3, 8, TRUE },
	/* 15 */ { 3, 9, TRUE },

	/* 4 = CRLs */

	/* oldWithNew / newWithOld */
	/* 16 */ { 5, 1, TRUE },
	/* 17 */ { 5, 3, TRUE },

	/* Basic constraints */
	/* 18 */ { 6, 1, FALSE },
	/* 19 */ { 6, 2, FALSE },
	/* 20 */ { 6, 5, FALSE },
	/* 21 */ { 6, 6, FALSE },
	/* 22 */ { 6, 7, TRUE },
	/* The second-to-last cert in the path sets a pathLenConstraint of zero,
	   with the next cert being a CA cert (there's no EE cert present).  
	   cryptlib treats this as invalid since it can never lead to a valid
	   path once the EE cert is added */
	/* 23 */ { 6, 8, FALSE /* TRUE */ },
	/* 24 */ { 6, 9, FALSE },
	/* 25 */ { 6, 11, FALSE },
	/* 26 */ { 6, 12, FALSE },
	/* 27 */ { 6, 13, TRUE },
	/* As for 4.6.8 */
	/* 28 */ { 6, 14, FALSE /* TRUE */ },
	/* The following are 4.5.x-style  oldWithNew / newWithOld, but with path 
	   constraints */
	/* 29 */ { 6, 15, TRUE },
	/* 30 */ { 6, 16, FALSE },
	/* 31 */ { 6, 17, TRUE },

	/* Key usage */
	/* 32 */ { 7, 1, FALSE },
	/* 33 */ { 7, 2, FALSE },

	/* Policies */
	/* The first cert asserts a policy that differs from that of all other
	   certs in the path.  If no explicit policy is required (by setting 
	   CRYPT_OPTION_REQUIREPOLICY to FALSE) it will verify, otherwise it 
	   won't */
	/* 34 */ { 8, 3, TRUE, TRUE },	/* Policy optional */
	/* 35 */ { 8, 3, FALSE },
	/* 36 */ { 8, 4, FALSE },
	/* 37 */ { 8, 6, TRUE },
	/* 38 */ { 8, 10, TRUE },
	/* 39 */ { 8, 11, TRUE },
	/* 40 */ { 8, 14, TRUE },
	/* 41 */ { 8, 15, TRUE },
	/* 42 */ { 8, 20, TRUE },

	/* Policy constraints.  For these tests policy handling is dictated by
	   policy constraints so we don't require explicit policies */
	/* 43 */ { 9, 2, TRUE, TRUE },
	/* The NIST test value for this one is wrong.  RFC 3280 section 4.2.1.12 
	   says:

		If the requireExplicitPolicy field is present, the value of
		requireExplicitPolicy indicates the number of additional 
		certificates that may appear in the path before an explicit policy 
		is required for the entire path.  When an explicit policy is 
		required, it is necessary for all certificates in the path to 
		contain an acceptable policy identifier in the certificate policies 
		extension.

	   Test 4.9.3 has requireExplicitPolicy = 4 in a chain of 4 certs, for 
	   which the last one has no policy.  NIST claims this shouldn't 
	   validate, which is incorrect */
	/* 44 */ { 9, 3, TRUE /* FALSE */, TRUE },
	/* 45 */ { 9, 4, TRUE, TRUE },
	/* 46 */ { 9, 5, FALSE, TRUE },
	/* 47 */ { 9, 6, TRUE, TRUE },
	/* 48 */ { 9, 7, FALSE, TRUE },

	/* 10, 11 = Policy mappings */
	/* 49 */ { 10, 7, FALSE },
	/* 50 */ { 10, 8, FALSE },

	/* Policy inhibitAny */
	/* 51 */ { 12, 1, FALSE },
	/* 52 */ { 12, 2, TRUE },
	/* 53 */ { 12, 3, TRUE },
	/* 54 */ { 12, 4, FALSE },
	/* The NIST test results for 4.12.7 and 4.12.9 are wrong, or more 
	   specifically the PKIX spec is wrong, contradicting itself in the body 
	   of the spec and the path-processing pseudocode, in that there's no 
	   path-kludge exception for policy constraints in the body, but there 
	   is one in the pseudocode.  Since these chains contain path-kludge
	   certs, the paths are invalid - they would only be valid if there was
	   a path-kludge exception for inhibitAnyPolicy.  Note that 4.9.7 and
	   4.9.8 have the same conditions for requireExplicitPolicy, but this 
	   time the NIST test results go the other way.  So although the PKIX 
	   spec is wrong, the NIST test is also wrong in that it applies an
	   inconsistent interpretation of the contradictions in the PKIX spec */
	/* 55 */ { 12, 7, FALSE /* TRUE */ },
	/* 56 */ { 12, 8, FALSE },
	/* 57 */ { 12, 9, FALSE /* TRUE */ },

	/* Name constraints */
	/* 58 */ { 13, 1, TRUE },
	/* 59 */ { 13, 2, FALSE },
	/* 60 */ { 13, 3, FALSE },
	/* 61 */ { 13, 4, TRUE },
	/* 62 */ { 13, 5, TRUE },
	/* 63 */ { 13, 6, TRUE },
	/* 64 */ { 13, 7, FALSE },
	/* 65 */ { 13, 8, FALSE },
	/* 66 */ { 13, 9, FALSE },
	/* 67 */ { 13, 10, FALSE },
	/* 68 */ { 13, 11, TRUE },
	/* 69 */ { 13, 12, FALSE },
	/* 70 */ { 13, 13, FALSE },
	/* 71 */ { 13, 14, TRUE },
	/* 72 */ { 13, 15, FALSE },
	/* 73 */ { 13, 17, FALSE },
	/* 74 */ { 13, 18, TRUE },
	/* 75 */ { 13, 19, TRUE },
	/* 76 */ { 13, 20, FALSE },
	/* 77 */ { 13, 21, TRUE },
	/* 78 */ { 13, 22, FALSE },
	/* 79 */ { 13, 23, TRUE },
	/* 80 */ { 13, 24, FALSE },
	/* 81 */ { 13, 25, TRUE },
	/* 82 */ { 13, 26, FALSE },
	/* 83 */ { 13, 27, TRUE },
	/* 84 */ { 13, 28, FALSE },
	/* 85 */ { 13, 29, FALSE },
	/* 86 */ { 13, 30, TRUE },
	/* 87 */ { 13, 31, FALSE },
	/* 88 */ { 13, 32, TRUE },
	/* 89 */ { 13, 33, FALSE },
	/* 90 */ { 13, 34, TRUE },
	/* 91 */ { 13, 35, FALSE },
	/* 92 */ { 13, 36, TRUE },
	/* 93 */ { 13, 37, FALSE },
	/* The NIST test results for 4.13.38 are wrong.  PKIX section 4.2.1.11
	   says:

		DNS name restrictions are expressed as foo.bar.com.  Any DNS name
		that can be constructed by simply adding to the left hand side of 
		the name satisfies the name constraint.  For example, 
		www.foo.bar.com would satisfy the constraint but foo1.bar.com would 
		not.

	   The permitted subtree is testcertificates.gov and the altName is
	   mytestcertificates.gov, which satisfies the above rule, so the path
	   should be valid and not invalid */
	/* 94 */ { 13, 38, TRUE /* FALSE */ },

	/* 14, 15 = CRLs */

	/* Private cert extensions */
	/* 95 */ { 16, 1, TRUE },
	/* 96 */ { 16, 2, FALSE },
	{ 0, 0 }
	};

static int testPath( const PATH_TEST_INFO *pathInfo )
	{
	CRYPT_CERTIFICATE cryptCertPath;
	char pathName[ 64 ];
	int pathNo, requirePolicy, status;

	/* Convert the composite path info into a single number used for fetching
	   the corresponding data file */
	sprintf( pathName, "4%d%d", pathInfo->fileMajor, pathInfo->fileMinor );
	pathNo = atoi( pathName );

	/* Test the path */
	sprintf( pathName, "4.%d.%d", pathInfo->fileMajor, pathInfo->fileMinor );
	printf( "  Path %s%s...", pathName, pathInfo->policyOptional ? \
			" without explicit policy" : "" );
	status = importCertFromTemplate( &cryptCertPath, 
									 PATHTEST_FILE_TEMPLATE, pathNo );
	if( cryptStatusError( status ) )
		{
		printf( "Cert import for test path %s failed, line %d.\n",
				pathName, __LINE__ );
		return( FALSE );
		}
	if( pathInfo->policyOptional )
		{
		/* By default we require policy chaining, for some tests we can turn 
		   this off to check non-explict policy processing */
		cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_REQUIREPOLICY, 
						   &requirePolicy );
		assert( requirePolicy != FALSE );
		cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_REQUIREPOLICY, 
						   FALSE );
		}
	status = cryptCheckCert( cryptCertPath, CRYPT_UNUSED );
	if( pathInfo->policyOptional )
		cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_REQUIREPOLICY, 
						   requirePolicy );
	if( pathInfo->isValid )
		{
		if( cryptStatusError( status ) )
			{
			puts( " didn't verify even though it should be valid." );
			return( attrErrorExit( cryptCertPath, "cryptCheckCert()", 
								   status, __LINE__ ) );
			}
		}
	else
		if( cryptStatusOK( status ) )
			{
			puts( " verified even though it should have failed." );
			return( FALSE );
			}
	puts( " succeeded." );
	cryptDestroyCert( cryptCertPath );

	return( TRUE );
	}

int testPathProcessing( void )
	{
	CRYPT_CERTIFICATE cryptRootCert;
	int certTrust, complianceLevel, i, status;

	puts( "Testing path processing..." );

	/* Get the root cert and make it implicitly trusted and crank the 
	   compliance level up to maximum, since we're going to be testing some
	   pretty obscure extensions */
	status = importCertFromTemplate( &cryptRootCert, 
									 PATHTEST_FILE_TEMPLATE, 0 );
	if( cryptStatusOK( status ) )
		status = setRootTrust( cryptRootCert, &certTrust, 1 );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't create trusted root cert for path processing, "
				"line %d.\n", __LINE__ );
		return( FALSE );
		}
	cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   &complianceLevel );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   CRYPT_COMPLIANCELEVEL_PKIX_FULL );

	/* Process each cert path and make sure that it succeeds or fails as 
	   required */
	for( i = 0; pathTestInfo[ i ].fileMajor; i++ )
		if( !testPath( &pathTestInfo[ i ] ) )
			break;
	setRootTrust( cryptRootCert, NULL, certTrust );
	cryptDestroyCert( cryptRootCert );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL, 
					   complianceLevel );
	if( pathTestInfo[ i ].fileMajor )
		return( FALSE );

	puts( "Path processing succeeded." );
	return( TRUE );
	}

/* Generic test routines used for debugging.  These are only meant to be 
   used interactively, and throw exceptions rather than returning status 
   values */

void xxxCertImport( const char *fileName )
	{
	CRYPT_CERTIFICATE cryptCert;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, status;

	filePtr = fopen( fileName, "rb" );
	assert( filePtr != NULL );
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	status = cryptImportCert( buffer, count, CRYPT_UNUSED, &cryptCert );
	assert( cryptStatusOK( status ) );
	cryptDestroyCert( cryptCert );
	}

/****************************************************************************
*																			*
*							Certificate Processing Test						*
*																			*
****************************************************************************/

static const CERT_DATA certProcessData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Smith" ) },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, TEXT( "dave@wetas-r-us.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.wetas-r-us.com" ) },

	/* Re-select the subject name after poking around in the altName */
	{ CRYPT_CERTINFO_SUBJECTNAME, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

/* Create a certification request */

static int createCertRequest( void *certRequest,
							  const CRYPT_ALGO_TYPE cryptAlgo,
							  const BOOLEAN useCRMF )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT cryptContext;
	int length, status;

	/* Create a new key */
	cryptCreateContext( &cryptContext, CRYPT_UNUSED, cryptAlgo );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL,
							 TEXT( "Private key" ), 
							 paramStrlen( TEXT( "Private key" ) ) );
	cryptSetAttribute( cryptContext, CRYPT_CTXINFO_KEYSIZE, 64 );
	status = cryptGenerateKey( cryptContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the certification request */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED, useCRMF ? \
				CRYPT_CERTTYPE_REQUEST_CERT : CRYPT_CERTTYPE_CERTREQUEST );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusError( status ) )
		return( status );
	if( !addCertFields( cryptCert, complexCertRequestData ) )
		return( -1 );
#ifndef _WIN32_WCE
	if( useCRMF )
		{
		const time_t startTime = time( NULL ) - 1000;
		const time_t endTime = time( NULL ) + 86400;

		/* Since we're using a CRMF request, set some fields that can't
		   be specified in the standard cert request */
		status = cryptSetAttributeString( cryptCert,
					CRYPT_CERTINFO_VALIDFROM, &startTime, sizeof( time_t ) );
		if( cryptStatusOK( status ) )
			status = cryptSetAttributeString( cryptCert,
					CRYPT_CERTINFO_VALIDTO, &endTime, sizeof( time_t ) );
		}
#endif /* _WIN32_WCE */
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, cryptContext );
	if( cryptStatusOK( status ) )
		status = cryptExportCert( certRequest, BUFFER_SIZE, &length,
								  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusOK( status ) )
		status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		return( status );

	/* Clean up */
	cryptDestroyContext( cryptContext );
	return( length );
	}

/* Create a certificate from a cert request */

static int createCertificate( void *certificate, const void *certRequest,
							  const int certReqLength,
							  const CRYPT_CONTEXT caKeyContext )
	{
	CRYPT_CERTIFICATE cryptCert, cryptCertRequest;
	int length, status;

	/* Import and verify the certification request */
	status = cryptImportCert( certRequest, certReqLength, CRYPT_UNUSED,
							  &cryptCertRequest );
	if( cryptStatusOK( status ) )
		status = cryptCheckCert( cryptCertRequest, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_CERTREQUEST, cryptCertRequest );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, caKeyContext );
	if( cryptStatusOK( status ) )
		status = cryptExportCert( certificate, BUFFER_SIZE, &length,
								  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusOK( status ) )
		status = cryptDestroyCert( cryptCert );

	/* Clean up */
	cryptDestroyCert( cryptCertRequest );
	return( ( cryptStatusOK( status ) ) ? length : status );
	}

/* Create a certificate directly, used for algorithms that don't support
   self-signed cert requests */

static int createCertDirect( void *certificate,
							 const CRYPT_ALGO_TYPE cryptAlgo,
							 const CRYPT_CONTEXT caKeyContext )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT cryptContext;
	int length, status;

	/* Create a new key */
	cryptCreateContext( &cryptContext, CRYPT_UNUSED, cryptAlgo );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL,
							 TEXT( "Private key" ), 
							 paramStrlen( TEXT( "Private key" ) ) );
	cryptSetAttribute( cryptContext, CRYPT_CTXINFO_KEYSIZE, 64 );
	status = cryptGenerateKey( cryptContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the certification */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusError( status ) )
		return( status );
	if( !addCertFields( cryptCert, certProcessData ) )
		return( FALSE );
	status = cryptSignCert( cryptCert, caKeyContext );
	if( cryptStatusOK( status ) )
		status = cryptExportCert( certificate, BUFFER_SIZE, &length,
								  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusOK( status ) )
		status = cryptDestroyCert( cryptCert );

	/* Clean up */
	cryptDestroyContext( cryptContext );
	return( ( cryptStatusOK( status ) ) ? length : status );
	}

/* Test the full certification process */

static int certProcess( const CRYPT_ALGO_TYPE cryptAlgo,
						const char *algoName,
						const CRYPT_CONTEXT cryptCAKey,
						const BOOLEAN useCRMF )
	{
	CRYPT_CERTIFICATE cryptCert;
	const char *certName = \
			( cryptAlgo == CRYPT_ALGO_RSA ) ? \
				( useCRMF ? "prcrtrsa_c" : "prcrtrsa" ) : \
			( cryptAlgo == CRYPT_ALGO_DSA ) ? "prcrtdsa" : \
			( cryptAlgo == CRYPT_ALGO_DH ) ? "prcrtdh" : \
			( cryptAlgo == CRYPT_ALGO_ELGAMAL ) ? "prcrtelg" : "prcrtxxx";
	int length, status;

	printf( "Testing %s certificate processing%s...\n", algoName,
			useCRMF ? " from CRMF request" : "" );

	/* Some algorithms can't create self-signed cert requests so we have to
	   create the cert directly */
	if( cryptAlgo != CRYPT_ALGO_ELGAMAL && cryptAlgo != CRYPT_ALGO_DH )
		{
		const char *reqName = \
			( cryptAlgo == CRYPT_ALGO_RSA ) ? \
				( useCRMF ? "prreqrsa_c" : "prreqrsa" ) : \
			( cryptAlgo == CRYPT_ALGO_DSA ) ? "prreqdsa" : \
			( cryptAlgo == CRYPT_ALGO_DH ) ? "prreqdh" : \
			( cryptAlgo == CRYPT_ALGO_ELGAMAL ) ? "prreqelg" : "prreqxxx";

		/* Create the certification request */
		status = length = createCertRequest( certBuffer, cryptAlgo, useCRMF );
		if( cryptStatusError( status ) )
			{
			printf( "Certification request creation failed with error code "
					"%d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		debugDump( reqName, certBuffer, length );

		/* Create a certificate from the certification request */
		status = createCertificate( certBuffer, certBuffer, length,
									cryptCAKey );
		}
	else
		status = createCertDirect( certBuffer, cryptAlgo, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate creation failed with error code %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}
	length = status;
	debugDump( certName, certBuffer, length );

	/* Import the certificate and check its validity using the CA key (we use
	   the private key context since it's handy, in practice we should use
	   the public key certificate */
	status = cryptImportCert( certBuffer, length, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusOK( status ) )
		status = cryptCheckCert( cryptCert, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate validation failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyCert( cryptCert );
	printf( "%s certificate processing succeeded.\n\n", algoName );
	return( TRUE );
	}

int testCertProcess( void )
	{
	CRYPT_CONTEXT cryptCAKey;
	int status;

	/* Get the CA's private key */
	status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "CA private key read failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Test each PKC algorithm */
	if( !certProcess( CRYPT_ALGO_RSA, "RSA", cryptCAKey, FALSE ) )
		return( FALSE );
	if( !certProcess( CRYPT_ALGO_DSA, "DSA", cryptCAKey, FALSE ) )
		return( FALSE );
	if( !certProcess( CRYPT_ALGO_ELGAMAL, "Elgamal", cryptCAKey, FALSE ) )
		return( FALSE );
	if( !certProcess( CRYPT_ALGO_DH, "Diffie-Hellman", cryptCAKey, FALSE ) )
		return( FALSE );

	/* Run the test again with a CRMF instead of PKCS #10 request */
	if( !certProcess( CRYPT_ALGO_RSA, "RSA", cryptCAKey, TRUE ) )
		return( FALSE );

	/* Clean up */
	cryptDestroyContext( cryptCAKey );
	return( TRUE );
	}

/****************************************************************************
*																			*
*							CA Certificate Management Test					*
*																			*
****************************************************************************/

/* Since opening the cert store for update creates a log entry each time,
   we open it once at the start and then call a series of sub-tests with
   the store open throughout the tests.  This also allows us to keep the
   CA key active througout */

static const CERT_DATA cert1Data[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Test user 1" ) },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, TEXT( "test1@testusers.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.wetas-r-us.com" ) },

	/* Re-select the subject name after poking around in the altName */
	{ CRYPT_CERTINFO_SUBJECTNAME, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};
static const CERT_DATA revokableCert1Data[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Revoked cert user 1" ) },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, TEXT( "test2@testusers.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.wetas-r-us.com" ) },

	/* Re-select the subject name after poking around in the altName */
	{ CRYPT_CERTINFO_SUBJECTNAME, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};
static const CERT_DATA revokableCert2Data[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Revoked cert user 2" ) },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, TEXT( "revoked1@testusers.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.wetas-r-us.com" ) },

	/* Re-select the subject name after poking around in the altName */
	{ CRYPT_CERTINFO_SUBJECTNAME, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};
static const CERT_DATA expiredCert1Data[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Expired cert user 1" ) },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, TEXT( "revoked2@testusers.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.wetas-r-us.com" ) },

	/* Re-select the subject name after poking around in the altName */
	{ CRYPT_CERTINFO_SUBJECTNAME, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};
static const CERT_DATA expiredCert2Data[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Expired cert user 2" ) },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, TEXT( "expired2@testusers.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.wetas-r-us.com" ) },

	/* Re-select the subject name after poking around in the altName */
	{ CRYPT_CERTINFO_SUBJECTNAME, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};
static const CERT_DATA certCAData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Test CA user" ) },

	/* CA extensions.  These should be rejected/stripped by the cert 
	   management code, since new CAs can only be created by the issuing CA
	   specifying it in the PKI user info */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

/* Add a certification request to the cert store */

static int addCertRequest( const CRYPT_KEYSET cryptCertStore,
						   const CERT_DATA *certReqData,
						   const BOOLEAN isExpired )
	{
	CRYPT_CONTEXT cryptContext;
	CRYPT_CERTIFICATE cryptCertRequest;
	int length, status;

	/* Generate a (short) key for the request */
	cryptCreateContext( &cryptContext, CRYPT_UNUSED, CRYPT_ALGO_RSA );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL,
							 TEXT( "Private key" ), 
							 paramStrlen( TEXT( "Private key" ) ) );
	cryptSetAttribute( cryptContext, CRYPT_CTXINFO_KEYSIZE, 64 );
	status = cryptGenerateKey( cryptContext );
	if( cryptStatusError( status ) )
		{
		printf( "Creation of private key for cert failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Create the certification request.  If we're adding an expiry time
	   we have to make it a CRMF request since a standard request can't
	   handle this */
	status = cryptCreateCert( &cryptCertRequest, CRYPT_UNUSED, isExpired ? \
					CRYPT_CERTTYPE_REQUEST_CERT : CRYPT_CERTTYPE_CERTREQUEST );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptCertRequest,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
#ifndef _WIN32_WCE
	if( cryptStatusOK( status ) && isExpired )
		{
		const time_t theTime = time( NULL ) + 5;

		/* Set the expiry time to a few seconds after the current time to
		   ensure that the cert has expired by the time we need it.  This 
		   is a tiny bit risky since it requires that the interval between
		   setting this attribute and the creation of the cert below is
		   less than five seconds, however there's no easy way to guarantee
		   the creation of a pre-expired cert since if we set the time too
		   far back it won't be created */
		status = cryptSetAttributeString( cryptCertRequest,
					CRYPT_CERTINFO_VALIDTO, &theTime, sizeof( time_t ) );
		}
#endif /* _WIN32_WCE */
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCertRequest, "cryptSetAttribute()",
							   status, __LINE__ ) );
	if( !addCertFields( cryptCertRequest, certReqData ) )
		return( FALSE );
	status = cryptSignCert( cryptCertRequest, cryptContext );
	cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCertRequest, "cryptSignCert()",
							   status, __LINE__ ) );

	/* Export the request, destroy it, and recreate it by importing it again.
	   This is just a pedantic check to make sure that we emulate exactly a
	   real-world scenario of an externally-obtained request */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &length,
							  CRYPT_CERTFORMAT_CERTIFICATE,
							  cryptCertRequest );
	cryptDestroyCert( cryptCertRequest );
	if( cryptStatusOK( status ) )
		status = cryptImportCert( certBuffer, length, CRYPT_UNUSED,
								  &cryptCertRequest );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't export/re-import cert request, status = %d.\n",
				status );
		return( FALSE );
		}

	/* Add the request to the cert store */
	status = cryptCAAddItem( cryptCertStore, cryptCertRequest );
	if( cryptStatusError( status ) )
		return( extErrorExit( cryptCertStore, "cryptCAAddItem()", status,
							  __LINE__ ) );

	return( cryptCertRequest );
	}

/* Add a revocation request to the cert store.  This code isn't currently
   used because CMP doesn't allow revocation requests to be signed, so we
   can't create a signed object to add directly but have to come in via
   CMP */

#if 0

static int addRevRequest( const CRYPT_KEYSET cryptCertStore,
						  const CERT_DATA *certReqData )
	{
	CRYPT_CERTIFICATE cryptCert, cryptCertRequest;
	int i, status;

	/* Find the CN of the cert we're revoking and use it to fetch the cert */
	for( i = 0; certReqData[ i ].componentType != CRYPT_ATTRIBUTE_NONE; i++ )
		if( certReqData[ i ].type == CRYPT_CERTINFO_COMMONNAME )
			printf( "Revoking certificate for '%s'.\n",
					( char * ) certReqData[ i ].stringValue );
	status = cryptGetPublicKey( cryptCertStore, &cryptCert, CRYPT_KEYID_NAME,
								certReqData[ i ].stringValue );
	if( cryptStatusError( status ) )
		return( extErrorExit( cryptCertStore, "cryptGetPublicKey()", status,
							  __LINE__ ) );

	/* Create the revocation request */
	status = cryptCreateCert( &cryptCertRequest, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_REQUEST_REVOCATION );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptCertRequest, CRYPT_CERTINFO_CERTIFICATE,
								cryptCert );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCertRequest, "cryptSetAttribute()",
							   status, __LINE__ ) );
	if( !addCertFields( cryptCertRequest, revRequestData ) )
		return( FALSE );

	/* Add the request to the cert store */
	status = cryptCAAddItem( cryptCertStore, cryptCertRequest );
	if( cryptStatusError( status ) )
		return( extErrorExit( cryptCertStore, "cryptCAAddItem()", status,
							  __LINE__ ) );

	return( cryptCertRequest );
	}
#endif /* 0 */

/* Issue a certificate from a cert request */

static int issueCert( const CRYPT_KEYSET cryptCertStore,
					  const CRYPT_CONTEXT cryptCAKey,
					  const CERT_DATA *certReqData, const BOOLEAN isExpired,
					  const BOOLEAN issueShouldFail )
	{
	CRYPT_CERTIFICATE cryptCertRequest;
	int i, status;

	/* Provide some feedback on what we're doing */
	for( i = 0; certReqData[ i ].componentType != CRYPT_ATTRIBUTE_NONE; i++ )
		if( certReqData[ i ].type == CRYPT_CERTINFO_COMMONNAME )
			printf( "Issuing certificate for '%s'.\n",
					( char * ) certReqData[ i ].stringValue );

	/* Issue the cert via the cert store */
	cryptCertRequest = addCertRequest( cryptCertStore, certReqData, isExpired );
	if( !cryptCertRequest )
		return( FALSE );
	status = cryptCACertManagement( NULL, CRYPT_CERTACTION_ISSUE_CERT,
									cryptCertStore, cryptCAKey,
									cryptCertRequest );
	cryptDestroyCert( cryptCertRequest );
	if( cryptStatusError( status ) )
		{
		if( issueShouldFail )
			/* If this is a check of the request validity-checking system, 
			   the issue is supposed to fail */
			return( TRUE );
		if( isExpired && status == CRYPT_ERROR_INVALID )
			{
			puts( "The short-expiry-time certificate has already expired at "
				  "the time of issue.\nThis happened because there was a "
				  "delay of more than 5s between adding the\nrequest and "
				  "issuing the certificate for it.  Try re-running the test "
				  "on a\nless-heavily-loaded system, or increase the expiry "
				  "delay to more than 5s." );
			return( FALSE );
			}
		return( extErrorExit( cryptCertStore, "cryptCACertManagement()", 
							  status, __LINE__ ) );
		}

	return( issueShouldFail ? FALSE : TRUE );
	}

/* Issue a CRL.  Although we can't do this directly (see the comment above
   for the revocation request code) we can at least test the ability to
   create an empty CRL (and if the CMP code has been run there will probably
   be a few revocation entries present to fill the CRL) */

static int issueCRL( const CRYPT_KEYSET cryptCertStore,
					 const CRYPT_CONTEXT cryptCAKey )
	{
	CRYPT_CERTIFICATE cryptCRL;
	int noEntries = 0, status;

	/* Issue the CRL via the cert store */
	status = cryptCACertManagement( &cryptCRL, CRYPT_CERTACTION_ISSUE_CRL,
									cryptCertStore, cryptCAKey,
									CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( extErrorExit( cryptCertStore, "cryptCACertManagement()", 
							  status, __LINE__ ) );

	/* Print information on the CRL */
	if( cryptStatusOK( cryptSetAttribute( cryptCRL,
										  CRYPT_CERTINFO_CURRENT_CERTIFICATE,
										  CRYPT_CURSOR_FIRST ) ) )
		do
			noEntries++;
		while( cryptSetAttribute( cryptCRL,
								  CRYPT_CERTINFO_CURRENT_CERTIFICATE,
								  CRYPT_CURSOR_NEXT ) == CRYPT_OK );
	printf( "CRL has %d entr%s.\n", noEntries, 
			( noEntries == 1 ) ? "y" : "ies" );
	if( !noEntries )
		puts( "  (This is probably because there haven't been any revocation "
			  "entries added\n   via the CMP test yet)." );

	/* Clean up */
	cryptDestroyCert( cryptCRL );
	return( TRUE );
	}

/* Fetch the issued cert that was created from a given cert template */

static CRYPT_CERTIFICATE getCertFromTemplate( const CRYPT_KEYSET cryptCertStore,
											  const CERT_DATA *certReqData )
	{
	CRYPT_CERTIFICATE cryptCert;
	int i, status;

	for( i = 0; certReqData[ i ].componentType != CRYPT_ATTRIBUTE_NONE; i++ )
		if( certReqData[ i ].type == CRYPT_CERTINFO_COMMONNAME )
			break;
	status = cryptGetPublicKey( cryptCertStore, &cryptCert, CRYPT_KEYID_NAME,
							    certReqData[ i ].stringValue );
	return( cryptStatusOK( status ) ? cryptCert : status );
	}

int testCertManagement( void )
	{
	CRYPT_CERTIFICATE cryptCert, cryptCertRequest;
	CRYPT_CONTEXT cryptCAKey;
	CRYPT_KEYSET cryptCertStore;
	time_t certTime;
	int dummy, status;

	puts( "Testing certificate management using cert store..." );

	/* Get the CA's private key */
	status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "CA private key read failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Create the cert store keyset with a check to make sure that this 
	   access method exists so we can return an appropriate error message.  
	   If the database table already exists, this will return a duplicate 
	   data error so we retry the open with no flags to open the existing 
	   database keyset for write access */
	status = cryptKeysetOpen( &cryptCertStore, CRYPT_UNUSED,
							  CERTSTORE_KEYSET_TYPE, CERTSTORE_KEYSET_NAME,
							  CRYPT_KEYOPT_CREATE );
	if( cryptStatusOK( status ) )
		puts( "Created new certificate store '" CERTSTORE_KEYSET_NAME_ASCII 
			  "'." );
	if( status == CRYPT_ERROR_PARAM3 )
		{
		/* This type of keyset access isn't available, return a special error
		   code to indicate that the test wasn't performed, but that this
		   isn't a reason to abort processing */
		cryptDestroyContext( cryptCAKey );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	if( status == CRYPT_ERROR_DUPLICATE )
		status = cryptKeysetOpen( &cryptCertStore, CRYPT_UNUSED,
								  CERTSTORE_KEYSET_TYPE, CERTSTORE_KEYSET_NAME,
								  CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		if( status == CRYPT_ERROR_OPEN )
			{
			cryptDestroyContext( cryptCAKey );
			return( CRYPT_ERROR_FAILED );
			}
		return( FALSE );
		}

	/* Create a cert request, add it to the store, and destroy it, simulating
	   a delayed cert issue in which the request can't immediately be
	   converted into a cert.  Then read the request back from the store and
	   issue a certificate based on it */
	puts( "Issuing certificate for 'Test user 1'..." );
	cryptCertRequest = addCertRequest( cryptCertStore, cert1Data, FALSE );
	if( !cryptCertRequest )
		return( FALSE );
	cryptDestroyCert( cryptCertRequest );
	status = cryptCAGetItem( cryptCertStore, &cryptCertRequest,
							 CRYPT_CERTTYPE_REQUEST_CERT, CRYPT_KEYID_NAME,
							 TEXT( "Test user 1" ) );
	if( cryptStatusError( status ) )
		return( extErrorExit( cryptCertStore, "cryptCAGetItem()", status,
							  __LINE__ ) );
	status = cryptCACertManagement( &cryptCert, CRYPT_CERTACTION_ISSUE_CERT,
									cryptCertStore, cryptCAKey,
									cryptCertRequest );
	cryptDestroyCert( cryptCertRequest );
	if( cryptStatusError( status ) )
		return( extErrorExit( cryptCertStore, "cryptCACertManagement()",
							  status, __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Issue some more certs, this time directly from the request and without
	   bothering to obtain the resulting cert.  The first two have a validity
	   time that expires in a few seconds so that we can use them to test
	   cert expiry processing, we issue these first to ensure that as much
	   time as possible passes due to other operations occurring before we
	   run the expiry.  The second two are for revocation and CRL testing */
	if( !issueCert( cryptCertStore, cryptCAKey, expiredCert1Data, TRUE, FALSE ) )
		return( FALSE );
	if( !issueCert( cryptCertStore, cryptCAKey, expiredCert2Data, TRUE, FALSE ) )
		return( FALSE );
	if( !issueCert( cryptCertStore, cryptCAKey, revokableCert1Data, FALSE, FALSE ) )
		return( FALSE );
	if( !issueCert( cryptCertStore, cryptCAKey, revokableCert2Data, FALSE, FALSE ) )
		return( FALSE );

	/* The following tests are specifically inserted at this point (rather 
	   than at some other point in the test run) because they'll add some 
	   further delay before the expiry operation */

	/* Try and get a CA cert issued.  This should fail, since new CAs can 
	   only be created if the issuing CA specifies it (either directly when 
	   it creates the cert manually or via the PKI user info), but never at 
	   the request of the user */
	if( !issueCert( cryptCertStore, cryptCAKey, certCAData, FALSE, TRUE ) )
		{
		printf( "Issue of cert from invalid request succeeded when it "
				"should have failed,\nline %d.\n", __LINE__ );
		return( FALSE );
		}

	/* Get a cert and (to-be-)revoked cert from the store and save them to
	   disk for later tests */
	status = cryptCert = getCertFromTemplate( cryptCertStore, cert1Data );
	if( !cryptStatusError( status ) )
		{
		BYTE fileName[ BUFFER_SIZE ];
		FILE *filePtr;
		int length;

		filenameFromTemplate( fileName, OCSP_EEOK_FILE_TEMPLATE, 1 );
		cryptExportCert( certBuffer, BUFFER_SIZE, &length, 
						 CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
		if( ( filePtr = fopen( fileName, "wb" ) ) != NULL )
			{
			fwrite( certBuffer, length, 1, filePtr );
			fclose( filePtr );
			}
		cryptDestroyCert( cryptCert );
		}
	if( !cryptStatusError( status ) )
		status = cryptCert = getCertFromTemplate( cryptCertStore,
												  revokableCert1Data );
	if( !cryptStatusError( status ) )
		{
		BYTE fileName[ BUFFER_SIZE ];
		FILE *filePtr;
		int length;

		filenameFromTemplate( fileName, OCSP_EEREV_FILE_TEMPLATE, 1 );
		cryptExportCert( certBuffer, BUFFER_SIZE, &length, 
						 CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
		if( ( filePtr = fopen( fileName, "wb" ) ) != NULL )
			{
			fwrite( certBuffer, length, 1, filePtr );
			fclose( filePtr );
			}
		cryptDestroyCert( cryptCert );
		}
	if( cryptStatusError( status ) )
		puts( "Issued certificates couldn't be fetched from the cert store "
			  "and written to\ndisk, the OCSP server test will abort when it "
			  "fails to find these\ncertificates." );

	/* Issue a CRL.  This will probably be a zero-length CRL unless we've run
	   the CMP tests because we can't directly revoke a cert.  Again, we
	   perform it before the expiry test because it'll add some further
	   delay */
	if( !issueCRL( cryptCertStore, cryptCAKey ) )
		return( FALSE );

	/* Get the most recent of the expired certs and wait for it to expire
	   if necessary */
	status = cryptCert = getCertFromTemplate( cryptCertStore,
											  expiredCert1Data );
	if( !cryptStatusError( status ) )
		status = cryptGetAttributeString( cryptCert, CRYPT_CERTINFO_VALIDTO,
										  &certTime, &dummy );
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't get expiry information for expired cert." );
		return( FALSE );
		}
#ifndef _WIN32_WCE
	if( certTime >= time( NULL ) )
		{
		printf( "Waiting for certificates to expire.." );
		while( certTime >= time( NULL ) )
			{
			delayThread( 1 );
			printf( "." );
			}
		puts( " done." );
		}
#endif /* _WIN32_WCE */
	cryptDestroyCert( cryptCert );

	/* Expire the certs */
	puts( "Expiring certificates..." );
	status = cryptCACertManagement( NULL, CRYPT_CERTACTION_EXPIRE_CERT,
									cryptCertStore, CRYPT_UNUSED,
									CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( extErrorExit( cryptCertStore, "cryptCACertManagement()",
							  status, __LINE__ ) );

	/* Clean up */
	cryptDestroyContext( cryptCAKey );
	cryptKeysetClose( cryptCertStore );
	puts( "Certificate management using cert store succeeded.\n" );
	return( TRUE );
	}
