/****************************************************************************
*																			*
*						cryptlib LDAP Mapping Routines						*
*					  Copyright Peter Gutmann 1998-2002						*
*																			*
****************************************************************************/

/* The following code can be built to use the Netscape or Windows LDAP
   clients.  By default the Windows client is used under Windows and the
   Netscape client is used elsewhere, this can be overridden by defining
   NETSCAPE_CLIENT which causes the Netscape client to be used in all
   cases.  The Windows client appears to be considerably more buggy than
   the Netscape one, so if you get data corruption and other problems try
   switching to the Netscape client (see the comment next to ber_free() for
   more details on some of these problems).

   A generalisation of this is that you shouldn't be using LDAP for
   certificate storage at all unless you're absolutely forced to.  LDAP
   is a truly awful mechanism for storing and retrieving certificates,
   technical reasons for this may be found in the Godzilla crypto tutorial
   and in any database text written within the last 20 years */

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "keyset.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
#endif /* Compiler-specific includes */

#ifdef USE_LDAP

/* LDAP requires us to set up complicated structures to handle DN's.  The
   following values define the upper limit for DN string data and the
   maximum number of attributes we write to a directory */

#define MAX_DN_STRINGSIZE		1024
#define MAX_LDAP_ATTRIBUTES		20

/* These should really be taken from the system include directory but this
   leads to too many complaints from people who don't read the LDAP
   installation section of the manual */

#if defined( __WINDOWS__ ) && !defined( NETSCAPE_CLIENT )
  /* cryptlib.h includes a trap for inclusion of wincrypt.h before 
     cryptlib.h which results in a compiler error if both files are 
	 included.  To disable this, we need to undefine the CRYPT_MODE_ECB 
	 defined in cryptlib.h */
  #undef CRYPT_MODE_ECB
  #include <winldap.h>
  #define LDAP_API		LDAPAPI		/* Windows LDAP API type */
  #define timeval		l_timeval	/* Windows uses nonstandard name */
#else
  #define NETSCAPE_CLIENT			/* Force use of Netscape on non-Win.sys.*/
  #if defined( INC_ALL ) || defined( INC_CHILD )
	#include "ldap.h"
  #else
	#include "keyset/ldap.h"
  #endif /* Compiler-specific includes */
  #define LDAP_API		LDAP_CALL	/* Netscape LDAP API type */
  #define ber_free		ldap_ber_free	/* Netscape uses nonstandard name */
#endif /* Windows vs Netscape client */

/****************************************************************************
*																			*
*						 	Windows Init/Shutdown Routines					*
*																			*
****************************************************************************/

#ifdef __WINDOWS__

/* Global function pointers.  These are necessary because the functions need
   to be dynamically linked since few older systems contain the necessary
   DLL's (LDAP?  Get real).  Explicitly linking to them will make cryptlib
   unloadable on most systems */

#define NULL_HINSTANCE	( HINSTANCE ) NULL

static HINSTANCE hLDAP = NULL_HINSTANCE;

typedef void ( LDAP_API *BER_FREE )( BerElement *ber, int freebuf );
typedef int ( LDAP_API *LDAP_ADD_S )( LDAP *ld, const char *dn, LDAPMod **attrs );
typedef int ( LDAP_API *LDAP_DELETE_S )( LDAP *ld, const char *dn );
typedef char * ( LDAP_API *LDAP_ERR2STRING )( int err );
typedef char * ( LDAP_API *LDAP_FIRST_ATTRIBUTE )( LDAP *ld, LDAPMessage *entry,
										  BerElement **ber );
typedef LDAPMessage * ( LDAP_API *LDAP_FIRST_ENTRY )( LDAP *ld, LDAPMessage *result );
#ifdef NETSCAPE_CLIENT
  typedef int ( LDAP_API *LDAP_GET_LDERRNO )( LDAP *ld, char **m, char **s );
#else
  typedef int ( LDAP_API *LDAP_GETLASTERROR )( void );
#endif /* NETSCAPE_CLIENT */
typedef struct berval ** ( LDAP_API *LDAP_GET_VALUES_LEN )( LDAP *ld, LDAPMessage *entry,
												   const char *attr );
typedef LDAP * ( LDAP_API *LDAP_INIT )( const char *host, int port );
typedef int ( LDAP_API *LDAP_IS_LDAP_URL )( char *url );
typedef void ( LDAP_API *LDAP_MEMFREE )( void *p );
typedef void ( LDAP_API *LDAP_MODSFREE )( LDAPMod **mods, int freemods );
typedef int ( LDAP_API *LDAP_MSGFREE )( LDAPMessage *lm );
typedef LDAPMessage * ( LDAP_API *LDAP_NEXT_ENTRY )( LDAP *ld, LDAPMessage *result );
typedef int ( LDAP_API *LDAP_SEARCH_ST )( LDAP *ld, const char *base, int scope,
								const char *filter, char **attrs,
								int attrsonly, struct timeval *timeout,
								LDAPMessage **res );
typedef int ( LDAP_API *LDAP_SET_OPTION )( LDAP *ld, int option, void *optdata );
typedef int ( LDAP_API *LDAP_SIMPLE_BIND_S )( LDAP *ld, const char *who,
									 const char *passwd );
typedef int ( LDAP_API *LDAP_UNBIND )( LDAP *ld );
typedef int ( LDAP_API *LDAP_URL_SEARCH_ST )( LDAP *ld, char *url, int attrsonly,
											  struct timeval *timeout,
											  LDAPMessage **res );
typedef void ( LDAP_API *LDAP_VALUE_FREE_LEN )( struct berval **vals );
static BER_FREE p_ber_free = NULL;
static LDAP_ADD_S p_ldap_add_s = NULL;
static LDAP_DELETE_S p_ldap_delete_s = NULL;
static LDAP_ERR2STRING p_ldap_err2string = NULL;
static LDAP_FIRST_ATTRIBUTE p_ldap_first_attribute = NULL;
static LDAP_FIRST_ENTRY p_ldap_first_entry = NULL;
#ifdef NETSCAPE_CLIENT
  static LDAP_GET_LDERRNO p_ldap_get_lderrno = NULL;
#else
  static LDAP_GETLASTERROR p_LdapGetLastError = NULL;
#endif /* NETSCAPE_CLIENT */
static LDAP_GET_VALUES_LEN p_ldap_get_values_len = NULL;
static LDAP_INIT p_ldap_init = NULL;
static LDAP_IS_LDAP_URL p_ldap_is_ldap_url = NULL;
static LDAP_MEMFREE p_ldap_memfree = NULL;
static LDAP_NEXT_ENTRY p_ldap_next_entry = NULL;
static LDAP_MSGFREE p_ldap_msgfree = NULL;
static LDAP_SEARCH_ST p_ldap_search_st = NULL;
static LDAP_SET_OPTION p_ldap_set_option = NULL;
static LDAP_SIMPLE_BIND_S p_ldap_simple_bind_s = NULL;
static LDAP_UNBIND p_ldap_unbind = NULL;
static LDAP_URL_SEARCH_ST p_ldap_url_search_st = NULL;
static LDAP_VALUE_FREE_LEN p_ldap_value_free_len = NULL;

/* The use of dynamically bound function pointers vs statically linked
   functions requires a bit of sleight of hand since we can't give the
   pointers the same names as prototyped functions.  To get around this we
   redefine the actual function names to the names of the pointers */

#define ber_free				p_ber_free
#define ldap_add_s				p_ldap_add_s
#define ldap_delete_s			p_ldap_delete_s
#define ldap_err2string			p_ldap_err2string
#define ldap_first_attribute	p_ldap_first_attribute
#define ldap_first_entry		p_ldap_first_entry
#ifdef NETSCAPE_CLIENT
  #define ldap_get_lderrno		p_ldap_get_lderrno
#else
  #define LdapGetLastError		p_LdapGetLastError
#endif /* NETSCAPE_CLIENT */
#define ldap_get_values_len		p_ldap_get_values_len
#define ldap_init				p_ldap_init
#define ldap_is_ldap_url		p_ldap_is_ldap_url
#define ldap_memfree			p_ldap_memfree
#define ldap_msgfree			p_ldap_msgfree
#define ldap_next_entry			p_ldap_next_entry
#define ldap_search_st			p_ldap_search_st
#define ldap_set_option			p_ldap_set_option
#define ldap_simple_bind_s		p_ldap_simple_bind_s
#define ldap_unbind				p_ldap_unbind
#define ldap_url_search_st		p_ldap_url_search_st
#define ldap_value_free_len		p_ldap_value_free_len

/* The name of the LDAP driver, in this case the Netscape LDAPv3 driver */

#ifdef __WIN16__
  #define LDAP_LIBNAME			"NSLDSS16.DLL"
#else
  #ifdef NETSCAPE_CLIENT
	#define LDAP_LIBNAME		"NSLDAP32v30.DLL"
  #else
	#define LDAP_LIBNAME		"wldap32.dll"
  #endif /* NETSCAPE_CLIENT */
#endif /* __WIN16__ */

/* Dynamically load and unload any necessary LDAP libraries */

int dbxInitLDAP( void )
	{
#ifdef __WIN16__
	UINT errorMode;
#endif /* __WIN16__ */

	/* If the LDAP module is already linked in, don't do anything */
	if( hLDAP != NULL_HINSTANCE )
		return( CRYPT_OK );

	/* Obtain a handle to the module containing the LDAP functions */
#ifdef __WIN16__
	errorMode = SetErrorMode( SEM_NOOPENFILEERRORBOX );
	hLDAP = LoadLibrary( LDAP_LIBNAME );
	SetErrorMode( errorMode );
	if( hLDAP < HINSTANCE_ERROR )
		{
		hLDAP = NULL_HINSTANCE;
		return( CRYPT_ERROR );
		}
#else
	if( ( hLDAP = LoadLibrary( LDAP_LIBNAME ) ) == NULL_HINSTANCE )
		return( CRYPT_ERROR );
#endif /* __WIN32__ */

	/* Now get pointers to the functions */
#ifdef NETSCAPE_CLIENT
	p_ber_free = ( BER_FREE ) GetProcAddress( hLDAP, "ldap_ber_free" );
#else
	p_ber_free = ( BER_FREE ) GetProcAddress( hLDAP, "ber_free" );
#endif /* NETSCAPE_CLIENT */
	p_ldap_add_s = ( LDAP_ADD_S ) GetProcAddress( hLDAP, "ldap_add_s" );
	p_ldap_delete_s = ( LDAP_DELETE_S ) GetProcAddress( hLDAP, "ldap_delete_s" );
	p_ldap_err2string = ( LDAP_ERR2STRING ) GetProcAddress( hLDAP, "ldap_err2string" );
	p_ldap_first_attribute = ( LDAP_FIRST_ATTRIBUTE ) GetProcAddress( hLDAP, "ldap_first_attribute" );
	p_ldap_first_entry = ( LDAP_FIRST_ENTRY ) GetProcAddress( hLDAP, "ldap_first_entry" );
#ifdef NETSCAPE_CLIENT
	p_ldap_get_lderrno = ( LDAP_GET_LDERRNO ) GetProcAddress( hLDAP, "ldap_get_lderrno" );
#else
	p_LdapGetLastError = ( LDAP_GETLASTERROR ) GetProcAddress( hLDAP, "LdapGetLastError" );
#endif /* NETSCAPE_CLIENT */
	p_ldap_get_values_len = ( LDAP_GET_VALUES_LEN ) GetProcAddress( hLDAP, "ldap_get_values_len" );
	p_ldap_init = ( LDAP_INIT ) GetProcAddress( hLDAP, "ldap_init" );
	p_ldap_is_ldap_url = ( LDAP_IS_LDAP_URL ) GetProcAddress( hLDAP, "ldap_is_ldap_url" );
	p_ldap_memfree = ( LDAP_MEMFREE ) GetProcAddress( hLDAP, "ldap_memfree" );
	p_ldap_msgfree = ( LDAP_MSGFREE ) GetProcAddress( hLDAP, "ldap_msgfree" );
	p_ldap_next_entry = ( LDAP_NEXT_ENTRY ) GetProcAddress( hLDAP, "ldap_next_entry" );
	p_ldap_search_st = ( LDAP_SEARCH_ST ) GetProcAddress( hLDAP, "ldap_search_st" );
	p_ldap_set_option = ( LDAP_SET_OPTION ) GetProcAddress( hLDAP, "ldap_set_option" );
	p_ldap_simple_bind_s = ( LDAP_SIMPLE_BIND_S ) GetProcAddress( hLDAP, "ldap_simple_bind_s" );
	p_ldap_unbind = ( LDAP_UNBIND ) GetProcAddress( hLDAP, "ldap_unbind" );
	p_ldap_url_search_st = ( LDAP_URL_SEARCH_ST ) GetProcAddress( hLDAP, "ldap_url_search_st" );
	p_ldap_value_free_len = ( LDAP_VALUE_FREE_LEN ) GetProcAddress( hLDAP, "ldap_value_free_len" );

	/* Make sure we got valid pointers for every LDAP function */
	if( p_ldap_add_s == NULL ||
#ifdef NETSCAPE_CLIENT
		p_ber_free == NULL ||
#endif /* NETSCAPE_CLIENT */
		p_ldap_delete_s == NULL || p_ldap_err2string == NULL || \
		p_ldap_first_attribute == NULL || p_ldap_first_entry == NULL || \
		p_ldap_init == NULL ||
#ifdef NETSCAPE_CLIENT
		p_ldap_get_lderrno == NULL || p_ldap_is_ldap_url == NULL ||
		p_ldap_url_search_st == NULL ||
#else
		p_LdapGetLastError == NULL ||
#endif /* NETSCAPE_CLIENT */
		p_ldap_get_values_len == NULL || p_ldap_memfree == NULL || \
		p_ldap_msgfree == NULL || p_ldap_next_entry == NULL || \
		p_ldap_search_st == NULL || p_ldap_set_option == NULL || \
		p_ldap_simple_bind_s == NULL || p_ldap_unbind == NULL || \
		p_ldap_value_free_len == NULL )
		{
		/* Free the library reference and reset the handle */
		FreeLibrary( hLDAP );
		hLDAP = NULL_HINSTANCE;
		return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

void dbxEndLDAP( void )
	{
	if( hLDAP != NULL_HINSTANCE )
		FreeLibrary( hLDAP );
	hLDAP = NULL_HINSTANCE;
	}
#endif /* __WINDOWS__ */

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Assign a name for an LDAP object/attribute field */

static void assignFieldName( const CRYPT_USER cryptOwner, char *buffer,
							 CRYPT_ATTRIBUTE_TYPE option )
	{
	RESOURCE_DATA msgData;
	int status;

	setMessageData( &msgData, buffer, CRYPT_MAX_TEXTSIZE );
	status = krnlSendMessage( cryptOwner, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, option );
	assert( cryptStatusOK( status ) );
	buffer[ msgData.length ] = '\0';
	}

/* Get information on an LDAP error */

static void getErrorInfo( KEYSET_INFO *keysetInfo, int ldapStatus )
	{
	LDAP_INFO *ldapInfo = keysetInfo->keysetLDAP;
	char *errorMessage;

#ifdef NETSCAPE_CLIENT
	keysetInfo->errorCode = ldap_get_lderrno( ldapInfo->ld, NULL,
											  &errorMessage );
#else
	ldapInfo->errorCode = LdapGetLastError();
	if( ldapInfo->errorCode == LDAP_SUCCESS )
		/* In true Microsoft fashion LdapGetLastError() can return
		   LDAP_SUCCESS with the error string set to "Success.", so if we
		   get this we use the status value returned by the original LDAP
		   function call instead */
		ldapInfo->errorCode = ldapStatus;
	errorMessage = ldap_err2string( ldapInfo->errorCode );
  #if 0
	/* The exact conditions under which ldap_err2string() does something
	   useful are somewhat undefined, it may be necessary to use the
	   following which works with general Windows error codes rather than
	   special-case LDAP function result codes */
	ldapInfo->errorCode = GetLastError();
	FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				   NULL, ldapInfo->errorCode,
				   MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ),
				   ldapInfo->errorMessage, MAX_ERRMSG_SIZE - 1, NULL );
  #endif /* 0 */
#endif /* Netscape vs MS LDAP client */
	if( errorMessage != NULL )
		{
		strncpy( ldapInfo->errorMessage, errorMessage, MAX_ERRMSG_SIZE - 1 );
		ldapInfo->errorMessage[ MAX_ERRMSG_SIZE - 1 ] = '\0';
		}
	else
		*ldapInfo->errorMessage = '\0';
	}

/* Map an LDAP error to the corresponding cryptlib error.  Some Windows LDAP
   error codes differ slightly from the standard LDAP names so we have to
   adjust them as appropriate */

static int mapLDAPerror( const int ldapError, const int defaultError )
	{
	switch( ldapError )
		{
		case LDAP_INAPPROPRIATE_AUTH:
		case LDAP_INVALID_CREDENTIALS:
		case LDAP_AUTH_UNKNOWN:
#ifdef NETSCAPE_CLIENT
		case LDAP_INSUFFICIENT_ACCESS:
#else
		case LDAP_INSUFFICIENT_RIGHTS:
		case LDAP_AUTH_METHOD_NOT_SUPPORTED:
#endif /* NETSCAPE_CLIENT */
			return( CRYPT_ERROR_PERMISSION );

#ifdef NETSCAPE_CLIENT
		case LDAP_TYPE_OR_VALUE_EXISTS:
#else
		case LDAP_ATTRIBUTE_OR_VALUE_EXISTS:
#endif /* NETSCAPE_CLIENT */
			return( CRYPT_ERROR_DUPLICATE );

#ifndef NETSCAPE_CLIENT
		case LDAP_CONFIDENTIALITY_REQUIRED:
			return( CRYPT_ERROR_NOSECURE );
#endif /* NETSCAPE_CLIENT */

		case LDAP_INVALID_DN_SYNTAX:
			return( CRYPT_ARGERROR_STR1 );

#ifndef NETSCAPE_CLIENT
		case LDAP_NO_RESULTS_RETURNED:
#endif /* NETSCAPE_CLIENT */
		case LDAP_NO_SUCH_ATTRIBUTE:
		case LDAP_NO_SUCH_OBJECT:
			return( CRYPT_ERROR_NOTFOUND );

#ifndef NETSCAPE_CLIENT
		case LDAP_NOT_SUPPORTED:
			return( CRYPT_ERROR_NOTAVAIL );
#endif /* NETSCAPE_CLIENT */

		case LDAP_RESULTS_TOO_LARGE:
			return( CRYPT_ERROR_OVERFLOW );
		}

	return( defaultError );
	}

/* Copy attribute information into an LDAPMod structure so it can be written to
   the directory */

static LDAPMod *copyAttribute( const char *attributeName,
							   const void *attributeValue,
							   const int attributeLength )
	{
	LDAPMod *ldapModPtr;

	/* Allocate room for the LDAPMod structure and the data pointers.
	   mod_values and mod_bvalues members have the same representation so we
	   can allocate them with the same malloc */
	if( ( ldapModPtr = ( LDAPMod * ) clAlloc( "copyAttribute", \
											  sizeof( LDAPMod ) ) ) == NULL )
		return( NULL );
	if( ( ldapModPtr->mod_values = clAlloc( "copyAttribute", \
											2 * sizeof( void * ) ) ) == NULL )
		{
		clFree( "copyAttribute", ldapModPtr );
		return( NULL );
		}

	/* Set up the pointers to the attribute information.  This differs
	   slightly depending on whether we're adding text or binary data */
	if( !attributeLength )
		{
		ldapModPtr->mod_op = LDAP_MOD_ADD;
		ldapModPtr->mod_type = ( char * ) attributeName;
		ldapModPtr->mod_values[ 0 ] = ( char * ) attributeValue;
		ldapModPtr->mod_values[ 1 ] = NULL;
		}
	else
		{
		if( ( ldapModPtr->mod_bvalues[ 0 ] = \
				clAlloc( "copyAttribute", sizeof( struct berval ) ) ) == NULL )
			{
			clFree( "copyAttribute", ldapModPtr->mod_values );
			clFree( "copyAttribute", ldapModPtr );
			return( NULL );
			}
		ldapModPtr->mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
		ldapModPtr->mod_type = ( char * ) attributeName;
		ldapModPtr->mod_bvalues[ 0 ]->bv_len = attributeLength;
		ldapModPtr->mod_bvalues[ 0 ]->bv_val = ( char * ) attributeValue;
		ldapModPtr->mod_bvalues[ 1 ] = NULL;
		}

	return( ldapModPtr );
	}

/* Encode DN information in the RFC 1779 reversed format.  We don't have to
   check for overflows because the cert.management code limits the size of
   each component to a small fraction of the total buffer size */

static void copyComponent( char *dest, char *src )
	{
	while( *src )
		{
		const char ch = *src++;

		if( ch == ',' )
			*dest++ = '\\';
		*dest++ = ch;
		}
	*dest++ = '\0';
	}

static int encodeDN( char *dn, char *C, char *SP, char *L, char *O, char *OU,
					 char *CN )
	{
	char *bufPtr = dn;

	strcpy( dn, "CN=" );
	strcpy( dn + 3, CN );
	bufPtr += strlen( bufPtr );
	if( *OU )
		{
		strcpy( bufPtr, ",OU=" );
		copyComponent( bufPtr + 4, OU );
		bufPtr += strlen( bufPtr );
		}
	if( *O )
		{
		strcpy( bufPtr, ",O=" );
		copyComponent( bufPtr + 3, O );
		bufPtr += strlen( bufPtr );
		}
	if( *L )
		{
		strcpy( bufPtr, ",L=" );
		copyComponent( bufPtr + 3, L );
		bufPtr += strlen( bufPtr );
		}
	if( *SP )
		{
		strcpy( bufPtr, ",ST=" );	/* Not to be confused with ST=street */
		copyComponent( bufPtr + 4, SP );
		bufPtr += strlen( bufPtr );
		}
	strcpy( bufPtr, ",C=" );
	copyComponent( bufPtr + 3, C );

	return( CRYPT_OK );
	}

/* Decompose an LDAP URL of the general form ldap://server:port/user into its
   various components */

static int parseURL( char *ldapServer, char **ldapUser, int *ldapPort )
	{
	char *strPtr;

	/* Clear return value */
	*ldapUser = NULL;
	*ldapPort = LDAP_PORT;

	/* Handle a leading URL specifier if this is present */
	if( !strCompare( ldapServer, "ldaps://", 8 ) )
		/* We can't do LDAP over SSL without a lot of extra work */
		return( CRYPT_ERROR_BADDATA );
	if( !strCompare( ldapServer, "ldap://", 7 ) )
		memmove( ldapServer, ldapServer + 7, strlen( ldapServer ) - 6 );

	/* Decompose what's left into a FQDN, port, and user name */
	if( ( strPtr = strchr( ldapServer, '/' ) ) != NULL )
		{
		*strPtr++ = '\0';
		*ldapUser = strPtr;
		}
	if( ( strPtr = strchr( ldapServer, ':' ) ) != NULL )
		{
		*strPtr++ = '\0';
		*ldapPort = aToI( strPtr );
		if( *ldapPort < 26 || *ldapPort > 65534L )
			return( CRYPT_ERROR_BADDATA );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Directory Open/Close Routines					*
*																			*
****************************************************************************/

/* Close a previously-opened LDAP connection.  We have to have this before
   the init function since it may be called by it if the open process fails.
   This is necessary because the complex LDAP open may require a fairly
   extensive cleanup afterwards */

static void shutdownFunction( KEYSET_INFO *keysetInfo )
	{
	LDAP_INFO *ldapInfo = keysetInfo->keysetLDAP;

	ldap_unbind( ldapInfo->ld );
	ldapInfo->ld = NULL;
	}

/* Open a connection to an LDAP directory */

static int initFunction( KEYSET_INFO *keysetInfo, const char *server,
						 const CRYPT_KEYOPT_TYPE options )
	{
	LDAP_INFO *ldapInfo = keysetInfo->keysetLDAP;
	char ldapServer[ MAX_URL_SIZE ], *ldapUser;
	int maxEntries = 2, timeout, ldapPort, ldapStatus = LDAP_OTHER, status;

	/* Check the URL.  The Netscape API provides the function
	   ldap_is_ldap_url() for this, but this requires a complete LDAP URL
	   rather than just a server name and port */
	if( strlen( server ) > MAX_URL_SIZE - 1 )
		return( CRYPT_ARGERROR_STR1 );
	strcpy( ldapServer, server );
	status = parseURL( ldapServer, &ldapUser, &ldapPort );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_STR1 );

	/* Open the connection to the server */
	if( ( ldapInfo->ld = ldap_init( ldapServer, ldapPort ) ) == NULL )
		return( CRYPT_ERROR_OPEN );
	if( ( ldapStatus = ldap_simple_bind_s( ldapInfo->ld, ldapUser, 
										   NULL ) ) != LDAP_SUCCESS )
		{
		getErrorInfo( keysetInfo, ldapStatus );
		ldap_unbind( ldapInfo->ld );
		ldapInfo->ld = NULL;
		return( mapLDAPerror( ldapStatus, CRYPT_ERROR_OPEN ) );
		}

	/* Set the search timeout and limit the maximum number of returned
	   entries to 2 (setting the search timeout is mostly redundant since we
	   use search_st anyway, however there may be other operations which also
	   require some sort of timeout which can't be explicitly specified */
	krnlSendMessage( keysetInfo->ownerHandle, IMESSAGE_GETATTRIBUTE,
					 &timeout, CRYPT_OPTION_NET_READTIMEOUT );
	if( timeout < 15 )
		/* Network I/O may be set to be nonblocking, so we make sure we try
		   for at least 15s before timing out */
		timeout = 15;
	ldap_set_option( ldapInfo->ld, LDAP_OPT_TIMELIMIT, &timeout );
	ldap_set_option( ldapInfo->ld, LDAP_OPT_SIZELIMIT, &maxEntries );

	/* Set up the names of the objects and attributes */
	assignFieldName( keysetInfo->ownerHandle, ldapInfo->nameObjectClass,
					 CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS );
	assignFieldName( keysetInfo->ownerHandle, ldapInfo->nameFilter,
					 CRYPT_OPTION_KEYS_LDAP_FILTER );
	assignFieldName( keysetInfo->ownerHandle, ldapInfo->nameCACert,
					 CRYPT_OPTION_KEYS_LDAP_CACERTNAME );
	assignFieldName( keysetInfo->ownerHandle, ldapInfo->nameCert,
					 CRYPT_OPTION_KEYS_LDAP_CERTNAME );
	assignFieldName( keysetInfo->ownerHandle, ldapInfo->nameCRL,
					 CRYPT_OPTION_KEYS_LDAP_CRLNAME );
	assignFieldName( keysetInfo->ownerHandle, ldapInfo->nameEmail,
					 CRYPT_OPTION_KEYS_LDAP_EMAILNAME );
	krnlSendMessage( keysetInfo->ownerHandle, IMESSAGE_GETATTRIBUTE,
					 &ldapInfo->objectType,
					 CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Directory Access Routines						*
*																			*
****************************************************************************/

/* Retrieve a key attribute from an LDAP directory */

static int getItemFunction( KEYSET_INFO *keysetInfo,
							CRYPT_HANDLE *iCryptHandle,
							const KEYMGMT_ITEM_TYPE itemType,
							const CRYPT_KEYID_TYPE keyIDtype,
							const void *keyID,  const int keyIDlength,
							void *auxInfo, int *auxInfoLength,
							const int flags )
	{
	LDAP_INFO *ldapInfo = keysetInfo->keysetLDAP;
	LDAPMessage *result, *resultEntry;
	BerElement *ber;
	struct berval **valuePtrs;
	char *attributePtr;
	int status = CRYPT_OK;

	assert( keyIDtype != CRYPT_KEYID_NONE || iCryptHandle != NULL );
	assert( itemType == KEYMGMT_ITEM_PUBLICKEY );
	assert( auxInfo == NULL ); assert( *auxInfoLength == 0 );

	/* If we're not in the middle of an ongoing fetch, send the query to the
	   server */
	if( !ldapInfo->queryInProgress )
		{
		const CRYPT_CERTTYPE_TYPE objectType = ldapInfo->objectType;
		const char *certAttributes[] = { ldapInfo->nameCert, NULL };
		const char *caCertAttributes[] = { ldapInfo->nameCACert, NULL };
		const char *crlAttributes[] = { ldapInfo->nameCRL, NULL };
		struct timeval ldapTimeout = { 0 };
		char dn[ MAX_DN_STRINGSIZE ];
		int ldapStatus = LDAP_OTHER, timeout;

		assert( keyIDtype == CRYPT_KEYID_NAME || \
				keyIDtype == CRYPT_KEYID_URI );

		/* Network I/O may be set to be nonblocking, so we make sure we try
		   for at least 15s before timing out */
		krnlSendMessage( keysetInfo->ownerHandle, IMESSAGE_GETATTRIBUTE, 
						 &timeout, CRYPT_OPTION_NET_READTIMEOUT );
		ldapTimeout.tv_sec = max( timeout, 15 );

		/* Convert the DN into a null-terminated form */
		if( keyIDlength > MAX_DN_STRINGSIZE - 1 )
			return( CRYPT_ARGERROR_STR1 );
		memcpy( dn, keyID, keyIDlength );
		dn[ keyIDlength ] = '\0';

		/* If the LDAP search-by-URL functions are available and the key ID
		   is an LDAP URL, perform a search by URL */
		if( ldap_is_ldap_url != NULL && ldap_is_ldap_url( dn ) )
			ldapStatus = ldap_url_search_st( ldapInfo->ld, dn, FALSE, 
											 &ldapTimeout, &result );
		else
			{
			/* Try and retrieve the entry for this DN from the directory.
			   We use a base specified by the DN, a chop of 0 (to return
			   only the current entry), any object class (to get around the
			   problem of implementations which stash certs in whatever they
			   feel like), and look for a certificate attribute.  If the
			   search fails for this attribute, we try again but this time
			   go for a CA certificate attribute which unfortunately slows
			   down the search somewhat when the cert isn't found but can't
			   really be avoided since there's no way to tell in advance
			   whether a cert will be an end entity or a CA cert.  To
			   complicate things even further, we may also need to check for
			   a CRL in case this is what the user is after */
			if( objectType == CRYPT_CERTTYPE_NONE || \
				objectType == CRYPT_CERTTYPE_CERTIFICATE )
				ldapStatus = ldap_search_st( ldapInfo->ld, dn, LDAP_SCOPE_BASE,
											 ldapInfo->nameFilter,
											 ( char ** ) certAttributes, 0,
											 &ldapTimeout, &result );
			if( ldapStatus != LDAP_SUCCESS && \
				( objectType == CRYPT_CERTTYPE_NONE || \
				  objectType == CRYPT_CERTTYPE_CERTIFICATE ) )
				ldapStatus = ldap_search_st( ldapInfo->ld, dn, LDAP_SCOPE_BASE,
											 ldapInfo->nameFilter,
											 ( char ** ) caCertAttributes, 0,
											 &ldapTimeout, &result );
			if( ldapStatus != LDAP_SUCCESS && \
				( objectType == CRYPT_CERTTYPE_NONE || \
				  objectType == CRYPT_CERTTYPE_CRL ) )
				ldapStatus = ldap_search_st( ldapInfo->ld, dn, LDAP_SCOPE_BASE,
											 ldapInfo->nameFilter,
											 ( char ** ) crlAttributes, 0,
											 &ldapTimeout, &result );
			}
		if( ldapStatus != LDAP_SUCCESS )
			{
			getErrorInfo( keysetInfo, ldapStatus );
			return( mapLDAPerror( ldapStatus, CRYPT_ERROR_READ ) );
			}

		/* We got something, start fetching the results */
		if( ( resultEntry = ldap_first_entry( ldapInfo->ld, 
											  result ) ) == NULL )
			{
			ldap_msgfree( result );
			return( CRYPT_ERROR_NOTFOUND );
			}

		/* If we've been passed a null crypt handle, this is the start of a
		   general-purpose query rather than a single cert fetch, save the
		   query state and record the fact that we're in the middle of a
		   query */
		if( iCryptHandle == NULL )
			{
			ldapInfo->result = result;
			ldapInfo->queryInProgress = TRUE;
			}
		}
	else
		{
		/* We're in an ongoing query, try and fetch the next set of results */
		if( ( resultEntry = ldap_next_entry( ldapInfo->ld,
											 ldapInfo->result ) ) == NULL )
			{
			/* No more results, wrap up the processing */
			ldap_msgfree( ldapInfo->result );
			ldapInfo->result = NULL;
			return( CRYPT_ERROR_COMPLETE );
			}
		}

	/* Copy out the certificate */
	if( ( attributePtr = ldap_first_attribute( ldapInfo->ld, resultEntry, 
											   &ber ) ) == NULL )
		{
		if( ldapInfo->queryInProgress )
			ldap_msgfree( result );
		return( CRYPT_ERROR_NOTFOUND );
		}
	valuePtrs = ldap_get_values_len( ldapInfo->ld, resultEntry, 
									 attributePtr );
	if( valuePtrs != NULL )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;

		/* Create a certificate object from the returned data */
		setMessageCreateObjectIndirectInfo( &createInfo, valuePtrs[ 0 ]->bv_val,
											valuePtrs[ 0 ]->bv_len,
											CRYPT_CERTTYPE_NONE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
								  &createInfo, OBJECT_TYPE_CERTIFICATE );
		if( cryptStatusOK( status ) )
			*iCryptHandle = createInfo.cryptHandle;

		ldap_value_free_len( valuePtrs );
		}
	else
		status = CRYPT_ERROR_NOTFOUND;

	/* Clean up.  The ber_free() function is rather problematic because
	   Netscape uses the nonstandard ldap_ber_free() name (which can be fixed
	   with proprocessor trickery) and Microsoft first omitted it entirely
	   (up to NT4 SP4) and then later added it as a stub (Win2K, rumour has
	   it that the only reason this function even exists is because the
	   Netscape client required it).  Because it may or may not exist in the
	   MS client, we call it if we resolved its address, otherwise we skip
	   it.

	   The function is further complicated by the fact that LDAPv3 says the
	   second parameter should be 0, however the Netscape client docs used to
	   require it to be 1 and the MS client was supposed to ignore it so the
	   code passed in a 1.  Actually the way the MS implementation handles
	   the BER data is that the BerElement returned by ldap_first_attribute()
	   is (despite what the MSDN docs claim) just a data structure pointed to
	   by lm_ber in the LDAPMessage structure, all that
	   ldap_first_attribute() does is redirect the lm_ber pointer inside the
	   LDAPMessage, so actually freeing this wouldn't be a good idea).

	   Later, the Netscape docs were updated to require a 0, presumably to
	   align them with the LDAPv3 spec.  On some systems it makes no
	   difference whether you pass in a 0 or 1 to the call, but on others it
	   can cause an access violation.  Presumably eventually everyone will
	   move to something which implements the new rather than old Netscape-
	   documented behaviour, so we pass in 0 as the argument.

	   It gets worse than this though.  Calling ber_free() with newer
	   versions of the Windows LDAP client with any argument at all causes
	   internal data corruption which typically first results in a soft
	   failure (eg a data fetch fails) and then eventually a hard failure
	   such as an access violation after further calls are made.  The only
	   real way to fix this is to avoid calling it entirely, this doesn't
	   seem to leak any more memory than Winsock leaks anyway (that is,
	   there are a considerable number of memory and handle leaks, but the
	   number doesn't increase if ber_free() isn't called).

	   There have been reports that with some older versions of the Windows
	   LDAP client (eg the one in Win95) the ldap_msgfree() call generates
	   an exception in wldap.dll, if this is a problem you need to either
	   install a newer LDAP DLL or switch to the Netscape one.

	   The reason for some of the Windows problems are because the
	   wldap32.lib shipped with VC++ uses different ordinals than the
	   wldap32.dll which comes with the OS (see MSKB article Q283199), so
	   that simply using the out-of-the-box development tools with the out-
	   of-the-box OS can result in access violations and assorted other
	   problems */
#ifdef NETSCAPE_CLIENT
	if( ber_free != NULL )
		ber_free( ber, 0 );
#endif /* NETSCAPE_CLIENT */
	ldap_memfree( attributePtr );
	if( !ldapInfo->queryInProgress )
		ldap_msgfree( result );
	return( status );
	}

/* Add an entry/attribute to an LDAP directory.  The LDAP behaviour differs
   somewhat from DAP in that assigning a value to a nonexistant attribute
   implicitly creates the required attribute.  In addition deleting the last
   value automatically deletes the entire attribute, the delete item code
   assumes the user is requesting a superset of this behaviour and deletes
   the entire entry */

static int addCert( KEYSET_INFO *keysetInfo, const CRYPT_HANDLE iCryptHandle )
	{
	LDAP_INFO *ldapInfo = keysetInfo->keysetLDAP;
	LDAPMod *ldapMod[ MAX_LDAP_ATTRIBUTES ];
	RESOURCE_DATA msgData;
	BYTE keyData[ MAX_CERT_SIZE ];
	char dn[ MAX_DN_STRINGSIZE ];
	char C[ CRYPT_MAX_TEXTSIZE + 1 ], SP[ CRYPT_MAX_TEXTSIZE + 1 ],
		L[ CRYPT_MAX_TEXTSIZE + 1 ], O[ CRYPT_MAX_TEXTSIZE + 1 ],
		OU[ CRYPT_MAX_TEXTSIZE + 1 ], CN[ CRYPT_MAX_TEXTSIZE + 1 ],
		email[ CRYPT_MAX_TEXTSIZE + 1 ];
	int keyDataLength, ldapModIndex = 1, status = CRYPT_OK;

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
		}
	if( cryptStatusOK( status ) )
		SP[ msgData.length ] = '\0';
	if( cryptStatusOK( status ) || status == CRYPT_ERROR_NOTFOUND )
		{
		setMessageData( &msgData, L, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S, 
							&msgData, CRYPT_CERTINFO_LOCALITYNAME );
		}
	if( cryptStatusOK( status ) )
		L[ msgData.length ] = '\0';
	if( cryptStatusOK( status ) || status == CRYPT_ERROR_NOTFOUND )
		{
		setMessageData( &msgData, O, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S, 
							&msgData, CRYPT_CERTINFO_ORGANIZATIONNAME );
		}
	if( cryptStatusOK( status ) )
		O[ msgData.length ] = '\0';
	if( cryptStatusOK( status ) || status == CRYPT_ERROR_NOTFOUND )
		{
		setMessageData( &msgData, OU, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S, 
							&msgData, CRYPT_CERTINFO_ORGANIZATIONALUNITNAME );
		}
	if( cryptStatusOK( status ) )
		OU[ msgData.length ] = '\0';
	if( cryptStatusOK( status ) || status == CRYPT_ERROR_NOTFOUND )
		{
		setMessageData( &msgData, CN, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S, 
							&msgData, CRYPT_CERTINFO_COMMONNAME );
		}
	if( cryptStatusOK( status ) )
		CN[ msgData.length ] = '\0';
	if( cryptStatusOK( status ) || status == CRYPT_ERROR_NOTFOUND )
		/* Get the string form of the DN */
		status = encodeDN( dn, C, SP, L, O, OU, CN );
	if( cryptStatusOK( status ) )
		{
		/* Get the certificate data */
		setMessageData( &msgData, keyData, MAX_CERT_SIZE );
		status = krnlSendMessage( iCryptHandle, IMESSAGE_CRT_EXPORT,
								  &msgData, CRYPT_CERTFORMAT_CERTIFICATE );
		keyDataLength = msgData.length;
		}
	if( cryptStatusError( status ) )
		/* Convert any low-level cert-specific error into something generic
		   which makes a bit more sense to the caller */
		return( CRYPT_ARGERROR_NUM1 );

	/* Set up the fixed attributes and certificate data.  This currently
	   always adds a cert as a standard certificate rather than a CA
	   certificate because of uncertainty over what other implementations
	   will try and look for, once enough other software uses the CA cert
	   attribute this can be switched over */
	if( ( ldapMod[ 0 ] = copyAttribute( ldapInfo->nameObjectClass,
										"certPerson", 0 ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	if( ( ldapMod[ ldapModIndex++ ] = copyAttribute( ldapInfo->nameCert,
										keyData, keyDataLength ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;

	/* Set up the DN/identification information */
	if( cryptStatusOK( status ) && *email && \
		( ldapMod[ ldapModIndex++ ] = \
				copyAttribute( ldapInfo->nameEmail, email, 0 ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	if( cryptStatusOK( status ) && *CN && \
		( ldapMod[ ldapModIndex++ ] = copyAttribute( "CN", CN, 0 ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	if( cryptStatusOK( status ) && *OU && \
		( ldapMod[ ldapModIndex++ ] = copyAttribute( "OU", OU, 0 ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	if( cryptStatusOK( status ) && *O && \
		( ldapMod[ ldapModIndex++ ] = copyAttribute( "O", O, 0 ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	if( cryptStatusOK( status ) && *L && \
		( ldapMod[ ldapModIndex++ ] = copyAttribute( "L", L, 0 ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	if( cryptStatusOK( status ) && *SP && \
		( ldapMod[ ldapModIndex++ ] = copyAttribute( "SP", SP, 0 ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	if( cryptStatusOK( status ) && *C && \
		( ldapMod[ ldapModIndex++ ] = copyAttribute( "C", C, 0 ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	ldapMod[ ldapModIndex ] = NULL;

	/* Add the new attribute/entry */
	if( cryptStatusOK( status ) )
		{
		int ldapStatus;

		if( ( ldapStatus = ldap_add_s( ldapInfo->ld, dn,
									   ldapMod ) ) != LDAP_SUCCESS )
			{
			getErrorInfo( keysetInfo, ldapStatus );
			status = mapLDAPerror( ldapStatus, CRYPT_ERROR_WRITE );
			}
		}

	/* Clean up.  We do it the hard way rather than using
	   ldap_mods_free() here partially because the ldapMod[] array
	   isn't malloc()'d, but mostly because for the Netscape client
	   library ldap_mods_free() causes some sort of memory corruption,
	   possibly because it's trying to free the mod_values[] entries
	   which are statically allocated, and for the MS client the
	   function doesn't exist */
	for( ldapModIndex = 0; ldapMod[ ldapModIndex ] != NULL;
		 ldapModIndex++ )
		{
		if( ldapMod[ ldapModIndex ]->mod_op & LDAP_MOD_BVALUES )
			clFree( "addCert", ldapMod[ ldapModIndex ]->mod_bvalues[ 0 ] );
		clFree( "addCert", ldapMod[ ldapModIndex ]->mod_values );
		clFree( "addCert", ldapMod[ ldapModIndex ] );
		}
	return( status );
	}

static int setItemFunction( KEYSET_INFO *keysetInfo,
							const CRYPT_HANDLE iCryptHandle,
							const KEYMGMT_ITEM_TYPE itemType,
							const char *password, const int passwordLength,
							const int flags )
	{
	BOOLEAN seenNonDuplicate = FALSE;
	int type, status;

	assert( itemType == KEYMGMT_ITEM_PUBLICKEY );
	assert( password == NULL ); assert( passwordLength == 0 );

	/* Make sure we've been given a cert or cert chain */
	status = krnlSendMessage( iCryptHandle, MESSAGE_GETATTRIBUTE, &type, 
							  CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( type != CRYPT_CERTTYPE_CERTIFICATE && \
		type != CRYPT_CERTTYPE_CERTCHAIN )
		return( CRYPT_ARGERROR_NUM1 );

	/* Lock the cert for our exclusive use (in case it's a cert chain, we
	   also select the first cert in the chain), update the keyset with the
	   cert(s), and unlock it to allow others access */
	krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_CURSORFIRST,
					 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	status = krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		return( status );
	do
		{
		/* Add the certificate */
		status = addCert( keysetInfo, iCryptHandle );

		/* A cert being added may already be present, however we can't fail
		   immediately because what's being added may be a chain containing
		   further certs, so we keep track of whether we've successfully
		   added at least one cert and clear data duplicate errors */
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
		/* We reached the end of the chain without finding anything we could
		   add, return a data duplicate error */
		status = CRYPT_ERROR_DUPLICATE;

	return( status );
	}

/* Delete an entry from an LDAP directory */

static int deleteItemFunction( KEYSET_INFO *keysetInfo,
							   const KEYMGMT_ITEM_TYPE itemType,
							   const CRYPT_KEYID_TYPE keyIDtype,
							   const void *keyID, const int keyIDlength )
	{
	LDAP_INFO *ldapInfo = keysetInfo->keysetLDAP;
	char dn[ MAX_DN_STRINGSIZE ];
	int ldapStatus;

	assert( itemType == KEYMGMT_ITEM_PUBLICKEY );
	assert( keyIDtype == CRYPT_KEYID_NAME || keyIDtype == CRYPT_KEYID_URI );

	/* Convert the DN into a null-terminated form */
	if( keyIDlength > MAX_DN_STRINGSIZE - 1 )
		return( CRYPT_ARGERROR_STR1 );
	memcpy( dn, keyID, keyIDlength );
	dn[ keyIDlength ] = '\0';

	/* Delete the entry */
	if( ( ldapStatus = ldap_delete_s( ldapInfo->ld, dn ) ) != LDAP_SUCCESS )
		{
		getErrorInfo( keysetInfo, ldapStatus );
		return( mapLDAPerror( ldapStatus, CRYPT_ERROR_WRITE ) );
		}

	return( CRYPT_OK );
	}

/* Perform a getFirst/getNext query on the LDAP directory */

static int getFirstItemFunction( KEYSET_INFO *keysetInfo,
								 CRYPT_CERTIFICATE *iCertificate,
								 int *stateInfo,
								 const CRYPT_KEYID_TYPE keyIDtype,
								 const void *keyID, const int keyIDlength,
								 const KEYMGMT_ITEM_TYPE itemType,
								 const int options )
	{
	assert( stateInfo == NULL );
	assert( itemType == KEYMGMT_ITEM_PUBLICKEY );
	assert( options == KEYMGMT_FLAG_NONE );

	return( getItemFunction( keysetInfo, NULL, KEYMGMT_ITEM_PUBLICKEY,
							 CRYPT_KEYID_NAME, keyID, keyIDlength, NULL,
							 0, 0 ) );
	}

static int getNextItemFunction( KEYSET_INFO *keysetInfo,
								CRYPT_CERTIFICATE *iCertificate,
								int *stateInfo, const int options )
	{
	assert( stateInfo == NULL );

	return( getItemFunction( keysetInfo, iCertificate, KEYMGMT_ITEM_PUBLICKEY,
							 CRYPT_KEYID_NONE, NULL, 0, NULL, 0, 0 ) );
	}

/* Return status info for the keyset */

static BOOLEAN isBusyFunction( KEYSET_INFO *keysetInfo )
	{
	return( keysetInfo->keysetLDAP->queryInProgress );
	}

/* Get/set keyset attributes */

static void *getAttributeDataPtr( KEYSET_INFO *keysetInfo, 
								  const CRYPT_ATTRIBUTE_TYPE type )
	{
	LDAP_INFO *ldapInfo = keysetInfo->keysetLDAP;

	switch( type )
		{
		case CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS:
			return( ldapInfo->nameObjectClass );

		case CRYPT_OPTION_KEYS_LDAP_FILTER:
			return( ldapInfo->nameFilter );

		case CRYPT_OPTION_KEYS_LDAP_CACERTNAME:
			return( ldapInfo->nameCACert );

		case CRYPT_OPTION_KEYS_LDAP_CERTNAME:
			return( ldapInfo->nameCert );

		case CRYPT_OPTION_KEYS_LDAP_CRLNAME:
			return( ldapInfo->nameCRL );

		case CRYPT_OPTION_KEYS_LDAP_EMAILNAME:
			return( ldapInfo->nameEmail );
		}

	return( NULL );
	}

static int getAttributeFunction( KEYSET_INFO *keysetInfo, void *data,
								 const CRYPT_ATTRIBUTE_TYPE type )
	{
	const void *attributeDataPtr = getAttributeDataPtr( keysetInfo, type );

	if( attributeDataPtr == NULL )
		return( CRYPT_ARGERROR_VALUE );
	return( attributeCopy( data, attributeDataPtr, 
						   strlen( attributeDataPtr ) ) );
	}

static int setAttributeFunction( KEYSET_INFO *keysetInfo, const void *data,
								 const CRYPT_ATTRIBUTE_TYPE type )
	{
	const RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) data;
	BYTE *attributeDataPtr = getAttributeDataPtr( keysetInfo, type );

	assert( msgData->length <= CRYPT_MAX_TEXTSIZE );
	if( attributeDataPtr == NULL )
		return( CRYPT_ARGERROR_VALUE );
	memcpy( attributeDataPtr, msgData->data, msgData->length );
	attributeDataPtr[ msgData->length ] = '\0';

	return( CRYPT_OK );
	}

int setAccessMethodLDAP( KEYSET_INFO *keysetInfo )
	{
#ifdef __WINDOWS__
	/* Make sure the LDAP driver is bound in */
	if( hLDAP == NULL_HINSTANCE )
		return( CRYPT_ERROR_OPEN );
#endif /* __WINDOWS__ */

	/* Set the access method pointers */
	keysetInfo->initFunction = initFunction;
	keysetInfo->shutdownFunction = shutdownFunction;
	keysetInfo->getAttributeFunction = getAttributeFunction;
	keysetInfo->setAttributeFunction = setAttributeFunction;
	keysetInfo->getItemFunction = getItemFunction;
	keysetInfo->setItemFunction = setItemFunction;
	keysetInfo->deleteItemFunction = deleteItemFunction;
	keysetInfo->getFirstItemFunction = getFirstItemFunction;
	keysetInfo->getNextItemFunction = getNextItemFunction;
	keysetInfo->isBusyFunction = isBusyFunction;

	return( CRYPT_OK );
	}
#endif /* USE_LDAP */
