// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "configuration.h"

#include "file.h"
#include "list.h"
#include "log.h"
#include "scope.h"
#include "allocator.h"
#include "stringlist.h"

#include <unistd.h> // gethostname()
#include <netdb.h> // gethostbyname()

#include "sys.h" // memmove()


class ConfigurationData
{
public:
    ConfigurationData(): errors( 0 ) {}

    uint scalar[Configuration::NumScalars];
    String text[Configuration::NumTexts];
    bool toggle[Configuration::NumToggles];

    struct Error {
        Error() : s( Log::Info ) {}

        String e;
        Log::Severity s;
    };
    List<Error> * errors;
    StringList seen;
    bool contains( const String & s )
    {
        StringList::Iterator i( seen );
        while ( i && *i != s )
            ++i;
        if ( i )
            return true;
        return false;
    }
};


/*! \class Configuration configuration.h
    The Configuration class contains all configuration variables.

    Some configuration variables are set at compile time and are
    available via compiledIn(). These include the path of the
    configuration filename.

    Others are available by calling text(), scalar() or toggle() for
    the relevant variable. To add new configuration variables, the
    Configuration class needs extending.

    As a matter of policy, we check the configuration completely at
    startup. Configuration knows the type and name of all legal
    variables, so it can log errors as appropriate. Other classes must
    perform supplementary sanity checking, if possible at startup.
    (For example, if one variable setting makes another variable
    meaningless, the responsible class should check that and give an
    error message.)

    The configuration file contains an arbitrary number of
    single-line variable assignments, each of which specifies an
    integer, a toggle, or a string.

    Comments extend from a '#' sign until the end of the line. In
    quoted strings '#' may be used.

    During initialization, create a number of Configuration::String,
    Configuration::Scalar or Configuration::Toggle objects naming the
    variables. When all configuration variable objects have been
    created, call report(), and all errors are reported via the log
    server. Most syntax errors prevent the server(s) from starting up.

    Note that if you don't call report(), a typo may result in a
    variable silently being reverted to default.
*/


/*! Constructs an empty Configuration containing no variables. */

Configuration::Configuration()
{
}


/*! Reads \a file, adding to the previous configuration data held by
    the object. In case of error, \a file is not read and an error is
    logged. Unknown configuration variables are logged and ignored.
*/

void Configuration::read( const String & file )
{
    File f( file );
    if ( !f.valid() ) {
        log( "Error reading configuration file " + file,
             Log::Disaster );
        return;
    }

    log( "Using configuration file " + file, Log::Debug );

    String buffer( f.contents() );
    // we now want to loop across buffer, picking up entire lines and
    // parsing them as variables.
    uint i = 0;
    uint l = 0;
    while ( i <= buffer.length() ) {
        if ( i == buffer.length() ||
             buffer[i] == 10 ||
             buffer[i] == 13 ) {
            if ( i > l + 1 )
                add( buffer.mid( l, i-l ) );
            l = i + 1;
        }
        i++;
    }
}


ConfigurationData * Configuration::d;


static struct {
    const char * name;
    Configuration::Scalar variable;
    uint value;
} scalarDefaults[Configuration::NumScalars] = {
    { "db-port", Configuration::DbPort, 5432 },
    { "tlsproxy-port", Configuration::TlsProxyPort, 2061 },
    { "log-port", Configuration::LogPort, 2054 },
    { "ocd-port", Configuration::OcdPort, 2050 },
    { "ocadmin-port", Configuration::OcAdminPort, 2051 },
    { "pop-port", Configuration::PopPort, 110 },
    { "imap-port", Configuration::ImapPort, 143 },
    { "imaps-port", Configuration::ImapsPort, 993 },
    { "smtp-port", Configuration::SmtpPort, 25 },
    { "lmtp-port", Configuration::LmtpPort, 2026 },
    { "http-port", Configuration::HttpPort, 8808 },
    { "db-max-handles", Configuration::DbMaxHandles, 4 },
    { "db-handle-interval", Configuration::DbHandleInterval, 120 },
};


static struct {
    const char * name;
    Configuration::Text variable;
    const char * value;
} textDefaults[Configuration::NumTexts] = {
    { "db", Configuration::Db, "postgres" },
    { "db-user", Configuration::DbUser, DBUSER },
    { "db-name", Configuration::DbName, DBNAME },
    { "db-password", Configuration::DbPassword, "" },
    { "db-address", Configuration::DbAddress, DBADDRESS },
    { "hostname", Configuration::Hostname, "" },
    { "jail-user", Configuration::JailUser, ORYXUSER },
    { "jail-group", Configuration::JailGroup, ORYXGROUP },
    { "jail-directory", Configuration::JailDir, JAILDIR },
    { "allow-plaintext-passwords", Configuration::AllowPlaintextPasswords, "always" },
    { "logfile", Configuration::LogFile, LOGFILE },
    { "tlsproxy-address", Configuration::TlsProxyAddress, "127.0.0.1" },
    { "log-address", Configuration::LogAddress, "127.0.0.1" },
    { "ocd-address", Configuration::OcdAddress, "127.0.0.1" },
    { "ocadmin-address", Configuration::OcAdminAddress, "" },
    { "pop-address", Configuration::PopAddress, "" },
    { "imap-address", Configuration::ImapAddress, "" },
    { "imaps-address", Configuration::ImapsAddress, "" },
    { "smtp-address", Configuration::SmtpAddress, "" },
    { "lmtp-address", Configuration::LmtpAddress, "127.0.0.1" },
    { "http-address", Configuration::HttpAddress, "127.0.0.1" },
    { "tls-certificate", Configuration::TlsCertFile, "" },
    { "log-level", Configuration::LogLevel, "info" },
    { "logfile-mode", Configuration::LogfileMode, LOGFILEMODE },
    { "webmail-css-page", Configuration::WebmailCSS, "http://www.oryx.com/webmail/default.css" },
    { "webmail-js-page", Configuration::WebmailJS, "" },
    { "message-copy-directory", Configuration::MessageCopyDir, "" }
};


static struct {
    const char * name;
    Configuration::Toggle variable;
    bool value;
} toggleDefaults[Configuration::NumToggles] = {
    { "security", Configuration::Security, true },
    { "use-ipv4", Configuration::UseIPv4, true },
    { "use-ipv6", Configuration::UseIPv6, true },
    { "use-tls", Configuration::UseTls, true },
    { "use-smtp", Configuration::UseSmtp, false },
    { "use-lmtp", Configuration::UseLmtp, true },
    { "use-imap", Configuration::UseImap, true },
    { "use-imaps", Configuration::UseImaps, false },
    { "use-http", Configuration::UseHttp, false },
    { "use-pop", Configuration::UsePop, false },
    { "auth-plain", Configuration::AuthPlain, true },
    { "auth-cram-md5", Configuration::AuthCramMd5, true },
    { "auth-digest-md5", Configuration::AuthDigestMd5, true },
    { "auth-anonymous", Configuration::AuthAnonymous, false },
    { "accept-any-http-host", Configuration::AcceptAnyHttpHost, true },
    { "announce-draft-support", Configuration::AnnounceDraftSupport, true },
};



/*! Adds \a l to the list of unparsed variable lines, provided it's
    vaguely sensible.
*/

void Configuration::add( const String & l )
{
    uint i = 0;
    while ( i < l.length() && ( l[i] == ' ' || l[i] == '\t' ) )
        i++;
    if ( i == l.length() || l[i] == '#' )
        return;

    while ( i < l.length() &&
            ( ( l[i] >= 'a' && l[i] <= 'z' ) ||
              ( l[i] >= 'A' && l[i] <= 'Z' ) ||
              ( l[i] >= '0' && l[i] <= '9' ) ||
              ( l[i] == '-' ) ) )
        i++;
    String name = l.mid( 0, i ).lower().simplified();
    while ( l[i] == ' ' || l[i] == '\t' )
        i++;
    if ( l[i] == '#' ) {
        log( "comment immediately after variable name: " + l, Log::Disaster );
        return;
    }
    if ( l[i] != '=' ) {
        log( "no '=' after variable name: " + l, Log::Disaster );
        return;
    }
    i++;
    while ( l[i] == ' ' || l[i] == '\t' )
        i++;
    if ( d->contains( name ) )
        log( "Variable specified twice: " + name, Log::Disaster );
    d->seen.append( name );

    uint n = 0;
    while ( n < NumScalars && name != scalarDefaults[n].name )
        n++;
    if ( n < NumScalars ) {
        parseScalar( n, l.mid( i ) );
        return;
    }
    n = 0;
    while ( n < NumTexts && name != textDefaults[n].name )
        n++;
    if ( n < NumTexts ) {
        parseText( n, l.mid( i ) );
        return;
    }
    n = 0;
    while ( n < NumToggles && name != toggleDefaults[n].name )
        n++;
    if ( n < NumToggles ) {
        parseToggle( n, l.mid( i ) );
        return;
    }

    log( "Unknown variable: " + name, Log::Disaster );
}


void Configuration::parseScalar( uint n, const String & line )
{
    uint i = 0;
    while ( i < line.length() && line[i] >= '0' && line[i] <= '9' )
        i++;

    String name( scalarDefaults[n].name );
    bool ok = true;
    d->scalar[n] = line.mid( 0, i ).number( &ok );
    if ( !ok )
        log( "Bad number (too big?) for " + name + ": " + line.mid( 0, i ),
             Log::Disaster );
    else if ( d->scalar[n] > 0x7fffffff )
        log( name + " is too large, maximum is" + fn( 0x7fffffff ),
             Log::Disaster );

    while ( i < line.length() && ( line[i] == ' ' || line[i] == '\t' ) )
        i++;
    if ( i < line.length() && line[i] != '#' )
        log( "trailing garbage after " + name + " = " + fn( d->scalar[n] ),
             Log::Error );
}


void Configuration::parseText( uint n, const String & line )
{
    String name( textDefaults[n].name );
    uint i = 0;
    if ( line[0] == '"' || line[0] == '\'' ) {
        // quoted, either with ' or "
        i++;
        while ( i < line.length() && line[i] != line[0] )
            i++;
        if ( i >= line.length() )
            log( name + ": Quoted value ran off the end of the line",
                 Log::Disaster );
        d->text[n] = line.mid( 1, i-1 );
        i++;
    }
    else {
        // not quoted - a single word
        while ( i < line.length() &&
                ( ( line[i] >= '0' && line[i] <= '9' ) ||
                  ( line[i] >= 'a' && line[i] <= 'z' ) ||
                  ( line[i] >= 'A' && line[i] <= 'Z' ) ||
                  line[i] == '/' ||
                  line[i] == '.' ||
                  line[i] == '-' ) )
            i++;
        d->text[n] = line.mid( 0, i );
    }

    // followed by whitespace and possibly a comment?
    while ( i < line.length() && ( line[i] == ' ' || line[i] == '\t' ) )
        i++;
    if ( i < line.length() && line[i] != '#' )
        log( "trailing garbage after " + name + " = " + d->text[n],
             Log::Disaster );
}


void Configuration::parseToggle( uint n, const String & line )
{
    String name( toggleDefaults[n].name );
    uint i = 0;
    while ( i < line.length() &&
            ( ( line[i] >= '0' && line[i] <= '9' ) ||
              ( line[i] >= 'a' && line[i] <= 'z' ) ||
              ( line[i] >= 'A' && line[i] <= 'Z' ) ) )
        i++;
    String v = line.mid( 0, i ).lower();

    while ( i < line.length() && ( line[i] == ' ' || line[i] == '\t' ) )
        i++;
    if ( i < line.length() && line[i] != '#' )
        log( "trailing garbage after " + name + " = " + v,
             Log::Disaster );

    if ( v == "0" || v == "off" || v == "no" || v == "false" ||
         v == "disabled" )
        d->toggle[n] = false;
    else if ( v == "1" || v == "on" || v == "yes" || v == "true" ||
              v == "enabled" )
        d->toggle[n] = true;
    else
        log( "Invalid value for toggle " + name + ": " + v,
             Log::Disaster );
}


/*! Returns the compile-time \a setting. */

String Configuration::compiledIn( CompileTimeSetting setting )
{
    switch( setting ) {
    case ConfigDir:
        return CONFIGDIR;
        break;
    case PidFileDir:
        return PIDFILEDIR;
        break;
    case BinDir:
        return BINDIR;
        break;
    case ManDir:
        return MANDIR;
        break;
    case LibDir:
        return LIBDIR;
        break;
    case InitDir:
        return INITDIR;
        break;
    case OryxUser:
        return ORYXUSER;
        break;
    case OryxGroup:
        return ORYXGROUP;
        break;
    case Version:
        return VERSION;
        break;
    }
    return "";
}


/*! Returns the configured value of the scalar variable \a s, or its
    default value if it hasn't been configured.
*/

uint Configuration::scalar( Scalar s )
{
    if ( present( s ) )
        return d->scalar[s];
    return scalarDefaults[s].value;
}


/*! Returns true of scalar variable \a s has been configured, and false if
    the default value is to be used.
*/

bool Configuration::present( Scalar s )
{
    if ( d )
        return d->contains( scalarDefaults[s].name );
    return false;
}


/*! Returns the configured value of the text variable \a t, or its default
    value if it hasn't been configured.
*/

String Configuration::text( Text t )
{
    if ( present( t ) )
        return d->text[t];
    if ( t == Hostname )
        return osHostname();
    return textDefaults[t].value;
}


/*! Returns true of text variable \a t has been configured, and false if
    the default value is to be used.
*/

bool Configuration::present( Text t )
{
    if ( d )
        return d->contains( textDefaults[t].name );
    return false;
}


/*! Returns the configured value of the toggle \a t, or its default value
    if it hasn't been configured.
*/

bool Configuration::toggle( Toggle t )
{
    if ( present( t ) )
        return d->toggle[t];
    return toggleDefaults[t].value;
}


/*! Returns true of toggle \a t has been configured, and false if
    the default value is to be used.
*/

bool Configuration::present( Toggle t )
{
    if ( d )
        return d->contains( toggleDefaults[t].name );
    return false;
}


/*! Returns the variable name of configuration variable \a v. */

const char * Configuration::name( Text v )
{
    return textDefaults[v].name;
}


/*! Returns the variable name of configuration variable \a v. */

const char * Configuration::name( Scalar v )
{
    return scalarDefaults[v].name;
}


/*! Returns the variable name of configuration variable \a v. */

const char * Configuration::name( Toggle v )
{
    return toggleDefaults[v].name;
}


/*! Reports all errors seen so far. Most functions do not report
    errors themselves, because the Logger may not have read its
    configuration data yet by the time most of this code runs, and
    because some errors aren't detectable at once.

    When this function is called, all log lines that haven't been tied
    to variables are logged as erroneous.
*/

void Configuration::report()
{
    if ( !d->errors )
        return;

    Log l( Log::Configuration );
    Scope x( &l );

    List<ConfigurationData::Error>::Iterator it( d->errors );
    while ( it ) {
        ::log( it->e, it->s );
        ++it;
    }
    l.commit();

    d->errors = 0;
}


/*! Creates a new Configuration from file \a global.

    If \a global does not contain a textual variable called
    "hostname", this function tries to find a suitable default, and
    logs a disaster if nothing is satisfactory.
*/

void Configuration::setup( const String & global )
{
    d = new ConfigurationData;
    Allocator::addEternal( d, "configuration data" );

    if ( global[0] == '/' )
        read( global );
    else
        read( compiledIn( ConfigDir ) + "/" + global );

    String hn = text( Hostname );
    if ( hn.find( '.' ) < 0 )
        log( "Hostname does not contain a dot: " + hn, Log::Error );
    if ( hn.lower() == "localhost" || hn.lower().startsWith( "localhost." ) )
        log( "Using localhost as hostname", Log::Error );
}


/*! \fn String Configuration::hostname()
    Returns the configured hostname (or our best guess, if no hostname
    has been specified in the configuration).
*/


/*! Returns the best hostname we can find based on the operating
    system's functions.
*/

String Configuration::osHostname()
{
    char buffer[257];
    gethostname( buffer, 256 );
    buffer[256] = '\0';
    String host( buffer );
    if ( host.find( '.' ) < 0 ) {
        struct hostent * he = gethostbyname( buffer );
        if ( he ) {
            String candidate = he->h_name;
            int i = 0;
            bool done = false;
            do {
                uint hl = host.length();
                if ( candidate[hl] == '.' &&
                     candidate.mid( 0, hl ).lower() == host.lower() ) {
                    host = candidate;
                    done = true;
                }
                candidate = he->h_aliases[i];
                i++;
            } while ( !done && !candidate.isEmpty() );
        }
    }
    return host;
}


/*! Logs \a m as a message of severity \a s, but not yet. report()
    does it later, when the log subsystem is ready.
*/

void Configuration::log( const String & m, Log::Severity s )
{
    if ( !d->errors )
        d->errors = new List<ConfigurationData::Error>;
    ConfigurationData::Error * e = new ConfigurationData::Error;
    e->e = m;
    e->s = s;
    d->errors->append( e );
}
