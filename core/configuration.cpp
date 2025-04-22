// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "configuration.h"

#include "file.h"
#include "list.h"
#include "log.h"
#include "scope.h"
#include "allocator.h"
#include "estringlist.h"

// gethostname()
#include <unistd.h>
// gethostbyname()
#include <netdb.h>
// socket
#include <sys/types.h>
#include <sys/socket.h>
// IPPROTO_TCP
#include <netinet/in.h>
// errno
#include <errno.h>
// memmove()
#include <string.h>


class ConfigurationData
    : public Garbage
{
public:
    ConfigurationData(): errors( 0 ) {}

    uint scalar[Configuration::NumScalars];
    EString text[Configuration::NumTexts];
    bool toggle[Configuration::NumToggles];

    struct Error
        : public Garbage
    {
        Error() : s( Log::Info ) {}

        EString e;
        Log::Severity s;
    };
    List<Error> * errors;
    EStringList seen;
    bool contains( const EString & s )
    {
        EStringList::Iterator i( seen );
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
    available via compiledIn(). These include the path to the
    configuration file.

    Others are available by calling text(), scalar() or toggle() for
    the relevant variable.

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

    During initialization, create a number of Configuration::EString,
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

    If \a allowFailure is true, and the specified \a file cannot be
    read, it is not treated as an error.
*/

void Configuration::read( const EString & file, bool allowFailure )
{
    File f( file );
    if ( !f.valid() ) {
        if ( !allowFailure )
            log( "Error reading configuration file " + file,
                 Log::Disaster );
        return;
    }

    log( "Using configuration file " + file, Log::Debug );

    EString buffer( f.contents() );
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
    { "log-port", Configuration::LogPort, 2054 },
    { "pop-port", Configuration::PopPort, 110 },
    { "imap-port", Configuration::ImapPort, 143 },
    { "imaps-port", Configuration::ImapsPort, 993 },
    { "pops-port", Configuration::PopsPort, 995 },
    { "smtp-port", Configuration::SmtpPort, 25 },
    { "lmtp-port", Configuration::LmtpPort, 2026 },
    { "smtp-submit-port", Configuration::SmtpSubmitPort, 587 },
    { "smtps-port", Configuration::SmtpsPort, 465 },
    { "server-processes", Configuration::ServerProcesses, 2 },
    { "db-max-handles", Configuration::DbMaxHandles, 4 },
    { "db-handle-interval", Configuration::DbHandleInterval, 120 },
    { "db-handle-timeout", Configuration::DbHandleTimeout, 10 },
    { "managesieve-port", Configuration::ManageSievePort, 4190 },
    { "undelete-time", Configuration::UndeleteTime, 49 },
    { "smarthost-port", Configuration::SmartHostPort, 25 },
    { "statistics-port", Configuration::StatisticsPort, 17220 },
    { "ldap-server-port", Configuration::LdapServerPort, 389 },
    { "memory-limit", Configuration::MemoryLimit, 64 }
};


static struct {
    const char * name;
    Configuration::Text variable;
    const char * value;
} textDefaults[Configuration::NumTexts] = {
    { "db", Configuration::Db, "postgres" },
    { "db-name", Configuration::DbName, DBNAME },
    { "db-schema", Configuration::DbSchema, DBSCHEMA },
    { "db-owner", Configuration::DbOwner, DBOWNER },
    { "db-owner-password", Configuration::DbOwnerPassword, "" },
    { "db-user", Configuration::DbUser, AOXUSER },
    { "db-password", Configuration::DbPassword, "" },
    { "db-address", Configuration::DbAddress, DBADDRESS },
    { "hostname", Configuration::Hostname, "" },
    { "jail-user", Configuration::JailUser, AOXUSER },
    { "jail-group", Configuration::JailGroup, AOXGROUP },
    { "jail-directory", Configuration::JailDir, JAILDIR },
    { "allow-plaintext-passwords", Configuration::AllowPlaintextPasswords,
        "always" },
    { "allow-plaintext-access", Configuration::AllowPlaintextAccess,
        "always" },
    { "logfile", Configuration::LogFile, LOGFILE },
    { "log-address", Configuration::LogAddress, "127.0.0.1" },
    { "pop-address", Configuration::PopAddress, "" },
    { "imap-address", Configuration::ImapAddress, "" },
    { "imaps-address", Configuration::ImapsAddress, "" },
    { "pops-address", Configuration::PopsAddress, "" },
    { "smtp-address", Configuration::SmtpAddress, "" },
    { "lmtp-address", Configuration::LmtpAddress, "127.0.0.1" },
    { "smtp-submit-address", Configuration::SmtpSubmitAddress, "" },
    { "smtps-address", Configuration::SmtpsAddress, "" },
    { "tls-private-key", Configuration::TlsKeyFile, "" },
    { "tls-certificate", Configuration::TlsCertFile, "" },
    { "tls-certificate-label", Configuration::TlsCertLabel, "" },
    { "tls-certificate-secret", Configuration::TlsCertSecret, "secret" },
    { "log-level", Configuration::LogLevel, "significant" },
    { "logfile-mode", Configuration::LogfileMode, LOGFILEMODE },
    { "message-copy", Configuration::MessageCopy, "none" },
    { "message-copy-directory", Configuration::MessageCopyDir, MESSAGEDIR },
    { "entropy-source", Configuration::EntropySource, "/dev/urandom" },
    { "managesieve-address", Configuration::ManageSieveAddress, "" },
    { "smarthost-address", Configuration::SmartHostAddress, "127.0.0.1" },
    { "address-separator", Configuration::AddressSeparator, "" },
    { "statistics-address", Configuration::StatisticsAddress, "127.0.0.1" },
    { "ldap-server-address", Configuration::LdapServerAddress, "127.0.0.1" }
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
    { "use-smtp-submit", Configuration::UseSmtpSubmit, true },
    { "use-smtps", Configuration::UseSmtps, false },
    { "use-imap", Configuration::UseImap, true },
    { "use-imaps", Configuration::UseImaps, false },
    { "use-pops", Configuration::UsePops, false },
    { "use-pop", Configuration::UsePop, false },
    { "submit-copy-to-sender", Configuration::SubmitCopyToSender, false },
    { "auth-plain", Configuration::AuthPlain, true },
    { "auth-login", Configuration::AuthLogin, false },
    { "auth-cram-md5", Configuration::AuthCramMd5, true },
    { "auth-digest-md5", Configuration::AuthDigestMd5, false },
    { "auth-anonymous", Configuration::AuthAnonymous, false },
    { "use-sieve", Configuration::UseSieve, true },
    { "use-subaddressing", Configuration::UseSubaddressing, false },
    { "use-statistics", Configuration::UseStatistics, false },
    { "soft-bounce", Configuration::SoftBounce, true },
    { "check-sender-addresses", Configuration::CheckSenderAddresses, false },
    { "use-imap-quota", Configuration::UseImapQuota, true }
};



/*! Adds \a l to the list of unparsed variable lines, provided it's
    vaguely sensible.
*/

void Configuration::add( const EString & l )
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
    EString name = l.mid( 0, i ).lower().simplified();
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


/*! Parses \a line as a scalar and stores at Configuration::Scalar \a
    n. If there are any errors, the name of \a n is used for reporting.
*/

void Configuration::parseScalar( uint n, const EString & line )
{
    uint i = 0;
    while ( i < line.length() && line[i] >= '0' && line[i] <= '9' )
        i++;

    EString name( scalarDefaults[n].name );
    EString v( line.mid( 0, i ) );

    bool ok = true;
    d->scalar[n] = v.number( &ok );
    if ( v.isEmpty() )
        log( "No value specified for " + name, Log::Disaster );
    else if ( !ok )
        log( "Invalid numeric value for " + name + ": " + line,
             Log::Disaster );
    else if ( d->scalar[n] > 0x7fffffff )
        log( name + " is too large, maximum is" + fn( 0x7fffffff ),
             Log::Disaster );

    while ( i < line.length() && ( line[i] == ' ' || line[i] == '\t' ) )
        i++;
    if ( i < line.length() && line[i] != '#' ) {
        EString s;
        s.append( line[i] );

        log( "Non-numeric character " + s.quoted() + " after " + name + " = " +
             fn( d->scalar[n] ), Log::Error );
    }
}


/*! Parses \a line as a text and stores at Configuration::Text \a
    n. If there are any errors, the name of \a n is used for reporting.
*/

void Configuration::parseText( uint n, const EString & line )
{
    EString name( textDefaults[n].name );
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
                  line[i] == '_' ||
                  line[i] == '-' ) )
            i++;
        d->text[n] = line.mid( 0, i );
        if ( d->text[n].isEmpty() )
            log( "No value specified for " + name, Log::Disaster );
    }

    // followed by whitespace and possibly a comment?
    while ( i < line.length() && ( line[i] == ' ' || line[i] == '\t' ) )
        i++;
    if ( i < line.length() && line[i] != '#' ) {
        EString s;
        s.append( line[i] );

        log( "Unquoted special character " + s.quoted() + " after " +
             name + " = " + d->text[n], Log::Disaster );
    }
}


/*! Parses \a line as a toggle and stores at Configuration::Toggle \a
    n. If there are any errors, the name of \a n is used for reporting.
*/

void Configuration::parseToggle( uint n, const EString & line )
{
    EString name( toggleDefaults[n].name );
    uint i = 0;
    while ( i < line.length() &&
            ( ( line[i] >= '0' && line[i] <= '9' ) ||
              ( line[i] >= 'a' && line[i] <= 'z' ) ||
              ( line[i] >= 'A' && line[i] <= 'Z' ) ) )
        i++;
    EString v = line.mid( 0, i ).lower();

    if ( v.isEmpty() )
        log( "No value specified for " + name, Log::Disaster );
    else if ( v == "0" || v == "off" || v == "no" || v == "false" ||
              v == "disabled" )
        d->toggle[n] = false;
    else if ( v == "1" || v == "on" || v == "yes" || v == "true" ||
              v == "enabled" )
        d->toggle[n] = true;
    else
        log( "Invalid value for toggle " + name + ": " + v,
             Log::Disaster );

    while ( i < line.length() && ( line[i] == ' ' || line[i] == '\t' ) )
        i++;
    if ( i < line.length() && line[i] != '#' ) {
        EString s;
        s.append( line[i] );

        log( "Unrecognised character " + s.quoted() +
             " after " + name + " = " + v,
             Log::Disaster );
    }
}


/*! Returns the compile-time \a setting. */

const char * Configuration::compiledIn( CompileTimeSetting setting )
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
    case SbinDir:
        return SBINDIR;
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
    case AoxUser:
        return AOXUSER;
        break;
    case AoxGroup:
        return AOXGROUP;
        break;
    case PgUser:
        return PGUSER;
        break;
    case DefaultDbAddress:
        return DBADDRESS;
        break;
    case Version:
        return VERSION;
        break;
    }
    return "";
}


/*! Returns the fully-qualified name of the configuration file (e.g.
    /usr/local/archiveopteryx/archiveopteryx.conf) based on the
    compiledIn() value for the configuration directory.

    Merely a convenience.
*/

EString Configuration::configFile()
{
    EString s( compiledIn( ConfigDir ) );
    s.append( "/archiveopteryx.conf" );
    return s;
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

EString Configuration::text( Text t )
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

    Log l;
    Scope x( &l );

    List<ConfigurationData::Error>::Iterator it( d->errors );
    while ( it ) {
        ::log( it->e, it->s );
        ++it;
    }

    d->errors = 0;
}


/*! Creates a new Configuration from file \a global.

    If \a global does not contain a textual variable called
    "hostname", this function tries to find a suitable default, and
    logs a disaster if nothing is satisfactory.

    If \a global is an empty string, the function returns without trying
    to parse a configuration file. This experimental measure is meant to
    help lib/installer.

    If \a allowFailure is true, a non-existent configuration file is
    tolerated silently. Another installer-helping measure.
*/

void Configuration::setup( const EString & global, bool allowFailure )
{
    d = new ConfigurationData;
    Allocator::addEternal( d, "configuration data" );

    if ( global.isEmpty() )
        return;
    else if ( global[0] == '/' )
        read( global, allowFailure );
    else
        read( EString( compiledIn( ConfigDir ) ) + "/" + global,
              allowFailure );

    EString hn = text( Hostname );
    if ( hn.find( '.' ) < 0 )
        log( "Hostname does not contain a dot: " + hn, Log::Error );
    if ( hn.lower() == "localhost" || hn.lower().startsWith( "localhost." ) )
        log( "Using localhost as hostname", Log::Error );

    if ( !present( UseIPv6 ) && toggle( UseIPv6 ) ) {
        int s = ::socket( PF_INET6, SOCK_STREAM, IPPROTO_TCP );
        bool bad = false;
        bool good = false;
        if ( s < 0 ) {
            bad = true;
        }
        if ( !bad ) {
            struct sockaddr_in6 in6;
            in6.sin6_family = AF_INET6;
            in6.sin6_port = ntohs( 17 ); // stomping on fortune is okay
            in6.sin6_flowinfo = 0;
            int i = 0;
            while ( i < 15 ) {
                in6.sin6_addr.s6_addr[i] = 0;
                ++i;
            }
            in6.sin6_addr.s6_addr[15] = 1;
            in6.sin6_scope_id = 0;
            if ( ::bind( s, (struct sockaddr *)&in6, sizeof( in6 ) ) < 0 ) {
                if ( errno == EADDRINUSE )
                    good = true; // someone is using that: fine
                else
                    bad = true; // some other error: IPv6 presumably broken
            }
        }
        if ( !good && !bad && s >= 0 ) {
            if ( ::listen( s, 1 ) < 0 )
                bad = true;
            else
                good = true;
        }
        if ( s >= 0 )
            ::close( s );
        if ( bad ) {
            log( "Setting default use-ipv6=off", Log::Info );
            add( "use-ipv6 = false" );
        }
    }
}


/*! \fn EString Configuration::hostname()
    Returns the configured hostname (or our best guess, if no hostname
    has been specified in the configuration).
*/


/*! Returns the best hostname we can find based on the operating
    system's functions.
*/

EString Configuration::osHostname()
{
    char buffer[257];
    gethostname( buffer, 256 );
    buffer[256] = '\0';
    EString host( buffer );
    if ( host.find( '.' ) < 0 ) {
        struct hostent * he = gethostbyname( buffer );
        if ( he ) {
            EString candidate = he->h_name;
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

void Configuration::log( const EString & m, Log::Severity s )
{
    if ( !d->errors )
        d->errors = new List<ConfigurationData::Error>;
    ConfigurationData::Error * e = new ConfigurationData::Error;
    e->e = m;
    e->s = s;
    d->errors->append( e );
}


/*! Returns a list of the variables that refer to addresses. This
    function is a little slow. It never returns 0.
*/

List<Configuration::Text> * Configuration::addressVariables()
{
    uint i = 0;
    List<Text> * r = new List<Text>;
    while ( i < NumTexts ) {
        EString name( textDefaults[i].name );
        if ( name.endsWith( "-address" ) ) {
            Configuration::Text * t = new Configuration::Text;
            *t = (Configuration::Text)i;
            r->append( t );
        }
        i++;
    }
    return r;
}
