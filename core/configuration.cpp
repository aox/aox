#include "configuration.h"

#include "file.h"
#include "list.h"
#include "dict.h"
#include "log.h"
#include "test.h"
#include "scope.h"

#include <unistd.h> // gethostname()
#include <netdb.h> // gethostbyname()

// this needs to be last because sys.h sneakily includes lots of
// system header files.
#include "sys.h" // memmove()

class ConfigurationData
{
public:
    ConfigurationData(): reported( false ), fileExists( false ) {}

    Dict<Configuration::Something> unparsed;
    struct E {
        E(): s( Log::Error ) {}
        String m;
        Log::Severity s;
    };
    List<E> errors;
    String f;
    bool reported;
    bool fileExists;

    void log( const String & m, Log::Severity s = Log::Error ) {
        E * e = new E;
        e->m = m;
        e->s = s;
        errors.append( e );
    }
};


static String * hostname = 0;
static Configuration * global = 0;


/*! \class Configuration configuration.h
    The Configuration class contains all configuration variables.

    The file contains an arbitrary number of single-line variable
    assignments, each of which specifies an integer, a toggle, or
    a string.

    Comments extend from a '#' sign until the end of the line. In
    quoted strings, '#' may be used.

    To use this class, create a Configuration object naming the file
    and subsequently a number of Configuration::Scalar or
    Configuration::Toggle objects naming the variable. When all
    configuration variable objects have been created, you call
    report(), and all errors are reported via the log server. Note
    that if you don't call report(), a typo may result in a variable
    silently being reverted to default.

    There is one "global" configuration, which is used for the sort of
    things all our servers must have, e.g. the address of the log
    server.

    In addition to its normal variables, Configuration also contains a
    single magic variable, the hostname. The hostname can be set in
    the global configuration file, if not Configuration attempts to
    find a name.
*/


/*! Constructs an empty Configuration containing no variables. */

Configuration::Configuration()
{
    d = new ConfigurationData;
}


/*! Reads \a file, adding to the previous configuration data held by
    the object. In case of error, \a file is not read. Unknown
    configuration variables are logged and ignored.
*/

void Configuration::read( const String & file )
{
    d->f = file;
    File f( file, File::Read );
    if ( !f.valid() ) {
        d->log( "Error reading configuration file " + file );
        return;
    }

    d->log( "Using configuration file " + file, Log::Debug );

    d->fileExists = true;
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
              ( l[i] >= '0' && l[i] <= '9' ) ) )
        i++;
    String name = l.mid( 0, i ).lower().simplified();
    while ( l[i] == ' ' || l[i] == '\t' )
        i++;
    if ( l[i] == '#' ) {
        d->log( "comment immediately after variable name: " + l );
        return;
    }
    if ( l[i] != '=' ) {
        d->log( "no '=' after variable name: " + l );
        return;
    }
    i++;
    while ( l[i] == ' ' || l[i] == '\t' )
        i++;
    if ( d->unparsed.contains( name ) )
        d->log( "Variable specified twice: " + name );
    d->unparsed.insert( name, new Something( name, l.mid( i, l.length() ) ) );
}


/*! Tells the Configuration that if \a s1, \a s2, \a s3, \a s4, \a s5,
    \a s6, \a s7 or \a s8 are unused, report() should not bicker.

    This function exists to work around variables that are used in
    almost all programs, but unused in one. For example, the database
    settings are not used in the logd. In order to avoid warnings
    about the logd configuration, logd can ignore() the variables it
    knows it won't want.

    This function takes eight arguments, but only one, \a s1, is mandatory.
*/

void Configuration::ignore( const char * s1, const char * s2,
                            const char * s3, const char * s4,
                            const char * s5, const char * s6,
                            const char * s7, const char * s8 )
{
    if ( s1 && *s1 )
        ::global->d->unparsed.take( s1 );
    if ( s2 && *s2 )
        ::global->d->unparsed.take( s2 );
    if ( s3 && *s3 )
        ::global->d->unparsed.take( s3 );
    if ( s4 && *s4 )
        ::global->d->unparsed.take( s4 );
    if ( s5 && *s5 )
        ::global->d->unparsed.take( s5 );
    if ( s6 && *s6 )
        ::global->d->unparsed.take( s6 );
    if ( s7 && *s7 )
        ::global->d->unparsed.take( s7 );
    if ( s8 && *s8 )
        ::global->d->unparsed.take( s8 );
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
    Log l( Log::Configuration );

    Scope x;
    x.setLog( &l );

    ::global->d->reported = true;

    List< ConfigurationData::E >::Iterator i = ::global->d->errors.first();
    while ( i ) {
        log( i->s, i->m );
        i++;
    }

#if 0
    // don't want to write a dict iterator just now
    List< Configuration::Something >::Iterator j
        = ::global->d->unparsed.first();
    while ( j ) {
        log( Log::Error, "Unknown configuration variable: " + j->s1 );
        j++;
    }
#endif

    l.commit();
}


/*! \class Configuration::Variable configuration.h

    The Configuration::Variable class is the base class of configuration
    variables.

    Like all good base classes, it does little itself, merely
    remembers whether the instantiated object was supplied() in a
    configuration file or was left default, and whether the supplied
    value was valid().
*/


/*! \fn bool Configuration::Variable::valid() const

    Returns true if this configuration variable has a valid value,
    either from a configuration file or from a default.
*/


/*! \fn bool Configuration::Variable::supplied() const

    Returns true if this configuration variable was set by a
    configuration file.
*/

/*! \fn bool Configuration::Variable::setValue( const String & s )

    This pure virtual function is responsible for parsing \a s into a
    value commensurate with \a s and the variable type. (The class
    documentation for Configuration::String, Configuration::Scalar and
    Configuration::Toggle specifies the expected input formats.)
*/

/*! This is really the constructor, but it's called by the subclass
    constructor instead of being in the syntactical constructor.

    A gross hack for a good reason: This way, the virtual function
    setValue() can be called.

    \a c is the Configuration object to which this value belongs, and
    \a name is the name of this value.
*/

void Configuration::Variable::init( const String &name )
{
    Something *x = ::global->d->unparsed.take( name );

    if ( ::global->d->reported ) {
        // we're already up and running
        log( Log::Error,
             "Configuration variable created after parsing finished: " +
             name );
    }
    if ( x == 0 ) {
        // nothing - we keep the default value
    }
    else if ( setValue( x->s2 ) ) {
        // setValue set the value, so we turn on the 'supplied()' bit
        s = true;
    }
    else {
        // there was an error. log it later, when the logger is up,
        // and keep the default value.
        ok = false;
        ::global->d->log( "Parse error: " + x->s1 + " = " + x->s2 );
    }
}


/*! \fn bool Configuration::setValue( const String & s )

    This virtual function is called to set the variable's value to \a
    s. It must return true if \a s is syntactically valid (perhaps
    with trailing whitespace or comments), and false if not. If it
    returns false, the object must not be changed.
*/


/*! \class Configuration::Scalar configuration.h
  The Configuration::Scalar class keeps scalar configuration variables.

  A scalar is integer within the range 0 to 2147483647 inclusive.
*/


/*! Creates a new scalar configuration value named \a name in
    configuration file \a c (the file defaults to
    Configuration::global()), and whose default value is \a
    defaultValue.

    The scalar must be a nonnegative integer less than 2147483648.
*/

Configuration::Scalar::Scalar( const String & name, int defaultValue )
    : Variable(), value( defaultValue )
{
    init( name );
}


bool Configuration::Scalar::setValue( const String & line )
{
    uint i = 0;
    while ( i < line.length() && line[i] >= '0' && line[i] <= '9' )
        i++;

    bool ok = true;
    uint n = line.mid( 0, i ).number( &ok );
    if ( !ok || n > 0x7fffffff )
        return false;

    while ( i < line.length() && ( line[i] == ' ' || line[i] == '\t' ) )
        i++;
    if ( i < line.length() && line[i] != '#' )
        return false;

    value = n;
    return true;
}


/*! \class Configuration::Toggle configuration.h
  The Configuration::Scalar class keeps boolean configuration variables.

  A toggle is yes/no, true/false etc. In the API it is represented as
  a bool, in the configuration file it can be "yes", "true", "on", "1"
  on the one and and "no", "false", "off" or "0".
*/


/*! Creates a new toggle configuration value named \a name in
    configuration file \a c (the file defaults to
    Configuration::global()), and whose default value is \a
    defaultValue.
*/

Configuration::Toggle::Toggle( const String & name, bool defaultValue )
    : Variable(), value( defaultValue )
{
    init( name );
}


bool Configuration::Toggle::setValue( const String & line )
{
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
        return false;

    if ( v == "0" || v == "off" || v == "no" || v == "false" ||
         v == "disabled" )
        value = false;
    else if ( v == "1" || v == "on" || v == "yes" || v == "true" ||
              v == "enabled" )
        value = true;
    else
        return false;

    return true;

}


/*! \class Configuration::Text configuration.h
  The Configuration::Text class keeps textual configuration variables.

  Such a variable must be a single-line string. If it's a single word
  it can be stored just like that, if not it must be quoted either
  with " or '.
*/


/*! Creates a new toggle configuration text named \a name in
    configuration file \a c (the file defaults to
    Configuration::global()), and whose default value is \a
    defaultValue.

    All Texts must have single-lined values.
*/

Configuration::Text::Text( const String & name, const String & defaultValue )
    : Variable(), value( defaultValue )
{
    init( name );
}


bool Configuration::Text::setValue( const String & line )
{
    uint i = 0;
    String v;
    if ( line[0] == '"' || line[0] == '\'' ) {
        // quoted, either with ' or "
        i++;
        while ( i < line.length() && line[i] != line[0] )
            i++;
        if ( i >= line.length() )
            return false;
        v = line.mid( 1, i-1 );
        i++;
    }
    else {
        // not quoted - a single word
        while ( i < line.length() &&
                ( ( line[i] >= '0' && line[i] <= '9' ) ||
                  ( line[i] >= 'a' && line[i] <= 'z' ) ||
                  ( line[i] >= 'A' && line[i] <= 'Z' ) ||
                  line[i] == '.' ||
                  line[i] == '-' ) )
            i++;
        v = line.mid( 0, i );
    }

    // followed by whitespace and possibly a comment?
    while ( i < line.length() && ( line[i] == ' ' || line[i] == '\t' ) )
        i++;
    if ( i < line.length() && line[i] != '#' )
        return false; // no

    value = v;
    return true;

}


/*! Creates a new Configuration from file \a global and optionally
    also from \a server. Later, global() returns a pointer to this
    Configuration object.

    If neither \a global nor \a server contains a textual variable
    called "hostname", this function tries to find a suitable default,
    and logs a disaster if nothing is satisfactory.
*/

void Configuration::setup( const String & global, const String & server )
{
    ::global = new Configuration;
    ::global->read( global );
    if ( !server.isEmpty() )
        ::global->read( server );

    String host = osHostname();
    Configuration::Text hn( "hostname", host );
    if ( !hn.valid() )
        ::global->d->log( "Syntax error in hostname",
                          Log::Disaster );
    else if ( ((String)hn).find( '.' ) < 0 )
        ::global->d->log( "Hostname does not contain a dot: " + hn,
                          Log::Disaster );
    else if ( host == hn )
        ::global->d->log( "Using inferred hostname " + host,
                          Log::Debug );

    ::hostname = new String( hn );
}


/*! Returns the best hostname we can find based on the operating
    systems functions.
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


/*! Returns the hostname, as configured in our server or the operating
    system. If no hostname is avalable, this function returns an empty
    string.
*/

String Configuration::hostname()
{
    if ( ::hostname )
        return *::hostname;
    return "";
}


// this contains only good stuff... we don't test that bad stuff
// breaks. at least not yet.
static const char * conf =
"# comment\n"
"    # comment\n"
"i1 = 1\n"
"i2 = 2\n"
"i3 = 10\n"
"i4 = 2147483647\n"
"i5 = 2147483646\n"
"i6 = 2147483645\n"
"i7 = 0\n"
"\n"
"b1 = enabled\n"
"b2 = on\n"
"b3 = yes\n"
"b4 = true\n"
"b5 = 1\n"
"b6 = disabled\n"
"b7 = off\n"
"b8 = no\n"
"b9 = false\n"
"b0 = 0\n"
"\n"
"s1 = shrutipriya\n"
"s2 = \"shrutipriya\"\n"
"s3 = \"shrutipriya ' shrutipriya\"\n"
"s4 = 'shrutipriya'\n"
"s5 = 'shrutipriya \" shrutipriya'\n"
"\n"
"# comment again\n"
"\n"
"c1=sex#comment\n"
"c2 = sex#comment\n"
"c3=sex #comment\n"
"c4='sex'#comment\n";


static class ConfigurationTest : public Test {
public:
    ConfigurationTest() : Test( 250 ) {}
    void test() {
        setContext( "Testing Configuration" );

        verify( "osHostname() didn't return a dotted string",
                Configuration::osHostname().find( "." ) < 0 );

        verify( "hostname() didn't return a sane value for tests.",
                Configuration::hostname() != "" );

        // that setup works
        verify( "Incorrect initial value for global()",
                ::global );
        Configuration::setup( "/dev/null" );
        verify( "setup() did not",
                !::global );
        ::global = 0;
        ::hostname = 0;

        {
            File f( "/tmp/oryx-config-test.cf", File::Write );
            verify( "could not open test config file",
                    !f.valid() );
            f.write( String( conf, strlen( conf ) ) );
        }

        Configuration::setup( "/tmp/oryx-config-test.cf" );
        File::unlink( "/tmp/oryx-config-test.cf" );

        Configuration::Scalar i1( "i1", 0 );
        Configuration::Scalar i2( "i2", 0 );
        Configuration::Scalar i3( "i3", 0 );
        Configuration::Scalar i4( "i4", 0 );
        Configuration::Scalar i5( "i5", 0 );
        Configuration::Scalar i6( "i6", 0 );
        Configuration::Scalar i7( "i7", 1 );
        Configuration::Scalar i8( "i8", 42 ); // default

        verify(  "At least one supplied scalar was mishandled",
                 !i1.supplied(), !i2.supplied(),
                 !i3.supplied(), !i4.supplied(),
                 !i5.supplied(), !i6.supplied(),
                 !i7.supplied() );

        verify( "At least one supplied scalar was set to invalid",
                !i1.valid(), !i2.valid(), !i3.valid(), !i4.valid(),
                !i5.valid(), !i6.valid(), !i7.valid() );

        verify( "Scalar configuration broke for value 1",
                (int)i1 != 1 );
        verify( "Scalar configuration broke for value 2",
                (int)i2 != 2 );
        verify( "Scalar configuration broke for value 10",
                (int)i3 != 10 );
        verify( "Scalar configuration broke for value 2147483647",
                (int)i4 != 2147483647 );
        verify( "Scalar configuration broke for value 2147483646",
                (int)i5 != 2147483646 );
        verify( "Scalar configuration broke for value 2147483645",
                (int)i6 != 2147483645 );
        verify( "Scalar configuration broke for value 1",
                (int)i7 != 0 );
        verify( "Scalar configuration broke for value 42",
                (int)i8 != 42 );

        verify( "Default-valued scalar recorded as supplied", i8.supplied() );
        verify( "Default-valued scalar recorded as not OK", !i1.valid() );

        Configuration::Toggle b1( "b1", false );
        Configuration::Toggle b2( "b2", false );
        Configuration::Toggle b3( "b3", false );
        Configuration::Toggle b4( "b4", false );
        Configuration::Toggle b5( "b5", false );
        Configuration::Toggle b6( "b6", true );
        Configuration::Toggle b7( "b7", true );
        Configuration::Toggle b8( "b8", true );
        Configuration::Toggle b9( "b9", true );
        Configuration::Toggle b0( "b0", true );

        verify( "At least one supplied toggle was misparsed",
                !b1.valid(), !b2.valid(), !b3.valid(), !b4.valid(),
                !b5.valid(), !b6.valid(), !b7.valid(), !b8.valid(),
                !b9.valid(), !b0.valid() );

        verify( "At least one supplied toggle was recorded as default",
                !b1.supplied(), !b2.supplied(), !b3.supplied(),
                !b4.supplied(), !b5.supplied(), !b6.supplied(),
                !b7.supplied(), !b8.supplied(), !b9.supplied(),
                !b0.supplied() );


        verify( "At least one enabled toggle was misparsed",
                !b1, !b2, !b3, !b4, !b5 );

        verify( "At least one disabled toggle was misparsed",
                b6, b7, b8, b9, b0 );

        Configuration::Text s1( "s1", "abhijit" );
        Configuration::Text s2( "s2", "abhijit" );
        Configuration::Text s3( "s3", "abhijit" );
        Configuration::Text s4( "s4", "abhijit" );
        Configuration::Text s5( "s5", "abhijit" );
        verify( "At least one supplied text was misparsed",
                !s1.valid(), !s2.valid(), !s3.valid(), !s4.valid(),
                !s5.valid() );

        verify( "At least one supplied text was recorded as default",
                !s1.supplied(), !s2.supplied(), !s3.supplied(),
                !s4.supplied(), !s5.supplied() );


        verify( "At least one supplied string was misparsed",
                s1 != "shrutipriya",
                s2 != "shrutipriya",
                s3 != "shrutipriya ' shrutipriya",
                s4 != "shrutipriya",
                s5 != "shrutipriya \" shrutipriya" );

        Configuration::Text c1( "c1", "abstinence" );
        Configuration::Text c2( "c2", "abstinence" );
        Configuration::Text c3( "c3", "abstinence" );
        Configuration::Text c4( "c4", "abstinence" );
        Configuration::Text c5( "c5", "abstinence" );
        verify( "At least one comment was mishandle",
                !c1.valid(), !c2.valid(), !c3.valid(), !c4.valid(),
                !c5.valid() );

        verify( "At least one comment caused default/set problems",
                !c1.supplied(), !c2.supplied(), !c3.supplied(),
                !c4.supplied(), c5.supplied() );

        verify( "At least one comment caused wrong valued-result",
                c1 != "sex", c2 != "sex", c3 != "sex", c4 != "sex",
                c5 != "abstinence" );

        ::global = 0;
        ::hostname = 0;
    }
} configurationTest;

