#include "configuration.h"

#include "file.h"
#include "list.h"
#include "log.h"
#include "test.h"

#include <unistd.h> // gethostname()
#include <netdb.h> // gethostbyname()

// this needs to be last because sys.h sneakily includes lots of
// system header files.
#include "sys.h" // memmove()

class ConfigurationData
{
public:
    ConfigurationData(): reported( false ), fileExists( false ) {}

    List<Configuration::Something> unparsed;
    struct E {
        E(): s( Log::Error ) {}
        String m;
        Log::Severity s;
    };
    List<E> errors;
    String f;
    bool reported;
    bool fileExists;

    void error( const String & m, Log::Severity s = Log::Error ) {
        E * e = new E;
        e->m = m;
        e->s = s;
        errors.append( e );
    }
};


static String * hostname = 0;


/*! \class Configuration configuration.h
    The Configuration class describes a configuration file.

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


/*!  Constructs a configuration and reads \a file.
*/

Configuration::Configuration( const String & file )
{
    d = new ConfigurationData;
    read( file );
}


/*! Reads \a file, replacing the previous configuration data held by
    the object. In case of error, the Configuration object is left
    empty. Unknown configuration variables are logged and ignored.
*/

void Configuration::read( const String & file )
{
    clear();
    d->f = file;
    File f( file, File::Read );
    if ( !f.valid() )
        return;

    d->fileExists = true;
    String buffer( f.contents() );
    // we now want to loop from 0 to offset, picking up entire
    // lines and parsing them as variables.
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
        d->error( "comment immediately after variable name: " + l );
        return;
    }
    if ( l[i] != '=' ) {
        d->error( "no '=' after variable name: " + l );
        return;
    }
    i++;
    while ( l[i] == ' ' || l[i] == '\t' )
        i++;
    d->unparsed.append( new Something( name, l.mid( i, l.length() ) ) );
}


/*! Gets rid of all unparsed variable lines, so parsing an restart. */

void Configuration::clear()
{
    d->unparsed.clear();
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
    d->reported = true;
    Log l;

    if ( d->unparsed.isEmpty() && d->errors.isEmpty() )
        return;

    bool e = false;
    if ( !d->unparsed.isEmpty() )
        e = true;
    List< ConfigurationData::E >::Iterator i = d->errors.first();
    while ( i && !e ) {
        if ( i->s == Log::Error || i->s == Log::Disaster )
            e = true;
        i++;
    }
    
    if ( d->fileExists )
        log( Log::Info, "While reading config file " + d->f + ":" );
    else if ( e )
        log( Log::Info, "Unable to open config file " + d->f );

    i = d->errors.first();
    while ( i ) {
        log( i->s, i->m );
        i++;
    }

    List< Configuration::Something >::Iterator j = d->unparsed.first();
    while ( j ) {
        log( Log::Error, "Unknown configuration variable: " + j->s1 );
        j++;
    }

    l.commit( Log::Info );
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

void Configuration::Variable::init( Configuration * c, const String &name )
{
    List< Configuration::Something >::Iterator i;

    i = c->d->unparsed.first();
    while ( i && i->s1 != name )
        i++;

    Something *x = c->d->unparsed.take( i );

    if ( c->d->reported ) {
        // we're already up and running
        log( Log::Error,
             "Configuration variable created after parsing finished: " + name );
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
        c->d->error( "Parse error: " + x->s1 + " = " + x->s2 );
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

Configuration::Scalar::Scalar( const String & name, int defaultValue,
                               Configuration * c )
    : Variable(), value( defaultValue )
{
    init( c, name );
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

Configuration::Toggle::Toggle( const String & name, bool defaultValue,
                               Configuration * c )
    : Variable(), value( defaultValue )
{
    init( c, name );
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

Configuration::Text::Text( const String & name, const String & defaultValue,
                           Configuration * c )
    : Variable(), value( defaultValue )
{
    init( c, name );
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


static Configuration * global = 0;


/*! Returns the same pointer as the last return value of makeGlobal(). */

Configuration * Configuration::global()
{
    return ::global;
}


/*! Creates a new Configuration from file \a s. Later, global()
    returns a pointer to this Configuration object.

    If \a s does not contains a textual variable called "hostname",
    this function tries to find a suitable default, and logs a
    disaster if neither is satisfactory.
*/

void Configuration::makeGlobal( const String & s )
{
    ::global = new Configuration( s );
    char buffer[257];
    buffer[256] = '\0';
    gethostname( buffer, 256 );
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
    Configuration::Text hn( "hostname", host );
    if ( !hn.valid() )
        ::global->d->error( "Syntax error in hostname",
                            Log::Disaster );
    else if ( ((String)hn).find( '.' ) < 0 )
        ::global->d->error( "Hostname does not contain a dot: " + hn,
                            Log::Disaster );
    else if ( host == hn )
        ::global->d->error( "Using inferred hostname " + host, 
                            Log::Info );

    ::hostname = new String( hn );
}


/*! Returns the hostname, as configured in our server or the operating
    system. If no hostname is avalable, this function returns an empty
    string.
*/

String Configuration::hostname()
{
    if ( !::hostname ) {
        if ( !::global )
            return "oryx.invalid";
        return "";
    }
    return *::hostname;
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

        verify( "hostname() didn't return a sane value for tests.",
                Configuration::hostname() != "oryx.invalid" );

        // that makeGlobal works
        verify( "Incorrect initial value for global()",
                Configuration::global() );
        Configuration::makeGlobal( "/dev/null" );
        verify( "global() incorrectly set up",
                !Configuration::global() );
        ::global = 0;

        {
            File f( "/tmp/oryx-config-test.cf", File::Write );
            verify( "could not open test config file",
                    !f.valid() );
            f.write( String( conf, strlen( conf ) ) );
        }

        Configuration a( "/tmp/oryx-config-test.cf" );
        File::unlink( "/tmp/oryx-config-test.cf" );

        Configuration::Scalar i1( "i1", 0, &a );
        Configuration::Scalar i2( "i2", 0, &a );
        Configuration::Scalar i3( "i3", 0, &a );
        Configuration::Scalar i4( "i4", 0, &a );
        Configuration::Scalar i5( "i5", 0, &a );
        Configuration::Scalar i6( "i6", 0, &a );
        Configuration::Scalar i7( "i7", 1, &a );
        Configuration::Scalar i8( "i8", 42, &a ); // default

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

        Configuration::Toggle b1( "b1", false, &a );
        Configuration::Toggle b2( "b2", false, &a );
        Configuration::Toggle b3( "b3", false, &a );
        Configuration::Toggle b4( "b4", false, &a );
        Configuration::Toggle b5( "b5", false, &a );
        Configuration::Toggle b6( "b6", true, &a );
        Configuration::Toggle b7( "b7", true, &a );
        Configuration::Toggle b8( "b8", true, &a );
        Configuration::Toggle b9( "b9", true, &a );
        Configuration::Toggle b0( "b0", true, &a );

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

        Configuration::Text s1( "s1", "abhijit", &a );
        Configuration::Text s2( "s2", "abhijit", &a );
        Configuration::Text s3( "s3", "abhijit", &a );
        Configuration::Text s4( "s4", "abhijit", &a );
        Configuration::Text s5( "s5", "abhijit", &a );
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

        Configuration::Text c1( "c1", "abstinence", &a );
        Configuration::Text c2( "c2", "abstinence", &a );
        Configuration::Text c3( "c3", "abstinence", &a );
        Configuration::Text c4( "c4", "abstinence", &a );
        Configuration::Text c5( "c5", "abstinence", &a );
        verify( "At least one comment was mishandle",
                !c1.valid(), !c2.valid(), !c3.valid(), !c4.valid(),
                !c5.valid() );

        verify( "At least one comment caused default/set problems",
                !c1.supplied(), !c2.supplied(), !c3.supplied(),
                !c4.supplied(), c5.supplied() );


        verify( "At least one comment caused wrong valued-result",
                c1 != "sex", c2 != "sex", c3 != "sex", c4 != "sex",
                c5 != "abstinence" );
    }
} configurationTest;
