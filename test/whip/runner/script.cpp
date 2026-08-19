// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "script.h"

#include "file.h"
#include "dict.h"
#include "allocator.h"
#include "estringlist.h"

#include <stdio.h>


static Dict<TestScript> * providers;


extern bool verbose;


class TestScriptData
    : public Garbage
{
public:
    TestScriptData(): current( 0 ), line( 0 ), linesLeft( 0 ),
                      failed( false ), necessary( true ), broken( false )
    {}

    struct Section
        : public Garbage
    {
        Section(): port( 0 ), mode( TestScript::Done ) {}
        EString protocol;
        uint port;
        EString clientName;
        EStringList lines;
        TestScript::Action mode;
    };

    Section * current;
    List<Section> sections;
    List<Section>::Iterator iterator;
    TestScript::Action parseState;
    EString filename;
    uint line;
    uint linesLeft;
    bool failed;
    bool necessary;
    bool broken;
    EString depends;
    EString provides;
};


/*! \class TestScript script.h

    This class reads a single script from a script file and hands it
    out on request, so it can be executed.

    It also contains code to find a script which provides a given
    state.
*/


/*! Constructs a test script based on the file \a f. If there's a
    syntax error, this records the error... how?

*/

TestScript::TestScript( File * f )
    : d( new TestScriptData )
{
    d->filename = f->name();
    if ( !f->valid() )
        error( "File does not exist: " + f->name() );
    else
        parse( f );
    if ( d->failed )
        return;
    d->provides = d->filename;
    while ( d->provides.contains( '/' ) )
        d->provides = d->provides.mid( d->provides.find( '/' ) + 1 );
    if ( !providers ) {
        providers = new Dict<TestScript>;
        Allocator::addEternal( providers, "all test scripts" );
    }
    providers->insert( d->provides, this );
}


/*! This private helper parses \a f and records the information in
    it. It may call record errors.
*/

void TestScript::parse( File * f )
{
    if ( verbose )
        fprintf( stderr, "parsing %s\n", f->name().cstr() );
    EString c = f->contents();
    uint i = 0;
    uint l = 0;
    d->line = 1;
    while ( i < c.length() ) {
        if ( c[i] == '\n' ) {
            parseLine( c.mid( l, i - l ) );
            d->line++;
            l = i + 1;
        }
        i++;
    }
    if ( i > l )
        parseLine( c.mid( l ) );
    if ( d->parseState != Done )
        error( "Script ended unexpectedly" );
    if ( d->linesLeft )
        error( "Missing at least " + fn( d->linesLeft ) +
               " lines plus 'end'" );
}


/*! Parses the single line \a l. Changes the parser's state, but does
    not act on the line.
*/

void TestScript::parseLine( const EString & l )
{
    switch ( d->parseState ) {
    case Command:
    case Connect:
        if ( l.startsWith( "#" ) ) {
            // it's a comment. skip it.
        }
        else if ( l != "end" && l != "broken" && !l.contains( ' ' ) ) {
            error( "Cannot find space after command" );
        }
        else {
            uint i = (uint)l.find( ' ' );
            if ( i > l.length() )
                i = l.length();
            EString command = l.mid( 0, i );
            bool ok = false;
            uint number = l.mid( i ).simplified().number( &ok );
            if ( command == "depends" ) {
                if ( !d->depends.isEmpty() )
                    error( "Duplicate dependency" );
                d->depends = l.mid( i ).simplified();
            }
            else if ( command == "connect" || command == "protocol" ) {
                TestScriptData::Section * sec = new TestScriptData::Section;
                sec->mode = Connect;
                EString s = l.mid( i ).simplified().lower();
                sec->protocol = s.section( " ", 1 );
                sec->clientName = s.section( " ", 2 );
                d->sections.append( sec );
                if ( sec->clientName.isEmpty() || sec->protocol.isEmpty() )
                    error( "use must be followed by a protocol "
                           "and a connection name" );
            }
            else if ( command == "listen" ) {
                TestScriptData::Section * sec = new TestScriptData::Section;
                sec->mode = Listen;
                EString s = l.mid( i ).simplified().lower();
                sec->port= s.section( " ", 1 ).number( &ok );
                sec->clientName = s.section( " ", 2 );
                if ( !ok || sec->port == 0 )
                    error( command +
                           " must be followed by a nonzero number" );
                d->sections.append( sec );
            }
            else if ( command == "send" || command == "receive" ) {
                if ( !ok || number == 0 )
                    error( command +
                           " must be followed by a nonzero number" );
                d->parseState = Send;
                if ( command == "receive" )
                    d->parseState = Receive;
                d->linesLeft = number;
                d->current = new TestScriptData::Section;
                d->current->mode = d->parseState;
                d->sections.append( d->current );
            }
            else if ( command == "end" ) {
                d->parseState = Done;
            }
            else if ( command == "broken" ) {
                d->broken = true;
            }
            else if ( command == "use" ) {
                TestScriptData::Section * sec = new TestScriptData::Section;
                sec->mode = Use;
                sec->clientName = l.mid( i ).simplified().lower();
                d->sections.append( sec );
                if ( sec->clientName.isEmpty() )
                    error( "use must be followed by a connection name" );
            }
            else if ( command == "close" ) {
                TestScriptData::Section * sec = new TestScriptData::Section;
                sec->mode = Close;
                sec->clientName = l.mid( i ).simplified().lower();
                d->sections.append( sec );
                if ( sec->clientName.isEmpty() )
                    error( "close must be followed by a connection name" );
            }
            else if ( command == "obliterate" ) {
                TestScriptData::Section * sec = new TestScriptData::Section;
                sec->mode = Obliterate;
                sec->clientName = l.mid( i ).simplified().lower(); // evil, evil hack
                d->sections.append( sec );
                if ( sec->clientName.isEmpty() )
                    error( "obliterate must be followed by a login name" );
            }
            else {
                error( "Unknown command " + command );
            }
        }
        break;
    case Send:
    case Receive:
        if ( l.contains( '\r' ) )
            error( "Saw raw CR in line " + l );
        d->current->lines.append( l );
        d->linesLeft--;
        if ( !d->linesLeft )
            d->parseState = Command;
        break;
    case Done:
        if ( !l.simplified().isEmpty() )
            error( "Nonempty line after script end" );
        break;
    default:
        error( "Internal error" );
        break;
    }
    if ( !d->provides.isEmpty() && d->provides == d->depends )
        error( "Provides and depends on same state" );
}


/*! Reports \a m as a parse error. Immediately. */

void TestScript::error( EString m )
{
    d->failed = true;
    if ( d->line > 0 )
        fprintf( stderr, "%s:%d:%s\n",
                 d->filename.cstr(), d->line, m.cstr() );
    else
        fprintf( stderr, "%s:%s\n", d->filename.cstr(), m.cstr() );
}


/*! Returns the name of the state provided by this script, if any. If
    there isn't one, provides() returns an empty string.
*/

EString TestScript::provides() const
{
    return d->provides;
}


/*! Returns the name of the state upon which this script
    depends. provider() can be used to find a script which ends in
    this state.

    If depends() returns an empty string, this script does not depend
    on anything.
*/

EString TestScript::depends() const
{
    return d->depends;
}


/*! Returns the type of the next outstanding action. string() returns
    the data for this action (and steps to the next action).

    If there is no outstanding action, this function returns Done.
*/

TestScript::Action TestScript::action() const
{
    if ( !d->iterator )
        return Done;
    return d->iterator->mode;
}


/*! Returns the string corresponding to the current action. */

EString TestScript::string()
{
    if ( !d->iterator )
        return "";
    return d->iterator->lines.join( "\r\n" ) + "\r\n";
}


/*! Returns a pointer to a TestScript that provides() \a name.

    In the future, we probably should extend this so it can look for
    something that provides \a name and itself depends on the current
    state.
*/

TestScript * TestScript::findProvider( const EString & name )
{
    if ( !::providers )
        return 0;
    return providers->find( name );
}


/*! Returns the name from which this script was read. */

EString TestScript::name() const
{
    return d->filename;
}


/*! Returns the protocol specified in this script, or an empty string
    if no protocol is specified.
*/

EString TestScript::protocol() const
{
    if ( !d->iterator )
        return "";
    return d->iterator->protocol;
}


/*! Starts the script (again). action() and string() will again return
    the first action.
*/

void TestScript::start()
{
    d->iterator = d->sections.first();
}


/*! Steps to the script's next action. action(), string() etc. return
    information pertaining to the next action.
*/

void TestScript::step()
{
    ++d->iterator;
}


/*! Returns true if this script is known to fail, and false if it
    hasn't been run, or has been run and succeeded.
*/

bool TestScript::failed() const
{
    return d->failed;
}


/*! Notifies this script that it has failed if \a f is true, and will
    fail again if executed again. If \a f is false, the script may
    assume that another execution is worthwhile.
*/

void TestScript::setFailed( bool f )
{
    d->failed = f;
}


/*! Returns true if running this script on its own is necessary, and
    false if some other script implicitly runs this.
*/

bool TestScript::necessary() const
{
    return d->necessary;
}


/*! Notifies this script that it must be run on its own if \a f is
    true, and that it's implicitly run by another script if \a f is
    false.

    The initial value is true.
*/

void TestScript::setNecessary( bool f )
{
    d->necessary = f;
}


/*! Returns true if this script is marked broken in the source, and
    should not be tried.
*/

bool TestScript::broken() const
{
    return d->broken;
}


/*! Returns the client name specified in the current command, or a
    null string for other commands.
*/

EString TestScript::clientName() const
{
    TestScriptData::Section * s = d->iterator;
    if ( !s )
        return "";
    return s->clientName;
}


/*! Returns the port whip should listen to, assuming the current
    section is a listen section. Does not advance the cursor.
*/

uint TestScript::port()
{
    TestScriptData::Section * s = d->iterator;
    if ( !s )
        return 0;
    return s->port;
}
