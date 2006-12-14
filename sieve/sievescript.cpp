// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sievescript.h"

#include "sieveproduction.h"
#include "sieveparser.h"
#include "stringlist.h"



class SieveScriptData
    : public Garbage
{
public:
    SieveScriptData(): Garbage(), script( 0 ) {}

    String source;
    List<SieveCommand> * script;
};


/*! \class SieveScript sievescript.h

    The SieveScript class models a single script. It contains
    commands, has errors, etc. It's used by the Sieve class to run
    scripts and and ManageSieveCommand to syntax-check them.
*/

/*!  Constructs an empty sieve script. */

SieveScript::SieveScript()
    : Garbage(), d( new SieveScriptData )
{
    // nothing needed
}


/*! Parses \a script and stores the script as this object. Any
    previous script content is deleted. If \a script is has parse
    errors, they may be accessed as parseErrors().
*/

void SieveScript::parse( const String & script )
{
    d->source = script;
    SieveParser p( script );
    d->script = p.commands();

    // if we're not yet at the end, treat whatever follows as another
    // command, which will have a nice big error message.
    p.whitespace();
    if ( !p.atEnd() )
        d->script->append( p.command() );
    
    List<SieveCommand>::Iterator s( d->script );
    while ( s ) {
        s->parse();
        ++s;
    }
}


/*! Returns a (multi-line) string describing all the parse errors seen
    by the last call to parse(). If there are no errors, the returned
    string is empty. If there are any, it is a multiline string with
    CRLF after each line (including the last).
*/

String SieveScript::parseErrors() const
{
    String errors;
    List<SieveCommand>::Iterator s( d->script );
    while ( s ) {
        List<SieveProduction>::Iterator i( s->bad() );
        ++s;
        while ( i ) {
            SieveProduction * p = i;
            ++i;
            errors.append( location( p->start() ) );
            errors.append( "In " );
            errors.append( p->name() );
            errors.append( ": " );
            errors.append( p->error() );
            errors.append( "\r\n" );
            while ( p->parent() ) {
                p = p->parent();
                errors.append( location( p->start() ) );
                errors.append( " (Error happened while parsing " );
                errors.append( p->name() );
                errors.append( ")\r\n" );
            }
        }
    }
    return errors;
}


/*! Returns a string describing the location of \a position in the
    current script.
*/

String SieveScript::location( uint position ) const
{
    uint i = 0;
    uint l = 1;
    while ( i < position ) {
        if ( d->source[i] == '\n' )
            l++;
        i++;
    }
    String r = fn( l );
    r.append( ":" );
    r.append( fn( position - i + 1 ) );
    r.append( ": " );
    return r;
}


/*! Returns true if this script contains no commands, and false
    otherwise.
*/

bool SieveScript::isEmpty() const
{
    return !d->script || d->script->isEmpty();
}


/*! Returns a copy of the source code of this script. */

String SieveScript::source() const
{
    return d->source;
}
