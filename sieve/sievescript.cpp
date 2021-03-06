// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "sievescript.h"

#include "sieveproduction.h"
#include "sieveparser.h"
#include "ustringlist.h"
#include "estringlist.h"



class SieveScriptData
    : public Garbage
{
public:
    SieveScriptData(): Garbage(), script( 0 ), errors( 0 ) {}

    EString source;
    List<SieveCommand> * script;
    List<SieveProduction> * errors;
};


/*! \class SieveScript sievescript.h

    The SieveScript class models a single script. It contains
    commands, has errors, etc. It's used by the Sieve class to run
    scripts and and ManageSieveCommand to syntax-check them.
*/

/*!  Constructs an empty sieve script. */

SieveScript::SieveScript()
    : SieveProduction( "sieve script" ), d( new SieveScriptData )
{
    // nothing needed
}


/*! Parses \a script and stores the script as this object. Any
    previous script content is deleted. If \a script is has parse
    errors, they may be accessed as parseErrors().
*/

void SieveScript::parse( const EString & script )
{
    d->source = script;
    SieveParser p( script );
    d->script = p.commands();

    // if we're not yet at the end, treat whatever follows as another
    // command, which will have a nice big error message.
    p.whitespace();
    if ( !p.atEnd() ) {
        SieveCommand * sc = p.command();
        sc->setError( "Junk at end of script" );
        d->script->append( sc );
    }

    // require is only permitted at the start
    List<SieveCommand>::Iterator s( d->script );
    while ( s && s->identifier() == "require" ) {
        s->setRequirePermitted( true );
        ++s;
    }

    // do the semantic bits of parsing
    s = d->script->first();
    EString prev;
    while ( s ) {
        s->setParent( this );
        s->parse( prev );
        prev = s->identifier();
        ++s;
    }

    // check that require lists the right extensions
    EStringList * extensions = p.extensionsNeeded();
    EStringList declared;
    s = d->script->first();
    while ( s && s->identifier() == "require" ) {
        if ( s->error().isEmpty() ) {
            UStringList * r = 0;
            if ( s->arguments() &&
                 s->arguments()->arguments() &&
                 s->arguments()->arguments()->first() )
                r = s->arguments()->arguments()->first()->stringList();
            UStringList::Iterator i( r );
            while ( i ) {
                if ( i->isAscii() )
                    declared.append( i->ascii() );
                ++i;
            }
        }
        ++s;
    }
    declared.append( "comparator-i;octet" );
    declared.append( "comparator-i;ascii-casemap" );
    declared.append( "fileinto" );
    declared.append( "reject" );
    EStringList::Iterator i( extensions );
    EStringList undeclared;
    while ( i ) {
        if ( !declared.contains( *i ) )
            undeclared.append( i->quoted() );
        ++i;
    }
    if ( !undeclared.isEmpty() ) {
        SieveCommand * f = d->script->first();
        if ( f->identifier() == "require" )
            f->setError( "Extensions used but not declared: " +
                         undeclared.join( ", " ) );
        else
            f->setError( "Missing require: require [ " +
                         undeclared.join( ", " ) + " ];" );
    }

    // and find all the errors
    d->errors = p.bad( this );
}


/*! Returns a (multi-line) string describing all the parse errors seen
    by the last call to parse(). If there are no errors, the returned
    string is empty. If there are any, it is a multiline string with
    CRLF after each line (except the last).
*/

EString SieveScript::parseErrors() const
{
    EString errors;
    List<SieveProduction>::Iterator i( d->errors );
    while ( i ) {
        SieveProduction * p = i;
        ++i;
        EString e = location( p->start() );
        e.append( "In " );
        e.append( p->name() );
        e.append( ": " );
        e.append( p->error() );
        e.append( "\r\n" );
        while ( p->parent() &&
                p->parent() != (SieveProduction*)this ) {
            p = p->parent();
            EString l = location( p->start() );
            l.append( "While parsing " );
            l.append( p->name() );
            l.append( ":\r\n" );
            e = l + e;
        }
        errors.append( e );
    }
    if ( errors.endsWith( "\r\n" ) )
        errors.truncate( errors.length()-2 );
    return errors;
}


/*! Returns a string describing the location of \a position in the
    current script.
*/

EString SieveScript::location( uint position ) const
{
    uint i = 0;
    uint l = 1;
    uint s = 0;
    while ( i < position ) {
        if ( d->source[i] == '\n' ) {
            l++;
            s = i + 1;
        }
        i++;
    }
    EString r = fn( l );
    r.append( ":" );
    r.appendNumber( position - s + 1 );
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

EString SieveScript::source() const
{
    return d->source;
}


/*! Returns a list of top-level commands in this script. "if" and
    other commands may also have children.

    Returns a null pointer if no script has been parsed, or a pointer
    to a (possiblty empty) list of commands if parse() has been
    called. The caller should not modify the list.
*/

List<SieveCommand> * SieveScript::topLevelCommands() const
{
    return d->script;
}
