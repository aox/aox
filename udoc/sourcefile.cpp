#include "sourcefile.h"

#include "parser.h"
#include "function.h"
#include "error.h"
#include "headerfile.h"
#include "class.h"
#include "docblock.h"
#include "intro.h"


/*! \class SourceFile sourcefile.h
  The SourceFile class models a C++ source file.

  When a SourceFile object is created, it automatically scans the file
  for documented classes and functions, scans HeaderFile files as directed
  and creates Class and Function objects.

  That's all.
*/


/*!  Constructs a SourceFile named \a f, and parses it if it can be opened. */

SourceFile::SourceFile( const String & f )
    : File( f, Read )
{
    if ( valid() )
        parse();
}


/*! This happy-happy little function parse (or scans, to be truthful)
    a C++ source file looking for documentation. It's the All of this
    class.
*/

void SourceFile::parse()
{
    bool any = false;
    Parser p( contents() );
    p.scan( "/*" "!" );
    while ( !p.atEnd() ) {
        any = true;
        p.whitespace();
        Function * f = 0;
        Class * c = 0;
        Intro * i = 0;
        String d;
        uint l = p.line();
        if ( p.lookingAt( "\\fn " ) ) {
            p.scan( " " );
            f = function( &p );
            d = p.textUntil( "*/" );
        }
        else if ( p.lookingAt( "\\chapter " ) ) {
            p.scan( " " );
            String name = p.word();
            if ( name.isEmpty() )
                (void)new Error( this, p.line(),
                                 "\\chapter must be followed by name" );
            i = new Intro( name );
            p.whitespace();
            d = p.textUntil( "*/" );
        }
        else if ( p.lookingAt( "\\class " ) ) {
            p.scan( " " );
            String className = p.identifier();
            if ( className.isEmpty() ) {
                (void)new Error( this, p.line(),
                                 "\\class must be followed by a class name" );
            }
            c = Class::find( className );
            if ( !c )
                c = new Class( className, 0, 0 );
            p.whitespace();
            String hn = p.word();
            while ( p.lookingAt( "." ) ) {
                p.step();
                hn.append( "." );
                hn.append( p.word() );
            }
            if ( hn.length() < 2 || hn.mid( hn.length() - 2) != ".h" ) {
                (void)new Error( this, p.line(),
                                 "Missing header file name" );
            }
            else {
                HeaderFile * h = HeaderFile::find( hn );
                if ( !h ) {
                    if ( name().find( "/" ) >= 0 ) {
                        String dir = name();
                        uint i = dir.length()-1;
                        while ( i > 0 && dir[i] != '/' )
                            i--;
                        hn = dir.mid( 0, i+1 ) + hn;
                    }
                    h = new HeaderFile( hn );
                    if ( !h->valid() )
                        (void)new Error( this, p.line(),
                                         "Cannot find header file " + hn +
                                         " (for class " + className + ")" );
                }
            }
            d = p.textUntil( "*/" );
        }
        else if ( p.lookingAt( "\\nodoc" ) ) {
            any = true;
            d = "hack";
        }
        else {
            d = p.textUntil( "*/" );
            f = function( &p );
        }
        if ( d.isEmpty() )
            (void)new Error( this, l, "Comment contains no documentation" );
        else if ( f )
            (void)new DocBlock( this, l, d, f );
        else if ( c )
            (void)new DocBlock( this, l, d, c );
        else if ( i )
            (void)new DocBlock( this, l, d, i );
        p.scan( "/" /* qdoc must not see that as one string */ "*!" );
    }
    if ( !any ) {
        Parser p( contents() );
        p.scan( "::" ); // any source in this file at all?
        if ( !p.atEnd() )
            (void)new Error( this, p.line(),
                             "File contains no documentation" );
    }
}


/*! This helper parses a function name using \a p or reports an
    error. It returns a pointer to the function, or a null pointer in
    case of error.
*/

Function * SourceFile::function( Parser * p )
{
    Function * f = 0;
    String t = p->type();
    uint l = p->line();
    String n = p->identifier();
    if ( n.isEmpty() && p->lookingAt( "(" ) && t.find( ':' ) > 0 ) {
        // constructor support hack. eeek.
        n = t;
        t = "";
    }
    String a = p->argumentList();
    if ( !n.isEmpty() && n.find( ':' ) > 0 &&
         !a.isEmpty() ) {
        f = Function::find( n, a );
        if ( f )
            f->setArgumentList( a );
        else
            f = new Function( t, n, a, this, l );
    }
    else {
        (void)new Error( this, l, "Unable to parse function name" );
    }
    return f;
}
