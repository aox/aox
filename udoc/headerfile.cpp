// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "headerfile.h"

#include "class.h"
#include "parser.h"
#include "error.h"
#include "function.h"
#include "list.h"


static List<HeaderFile> * headers = 0;


/*! \class HeaderFile headerfile.h
    The HeaderFile class models a header file.

    The HeaderFile file is viewed as a collection of class { ... }
    statements, each of which is scanned for member functions and
    superclass names. Other content is ignored (for now - enums may
    one day be handled).
*/



/*! Constructs a HeaderFile for \a file, which is presumed to be in the
    current directory.

    The file is parsed immediately.
*/

HeaderFile::HeaderFile( const String & file )
    : File( file, Read )
{
    if ( valid() ) {
        if ( !headers )
            headers = new List<HeaderFile>;
        headers->append( this );
        parse();
    }
}


/*! Parses this header file and creates Class and Function objects as
    appropriate.

    The parsing is minimalistic: All it does is look for a useful
    subset of class declarations, and process those.
*/

void HeaderFile::parse()
{
    Parser p( contents() );
    p.scan( "\nclass " );
    while ( !p.atEnd() ) {
        String className = p.identifier();
        String superclass = 0;
        p.whitespace();
        if ( p.lookingAt( ":" ) ) {
            p.step();
            String inheritance = p.word();
            if ( inheritance != "public" ) {
                (void)new Error( this, p.line(),
                                 "Non-public inheritance for class " +
                                 className );
                return;
            }
            String parent = p.identifier();
            if ( parent.isEmpty() ) {
                (void)new Error( this, p.line(),
                                 "Cannot parse superclass name for class " +
                                 className );
                return;
            }
            superclass = parent;
        }
        p.whitespace();
        if ( p.lookingAt( "{" ) ) {
            Class * c = Class::find( className );
            if ( !c )
                c = new Class( className, 0, 0 );
            c->setParent( superclass );
            if ( c && c->file() ) {
                (void) new Error( this, p.line(),
                                  "Class " + className +
                                  " conflicts with " + className + " at " +
                                  c->file()->name() + ":" +
                                  fn( c->line() ) );
                (void) new Error( c->file(), c->line(),
                                  "Class " + className +
                                  " conflicts with " + className + " at " +
                                  name() + ":" +
                                  fn( p.line() ) );
            }
            else {
                c->setSource( this, p.line() );
            }
            p.step();
            bool ok = false;
            do {
                ok = false;
                p.whitespace();
                while ( p.lookingAt( "public:" ) ||
                        p.lookingAt( "private:" ) ||
                        p.lookingAt( "protected:" ) ) {
                    p.scan( ":" );
                    p.step();
                    p.whitespace();
                }
                if ( p.lookingAt( "virtual " ) )
                    p.scan( " " );
                p.whitespace();
                String t;
                String n;
                uint l = p.line();
                if ( p.lookingAt( "operator " ) ) {
                    n = p.identifier();
                }
                else if ( p.lookingAt( "enum " ) ) {
                    ok = true;
                }
                else {
                    t = p.type();
                    n = p.identifier();
                    if ( n.isEmpty() ) {
                        // constructor/destructor?
                        if ( t == className || t == "~" + className ) {
                            n = t;
                            t = "";
                        }
                        else if ( t.isEmpty() && p.lookingAt( "~" ) ) {
                            p.step();
                            n = "~" + p.identifier();
                        }
                    }
                }
                if ( !n.isEmpty() ) {
                    String a = p.argumentList();
                    if ( !n.isEmpty() && n.find( ':' ) < 0 &&
                         !a.isEmpty() ) {
                        n = className + "::" + n;
                        Function * f = Function::find( n, a );
                        if ( !f )
                            f = new Function( t, n, a, this, l );
                        ok = true;
                    }
                }
                if ( ok )
                    p.scan( ";" );
            } while ( ok );
        }
        p.scan( "\nclass " );
    }
}


/*! Returns a pointer to the HeaderFile whose unqualified file name is \a
    s, or a null pointer if there is no such HeaderFile.
*/

HeaderFile * HeaderFile::find( const String & s )
{
    if ( !headers )
        return 0;

    List<HeaderFile>::Iterator it( headers->first() );
    HeaderFile * h = 0;
    String hack = "/" + s;
    while ( (h=it) != 0 &&
            h->name() != s &&
            !h->name().endsWith( hack ) )
        ++it;
    return h;
}
