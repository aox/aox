// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "docblock.h"

#include "function.h"
#include "class.h"
#include "intro.h"
#include "error.h"
#include "output.h"
#include "singleton.h"


/*! \class DocBlock docblock.h

    The DocBlock class represents a single atom of documentation.

    A documentation block is written as a C multi-line comment and
    documents a single class or a single function. DocBlock knows how
    to generate output for itself.
*/


/*!  Constructs a DocBlock from \a sourceFile, which starts at
     \a sourceLine, has source \a text and documents \a function.
*/

DocBlock::DocBlock( File * sourceFile, uint sourceLine,
                    const String & text, Function * function )
    : file( sourceFile ), line( sourceLine ),
      c( 0 ), f( function ), i( 0 ),
      t( text ), s( Plain ), isReimp( false ), introduces( false )
{
    f->setDocBlock( this );
}


/*!  Constructs a DocBlock from \a sourceFile, which starts at
     \a sourceLine, has source \a text and documents \a className.
*/

DocBlock::DocBlock( File * sourceFile, uint sourceLine,
                    const String & text, Class * className )
    : file( sourceFile ), line( sourceLine ),
      c( className ), f( 0 ), i( 0 ),
      t( text ), s( Plain ), introduces( false )
{
    c->setDocBlock( this );
}


/*!  Constructs a DocBlock from \a sourceFile, which starts at
     \a sourceLine, has source \a text and documents \a intro.
*/

DocBlock::DocBlock( File * sourceFile, uint sourceLine,
                    const String & text, Intro * intro )
    : file( sourceFile ), line( sourceLine ),
      c( 0 ), f( 0 ), i( intro ),
      t( text ), s( Plain ), introduces( false )
{
    i->setDocBlock( this );
}


/*! Returns true if this DocBlock documents a class, and false if not. */

bool DocBlock::isClass() const
{
    return c != 0;
}


/*! Returns true if this DocBlock documents an enum type, and false if
    not. At the moment, enums aren't supported; that'll change. */

bool DocBlock::isEnum() const
{
    return false;
}


/*! Returns the source text of the documentation. */

String DocBlock::text() const
{
    return t;
}


/*! Parses the text() and calls the Output functions on to generate
    suitable output.
*/

void DocBlock::generate()
{
    if ( f )
        generateFunctionPreamble();
    else if ( c )
        generateClassPreamble();
    else if ( i )
        generateIntroPreamble();

    int n = 0;
    uint l = line;
    uint i = 0;
    while ( i < t.length() ) {
        whitespace( i, l );
        word( i, l, n++ );
    }
    Output::endParagraph();
    if ( f ) {
        Function * super = f->super();
        if ( super ) {
            Output::addText( "Reimplements " );
            Output::addFunction( super->name() + "().", super );
            Output::endParagraph();
        }
    }
    if ( f && !isReimp ) {
        String a = f->arguments();
        uint i = 0;
        while ( i < a.length() ) {
            while ( i < a.length() && a[i] != ',' && a[i] != ')' )
                i++;
            if ( i < a.length() ) {
                uint j = i - 1;
                while ( j > 0 && a[j] != ' ' && a[j] != '&' && a[j] != '*' )
                    j--;
                String name = a.mid( j, i-j ).simplified();
                if ( j > 0 && j < i &&
                     !name.isEmpty() && !arguments.contains( name ) )
                    (void)new Error( file, line,
                                     "Undocumented argument: " + name );
                i++;
            }
        }
    }
    if ( this->i && !introduces )
        (void)new Error( file, line, "\\chapter must contain \\introduces" );
}


/*! Steps past whitespace, modifying the character index \a i and the
  line number \a l.
*/

void DocBlock::whitespace( uint & i, uint & l )
{
    bool first = ( i == 0 );
    uint ol = l;
    bool any = false;
    while ( i < t.length() && ( t[i] == 32 || t[i] == 9 ||
                                t[i] == 13 || t[i] == 10 ) ) {
        if ( t[i] == '\n' )
            l++;
        i++;
        any = true;
    }
    if ( l > ol+1 ) {
        if ( s == Introduces )
            setState( Plain, "(end of paragraph)", l );
        checkEndState( ol );
        Output::endParagraph();
    }
    else if ( any && !first && s != Introduces ) {
        Output::addSpace();
    }
}


/*! Steps past and processes a word, which in this context is any
    nonwhitespace. \a i is the character index, which is moved, \a l
    is the line number, and \a n is the word number.
*/

void DocBlock::word( uint & i, uint l, uint n )
{
    uint j = i;
    while ( j < t.length() && !( t[j] == 32 || t[j] == 9 ||
                                 t[j] == 13 || t[j] == 10 ) )
        j++;
    String w = t.mid( i, j-i );
    i = j;
    if ( w[0] != '\\' ) {
        plainWord( w, l );
    }
    else if ( w == "\\a" ) {
        if ( f )
            setState( Argument, w, l );
        else
            (void)new Error( file, l,
                             "\\a is only defined function documentation" );
    }
    else if ( w == "\\introduces" ) {
        if ( i )
            setState( Introduces, w, l );
        else
            (void)new Error( file, l,
                             "\\introduces is only valid after \\chapter" );
        introduces = true;
    }
    else if ( w == "\\overload" ) {
        overload( l, n );
    }
    else {
        (void)new Error( file, l, "udoc directive unknown: " + w );
    }
}


/*! Verifies that all state is appropriate for ending a paragraph or
  documentation block, and emits appropriate errors if not. \a l must
  be the line number at which the paragraph/doc block ends.
*/

void DocBlock::checkEndState( uint l )
{
    if ( s != Plain )
        (void)new Error( file, l,
                         "udoc directive hanging at end of paragraph" );
}


/*! Adds the plain word or link \a w to the documentation, reporting
  an error from line \a l if the link is dangling.
*/

void DocBlock::plainWord( const String & w, uint l )
{
    if ( s == Introduces ) {
        new Singleton( file, l, w );
        Class * c = Class::find( w );
        if ( c )
            i->addClass( c );
        else
            (void)new Error( file, l, "Cannot find class: " + w );
        return;
    }
    // find the last character of the word proper
    uint last = w.length() - 1;
    while ( last > 0 && ( w[last] == ',' || w[last] == '.' ||
                          w[last] == ':' || w[last] == ')' ) )
        last--;

    if ( s == Argument ) {
        String name = w.mid( 0, last+1 );
        if ( name[0] == '*' )
            name = name.mid( 1 ); // yuck, what an evil hack

        if ( arguments.contains( name ) )
            // fine, nothing more to do
            ;
        else if ( f->hasArgument( name ) )
            arguments.insert( name, (void*)1 );
        else
            (void)new Error( file, l, "No such argument: " + name );
        Output::addArgument( w );
        setState( Plain, "(after argument name)", l );
        return;
    }
    // is the word a plausible function name?
    else if ( w[last] == '(' ) {
        uint i = 0;
        while ( i < last && w[i] != '(' )
            i++;
        if ( i > 0 && ( ( w[0] >= 'a' && w[0] <= 'z' ) ||
                        ( w[0] >= 'A' && w[0] <= 'Z' ) ) ) {
            String name = w.mid( 0, i );
            Function * link = 0;
            Class * scope = c;
            if ( f && !scope )
                scope = f->parent();
            if ( name.find( ':' ) >= 0 ) {
                link = Function::find( name );
            }
            else {
                Class * parent = scope;
                while ( parent && !link ) {
                    String tmp = parent->name() + "::" + name;
                    link = Function::find( tmp );
                    if ( link )
                        name = tmp;
                    else
                        parent = parent->parent();
                }
            }
            if ( scope && !link && name != "main" ) {
                (void)new Error( file, l,
                                 "No link target for " + name +
                                 "() (in class " + scope->name() + ")" );
            }
            else if ( link && link != f ) {
                Output::addFunction( w, link );
                return;
            }
        }
    }
    // is it a plausible class name? or enum, or enum value?
    else if ( w[0] >= 'A' && w[0] <= 'Z' &&
              ( !c || w.mid( 0, last+1 ) != c->name() ) ) {
        Class * link = Class::find( w.mid( 0, last+1 ) );
        Class * thisClass = c;
        if ( f && !c )
            thisClass = f->parent();
        if ( link && link != thisClass ) {
            Output::addClass( w, link );
            return;
        }
        // here, we could look to see if that looks _very_ much like a
        // class name, e.g. contains all alphanumerics and at least
        // one "::", and give an error about undocumented classes if
        // not.
    }

    // nothing doing. just add it as text.
    Output::addText( w );
}


/*! Sets the DocBlock to state \a newState based on directive \a w,
  and gives an error from line \a l if the transition from the old
  state to the new is somehow wrong.
*/

void DocBlock::setState( State newState, const String & w, uint l )
{
    if ( s != Plain && newState != Plain )
        (void)new Error( file, l,
                         "udoc directive " + w +
                         " negates preceding directive" );
    if ( s == Introduces && !i )
        (void)new Error( file, l,
                         "udoc directive " + w +
                         " is only valid with \\chapter" );
    s = newState;
}


/*! Handles the "\overload" directive. \a l is the nine number where
    directive was seen and \a n is the word number (0 for the first
    word in a documentation block).
*/

void DocBlock::overload( uint l, uint n )
{
    if ( !f )
        (void)new Error( file, l,
                         "\\overload is only meaningful for functions" );
    else if ( f->hasOverload() )
        (void)new Error( file, l,
                         "\\overload repeated" );
    else
        f->setOverload();
}


static void addWithClass( const String & s, Class * in )
{
    Class * c = 0;
    uint i = 0;
    while ( c == 0 && i < s.length() ) {
        if ( s[i] >= 'A' && s[i] <= 'Z' ) {
            uint j = i;
            while ( ( s[j] >= 'A' && s[j] <= 'Z' ) ||
                    ( s[j] >= 'a' && s[j] <= 'z' ) ||
                    ( s[j] >= '0' && s[j] <= '9' ) )
                j++;
            c = Class::find( s.mid( i, j-i ) );
            i = j;
        }
        i++;
    }
    if ( c && c != in )
        Output::addClass( s, c );
    else
        Output::addText( s );
}


/*! Outputs boilerplante and genetated text to create a suitable
    headline and lead-in text for this DocBlock's function.
*/

void DocBlock::generateFunctionPreamble()
{
    Output::startHeadline( f );
    addWithClass( f->type(), f->parent() );
    Output::addText( " " );
    Output::addText( f->name() );
    String a = f->arguments();
    if ( a == "()" ) {
        Output::addText( f->arguments() );
    }
    else {
        uint s = 0;
        uint e = 0;
        while ( e < a.length() ) {
            while ( e < a.length() && a[e] != ',' )
                e++;
            addWithClass( a.mid( s, e+1-s ), f->parent() );
            s = e + 1;
            while ( a[s] == ' ' ) {
                Output::addSpace();
                s++;
            }
            e = s;
        }
    }
    Output::endParagraph();
}


/*! Generates the routine text that introduces the documentation for
    each class, e.g. what the class inherits.
*/

void DocBlock::generateClassPreamble()
{
    Output::startHeadline( c );
    Output::addText( "Class " );
    Output::addText( c->name() );
    Output::addText( "." );
    Output::endParagraph();
    bool p = false;
    if ( c->parent() ) {
        Output::addText( "Inherits " );
        Output::addClass( c->parent()->name(), c->parent() );
        p = true;
    }
    List<Class> * subclasses = c->subclasses();
    if ( subclasses && !subclasses->isEmpty() ) {
        if ( p )
            Output::addText( ". " );
        Output::addText( "Inherited by " );
        p = true;
        List<Class>::Iterator it( subclasses->first() );
        while( it ) {
            Class * sub = it;
            ++it;
            if ( !it ) {
                Output::addClass( sub->name() + ".", sub );
            }
            else if ( it == subclasses->last() ) {
                Output::addClass( sub->name(), sub );
                Output::addText( " and " );
            }
            else {
                Output::addClass( sub->name() + ",", sub );
                Output::addText( " " );
            }
        }
    }
    if ( p )
        Output::endParagraph();

    List<Function> * members = c->members();
    if ( !members || members->isEmpty() ) {
        (void)new Error( file, line,
                         "Class " + c->name() + " has no member functions" );
        return;
    }
    else {
        List<Function>::Iterator it( members->first() );
        while ( it )
            ++it;
    }
}


/*! Generates routine text to introduce an introduction. Yay! */

void DocBlock::generateIntroPreamble()
{
    Output::startHeadline( i );
}
