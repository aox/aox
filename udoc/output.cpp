// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "output.h"

#include "webpage.h"
#include "manpage.h"
#include "postscript.h"

static bool needSpace = false;


/*! \class Output output.h
  The Output class coordinates documentation output.

  It provides a number of static functions, each of which calls
  eponymous functions in each of the concrete output classes. The only
  output class currently is WebPage. PostScript and ManPage may be written
  when arnt is bored or they seem useful.
*/


/*! Starts a headline for \a i, with appropriate fonts etc. The
    headline runs until endParagraph() is called.
*/

void Output::startHeadline( Intro * i )
{
    endParagraph();
    if ( WebPage::current() )
        WebPage::current()->startHeadline( i );
    if ( ManPage::current() )
        ManPage::current()->startHeadline( i );
    if ( Postscript::current() )
        Postscript::current()->startHeadline( i );
}


/*! Starts a headline for \a c, with appropriate fonts etc. The
    headline runs until endParagraph() is called.
*/

void Output::startHeadline( Class * c )
{
    endParagraph();
    if ( WebPage::current() )
        WebPage::current()->startHeadline( c );
    if ( ManPage::current() )
        ManPage::current()->startHeadline( c );
    if ( Postscript::current() )
        Postscript::current()->startHeadline( c );
}


/*! Starts a headline for \a f, with appropriate fonts etc. The
    headline runs until endParagraph() is called.
*/

void Output::startHeadline( Function * f )
{
    endParagraph();
    if ( WebPage::current() )
        WebPage::current()->startHeadline( f );
    if ( ManPage::current() )
        ManPage::current()->startHeadline( f );
    if ( Postscript::current() )
        Postscript::current()->startHeadline( f );
}


/*! Ends the current paragraph on all output devices. */

void Output::endParagraph()
{
    needSpace = false;
    if ( WebPage::current() )
        WebPage::current()->endParagraph();
    if ( ManPage::current() )
        ManPage::current()->endParagraph();
    if ( Postscript::current() )
        Postscript::current()->endParagraph();
}


/*! Adds \a text as ordinary text to all output devices. */

void Output::addText( const EString & text )
{
    if ( needSpace ) {
        needSpace = false;
        addText( " " );
    }
    if ( WebPage::current() )
        WebPage::current()->addText( text );
    if ( ManPage::current() )
        ManPage::current()->addText( text );
    if ( Postscript::current() )
        Postscript::current()->addText( text );
}


/*! Adds \a url and \a title as a link to all capable output devices. */

void Output::addLink( const EString & url, const EString & title )
{
    if ( needSpace ) {
        needSpace = false;
        addText( " " );
    }
    if ( WebPage::current() )
        WebPage::current()->addLink( url, title );
    if ( ManPage::current() )
        ManPage::current()->addText( title );
    if ( Postscript::current() )
        Postscript::current()->addText( title );
}


/*! Adds \a text as an argument name to all output devices. */

void Output::addArgument( const EString & text )
{
    if ( needSpace ) {
        needSpace = false;
        addText( " " );
    }
    if ( WebPage::current() )
        WebPage::current()->addArgument( text );
    if ( ManPage::current() )
        ManPage::current()->addArgument( text );
    if ( Postscript::current() )
        Postscript::current()->addArgument( text );
}


/*! Adds a link to \a f titled \a text on all output devices. Each
    device may express the link differently.
*/

void Output::addFunction( const EString & text, Function * f )
{
    if ( needSpace ) {
        needSpace = false;
        addText( " " );
    }
    if ( WebPage::current() )
        WebPage::current()->addFunction( text, f );
    if ( ManPage::current() )
        ManPage::current()->addFunction( text, f );
    if ( Postscript::current() )
        Postscript::current()->addFunction( text, f );
}


/*! Adds a link to \a c titled \a text on all output devices. Each
    device may express the link differently.
*/

void Output::addClass( const EString & text, Class * c )
{
    if ( needSpace ) {
        needSpace = false;
        addText( " " );
    }
    if ( WebPage::current() )
        WebPage::current()->addClass( text, c );
    if ( ManPage::current() )
        ManPage::current()->addClass( text, c );
    if ( Postscript::current() )
        Postscript::current()->addClass( text, c );
}


/*! Adds a single space to all output devices, prettily optimizing so
    there aren't lots of spaces where none are needed.
*/

void Output::addSpace()
{
    needSpace = true;
    return;
}


static EString * o;

/*! Remembers that \a owner is the owner of the input. Most output
    will carry the name.
*/

void Output::setOwner( const EString & owner )
{
    if ( !o )
        o = new EString;
    *o = owner;
}


/*! Returns the owner string, or an empty string if none has been set. */

EString Output::owner()
{
    return o ? *o : "";
}


static EString * u;


/*! Remembers that \a url is the home page of the rights owner. Most
    output will link to or mention \a url.
*/

void Output::setOwnerHome( const EString & url )
{
    if ( !u )
        u = new EString;
    *u = url;
}


/*! Returns the URL of the rights owner, or an empty string if none
    has been set.
*/

EString Output::ownerHome()
{
    return u ? *u : "";
}
