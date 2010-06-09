// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "webpage.h"

#include "class.h"
#include "function.h"
#include "intro.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <unistd.h>

static WebPage * wp = 0;


/*! \class WebPage webpage.h
  The WebPage class provides documentation output to a web page.

  It implements the same functions as Output, but they're not static,
  and is called when Output's static functions are called.
*/


/*! Constructs a web page generator that'll write to files in
    directory \a dir. */

WebPage::WebPage( const char * dir )
    : fd( -1 ), directory( dir ), pstart( false )
{
    wp = this;
}


/*! Destroys the web page object, flushing and closing the generated file. */

WebPage::~WebPage()
{
    endPage();
    wp = 0;
}


/*! Returns a pointer to the most recently constructed WebPage object,
    or a null pointer if none has been constructed yet. */

WebPage * WebPage::current()
{
    return wp;
}


/*! As Output::startHeadline(). \a i is used to derive a file name. */

void WebPage::startHeadline( Intro * i )
{
    endPage();
    startPage( i->name().lower(), i->name() );
}


/*! As Output::startHeadline(). \a c is used to derive a file name. */

void WebPage::startHeadline( Class * c )
{
    endPage();
    startPage( c->name().lower(), c->name() + " documentation" );
    output( "<h1 class=\"classh\">" );
    para = "</h1>\n";
    pstart = true;
}


/*! As Output::startHeadline(). \a f is used to create an anchor. */

void WebPage::startHeadline( Function * f )
{
    EString a = anchor( f );
    EString o = "<h2 class=\"functionh\">";
    if ( !names.contains( a ) ) {
         o.append( "<a name=\"" + anchor( f ) + "\"></a>");
         names.append( a );
    }
    output( o );
    para = "</h2>\n";
    pstart = true;
}


/*! As Output::endParagraph(). */

void WebPage::endParagraph()
{
    if ( para.isEmpty() )
        return;
    output( para );
    para = "";
}


/*! As Output::addText(). \a text is used escaped (&amp; etc). */

void WebPage::addText( const EString & text )
{
    if ( para.isEmpty() ) {
        output( "<p class=\"text\">" );
        para = "\n";
        pstart = true;
    }

    uint i = 0;
    if ( pstart ) {
        while ( text[i] == ' ' )
            i++;
        if ( i >= text.length() )
            return;
        pstart = false;
    }

    EString s;
    while ( i < text.length() ) {
        if ( text[i] == '<' )
            s.append( "&lt;" );
        else if ( text[i] == '>' )
            s.append( "&gt;" );
        else if ( text[i] == '&' )
            s.append( "&amp;" );
        else
            s.append( text[i] );
        i++;
    }
    output( s );
}


/*! Adds a link to \a url with the given \a title. */

void WebPage::addLink( const EString & url, const EString & title )
{
    addText( "" );
    EString s( "<a href=\"" );
    s.append( url );
    s.append( "\">" );
    s.append( title );
    s.append( "</a>" );
    output( s );
}


/*! As Output::addArgument(). \a text is output in italics. */

void WebPage::addArgument( const EString & text )
{
    addText( "" );
    output( "<i>" );
    addText( text );
    output( "</i>" );
}


/*! As Output::addFunction(). If part of \a text corresponds to the
    name of \a f, then only that part is made into a link, otherwise
    all of \a text is made into a link.
*/

void WebPage::addFunction( const EString & text, Function * f )
{
    EString name = f->name();
    int ll = text.length();
    int ls = text.find( name );
    // if we don't find the complete function name, try just the member part
    if ( ls < 0 ) {
        int i = name.length();
        while ( i > 0 && name[i] != ':' )
            i--;
        if ( i > 0 ) {
            name = name.mid( i+1 );
            ls = text.find( name );
        }
    }
    if ( ls >= 0 )
        ll = name.length();
    else
        ls = 0;
    if ( ll < (int)text.length() && text.mid( ls+ll, 2 ) == "()" )
        ll = ll + 2;
    addText( "" );
    bool space = false;
    uint i = 0;
    while ( i < text.length() && !space ) {
        if ( text[i] == ' ' )
            space = true;
        i++;
    }
    if ( space )
        output( "<span class=nobr>" );
    addText( text.mid( 0, ls ) );
    output( "<a href=\"" );
    EString target = f->parent()->name().lower();
    if ( fn != target )
        output( target );
    output( "#" + anchor( f ) + "\">" );
    addText( text.mid( ls, ll ) );
    output( "</a>" );
    addText( text.mid( ls + ll ) );
    if ( space )
        output( "</span>" );
}


/*! As Output::addClass(). If part of \a text corresponds to the
    name of \a c, then only that part is made into a link, otherwise
    all of \a text is made into a link.
*/

void WebPage::addClass( const EString & text, Class * c )
{
    int ll = text.length();
    int ls = text.find( c->name() );
    if ( ls >= 0 )
        ll = c->name().length();
    else
        ls = 0;
    addText( "" );
    bool space = false;
    uint i = 0;
    while ( i < text.length() && !space ) {
        if ( text[i] == ' ' )
            space = true;
        i++;
    }
    if ( space )
        output( "<span class=nobr>" );
    addText( text.mid( 0, ls ) );
    bool link = true;
    EString target = c->name().lower();
    if ( target == fn )
        link = false;
    if ( link )
        output( "<a href=\"" + target + "\">" );
    addText( text.mid( ls, ll ) );
    if ( link )
        output( "</a>" );
    addText( text.mid( ls + ll ) );
    if ( space )
        output( "</span>" );
}


/*! Write \a s to the output file. */

void WebPage::output( const EString & s )
{
    if ( fd >= 0 && !s.isEmpty() )
        ::write( fd, s.data(), s.length() );
}


/*! This private helper returns the anchor (sans '#') corresponding to
    \a f.
*/

EString WebPage::anchor( Function * f )
{
    EString fn = f->name();
    int i = fn.length();
    while ( i > 0 && fn[i] != ':' )
        i--;
    if ( i > 0 )
        fn = fn.mid( i + 1 );
    if ( fn.startsWith( "~" ) )
        fn = "destructor";
    return fn;
}


/*! Emits any boilerplate to be emitted at the end of each page. */

void WebPage::endPage()
{
    if ( fd < 0 )
        return;

    endParagraph();

    para = "\n";
    output( "<p class=\"rights\">"
            "This web page based on source code belonging to " );
    if ( !Output::ownerHome().isEmpty() ) {
        output( "<a href=\"" + Output::ownerHome() + "\">" );
        addText( Output::owner() );
        output( "</a>. All rights reserved." );
    }
    else {
        addText( Output::owner() );
        output( ". All rights reserved." );
    }
    output( "</body></html>\n" );
    ::close( fd );
}


/*! Starts a new web page with base name \a name and title tag \a
    title. The \a title must not be empty per the HTML standard.
*/

void WebPage::startPage( const EString & name, const EString & title )
{
    names.clear();
    EString filename = directory + "/" + name;
    fd = ::open( filename.cstr(), O_CREAT|O_WRONLY|O_TRUNC, 0644 );
    output( "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\">\n"
            "<html lang=en><head>" );
    output( "<title>" );
    para = "\n";
    pstart = true;
    addText( title );
    output( "</title>\n" );
    output( "<link rel=stylesheet href=\"udoc.css\" type=\"text/css\">\n"
            "<link rel=generator "
            "href=\"http://archiveopteryx.org/udoc/\">\n"
            "</head><body>\n" );
}
