// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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
    : para( false ), fd( -1 ), directory( dir )
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
    startPage( c->name().lower(), c->name() + " Documentation" );
    output( "<p class=classh>" );
}


/*! As Output::startHeadline(). \a f is used to create an anchor. */

void WebPage::startHeadline( Function * f )
{
    output( "<p class=functionh>"
            "<a name=\"" + anchor( f ) + "\"></a>");
    para = true;
}


/*! As Output::endParagraph(). */

void WebPage::endParagraph()
{
    if ( para )
        output( "\n" );
    para = false;
}


/*! As Output::addText(). \a text is used escaped (&amp; etc). */

void WebPage::addText( const String & text )
{
    if ( !para ) {
        output( "<p class=text>" );
        para = true;
    }

    String s;
    uint i = 0;
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


/*! As Output::addArgument(). \a text is output in italics. */

void WebPage::addArgument( const String & text )
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

void WebPage::addFunction( const String & text, Function * f )
{
    String name = f->name();
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
    String target = f->parent()->name().lower() + ".html";
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

void WebPage::addClass( const String & text, Class * c )
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
    String target = c->name().lower() + ".html";
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

void WebPage::output( const String & s )
{
    if ( fd >= 0 && !s.isEmpty() )
        ::write( fd, s.data(), s.length() );
}


/*! This private helper returns the anchor (sans '#') corresponding to
    \a f.
*/

String WebPage::anchor( Function * f )
{
    String fn = f->name();
    int i = fn.length();
    while ( i > 0 && fn[i] != ':' )
        i--;
    if ( i > 0 )
        return fn.mid( i + 1 );
    return fn;
}


/*! Emits any boilerplate to be emitted at the end of each page. */

void WebPage::endPage()
{
    if ( fd < 0 )
        return;

    endParagraph();
    
    para = true;
    output( "<p class=rights>"
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
    output( "</div></div></div>" );
    output( "</body></html>\n" );
    ::close( fd );
}


/*! Starts a new web page with base name \a name and title tag \a
    title. The \a title must not be empty per the HTML standard.
*/

void WebPage::startPage( const String & name, const String & title )
{
    fn = name + ".html";
    String filename = directory + "/" + fn;
    fd = ::open( filename.cstr(), O_CREAT|O_WRONLY|O_TRUNC, 0644 );
    output( "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\">\n"
            "<html lang=en><head>" );
    output( "<title>" );
    para = true;
    addText( "Mailstore source code: " + title );
    output( "</title>\n" );
    output( "<link rel=stylesheet media=\"handheld,all\" "
            "href=\"../../oryx.css\" type=\"text/css\">\n"
            "</head><body onload=\"if(top.frames.length!=0)"
            "top.location=self.location;\">\n" );
    output( "<div class=top><ul class=nav>\n"
            "<li><a href=\"../../\">Home</a>"
            "<li><a href=\"../../products/\">Products</a>"
            "<li><a href=\"../../sitemap.html\">Sitemap</a>"
            "<li><a href=\"../../company/\">Contact Us</a>"
            "<li><a href=\"../../company/about.html\">About Us</a>"
            "</ul></div>\n" );
    output( "<div class=page><div class=left>"
            "<div class=logo><a href=\"http://www.oryx.com\">Oryx</a></div>"
            "<p>Generated using <a href=\"../../udoc/\">udoc</a>. "
            "Our apologies for less than ideal formatting.</div>"
            "<div class=container><div class=content>" );
}
