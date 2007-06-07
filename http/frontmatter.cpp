// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "frontmatter.h"

#include "configuration.h"
#include "pagecomponent.h"


/*! \class FrontMatter frontmatter.h
    Provides front matter needed to render the rest of a WebPage.

    This class inherits from String and provides a collection of static
    functions that return a pointer to a new FrontMatter object, whose
    contents are an HTML string suitable for inclusion into a WebPage.

    PageComponent constructors call PageComponent::addFrontMatter() on
    the FrontMatter objects they need, and the WebPage includes their
    contents in the <HEAD> section while rendering itself.

    For example, the title() function returns a FrontMatter object whose
    String value is "<title>sometitle</title>". Other functions include
    a styleSheet(), declare necessary Javascript functions, and so on.
*/

/*! Returns a link to the stylesheet. */

FrontMatter * FrontMatter::styleSheet()
{
    FrontMatter * fm = new FrontMatter;

    fm->append( "<style type=\"text/css\">\n" );
    fm->append( "@import url(\"" );
    fm->append( Configuration::text( Configuration::WebmailCSS ) );
    fm->append( "\");\n" );

    // The following classes are used to display different content
    // depending on whether JavaScript is active.
    //
    // - .jsonly is visible only if JS is active.
    // - .njsvisible is visible only if JS is inactive.
    // - .hidden is invisible.
    // - .njshidden is invisible too.
    //
    // During page load, the JavaScript code changes the js and njs
    // classes so that they act as described.

    fm->append( ".jsonly{display:none;}\n"
                ".njsvisible{}\n"
                ".hidden{display:none;}\n"
                ".njshidden{display:none;}\n" );

    fm->append( "</style>" );

    return fm;
}


/*! Returns a title element for \a s, which will be HTML quoted. */

FrontMatter * FrontMatter::title( const String & s )
{
    FrontMatter * fm = new FrontMatter;

    fm->append( "<title>" );
    fm->append( PageComponent::quoted( s ) );
    fm->append( "</title>" );

    return fm;
}


/*! Returns a glob of JavaScript code. */

FrontMatter * FrontMatter::jsToggles()
{
    // XXX: This thing should require the stylesheet frontmatter.

    FrontMatter * fm = new FrontMatter;

    fm->append( "<script language=javascript type=\"text/javascript\">\n" );

    // Define a useJS function to change the stylesheet to make the js
    // and njs classes work if JavaScript is enabled.
    fm->append( "var toggledToJs=false;\n"
                "function useJS(){\n"
                "if(toggledToJs) return;\n"
                "var r=new Array;\n"
                "if(document.styleSheets[0].cssRules)"
                "r=document.styleSheets[0].cssRules;\n"
                "else if(document.styleSheets[0].rules)"
                "r=document.styleSheets[0].rules;\n"
                "else return;\n"
                "var i=0;\n"
                "if(r[1].style.display=='none')"
                "i=1;\n"
                "r[i].style.display='';\n"
                "r[i+1].style.display='none';\n"
                "toggledToJs=true\n"
                "}\n" );

    // Call useJS at once (for browsers where we can modify the
    // stylesheet before the import has been completed), and in
    // window.onload for other browsers.
    fm->append( "useJS(); window.onload = 'useJS();';\n" );

    // A function to show an element
    fm->append( "function reveal(e){\n"
                "document.getElementById(e).className='visible';\n"
                "}\n" );

    // A function to hide an element
    fm->append( "function hide(e){\n"
                "document.getElementById(e).className='hidden';\n"
                "}\n" );

    // A function to set a button's text. Does not work on any other
    // HTML elements.
    fm->append( "function setButtonText(i,t){\n"
                "var e = document.getElementById(i);\n"
                "if(e){\n"
                "e.childNodes[0].data=t;\n"
                "}\n"
                "}\n" );

    // A function to expand/collapse a message
    fm->append( "var hiddenIds=new Array;\n"
                "function expandCollapse(i,a,b,c){\n"
                "if(hiddenIds[i]){\n"
                "reveal(a);\n"
                "reveal(b);\n"
                "hide(c);\n"
                "hiddenIds[i]=false\n"
                "}else{\n"
                "hide(a);\n"
                "hide(b);\n"
                "reveal(c);\n"
                "hiddenIds[i]=true\n"
                "}\n"
                "}\n" );

    fm->append( "</script>" );

    return fm;
}
