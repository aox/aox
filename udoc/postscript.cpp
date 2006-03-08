// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "postscript.h"

#include "file.h"
#include "error.h"
#include "class.h"
#include "function.h"


static const char * prologue =
    "%!PS-Adobe-3.0\n"
    "%%Creator: udoc, http://www.oryx.com/udoc/\n"
    "%%PageOrder: Ascend\n"
    "%%DocumentMedia:\n"
    "%%BoundingBox: 0 0 595 841\n"
    "%%DocumentData: Clean8Bit\n"
    "%%Orientation: Portrait\n"
    "%%EndComments\n"
    "\n"
    "%%BeginProlog\n"
    "\n"
    "/mm { 72 mul 25.4 div } bind def\n"
    "\n"
    "/lx 20 mm def\n"
    "/rx 190 mm def\n"
    "/dy 12 def\n"
    "/ty 279 mm def\n"
    "/by 25 mm def\n"
    "/page 1 def\n"
    "\n"
    "/header\n" // shows page number
    "{ page 10 string cvs dup stringwidth pop\n"
    "    rx exch sub 285 mm moveto\n"
    "    show\n"
    "} bind def\n"
    "/l\n" // shows a single line of text and moves the point down
    "{\n"
    " currentpoint 3 -1 roll show dy sub moveto\n"
    "} bind def\n"
    "\n"
    "/s\n" // tos: word. shows a single word and one trailing space.
    "{ dup stringwidth pop currentpoint pop add rx gt\n"
    "     { currentpoint exch pop dy sub\n"
    "       dup by lt { showpage pop ty /page page 1 add def header } if\n"
    "       lx exch moveto } if\n"
    "     show ( ) show \n"
    "} bind def\n"
    "\n"
    "/p\n" // tos: paragraph. shows the paragraph within x boundaries lx-rx
    "{ { ( ) search { s pop } { s exit } ifelse } loop\n"
    "  lx currentpoint exch pop dy 2 mul sub moveto\n"
    "} bind def\n"
    "\n"
    "%%EndProlog\n";

static Postscript * current = 0;


/*! \class Postscript postscript.h

    The Postscript class generates output in postscript form. Plain
    postscript level 1 is used, and all formatting is done on the
    printer, even wordwrapping.

    At the moment, all output uses the same font. That's a bug. Have
    to fix that.
*/



/*! Constructs an Postscript output function, opens \a f for writing
    and writes the postscript prologue.
*/

Postscript::Postscript( const char * f )
    : file( 0 )
{
    file = new File( f, File::Write );
    if ( !file->valid() ) {
        (void)new Error( file, 0,
                         "Postscript: Unable to open this file for writing" );
        file = 0;
        return;
    }
    ::current = this;
    output( prologue );
    output( "/Times findfont 9.5 scalefont setfont\n"
            "header\n"
            "lx ty moveto\n" );
}


/*! Destroys the writer and closes the file. */

Postscript::~Postscript()
{
    endParagraph();
    output( "showpage\n" );
    delete file;
}


/*! Returns a pointer to the current Postscript singleton. */

Postscript * Postscript::current()
{
    return ::current;
}


/*! As Output::startHeadline() */

void Postscript::startHeadline( Intro * )
{
    endParagraph();
}


/*! As Output::startHeadline(). */

void Postscript::startHeadline( Class * )
{
    endParagraph();
}


/*! As Output::startHeadline(). */

void Postscript::startHeadline( Function * )
{
    endParagraph();
}


/*! Ends a paragraph, if one is being output. */

void Postscript::endParagraph()
{
    if ( para.isEmpty() )
        return;

    String r;
    uint i = 0;
    while ( i < para.length() ) {
        if ( para[i] == '(' || para[i] == ')' || para[i] == '\\' )
            r.append( "\\" );
        r.append( para[i] );
        i++;
    }
    output( "(" + r.simplified() + ") p\n" );
    para = "";
}


/*! Outputs \a s to the destination file, taking care to escape
    characters correctly, and to start a new paragraph if necessary.
*/

void Postscript::addText( const String & s )
{
    para.append( s );
}


/*! Outputs \a s to the destination file, theorecically in
  italics. Right now it's exactly as addText().
*/

void Postscript::addArgument( const String & s )
{
    addText( s );
}


/*! Adds \a text to the destination file, if possible with the page
    number where \a f is documented.
*/

void Postscript::addFunction( const String & text, Function * f )
{
    addText( text );
    f = f;
}


/*! Adds \a text to the destination file, if possible with the page
    number where \a c is documented.

*/

void Postscript::addClass( const String & text, Class * c )
{
    addText( text );
    c = c;
}


/*! Writes \a s to the destination file as-is. */

void Postscript::output( const String & s )
{
    if ( file )
        file->write( s );
}
