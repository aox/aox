#include "intro.h"

#include "docblock.h"


static List<Intro> * intros = 0;



/*! \class Intro intro.h

    The Intro class introduces any number of classes (except
    zero). The introduction is output before the contained classes,
    and each class is output after its introduction.

    The Intro has a DocBlock, as usual. The DocBlock calls addClass()
    during parsing; output() uses this information to call
    Class::generateOutput() on the right classes afterwards. main()
    calls output() to build all the output.
*/



/*!  Constructs an empty

*/

Intro::Intro( const String & name )
    : n( name )
{
    if ( !intros )
        intros = new List<Intro>;
    intros->append( this );
}


/*! Notifies this Intro that it is documented by \a d. */

void Intro::setDocBlock( DocBlock * d )
{
    docBlock = d;
}


/*! Add \a c to the list of classes being introduced by this object. */

void Intro::addClass( Class * c )
{
    classes.insert( c );
}


/*! This static function processes all Intro objects and generates the
    appropriate output, including output for the classes introduced.
*/

void Intro::output()
{
    if ( !intros )
        return;

    SortedList<Intro>::Iterator it( intros->first() );
    while ( it != intros->end() ) {
        Intro * i = it;
        ++it;
        i->docBlock->generate();
        SortedList<Class>::Iterator c( i->classes.first() );
        while ( c != i->classes.end() ) {
            c->generateOutput();
            ++c;
        }
    }
}
