// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "class.h"

#include "file.h"
#include "list.h"
#include "function.h"
#include "docblock.h"
#include "error.h"


static SortedList<Class> * classes = 0;


/*! \class Class class.h

  The Class class models a C++ class and its documentation.

  A Class has zero or one parent classes, any number of member
  functions and one documentation block.

  The file has an origin file and line.
*/


/*! Constructs a Class object for the class named \a s, which is
    defined on \a sourceLine of \a sourceFile. Initially the class is
    considered to have no member functions, superclasses or
    subclasses.
*/

Class::Class( const String & s, File * sourceFile, uint sourceLine )
    : n( s ), f( sourceFile ), l( sourceLine ),
      super( 0 ), sub( 0 ),
      db( 0 ), done( false )
{
    if ( !classes )
        classes = new SortedList<Class>;
    classes->insert( this );
}


/*! \fn String Class::name() const

    Returns the class name, as specified to the constructor.
*/


/*! Returns a pointer to the Class object whose name() is \a s, or a
    null pointer of there is no such object.
*/

Class * Class::find( const String & s )
{
    if ( !classes )
        return 0;

    List<Class>::Iterator it( classes->first() );
    Class * c = 0;
    while ( (c=it) != 0 && c->n != s )
        ++it;
    return c;
}


/*! Notifies this Class that \a cn is its parent class. The initial
    value is an empty string, corresponding to a class that inherits
    nothing.

    Note that qdoc does not support multiple or non-public inheritance.
*/

void Class::setParent( const String & cn )
{
    new Error( file(), line(), "Setting superclass " + cn + " for " + name() );
    superclassName = cn;
}


/*! Returns the line number where this class was first seen. Should
    this be the line of the "\class", or of the header file
    class definition? Not sure. */

uint Class::line() const
{
    return l;
}

/*! Returns the file name where this class was seen. Should this be
    the .cpp containing the "\class", or the header file
    containing class definition? Not sure. */

File * Class::file() const
{
    return f;
}


/*! This static function processes all classes and generates the
    appropriate output.
*/

void Class::output()
{
    if ( !classes )
        return;

    SortedList<Class>::Iterator it( classes->first() );
    while ( it ) {
        Class * c = it;
        ++it;
        if ( !c->done )
            c->generateOutput();
    }
}


bool Class::operator<=( const Class & other ) const
{
    return n <= other.n;
}


/*! Does everything necessary to generate output for this class and
    all of its member functions.
*/

void Class::generateOutput()
{
    if ( !db ) {
        if ( !f ) {
            // if we don't have a file for this class, see if we can
            // get one from a function.
            Function * member = m.first();
            if ( member ) {
                f = member->file();
                l = member->line();
            }
        }
        // if we now have a file, we can complain
        if ( f )
            (void)new Error( file(), line(), "Undocumented class: " + n );
        return;
    }
    else if ( f ) {
        db->generate();
    }

    SortedList<Function>::Iterator it( m.first() );
    it = m.first();
    Function * f;
    while ( (f=it) != 0 ) {
        ++it;
        if ( f->docBlock() )
            f->docBlock()->generate();
        else if ( !f->super() )
            (void)new Error( f->file(), f->line(),
                             "Undocumented function: " +
                             f->name() + f->arguments() );
    }
    done = true;
}


/*! Remembers \a function as a member function in this class, so its
    documentation can be included by generateOutput() and friends.
*/

void Class::insert( Function * function )
{
    m.insert( function );
}



/*! Builds a hierarchy tree of documented classes, and emits errors if
  any the inheritance tree isn't fully documented.

  This function must be called before Function::super() can be.
*/

void Class::buildHierarchy()
{
    if ( !classes )
        return;

    List<Class>::Iterator it( classes->first() );
    Class * c = 0;
    while ( (c=it) != 0 ) {
        ++it;
        String n = c->superclassName;
        int i = n.find( '<' );
        if ( i >= 0 )
            n = n.mid( 0, i );
        if ( !n.isEmpty() ) {
            Class * p = find( n );
            c->super = p;
            if ( p && !p->sub )
                p->sub = new SortedList<Class>;
            if ( p )
                p->sub->append( c );
            if ( !c->super )
                (void)new Error( c->f, c->l, "Class " + c->n +
                                 " inherits undocumented class " +
                                 c->superclassName );
        }
    }
}


/*! Returns a pointer to a list of all classes that directly inherit
    this class. The returned list must neither be deleted nor
    changed. If no classes inherit this one, subclasses() returns a
    null pointer.*/

List<Class> * Class::subclasses() const
{
    return sub;
}


/*! Returns a pointer to the list of all the member functions in this
    class. The Class remains owner of the list; the caller should not
    delete or modify the list in any way.
*/

List<Function> * Class::members()
{
    return &m;
}


/*! \fn Class * Class::parent() const

    Returns a pointer to the superclass of this class, or a null
    pointer if this class doesn't inherit anything.
*/
