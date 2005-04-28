// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "function.h"

#include "class.h"
#include "list.h"
#include "parser.h"
#include "error.h"


static List<Function> * functions = 0;


/*! \class Function function.h
  The Function class models a member function.

  Member functions are the only functions in udoc's world.

  Each function has a file() and line() number, which consequently are
  the ones in the class declaration, and it should have a docBlock().
  (The DocBlock's file and line number presumably are in a .cpp file.)
*/


/*!  Constructs a function whose return type is \a type, whose full
    name (including class) is \a name and whose arguments are \a
    arguments. \a originFile and \a originLine point to the function's
    defining source, which will be used in any error messages.
*/

Function::Function( const String & type,
                    const String & name,
                    const String & arguments,
                    File * originFile, uint originLine )
    : c( 0 ), t( type ), f( originFile ), l( originLine ), db( 0 ), ol( false )
{
    if ( !functions )
        functions = new List<Function>;
    functions->append( this );

    uint i = name.length()-1;
    while ( i > 0 && name[i] != ':' )
        i--;
    if ( i == 0 || name[i-1] != ':' ) {
        // bad. error. how?
        return;
    }
    n = name;
    a = typesOnly( arguments );
    args = arguments;
    c = Class::find( name.mid( 0, i - 1 ) );
    if ( !c )
        c = new Class( name.mid( 0, i - 1 ), 0, 0 );
    c->insert( this );
}


/*! Returns a pointer to the Function object that is named (fully
    qualified) \a name and accepts \a arguments. If there is no such
    Function object, find() returns 0.
*/

Function * Function::find( const String & name,
                           const String & arguments )
{
    if ( !functions )
        return 0;

    String tmp = name;
    List<Function>::Iterator it( functions );
    Function * f = 0;
    if ( arguments.isEmpty() ) {
        while ( (f=it) != 0 && f->n != name )
            ++it;
    }
    else {
        String t = typesOnly( arguments );
        while ( (f=it) != 0 &&
                !( f->n == name && f->a == t ) )
            ++it;
    }
    return f;
}


/*! Returns a version of the argument list \a a which is stripped of
    argument names. For example, "( int a, const String & b, int )" is
    transformed into "( int a, const String &, int )".
*/

String Function::typesOnly( const String & a )
{
    if ( a == "()" )
        return a;
    String r;
    Parser p( a );
    p.step(); // past the '('
    String t;
    String s = "( ";
    do {
        t = p.type();
        if ( t.startsWith( "class " ) )
            t = t.mid( 6 );
        if ( t.startsWith( "struct " ) )
            t = t.mid( 7 );
        if ( !t.isEmpty() ) {
            r.append( s );
            r.append( t );
        }
        p.scan( "," );
        s = ", ";
    } while ( !t.isEmpty() );
    r.append( " )" );
    return r;
}



bool Function::operator<=( const Function & other ) const
{
    if ( c != other.c )
        return *c <= *other.c;
    if ( n != other.n )
        return n <= other.n;
    // here, it'll be good to check whether *this and whether other
    // are documented, and return the documented one first if their
    // status is different.
    return a <= other.a;
}


/*! Returns a pointer to the function which this function
    reimplements, or a null pointer if this function isn't a
    reimplementation (or if it is, but udoc can't see it.)
*/

Function * Function::super() const
{
    if ( !c || !c->parent() )
        return 0;

    Class * subclass = c;
    Function * result = 0;

    do {
        // normally the parent function's name is the same as this, but
        // for constructors or destructors it gets difficult. so let's
        // find out what the member name and immediate class name are.
        String sn = n;
        int i = sn.length()-1;
        while ( i >= 0 && sn[i] != ':' )
            i--;
        String memberName = sn.mid( i + 1 );
        i = i - 2;
        while ( i >= 0 && sn[i] != ':' )
            i--;
        if ( i < 0 )
            i = -1;
        String iClassName = sn.mid( i + 1 );
        i = 0;
        while ( iClassName[i] != ':' )
            i++;
        iClassName.truncate( i );

        // is it a constructor? destructor?
        if ( memberName == iClassName || memberName == "~" + iClassName ) {
            sn = subclass->parent()->name();
            i = sn.length() - 1;
            while ( i >= 0 && sn[i] != ':' )
                i--;
            i++;
            if ( memberName[0] == '~' )
                sn = sn + "::~" + sn.mid( i );
            else
                sn = sn + "::" + sn.mid( i );
        }
        else {
            sn = subclass->parent()->name() + "::" + memberName;
        }

        // after all that, we finally know what function we may be
        // reimplementing. so look for it and return it.
        result = find( sn, a );
        subclass = subclass->parent();
    } while ( !result && subclass->parent() );

    return result;
}


/*! Notifies this function that it has an "\overload" directive. */

void Function::setOverload()
{
    ol = true;
}


/*! Returns true if \a s is the variable name of one of this
    function's arguments as specified in the .cpp file, and false if
    not.
*/

bool Function::hasArgument( const String & s ) const
{
    int i = 0;
    while ( i >= 0 && i < (int)args.length() ) {
        i = args.find( s, i );
        if ( i >= 0 ) {
            i += s.length();
            while ( args[i] == ' ' )
                i++;
            if ( args[i] == '[' && args[i+1] == ']' )
                i += 2;
            while ( args[i] == ' ' )
                i++;
            if ( args[i] == ')' || args[i] == ',' )
                return true;
        }
    }
    return false;
}


/*! Notifies this Function that its argument list is really \a
    arguments, contrary to what it may previously have believed.

    It is legal to have different parameter names in the .h and .cpp
    file names. In that case, udoc needs to see and remember the names
    in the .cpp file, even if the Function was originally created
    based on the .h file.
*/

void Function::setArgumentList( const String & arguments )
{
    args = arguments;
}


/*! \fn File * Function::file() const

    Returns a pointer to the File where this Function is defined,
    suitable for error messages.
*/

/*! \fn uint Function::line() const

    Returns the line number where this Function was defined, suitable
    for error messages.
*/

/*! \fn DocBlock * Function::docBlock() const

    Returns a pointer to the DocBlock that documents this Function, or
    a null pointer if the Function is undocumented.
*/
