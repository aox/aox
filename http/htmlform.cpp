// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "htmlform.h"

#include "list.h"
#include "ustring.h"
#include "webpage.h"
#include "codec.h"
#include "link.h"
#include "http.h"


class HtmlFormData
    : public Garbage
{
public:
    HtmlFormData()
    {}

    EString action;
    EString method;

    struct Field {
        Field( const EString &n, const EString &t, const EString &d, bool r )
            : name( n ), type( t ), dflt( d ), required( r )
        {}

        EString name;
        EString type;
        EString dflt;
        UString value;
        bool required;
    };

    List<Field> fields;
};


/*! \class HtmlForm htmlform.h
    This class represents and can render an HTML <form> element.

    The user (typically a PageComponent) creates a form, adds one or
    more fields to it, and fetches the rendered HTML representation
    for output with html().
*/

/*! Creates an empty form object with the action \a a (which is empty by
    default, i.e. points to the current page) and method \a m ("post" by
    default).
*/

HtmlForm::HtmlForm( const EString &a, const EString &m )
    : d( new HtmlFormData )
{
    d->action = a;
    d->method = m;
}


/*! Adds a field named \a name of type \a type and with the default
    value \a dflt to this form. If \a required is true (which it is
    not, by default), the field is required, i.e. filled() will
    return false unless it has a non-empty value.
*/

void HtmlForm::addField( const EString &name, const EString &type,
                         const EString &dflt, bool required )
{
    // XXX: The simple list-of-fields representation will need changes
    // in future: fields will need to become user-visible objects, and
    // there will eventually be a need to iterate over the field list.
    // But for now, the simple way works fine.
    // XXX: Note that dflt should be a UString, but we don't do that
    // yet because we can't give it a default of "".
    d->fields.append(
        new HtmlFormData::Field( name, type, dflt, required )
    );
}


/*! \overload
    This function adds a required field named \a name with the given
    \a type and default value \a dflt. It is equivalent to addField()
    with true as the last argument (i.e. "required"), and is provided
    only for clarity.
*/

void HtmlForm::requireField( const EString &name, const EString &type,
                             const EString &dflt )
{
    addField( name, type, dflt, true );
}

/*! Sets the value of the field named \a name to \a value. Does nothing
    if the given \a name does not correspond to a field that was added
    to this form (e.g. by using requireField()). */

void HtmlForm::setValue( const EString &name, const UString &value )
{
    List<HtmlFormData::Field>::Iterator it( d->fields );
    while ( it && it->name != name )
        ++it;
    if ( it )
        it->value = value;
}


/*! Fills in the values of all the fields in this form from the values
    submitted to \a page. If "name=x" is included in the request body,
    it is assumed to be the value of the field named "name" here. */

void HtmlForm::setValuesFrom( WebPage * page )
{
    HTTP * server = page->link()->server();
    List<HtmlFormData::Field>::Iterator it( d->fields );
    while ( it ) {
        it->value = server->parameter( it->name );
        ++it;
    }
}


/*! Returns the current value of the field named \a name. Returns an
    empty string if no value has been set (with setValuesFrom() or
    setValue()) and the field has no default value either.
*/

UString HtmlForm::getValue( const EString &name )
{
    List<HtmlFormData::Field>::Iterator it( d->fields );
    while ( it && it->name != name )
        ++it;

    UString u;
    AsciiCodec c;
    if ( it && !it->value.isEmpty() )
        return it->value;
    else if ( it )
        u.append( c.toUnicode( it->dflt ) );
    return u;
}


/*! Returns true if all the required fields in this form have non-empty
    values, which may be either the defaults (as specified in the call
    to requireField()) or input values that override them (i.e. those
    set by setValuesFrom()). Returns false if any required field hasn't
    been filled in.
*/

bool HtmlForm::filled() const
{
    List<HtmlFormData::Field>::Iterator it( d->fields );
    while ( it ) {
        if ( it->value.isEmpty() &&
             it->dflt.isEmpty() )
            return false;
        ++it;
    }

    return true;
}


/*! Discards any values set with setValue() or setValuesFrom() (but not
    any default values specified in addField() or requireField()). After
    a call to this function, html() will return an empty form.
*/

void HtmlForm::clear()
{
    List<HtmlFormData::Field>::Iterator it( d->fields );
    while ( it ) {
        it->value.truncate();
        ++it;
    }
}

/*! Returns an HTML representation of this form. */

EString HtmlForm::html() const
{
    EString s( "<form method=" );
    s.append( d->method );
    if ( !d->action.isEmpty() ) {
        s.append( " action=" );
        s.append( d->action.quoted() );
    }
    s.append( ">\n" );

    List<HtmlFormData::Field>::Iterator it( d->fields );
    while ( it ) {
        UString v( it->value );
        if ( v.isEmpty() && !it->dflt.isEmpty() ) {
            AsciiCodec c;
            v = c.toUnicode( it->dflt );
        }

        if ( it->type == "text" ) {
            s.append( "<label for=" );
            s.append( it->name.quoted() );
            s.append( ">" );
            s.append( it->name.headerCased() );
            s.append( ":</label>" );
            s.append( "<input type=text name=" );
            s.append( it->name.quoted() );
            if ( !v.isEmpty() ) {
                s.append( " value=" );
                s.append( v.ascii().quoted() );
            }
            s.append( "><br>\n" );
        }
        else if ( it->type == "submit" ) {
            s.append( "<input id=" );
            s.append( it->name.quoted() );
            s.append( " type=submit" );
            if ( !v.isEmpty() ) {
                s.append( " value=" );
                s.append( v.ascii().quoted() );
            }
            s.append( ">\n" );
        }

        ++it;
    }

    s.append( "</form>\n" );
    return s;
}
