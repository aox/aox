// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "userpane.h"

#include <qlayout.h>
#include <qlabel.h>
#include <qlistbox.h>
#include <qlineedit.h>
#include <qpushbutton.h>
#include <qapplication.h>

#include <sys/types.h> // getpwent, endpwent
#include <pwd.h> // ditto


class UserPaneData
{
public:
    UserPaneData(): users( 0 ), login( 0 ), realName( 0 ),
                    password1( 0 ), password2( 0 ), passwordError( 0 ),
                    address( 0 ), aliases( 0 ) {}
    QListBox * users;
    QLineEdit * login;
    QLineEdit * realName;
    QLineEdit * password1;
    QLineEdit * password2;
    QLabel * passwordError;
    QLineEdit * address;
    QListBox * aliases;
};


static uint strut()
{
    uint h = QApplication::globalStrut().height();
    uint w = QApplication::globalStrut().width();
    if ( w > h * 8 / 5 )
        return w;
    if ( h < 9 )
        return 15;
    return h * 8 / 5;
}



/*! \class UserPane userpane.h

    The UserPane class shows the user management functions in the
    Console.
*/


/*!  Constructs a UserPane. */

UserPane::UserPane( QWidget * parent )
    : QWidget( parent, "user pane" ), d( new UserPaneData )
{
    QGridLayout * tll = new QGridLayout( this, 12, 4, 6 );

    QLabel * l = new QLabel( tr( "&Users" ),
                             this );
    tll->addWidget( l, 0, 0 );

    d->users = new QListBox( this, "user list" );
    l->setBuddy( d->users );
    tll->addMultiCellWidget( d->users, 1, 9, 0, 0 );

    QPushButton * pb = new QPushButton( tr( "&Refresh",
                                            "Refresh list all users" ),
                                        this, "refresh user list" );
    tll->addWidget( pb, 10, 0, AlignLeft ); // writing...
    pb->setFocusPolicy( NoFocus );

    // the fields on the left: login
    l = new QLabel( tr( "User &Login" ), this );
    tll->addMultiCellWidget( l, 0, 0, 2, 3 );

    d->login = new QLineEdit( this, "login editor" );
    tll->addWidget( d->login, 1, 3 );
    l->setBuddy( d->login );
    connect( d->login, SIGNAL(lostFocus()),
             this, SLOT(updateExceptLogin()) );

    // real name
    l = new QLabel( tr( "Real &Name" ), this );
    tll->addMultiCellWidget( l, 2, 2, 2, 3 );

    d->realName = new QLineEdit( this, "real-name editor" );
    tll->addWidget( d->realName, 3, 3 );
    l->setBuddy( d->realName );
    connect( d->realName, SIGNAL(lostFocus()),
             this, SLOT(perhapsUpdateLogin()) );

    // password
    l = new QLabel( tr( "Password" ), this );
    tll->addMultiCellWidget( l, 4, 4, 2, 3 );

    d->password1 = new QLineEdit( this, "password editor" );
    d->password2 = new QLineEdit( this, "password confirmation" );
    d->password1->setEchoMode( QLineEdit::Password );
    d->password2->setEchoMode( QLineEdit::Password );
    QBoxLayout * h = new QBoxLayout( QBoxLayout::LeftToRight, 6 );
    h->addWidget( d->password1, 2 );
    h->addWidget( d->password2, 2 );
    tll->addLayout( h, 5, 3 );
    l->setBuddy( d->password1 );
    d->passwordError = new QLabel( this, "password error message" );

    // address (+ password error)
    l = new QLabel( tr( "Address" ), this );
    h = new QBoxLayout( QBoxLayout::LeftToRight, 6 );
    tll->addMultiCellLayout( h, 6, 6, 2, 3 );
    h->addWidget( l );
    h->addStretch( 1 );
    h->addWidget( d->passwordError );

    d->address = new QLineEdit( this, "real-name editor" );
    tll->addWidget( d->address, 7, 3 );
    l->setBuddy( d->address );

    // aliases
    l = new QLabel( tr( "Extra Aliases" ), this );
    tll->addMultiCellWidget( l, 8, 8, 2, 3 );

    d->aliases = new QListBox( this, "extra-address listbox" );
    tll->addWidget( d->aliases, 9, 3 );
    l->setBuddy( d->aliases );

    h = new QBoxLayout( QBoxLayout::LeftToRight, 6 );
    pb = new QPushButton( tr( "Add", "Add new user alias" ),
                          this, "add user alias" );
    connect( pb, SIGNAL(clicked()),
             this, SLOT(addAlias()) );
    h->addWidget( pb, 1 );

    pb = new QPushButton( tr( "Remove", "Remove existing user alias" ),
                          this, "remove user alias" );
    connect( pb, SIGNAL(clicked()),
             this, SLOT(removeAlias()) );
    h->addWidget( pb, 1 );
    h->addStretch( 2 );
    tll->addLayout( h, 10, 3 );

    // finally, tell the master grid where it can stretch, and where
    // it must have space.
    tll->setColSpacing( 1, 0 );
    //tll->setColSpacing( 1, QApplication::globalStrut() );
    tll->setColSpacing( 1, strut() );
    tll->setColSpacing( 2, strut() );
    tll->setColStretch( 3, 2 );

    tll->setRowStretch( 9, 2 );
}


/*! Adds an alias, except it doesn't. The alias functionality must
  change and this function must go away.

*/

void UserPane::addAlias()
{
    debug( "addAlias" );
}


/*! As for addAlias().

*/

void UserPane::removeAlias()
{
    debug( "removeAlias" );
}


/*! Updates other parts of the pane when the login has changed. Runs
    whenever the user e.g. presses enter in the login field. */

void UserPane::updateExceptLogin()
{
    // choose the right login in the users list
    QListBoxItem * i = d->users->findItem( d->login->text(), ExactMatch );
    d->users->setCurrentItem( i );

    // more goes here
}


// helpers to pick a good login name

static QString first( QString s )
{
    int i = s.find( ' ' );
    if ( i > 0 )
        return s.left( i );
    return "";
}


static QString last( QString s )
{
    int i = s.findRev( ' ' );
    if ( i > 0 )
        return s.mid( i + 1 );
    return "";
}

static QString initials( const QString & s )
{
    QString r;
    int i = 0;
    while ( i < (int)s.length() ) {
        r += s[i];
        i = s.find( " ", i ) + 1;
        if ( i == 0 )
            i = r.length();
    }
    return r;
}


static QString firstl( const QString & s )
{
    return first( s ) + initials( s ).right( 1 );
}


static QString firstml( const QString & s )
{
    return first( s ) + initials( s ).mid( 1 );
}


static QString flast( const QString & s )
{
    return s.left( 1 ) + last( s );
}


static QString fmlast( const QString & s )
{
    return initials( s ) + last( s ).mid( 1 );
}


static QString unixLogin( const QString & s ) {
    QString l = s.lower().simplifyWhiteSpace();
    struct passwd * p = 0;
    QString r;
    do {
        p = getpwent();
        if ( p ) {
            QString g = p->pw_gecos;
            g = g.lower().section( ',', 0, 0 );
            if ( l == g )
                r = p->pw_name;
        }
    } while ( r.isEmpty() && p );
    endpwent();
    return r;
}


/*! If the login is empty, try and invent one matching the name. */

void UserPane::perhapsUpdateLogin()
{
    if ( !d->login->text().isEmpty() || d->realName->text().isEmpty() )
        return;

    QStringList l;
    QString n = d->realName->text().lower();
    l.append( unixLogin( n ) );
    if ( n.contains( " " ) ) {
        l.append( first( n ) );
        l.append( firstl( n ) );
        l.append( firstml( n ) );
        l.append( initials( n ) );
        l.append( last( n ) );
        l.append( flast( n ) );
        l.append( fmlast( n ) );
    }
    else {
        l.append( n.lower() );
    }

    QStringList::Iterator it = l.begin();
    while ( it != l.end() && d->login->text().isEmpty() ) {
        if ( !d->users->findItem( *it, ExactMatch ) ) {
            d->login->setText( *it );
            d->users->setCurrentItem( -1 );
        }
        ++it;
    }
}
