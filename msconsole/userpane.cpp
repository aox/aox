// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "userpane.h"

#include <qlayout.h>
#include <qlabel.h>
#include <qlistbox.h>
#include <qlineedit.h>
#include <qpushbutton.h>
#include <qapplication.h>



class UserPaneData
{
public:
    UserPaneData(): users( 0 ), login( 0 ), realName( 0 ),
                    password1( 0 ), password2( 0 ),
                    address( 0 ), aliases( 0 ) {}
    QListBox * users;
    QLineEdit * login;
    QLineEdit * realName;
    QLineEdit * password1;
    QLineEdit * password2;
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

    // the fields on the left: login
    l = new QLabel( tr( "User &Login" ), this );
    tll->addMultiCellWidget( l, 0, 0, 2, 3 );

    d->login = new QLineEdit( this, "login editor" );
    tll->addWidget( d->login, 1, 3 );
    l->setBuddy( d->login );

    // real name
    l = new QLabel( tr( "Real &Name" ), this );
    tll->addMultiCellWidget( l, 2, 2, 2, 3 );

    d->realName = new QLineEdit( this, "real-name editor" );
    tll->addWidget( d->realName, 3, 3 );
    l->setBuddy( d->realName );

    // password
    l = new QLabel( tr( "Password" ), this );
    tll->addMultiCellWidget( l, 4, 4, 2, 3 );

    d->password1 = new QLineEdit( this, "password editor" );
    d->password2 = new QLineEdit( this, "password confirmation" );
    QBoxLayout * h = new QBoxLayout( QBoxLayout::LeftToRight, 6 );
    h->addWidget( d->password1, 2 );
    h->addWidget( d->password2, 2 );
    tll->addLayout( h, 5, 3 );
    l->setBuddy( d->password1 );

    // address
    l = new QLabel( tr( "Address" ), this );
    tll->addMultiCellWidget( l, 6, 6, 2, 3 );

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
