// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include <limits.h>

#include "cstring.h"

#include "permissioneditor.h"

#include "permissions.h"
#include "allocator.h"
#include "mailbox.h"
#include "query.h"

#include <qapplication.h>
#include <qpushbutton.h>
#include <qcheckbox.h>
#include <qptrlist.h>
#include <qtooltip.h>
#include <qlayout.h>
#include <qlabel.h>


class PermissionEditorData
    : public Garbage
{
public:
    PermissionEditorData()
        : add( 0 ), mailbox( 0 ), tll( 0 ),
          rows( new QPtrList<PermissionEditorRow> ), unflicker( 0 )
    {}

    QPushButton * add;
    Mailbox * mailbox;
    QGridLayout * tll;
    QPtrList<PermissionEditorRow> * rows;
    QPtrList<PermissionEditorRow> * unflicker;

    QLabel * rights[Permissions::NumRights];
};


/*! \class PermissionEditor permissioneditor.h

    The PermissionEditor class presents the RFC 2086 access control
    list for a mailbox on-screen, allows editing them and finally
    writing them back to the database.

    The class has no real public API - it receives its commands from
    the user via the UI, not from the rest of the program.
*/


/*! Constructs a PermissionEditor visually located in \a parent. After
    construction the editor shows nothing, since there is no Mailbox
    yet.
*/

PermissionEditor::PermissionEditor( QWidget * parent )
    : QWidget( parent ), d( new PermissionEditorData )
{
    Allocator::addEternal( d, "permission editor GC-able data" );
    d->add = new QPushButton( tr( "Add" ), this );
    connect( d->add, SIGNAL(clicked()),
             this, SLOT(addColumn()) );

    d->rights[Permissions::Lookup]
        = new QLabel( "Lookup", this );
    QToolTip::add( d->rights[Permissions::Lookup],
                   tr( "<p>If set, the mailbox name is visible. "
                       "This is always true.</p>" ) );

    d->rights[Permissions::Read]
        = new QLabel( "Read", this );
    QToolTip::add( d->rights[Permissions::Read],
                   tr( "<p>If set, "
                       "the user can ready messages in this mailbox.</p>" ) );

    d->rights[Permissions::KeepSeen]
        = new QLabel( "Keep Seen", this );
    QToolTip::add( d->rights[Permissions::KeepSeen],
                   tr( "<p>If set, then reading messages sets the "
                       "<i>seen</i> flag.</p>" ) );

    d->rights[Permissions::Write]
        = new QLabel( "Write", this );
    QToolTip::add( d->rights[Permissions::Write],
                   tr( "<p>If set, then the user can change flags "
                       "(except <i>seen</i> and <i>deleted</i>).</p>" ) );

    d->rights[Permissions::Insert]
        = new QLabel( "Insert", this );
    QToolTip::add( d->rights[Permissions::Insert],
                   tr( "<p>If set, the user can write or copy new messages "
                       "into the mailbox.</p>" ) );

    d->rights[Permissions::Post]
        = new QLabel( "Post", this );
    QToolTip::add( d->rights[Permissions::Post],
                   tr( "<p>If set, the user can send mail to mailbox. "
                       "This right is not enforced. For the moment, "
                       "it cannot be disabled.</p>" ) );

    d->rights[Permissions::CreateMailboxes]
        = new QLabel( "CreateMailboxes", this );
    QToolTip::add( d->rights[Permissions::CreateMailboxes],
                   tr( "<p>If set, the user can create child mailboxes "
                       "of this mailbox.</p>" ) );

    d->rights[Permissions::DeleteMailbox]
        = new QLabel( "Delete Mailbox", this );
    QToolTip::add( d->rights[Permissions::DeleteMailbox],
                   tr( "<p>If set, the user can delete mailbox. "
                       "Note that deleting the messages in this mailbox "
                       "is covered by a separate right.</p>" ) );

    d->rights[Permissions::DeleteMessages]
        = new QLabel( "Delete Messages", this );
    QToolTip::add( d->rights[Permissions::DeleteMessages],
                   tr( "<p>If set, the user can can set the "
                       "<i>deleted</i> flag on messages.</p>" ) );

    d->rights[Permissions::Expunge]
        = new QLabel( "Expunge", this );
    QToolTip::add( d->rights[Permissions::Expunge],
                   tr( "<p>If set, the user can expunge messages that have "
                       "the <i>deleted</i> flag.</p>" ) );

    d->rights[Permissions::Admin]
        = new QLabel( "Admin", this );
    QToolTip::add( d->rights[Permissions::Admin],
                   tr( "<p>If set, the user can modify these rights.</p>" ) );
}


PermissionEditor::~PermissionEditor()
{
    Allocator::removeEternal( d );
}


/*! Deletes whatever was shown and starts showing the ACL for \a
    mailbox.
*/

void PermissionEditor::setMailbox( Mailbox * mailbox )
{
    if ( mailbox == d->mailbox )
        return;
    delete d->tll;
    d->tll = 0;
    delete d->unflicker;
    d->unflicker = d->rows;
    d->rows = new QPtrList<PermissionEditorRow>;
    d->rows->setAutoDelete( true );

    d->mailbox = mailbox;
    (void)new PermissionEditorFetcher( this, mailbox );

    // Mailbox::owner() really should return User*
    PermissionEditorRow * r = new PermissionEditorRow( this );
    r->label()->setText( QString::fromLatin1( "(owner)" ) );
    uint i = 0;
    while( i < Permissions::NumRights ) {
        QCheckBox * b = r->button( (Permissions::Right)i );
        b->setChecked( true );
        b->setEnabled( false );
        i++;
    }
    d->rows->append( r );
}


/*! Returns a pointer to the currently displayed Mailbox. The value is
    0 initially, meaning that no mailbox is being displayed.
*/

Mailbox * PermissionEditor::mailbox() const
{
    return d->mailbox;
}


/*! Creates a new QLayout object to lay out all the current ACL rows.

*/

void PermissionEditor::setupLayout()
{
    delete d->tll;
    d->tll = new QGridLayout( this, 4, 1 + d->rows->count(), 6 );
    QPtrListIterator<PermissionEditorRow> it( *d->rows );
    uint col = 0;
    PermissionEditorRow * r = 0;
    while ( (r=it.current()) != 0 ) {
        ++it;
        uint i = 0;
        d->tll->addWidget( r->label(), 0, col );
        r->label()->show();
        while ( i < Permissions::NumRights ) {
            d->tll->addWidget( r->button( (Permissions::Right)i ),
                               i+1, col );
            r->button( (Permissions::Right)i )->show();
            i++;
        }
        col++;
    }
    d->tll->addWidget( d->add, 0, col );
    d->add->show();
    uint i = 0;
    while ( i < Permissions::NumRights ) {
        d->tll->addWidget( d->rights[i], i+1, col );
        i++;
    }

    d->tll->activate();
    QApplication::postEvent( parentWidget(),
                             new QEvent( QEvent::LayoutHint ) );

    // finally, now that the screen is ready, kill the old items, kept
    // in the unflicker list.
    delete d->unflicker;
    d->unflicker = 0;
}


class PermissionEditorRowData
    : public Garbage
{
public:
    PermissionEditorRowData()
        : label( 0 )
    {
        uint i = 0;
        while( i < Permissions::NumRights )
            buttons[i++] = 0;
    }

    QCheckBox *buttons[Permissions::NumRights];
    QLabel * label;
};


/*! \class PermissionEditorRow permissioneditor.h

    PermissionEditorRow is a container for the widgets needed to
    control a single row in the grid used by PermissionEditor. It
    exists only to provide teh button() and label() functions.
*/


/*! Constructs the widgets necessary for a single Permissions object
    (or for "anyone"). Each widget created has \a parent as parent.
*/

PermissionEditorRow::PermissionEditorRow( PermissionEditor * parent )
    : QObject( parent ), d( new PermissionEditorRowData )
{
    Allocator::addEternal( d, "permissioneditor row gcable" );
    d->label = new QLabel( parent );
    uint i = 0;
    while( i < Permissions::NumRights )
        d->buttons[i++] = new QCheckBox( parent );

    // two rights are hardwired to true in the oryx system
    d->buttons[Permissions::Lookup]->setChecked( true );
    d->buttons[Permissions::Lookup]->setEnabled( false );
    d->buttons[Permissions::Post]->setChecked( true );
    d->buttons[Permissions::Post]->setEnabled( false );
}


/*! Deletes the buttons and label held in this row. This is probably
    the only Oryx destructor that's actually necessary, and it's
    necessary because many other pointers to the child widgets need to
    be removed.
*/

PermissionEditorRow::~PermissionEditorRow()
{
    Allocator::removeEternal( d );
    delete d->label;
    uint i = 0;
    while( i < Permissions::NumRights )
        delete d->buttons[i++];
    d = 0;
}


/*! Returns a pointer to the button displaying and controlling \a
    right.
*/

QCheckBox * PermissionEditorRow::button( Permissions::Right right ) const
{
    return d->buttons[right];
}


/*! Returns a pointer to the label at the top of the column. */

QLabel * PermissionEditorRow::label() const
{
    return d->label;
}


static const char * defaultRights = "lp";


class PermissionEditorFetcherData
    : public Garbage
{
public:
    PermissionEditorFetcherData(): q( 0 ), e( 0 ), m( 0 ) {}
    Query * q;
    PermissionEditor * e;
    Mailbox * m;
    String anyone;
};


/*! Creates an object to fetch all the ACLs for \a m and call
    the PermissionEditor::add() of \a e for each.
*/

PermissionEditorFetcher::PermissionEditorFetcher( PermissionEditor * e,
                                                  Mailbox * m )
    : EventHandler(), d( new PermissionEditorFetcherData )
{
    Allocator::addEternal( d, "permissioneditorfetcher gcable data" );
    d->q = new Query( "select identifier, rights "
                      "from permissions where mailbox=$1 "
                      "order by identifier",
                      this );
    d->q->bind( 1, m->id() );
    d->q->execute();
    d->e = e;
    d->m = m;
    d->anyone = defaultRights;
}


PermissionEditorFetcher::~PermissionEditorFetcher()
{
    Allocator::removeEternal( d );
}


void PermissionEditorFetcher::execute()
{
    Row * r;
    while ( (r=d->q->nextRow()) != 0 ) {
        String rights( r->getString( "rights" ) );
        String id( r->getString( "identifier" ) );
        if ( d->m != d->e->mailbox() )
            ;
        else if ( id == "anyone" )
            d->anyone = rights;
        else
            d->e->add( id, rights );
    }
    if ( !d->q->done() || d->m != d->e->mailbox() )
        return;
    if ( !d->anyone.isEmpty() )
        d->e->add( "anyone", d->anyone );
    d->e->setupLayout();
}


/*! Creates and shows a PermissionEditorRow indicating that \a
    identifier has \a rights, and allowing change.

    It would be good to take any old PermissionEditorRow we had for
    the last mailbox instead of creating a new one, if a suitable row
    is at hand. Minimizes flicker.
*/

void PermissionEditor::add( const String & identifier, const String & rights )
{
    PermissionEditorRow * r = new PermissionEditorRow( this );
    r->label()->setText( QString::fromUtf8( identifier.data(),
                                            identifier.length() ) );
    uint i = 0;
    while( i < Permissions::NumRights ) {
        char rc = Permissions::rightChar( (Permissions::Right)i );
        if ( rights.find( rc ) >= 0 )
            r->button( (Permissions::Right)i )->setChecked( true );
        i++;
    }
    d->rows->append( r );
}


/*! Adds a new row, including editable name.

    Todo: Editable name. Here or elsewhere?

*/

void PermissionEditor::addColumn()
{
    PermissionEditorRow * r = new PermissionEditorRow( this );
    r->label()->setText( tr( "ugga" ) );
    uint i = 0;
    String rights( defaultRights );
    while( i < Permissions::NumRights ) {
        char rc = Permissions::rightChar( (Permissions::Right)i );
        if ( rights.find( rc ) >= 0 )
            r->button( (Permissions::Right)i )->setChecked( true );
        i++;
    }
    PermissionEditorRow * anyone = d->rows->last();
    if ( anyone )
        d->rows->take();
    d->rows->append( r );
    if ( anyone )
        d->rows->append( anyone );
    setupLayout();
}
