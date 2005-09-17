// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "acl.h"

#include "string.h"


class AclData {
public:
    AclData()
    {}

    String mbox;
    String authid;
    String rights;
};


/*! \class SetAcl acl.h
    Implements the SETACL command from RFC 2086.
*/

/*! Creates a new SetAcl handler. */

SetAcl::SetAcl()
    : d( new AclData )
{
}


void SetAcl::parse()
{
    space();
    d->mbox = astring();
    space();
    d->authid = astring();
    space();
    d->rights = astring();
    end();
}


void SetAcl::execute()
{
    finish();
}



/*! \class DeleteAcl acl.h
    Implements the DELETEACL command from RFC 2086.
*/

/*! Creates a new DeleteAcl handler. */

DeleteAcl::DeleteAcl()
    : d( new AclData )
{
}


void DeleteAcl::parse()
{
    space();
    d->mbox = astring();
    space();
    d->authid = astring();
    end();
}


void DeleteAcl::execute()
{
    finish();
}



/*! \class GetAcl acl.h
    Implements the GETACL command from RFC 2086.
*/

/*! Creates a new GetAcl handler. */

GetAcl::GetAcl()
    : d( new AclData )
{
}


void GetAcl::parse()
{
    space();
    d->mbox = astring();
    end();
}


void GetAcl::execute()
{
    finish();
}



/*! \class ListRights acl.h
    Implements the LISTRIGHTS command from RFC 2086.
*/

/*! Creates a new ListRights handler. */

ListRights::ListRights()
    : d( new AclData )
{
}


void ListRights::parse()
{
    space();
    d->mbox = astring();
    space();
    d->authid = astring();
    end();
}


void ListRights::execute()
{
    finish();
}



/*! \class MyRights acl.h
    Implements the MYRIGHTS command from RFC 2086.
*/

/*! Creates a new MyRights handler. */

MyRights::MyRights()
    : d( new AclData )
{
}


void MyRights::parse()
{
    space();
    d->mbox = astring();
    end();
}


void MyRights::execute()
{
    finish();
}
