// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ACL_H
#define ACL_H

#include "command.h"


class Acl
    : public Command
{
public:
    enum Type { SetAcl, DeleteAcl, GetAcl, ListRights, MyRights };

    Acl( Type );

    void parse();
    void execute();

private:
    class AclData * d;
};


#endif
