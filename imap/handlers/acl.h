// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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
