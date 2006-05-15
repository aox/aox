// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SIEVEACTION_H
#define SIEVEACTION_H

#include "global.h"

class Mailbox;
class Address;
class Message;
class EventHandler;


class SieveAction
    : public Garbage
{
public:
    enum Type { Reject, FileInto, Redirect, Discard };

    SieveAction( Type );

    Type type() const;

    void setMailbox( Mailbox * );
    Mailbox * mailbox() const;

    void setAddress( Address * );
    Address * address() const;

    void execute( EventHandler * owner );
    bool done() const;
    bool failed() const;

private:
    class SieveActionData * d;
};


#endif
