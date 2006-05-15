// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SIEVEACTION_H
#define SIEVEACTION_H

#include "sievecommand.h"

class Mailbox;
class Address;
class Message;


class SieveAction
    : public SieveCommand
{
public:
    enum Type { Reject, Fileinto, Redirect, Keep, Discard };

    SieveAction( Type );

    Type type() const;

    void setMailbox( Mailbox * );
    Mailbox * mailbox() const;

    void setAddress( Address * );
    Address * address() const;

private:
    class SieveActionData * d;
};


#endif
