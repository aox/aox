 // Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SIEVECOMMAND_H
#define SIEVECOMMAND_H

#include "global.h"

class Mailbox;
class Address;
class Sieve;


class SieveCommand
    : public Garbage
{
public:
    enum Type { If, Require, Stop,
                Reject, FileInto, Redirect, Keep, Discard };

    SieveCommand( Type type );

    Type type() const;

    void setMailbox( Mailbox * );
    Mailbox * mailbox() const;

    void setAddress( Address * );
    Address * address() const;

    void evaluate( Sieve * );

private:
    class SieveCommandData * d;
};


#endif
