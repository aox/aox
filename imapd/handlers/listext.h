// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LISTEXT_H
#define LISTEXT_H

#include "command.h"

class Mailbox;


// this file is misnamed. the only way out seems to be calling the
// handlers something longer, e.g. ImapCList for this class. but let's
// delay that until we have more than one problem.


class Listext
    : public Command
{
public:
    Listext();

    void parse();
    void execute();

private:
    String listMailbox();
    void addReturnOption( const String & );
    void addSelectOption( const String & );

    void list( Mailbox *, const String & );
    void sendListResponse( Mailbox * );

private:
    class ListextData * d;
};


#endif
