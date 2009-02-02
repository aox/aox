// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LISTEXT_H
#define LISTEXT_H

#include "command.h"

class Mailbox;


class Listext
    : public Command
{
public:
    Listext();

    void parse();
    void execute();

private:
    void addReturnOption( const EString & );
    void addSelectOption( const EString & );

    void list( Mailbox *, const UString & );
    void listChildren( Mailbox *, const UString & );
    void sendListResponse( Mailbox * );

    void reference();

private:
    class ListextData * d;
};


#endif
