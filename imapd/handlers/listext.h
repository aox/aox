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
    String listMailbox();
    void addReturnOption( const String & );
    void addSelectOption( const String & );

    void list( Mailbox *, const String & );
    void listChildren( Mailbox *, const String & );
    void sendListResponse( Mailbox *, const String & );

private:
    class ListextData * d;
};


#endif
