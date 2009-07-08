// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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

    void makeResponse( class Row * );

    void reference();

private:
    class ListextData * d;
};


#endif
