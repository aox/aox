// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef THREADER_H
#define THREADER_H

#include "event.h"

#include "list.h"


class Mailbox;
class MessageSet;


class Thread
    : public Garbage
{
public:
    Thread();

    MessageSet members() const;
    void add( uint );

    void setSubject( const String & );
    String subject() const;

    uint id() const;
    void setId( uint );

private:
    class ThreadData * d;
};


class Threader
    : public EventHandler
{
public:
    Threader( Mailbox * );

    bool updated() const;
    Mailbox * mailbox() const;

    void refresh( EventHandler * );

    void execute();

private:
    class ThreaderData * d;
};


#endif
