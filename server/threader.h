// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef THREADER_H
#define THREADER_H

#include "event.h"


class Mailbox;


class Threader
    : public EventHandler
{
public:
    Threader( Mailbox *, EventHandler * );

    void execute();
    
private:
    class ThreaderData * d;
};


class Thread
    : public Garbage
{
public:
    Thread();

    class ThreadMember * member( uint ) const;
    uint count() const;

    uint id() const;
    void setId( uint );

private:
    class ThreadData * d;
};


class ThreadMember
    : public Garbage
{
public:
    ThreadMember( Mailbox *, uid *, const UString &, List<Address> * );

    uint uid() const;
    Mailbox * mailbox() const;
    List<Address> * from() const;
    UString subject() const;

private:
    class ThreadMemberData * d;
};


#endif
