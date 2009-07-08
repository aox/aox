// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef THREADER_H
#define THREADER_H

#include "event.h"

#include "list.h"


class UString;
class Mailbox;
class IntegerSet;


class SubjectThread
    : public Garbage
{
public:
    SubjectThread();

    IntegerSet members() const;
    void add( uint );

    void setSubject( const UString & );
    UString subject() const;

    uint id() const;
    void setId( uint );

private:
    class SubjectThreadData * d;
};


class Threader
    : public EventHandler
{
public:
    Threader( const Mailbox * );

    bool updated( bool = false ) const;
    const Mailbox * mailbox() const;

    void refresh( EventHandler * );

    void execute();

    List<SubjectThread> * subjectThreads() const;

private:
    class ThreaderData * d;
};


#endif
