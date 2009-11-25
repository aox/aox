// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef NOTIFY_H
#define NOTIFY_H

#include "list.h"
#include "command.h"


class Event;
class Mailbox;


class Notify
    : public Command
{
public:
    Notify();

    void parse();
    void execute();

private:
    class NotifyData * d;

private:
    void parseEventGroup();
    void parseEvent( class EventFilterSpec * );
    List<Mailbox> * parseMailboxes();
};


#endif
