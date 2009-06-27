// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef EVENTMAP_H
#define EVENTMAP_H

#include "event.h"
#include "list.h"


class Mailbox;


class EventFilterSpec
    : public Garbage
{
public:
    EventFilterSpec();

    enum Type { Selected, SelectedDelayed,
                Inboxes, Personal, Subscribed, Subtree, Mailboxes };
    void setType( Type );
    Type type() const;

    void setMailboxes( List<Mailbox> * );
    List<Mailbox> * mailboxes() const;

    void setNewMessageFetcher( class Fetch * );
    class Fetch * newMessageFetcher() const;

    enum Event { NewMessage, MessageChange,
                 Expunge,
                 FlagChange, AnnotationChange,
                 MailboxName,
                 // Subscription has to be last
                 Subscription };
    void setNotificationWanted( Event, bool );
    bool notificationWanted( Event );

    bool appliesTo( Mailbox * );

private:
    class EventFilterSpecData * d;
};


class EventMap
    : public EventHandler
{
public:
    EventMap();

    EventFilterSpec * applicable( Mailbox *, Mailbox * );

    void add( EventFilterSpec * );

    void execute();

    void refresh( class Transaction *, class User * );

    List<Mailbox> * mailboxes() const;

private:
    class EventMapData * d;
};


#endif
