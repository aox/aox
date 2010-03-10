// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef USER_H
#define USER_H

#include "event.h"

#include "ustring.h"
#include "estring.h"
#include "list.h"

class Mailbox;
class Address;
class Query;


class User
    : public EventHandler
{
public:
    User();

    enum State { Refreshed, Nonexistent, Unverified };
    State state() const;

    void setId( uint );
    uint id() const;

    void setLogin( const UString & );
    UString login() const;

    void setSecret( const UString & );
    UString secret() const;

    UString ldapdn() const;

    void setInbox( Mailbox * & );
    Mailbox * inbox() const;

    void setAddress( Address * );
    Address * address();

    int64 quota() const;

    Mailbox * home() const;
    Mailbox * mailbox( const UString & ) const;
    UString mailboxName( const UString & ) const;

    bool exists();

    void refresh( EventHandler * );
    Query * create( EventHandler * );
    Query * remove( class Transaction * );
    Query * changeSecret( EventHandler * );

    void execute();

    bool valid();
    EString error() const;

private:
    void refreshHelper();
    void createHelper();
    void csHelper();

private:
    class UserData * d;
};


#endif
