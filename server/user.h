// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef USER_H
#define USER_H

#include "event.h"

#include "string.h"
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

    uint id() const;

    void setLogin( const String & );
    String login() const;

    void setSecret( const String & );
    String secret() const;

    void setInbox( Mailbox * & );
    Mailbox * inbox() const;

    void setAddress( Address * );
    Address * address();

    Mailbox * home() const;

    bool exists();

    void refresh( EventHandler * );
    Query * create( EventHandler * );
    Query * remove( EventHandler * );
    Query * changeSecret( EventHandler * );

    void execute();

    bool valid();
    String error() const;

private:
    void refreshHelper();
    void createHelper();
    void removeHelper();
    void csHelper();

private:
    class UserData * d;
};


#endif
