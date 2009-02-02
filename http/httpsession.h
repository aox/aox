// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef HTTPSESSION_H
#define HTTPSESSION_H


class User;
class EString;

#include "global.h"


class HttpSession
    : public Garbage
{
public:
    HttpSession();

    EString key() const;
    User *user() const;
    void setUser( User * );
    void refresh();
    void expireNow();
    bool expired() const;

    static HttpSession *find( const EString & );

private:
    class HttpSessionData *d;
};


#endif
