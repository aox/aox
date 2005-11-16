// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SELECTOR_H
#define SELECTOR_H

#include "list.h"
#include "query.h"
#include "string.h"
#include "ustring.h"
#include "session.h"
#include "messageset.h"


class Selector
    : public Garbage
{
public:
    enum Action {
        OnDate, SinceDate, BeforeDate, Contains, Larger, Smaller,
        And, Or, Not, All, None
    };

    enum Field {
        InternalDate, Sent, Header, Body, Rfc822Size, Flags, Uid,
        Annotation, NoField
    };

    Selector();

    Selector( Field, Action, uint );
    Selector( Field, Action, const String & = 0 );
    Selector( Field, Action, const UString & );
    Selector( Field, Action, const String &, const UString & );
    Selector( Field, Action, const String &, const String &,
              const UString & );
    Selector( const MessageSet & );
    Selector( Action );

    Selector & operator =( const Selector & );

    uint placeHolder();

    const Selector * root() const;
    const Selector * parent() const;

    Session * session() const;

    String error();
    void setError( const String & );

    Query * query( class User *, class Session *, class EventHandler * );

    void simplify();

    void add( Selector * );

    String debugString() const;
    bool needSession() const;
    enum MatchResult {
        Yes,
        No,
        Punt // really "ThrowHandsUpInAirAndDespair"
    };
    MatchResult match( class Message *, uint );

private:
    class SelectorData * d;

    String where();
    String whereInternalDate();
    String whereSent();
    String whereHeader();
    String whereHeaderField();
    String whereAddressField( const String & = "" );
    String whereBody();
    String whereRfc822Size();
    String whereFlags();
    String whereUid();
    String whereAnnotation();
    String whereNoField();
    String mboxId();
};


#endif
