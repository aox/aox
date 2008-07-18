// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SELECTOR_H
#define SELECTOR_H

#include "list.h"
#include "query.h"
#include "string.h"
#include "ustring.h"
#include "session.h"
#include "messageset.h"


class StringList;


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
        Annotation, Modseq, Age, NoField
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

    Field field() const;
    Action action() const;
    const MessageSet & messageSet() const;

    uint placeHolder();

    const Selector * root() const;
    const Selector * parent() const;

    String error();
    void setError( const String & );

    Query * query( class User *, class Mailbox *,
                   class Session *, class EventHandler *,
                   bool = true, class StringList * = 0, bool = false );

    void simplify();

    void add( Selector * );

    String debugString() const;
    bool needSession() const;
    enum MatchResult {
        Yes,
        No,
        Punt // really "ThrowHandsUpInAirAndDespair"
    };
    MatchResult match( class Session *, uint );

    String string();

    static Selector * fromString( const String & );

    bool dynamic() const;
    bool timeSensitive() const;
    bool usesModseq() const;

    String mboxId();

    String stringArgument() const;
    UString ustringArgument() const;
    int integerArgument() const;
    MessageSet messageSetArgument() const;
    List<Selector> * children();

private:
    class SelectorData * d;

    String where();
    String whereInternalDate();
    String whereSent();
    String whereHeader();
    String whereHeaderField();
    String whereAddressField( const String & = "" );
    String whereAddressFields( const StringList &, const UString & );
    String whereBody();
    String whereRfc822Size();
    String whereFlags();
    String whereUid();
    String whereAnnotation();
    String whereModseq();
    String whereAge();
    String whereNoField();

    String mm();

    String whereSet( const MessageSet & );
};


#endif
