// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SELECTOR_H
#define SELECTOR_H

#include "list.h"
#include "query.h"
#include "estring.h"
#include "ustring.h"
#include "session.h"
#include "integerset.h"


class EStringList;


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
        Annotation, Modseq, Age, NoField, MailboxTree
    };

    Selector();

    Selector( Field, Action, uint );
    Selector( Field, Action, const EString & = 0 );
    Selector( Field, Action, const UString & );
    Selector( Field, Action, const EString &, const UString & );
    Selector( Field, Action, const EString &, const EString &,
              const UString & );
    Selector( const IntegerSet & );
    Selector( Action );
    Selector( Mailbox *, bool );

    Field field() const;
    Action action() const;
    const IntegerSet & messageSet() const;

    uint placeHolder();

    const Selector * root() const;
    const Selector * parent() const;

    EString error();
    void setError( const EString & );

    Query * query( class User *, class Mailbox *,
                   class Session *, class EventHandler *,
                   bool = true, class EStringList * = 0, bool = false );

    void simplify();

    void add( Selector * );

    EString debugString() const;
    bool needSession() const;
    enum MatchResult {
        Yes,
        No,
        Punt // really "ThrowHandsUpInAirAndDespair"
    };
    MatchResult match( class Session *, uint );

    EString string();

    static Selector * fromString( const EString & );

    bool dynamic() const;
    bool timeSensitive() const;
    bool usesModseq() const;

    EString stringArgument() const;
    UString ustringArgument() const;
    int integerArgument() const;
    IntegerSet messageSetArgument() const;
    List<Selector> * children();
    Mailbox * mailbox() const;
    bool alsoChildren() const;

    static void setup();

private:
    class SelectorData * d;

    EString where();
    EString whereInternalDate();
    EString whereSent();
    EString whereHeader();
    EString whereHeaderField();
    EString whereAddressField( const EString & = "" );
    EString whereAddressFields( const EStringList &, const UString & );
    EString whereBody();
    EString whereRfc822Size();
    EString whereFlags();
    EString whereUid();
    EString whereAnnotation();
    EString whereModseq();
    EString whereAge();
    EString whereNoField();
    EString whereMailbox();

    EString mm();

    EString whereSet( const IntegerSet & );
};


class RetentionSelector
    : public EventHandler
{
public:
    RetentionSelector( Mailbox *, EventHandler * );
    RetentionSelector( Transaction *, EventHandler * );

    void execute();
    bool done();

    Selector * retains();
    Selector * deletes();

private:
    class RetentionSelectorData * d;
};

#endif
