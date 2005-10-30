// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ANNOTATION_H
#define ANNOTATION_H

#include "global.h"
#include "list.h"
#include "event.h"
#include "stringlist.h"


class AnnotationName
    : public Garbage
{
public:
    AnnotationName( const String & );
    AnnotationName( const String &, uint );

    String name() const;
    uint id() const;

    static AnnotationName * find( const String & );
    static AnnotationName * find( uint );

    static void setup();

    static uint largestId();

private:
    class AnnotationNameData * d;
    friend class AnnotationNameFetcher;
};


class AnnotationNameFetcher
    : public EventHandler
{
public:
    AnnotationNameFetcher( EventHandler * owner );

    void execute();

private:
    class AnnotationNameFetcherData * d;
    friend class AnnotationName;
};


class AnnotationNameCreator
    : public EventHandler
{
public:
    AnnotationNameCreator( EventHandler *, const StringList & );

    void execute();

private:
    class AnnotationNameCreatorData * d;
    friend class AnnotationName;
};


class Annotation
    : public Garbage
{
public:
    Annotation();

    void setValue( const String & );
    String value() const;
    void setType( const String & );
    String type() const;
    void setLanguage( const String & );
    String language() const;
    void setDisplayName( const String & );
    String displayName() const;
    void setEntryName( AnnotationName * );
    AnnotationName * entryName() const;
    void setOwnerId( uint );
    uint ownerId() const;

private:
    class AnnotationData * d;
};


#endif
