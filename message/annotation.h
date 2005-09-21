// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ANNOTATION_H
#define ANNOTATION_H

#include "global.h"
#include "list.h"
#include "event.h"
#include "stringlist.h"


class Annotation
    : public Garbage
{
public:
    Annotation( const String &, uint );

    String name() const;
    uint id() const;

    static Annotation * find( const String & );
    static Annotation * find( uint );

    static void setup();

private:
    class AnnotationData * d;
    friend class AnnotationFetcher;
};


class AnnotationFetcher : public EventHandler
{
public:
    AnnotationFetcher( EventHandler * owner );

    void execute();

private:
    class AnnotationFetcherData * d;
    friend class Annotation;
};


class AnnotationCreator : public EventHandler
{
public:
    AnnotationCreator( EventHandler *, const StringList & );

    void execute();

private:
    class AnnotationCreatorData * d;
    friend class Annotation;
};

#endif
