// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LIST_H
#define LIST_H

#include "global.h"
#include "string.h"


template< class T >
class List
    : public Garbage
{
public:
    List() { head = tail = 0; }
    ~List() {}


    class Node {
    public:
        Node( T *d ) {
            prev = next = 0;
            data = d;
        }

        Node *prev, *next;
        T *data;
    };


    bool isEmpty() const
    {
        return head == 0;
    }

    uint count() const
    {
        uint n = 0;
        Node *cur = head;

        while ( cur ) {
            cur = cur->next;
            n++;
        }

        return n;
    }

    void clear()
    {
        Node *cur = head;
        while ( cur ) {
            Node *n = cur->next;
            delete cur;
            cur = n;
        }
        head = tail = 0;
    }


    class Iterator {
    public:
        Iterator()                   { cur = 0; }
        Iterator( Node *n )          { cur = n; }
        Iterator( const List< T > *l ) {
            cur = l->head;
        }
        Iterator( const List< T > &l ) {
            cur = l.head;
        }

        Node *node() const           { return cur; }
        operator bool()              { return cur != 0; }
        operator T *()               { return cur ? cur->data : 0; }
        T *operator ->()             { ok(); return cur->data; }
        Iterator &operator ++()      { ok(); return next(); }
        Iterator &operator --()      { ok(); return prev(); }
        Iterator &operator ++( int ) {
            ok();
            Node *p = cur; cur = cur->next;
            return newRef(p);
        }

        Iterator &operator --( int ) {
            ok();
            Node *p = cur; cur = cur->prev;
            return newRef(p);
        }


        T &operator *() {
            ok();
            if ( !cur->data )
                die( Range );
            return *(cur->data);
        }

        bool operator ==( const Iterator &x ) { return cur == x.cur; }
        bool operator !=( const Iterator &x ) { return cur != x.cur; }

        static Iterator &newRef( Node *n ) {
            return *( new Iterator(n) );
        }

    private:
        Iterator &next() { cur = cur->next; return *this; }
        Iterator &prev() { cur = cur->prev; return *this; }

        void ok() {
            if ( !cur )
                die( Range );
        }

        Node *cur;
    };


    T *firstElement() const {
        if ( head )
            return head->data;
        return 0;
    }


    Iterator &first() const { return Iterator::newRef( head ); }
    Iterator &last()  const { return Iterator::newRef( tail ); }
    Iterator &end()   const { return Iterator::newRef( 0 );    }


    T *take( Iterator &i )
    {
        Node *cur = i.node();

        if ( !cur )
            return 0;
        if ( cur->next )
            cur->next->prev = cur->prev;
        if ( cur->prev )
            cur->prev->next = cur->next;

        if ( cur == head )
            head = cur->next;
        if ( cur == tail )
            tail = cur->prev;

        ++i;

        T *d = cur->data;
        delete cur;
        return d;
    }


    T *pop()
    {
        return take( last() );
    }

    T *shift()
    {
        Node *cur = head;

        if ( !cur )
            return 0;
        if ( cur->next )
            cur->next->prev = 0;
        head = cur->next;
        if ( cur == tail )
            tail = 0;
        return cur->data;
    }


    void insert( const Iterator &i, T *d )
    {
        Node *n = new Node( d );
        Node *cur = i.node();

        if ( !cur ) {
            append( d );
        }
        else if ( head == cur ) {
            prepend( d );
        }
        else {
            n->next = cur;
            n->prev = cur->prev;
            cur->prev->next = n;
            cur->prev = n;
        }
    }

    void append( T *d )
    {
        Node *n = new Node( d );

        if ( !head && !tail ) {
            head = tail = n;
        }
        else {
            tail->next = n;
            n->prev = tail;
            tail = n;
        }
    }

    void prepend( T *d )
    {
        Node *n = new Node( d );

        if ( !head && !tail ) {
            head = tail = n;
        }
        else {
            head->prev = n;
            n->next = head;
            head = n;
        }
    }


    Iterator &find( const T *d )
    {
        Node *cur = head;

        while ( cur && cur->data != d )
            cur = cur->next;
        return Iterator::newRef( cur );
    }

    Iterator &find( const String &s )
    {
        Node *cur = head;

        while ( cur && *cur->data != s )
            cur = cur->next;
        return Iterator::newRef( cur );
    }

    T *remove( const T *d )
    {
        Node *cur = head;

        while ( cur && cur->data != d )
            cur = cur->next;
        if ( cur ) {
            if ( cur->next )
                cur->next->prev = cur->prev;
            if ( cur->prev )
                cur->prev->next = cur->next;

            if ( cur == head )
                head = cur->next;
            if ( cur == tail )
                tail = cur->prev;

            return cur->data;
        }

        return 0;
    }

private:
    Node *head, *tail;

    friend class List< T >::Iterator;

    // Some operators are disabled because of unpredictable behaviour.
    // (Deep copy? Does order matter for equality?)
    List< T > &operator =( const List< T > & ) { return *this; }
    bool operator ==( const List< T > & ) const { return false; }
    bool operator !=( const List< T > & ) const { return false; }
};


template< class T >
class SortedList
    : public List< T >
{
public:
    typedef typename List< T >::Iterator Iterator;

    void insert( T *d )
    {
        Iterator it( List< T >::first() );
        while ( it && *it <= *d )
            ++it;

        List< T >::insert( it, d );
    }
};

#endif
