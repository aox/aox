#ifndef _FETCH_H_
#define _FETCH_H_

/* This represents a FETCH query as sent by the client. */
struct fetch_request {
    int seen;
    int uid, flags, internaldate, body, bodystructure, envelope;
    int rfc822_size, rfc822_header, rfc822_text;

    struct body_item {
        char *section;
        enum {
            FETCH_NONE,
            FETCH_TEXT,
            FETCH_MIME,
            FETCH_HEADER,
            FETCH_FIELDS,
            FETCH_FIELDS_NOT
        } type;
        char **fields;
        int range, start, length;
    } *items;
    int n;
};

/* This represents the same query as sent to the database. */
struct fetch_select {
    char **queries;

    struct select_item {
        enum {
            UID,
            SEEN, DRAFT, RECENT, DELETED, FLAGGED, ANSWERED,
            INTERNALDATE,
            CONTENT_TYPE
        } type;
        int query;
        int field;
        int column;
        char *section;
        struct select_item *next;
    } *items;
    int n;
};

/* Parse a list of FETCH attributes. */
struct fetch_request *parse_fetch_attributes(char *s);

/* Convert a struct fetch_request into an SQL query. */
struct fetch_select *build_fetch_select(struct fetch_request *req);

#endif
