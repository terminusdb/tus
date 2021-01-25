
# TUS in swipl

TUS protocol for resumable file uploads via HTTP in swipl (see:
https://tus.io/)

This package implements both the server handlers and a simple client.

## Examples

### Server

To use the tus server with the HTTP library in swipl you can simply
add a `tus_dispatch` call to your http_handler from a chosen endpoint
as follows:

```prolog
:- http_handler(root(files), tus_dispatch,
                [ methods([options,head,post,patch]),
                  prefix
                ]).
```

In order to determine the location of a given resource when passed the
resource URL in other contexts you can use the utility predicate
`tus_uri_resource(URI, Resource)` together with
`tus_resource_path(Resource, Resource_Path)`. In this way once a
client has uploaded a resource it can be referred to in client-server
communications, and be moved, modified or manipulated by server code.

### Client

The client invocation requires only the endpoint of interest and a
file and can be envoked thus:

```prolog
tus_upload(Example, URL, _Resource)
```

The resource gives back a resource handle that the server can use to
manipulate files on the remote end.

## TODO

We have not implemented any of the optional parts of the protocol save
for `Create`. In particular we need functionality from `Expires`.

We also have not implemented respect for the `X-HTTP-Method-Override`
header which is a TUS requirement and as such we have not completely
implemented the `Core` according to specfication as yet.

## Copyright

Licensed under the Apache License, Version 2.0 (the "License"); you
may not use this file except in compliance with the License. You may
obtain a copy of the License at

```
http://www.apache.org/licenses/LICENSE-2.0
```

