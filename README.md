
# TUS in swipl

TUS protocol for resumable file uploads via HTTP in swipl (see:
https://tus.io/)

This package implements both the server handlers and a simple client.

The package implements the core protocol along with two extensions:

* Creation
* Expiration

## Examples

### Server

To use the TUS server with the HTTP library in swipl you can simply
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
file and can be invoked thus:

```prolog
tus_upload(Example, URL, _Resource)
```

The resource gives back a resource handle that the server can use to
manipulate files on the remote end.

## TODO

The remaining extensions would be desirable:

* Checksum
* Concatenation
* Termination

## Copyright

Licensed under the Apache License, Version 2.0 (the "License"); you
may not use this file except in compliance with the License. You may
obtain a copy of the License at

```
http://www.apache.org/licenses/LICENSE-2.0
```

