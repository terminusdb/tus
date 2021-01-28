
# TUS in swipl

TUS protocol for resumable file uploads via HTTP in swipl (see:
[TUS](https://tus.io/))

This package implements both the server handlers and a simple client.

The package implements the core protocol along with two extensions:

* Creation
* Expiration
* Checksum

# Options

Options for the server can be set with the `set_tus_options/1`
predicate which has the following options:

* `tus_storage_path(Path)`: The `Path` contains the location of the
storage folder to be used for uploads. If not set it will default to a
temporary directory.
* `tus_max_size(Size)`: The `Size` is the maximum allowable upload
size in bytes. Defaults to `17_179_869_184` bytes.
* `tus_client_chunk_size(Size)`: The `Size` is the size of chunks to
  be uploaded. The default is `16_777_216` bytes.
* `tus_expiry_seconds(Seconds)`: The `Seconds` is the total number of
  seconds before the resource expires. This will allow resources which
  are not fully uploaded to be removed.

For instance, to set a larger client chunk size one can call:

```prolog
:- set_tus_options([tus_client_chunk_size(33_554_432)]).
```

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

### Domains and Authorization in Server

The server does not manage authorization, but it is possible to use
authorization to provide isolation of user data by providing the
`tus_dispatch/2` predicate with options which include
`[domain(Domain)]`.

You can use any authorization system you'd like (basic, JWT etc.) to
guard access to this domain token and the domain token will be used to
ensure isolation.

The following code shows how you might add a handler which carries
with it a domain after authorization. There is a more complete example
in the tests in [prolog/tus.pl](prolog/tus.pl).

```prolog
:- meta_predicate auth_wrapper(2,?).
auth_wrapper(Goal,Request) :-
    authorize(Request, Domain),
    call(Goal, [domain(Domain)], Request).

spawn_auth_server(URL, Port) :-
    random_between(49152, 65535, Port),
    http_server(http_dispatch, [port(Port), workers(1)]),
    http_handler(root(files), auth_wrapper(tus_dispatch),
                 [ methods([options,head,post,patch]),
                   prefix
                 ]),
    format(atom(URL), 'http://127.0.0.1:~d/files', [Port]).
```

### Client

The client invocation requires only the endpoint of interest and a
file and can be invoked thus:

```prolog
tus_upload(Example, URL, Resource)
```

The `Resource` variable gives back a resource handle that the server can use to
refer to the resource in subsequent communication.

## TODO

The remaining extensions would be desirable:

* Creation with Upload
* Concatenation
* Termination

In addition the Creation extension should be checked from the Options
call before initiatiating an upload.

## Copyright

Licensed under the Apache License, Version 2.0 (the "License"); you
may not use this file except in compliance with the License. You may
obtain a copy of the License at

```
http://www.apache.org/licenses/LICENSE-2.0
```

