:- module(tus, [set_tus_options/1,         % +Options
                tus_dispatch/2,             % +Request
                tus_dispatch/2,             % +Method, +Request
                tus_upload/2                % +Method, +URI
               ]).

/** <module> TUS Protocol

Both client and server implementation of the TUS protocol.

*/

:- use_module(library(http/http_server_files)).
:- use_module(library(http/http_dispatch)).
:- use_module(library(http/html_write)).
:- use_module(library(http/http_path)).
:- use_module(library(http/html_head)).
:- use_module(library(http/http_parameters)).
:- use_module(library(http/http_json)).
:- use_module(library(http/http_client)).
:- use_module(library(http/http_header)).
:- use_module(library(http/thread_httpd)).

/* parsing tools */
:- use_module(tus_parse).

/* Options */
:- meta_predicate valid_options(+, 1).
valid_options(Options, Pred) :-
    must_be(list, Options),
    verify_options(Options, Pred).

verify_options([], _).
verify_options([H|T], Pred) :-
    (   call(Pred, H)
    ->  verify_options(T, Pred)
    ;   throw(error(domain_error(Pred, H), _))
    ).

set_tus_options(Options) :-
    retract_tus_dynamics,
    valid_options(Options, global_tus_option),
    create_prolog_flag(tus_options, Options, []).

global_tus_option(tus_storage_path(_Path)).
global_tus_option(tus_max_size(Size)) :-
    must_be(positive_integer, Size).
global_tus_option(tus_client_chunk_size(Size)) :-
    must_be(positive_integer, Size).

:- dynamic tus_storage_path_dynamic/1.

retract_tus_dynamics :-
    retractall(tus_storage_path_dynamic(_)).

/* Tus server constants */
tus_version_list('1.0.0').

tus_max_size(Size) :-
    current_prolog_flag(tus_options, Options),
    memberchk(tus_max_size(Size), Options),
    !.
tus_max_size(17_179_869_184).

tus_client_chunk_size(Size) :-
    current_prolog_flag(tus_options, Options),
    memberchk(tus_client_chunk_size(Size), Options),
    !.
tus_client_chunk_size(16_777_216).

tus_extention_list('creation').

tus_storage_path(Path) :-
    tus_storage_path_dynamic(Path),
    !.
tus_storage_path(Path) :-
    current_prolog_flag(tus_options, Options),
    memberchk(tus_storage_path(Path), Options),
    assertz(tus_storage_path_dynamic(Path)),
    !.
tus_storage_path(Temp) :-
    tmp_file('tus_storage', Temp),
    make_directory(Temp),
    assertz(tus_storage_path_dynamic(Temp)).

tus_extension_list('creation').

accept_tus_version(Version) :-
    member(Version, ['1.0.0']).

/*
File store manipulation utilities.
*/
tus_resource_name(File, Name) :-
    md5_hash(File, Name, []).

tus_resource_path(File, Path) :-
    tus_storage_path(Storage),
    atomic_list_concat([Storage, '/', File], Path).

tus_offset_suffix('offset').

tus_offset_path(File, Path) :-
    tus_resource_path(File, RPath),
    tus_offset_suffix(Offset),
    atomic_list_concat([RPath, '.', Offset], Path).

tus_size_suffix('size').

tus_size_path(File, Path) :-
    tus_resource_path(File, RPath),
    tus_size_suffix(Size),
    atomic_list_concat([RPath, '.', Size], Path).

tus_upload_suffix('upload').

tus_upload_path(File, Path) :-
    tus_resource_path(File, RPath),
    tus_upload_suffix(Upload),
    atomic_list_concat([RPath, '.', Upload], Path).

tus_lock_suffix('lock').

tus_lock_path(File, Path) :-
    tus_resource_path(File, RPath),
    tus_lock_suffix(Lock),
    atomic_list_concat([RPath, '.', Lock], Path).

resource_offset(File, Offset) :-
    tus_offset_path(File, Offset_File),
    read_file_to_string(Offset_File, Offset_String, []),
    atom_number(Offset_String, Offset).

set_resource_offset(File, Offset) :-
    setup_call_cleanup(
        (   tus_offset_path(File, Offset_Path),
            open(Offset_Path, write, OP)),
        format(OP, "~d", [Offset]),
        close(OP)
    ).

resource_size(File, Offset) :-
    tus_size_path(File, Offset_File),
    read_file_to_string(Offset_File, Offset_String, []),
    atom_number(Offset_String, Offset).

set_resource_size(File, Size) :-
    setup_call_cleanup(
        (   tus_size_path(File, Size_Path),
            open(Size_Path, write, SP)),
        format(SP, "~d", [Size]),
        close(SP)
    ).

% member(Status, [exists, created])
create_file_resource(File, _, Name, Status) :-
    tus_resource_name(File, Name),
    tus_resource_path(Name, Resource_Path),
    exists_file(Resource_Path),
    !,
    Status=exists.
create_file_resource(File, Size, Name, Status) :-
    tus_resource_name(File, Name),

    % File
    setup_call_cleanup(
        (   tus_lock_path(Name, Lock_Path),
            open(Lock_Path, write, LP, [lock(exclusive)]) % Get an exclusive lock
        ),
        setup_call_cleanup(
            (   tus_upload_path(Name,File_Path),
                open(File_Path, write, FP)
            ),
            (   % Size
                set_resource_size(Name, Size),

                % Offset
                set_resource_offset(Name, 0)
            ),
            close(FP)
        ),
        close(LP)
    ),
    Status=created.

patch_resource(Name, Patch, Offset, Length, New_Offset) :-

    % sanity check
    (   string_length(Patch, Length)
    ->  true
    ;   throw(error(bad_length(Length)))),

    (   resource_offset(Name, Offset)
    ->  true
    ;   throw(error(bad_offset(Offset)))),

    setup_call_cleanup(
        (   tus_lock_path(Name, Lock_Path),
            open(Lock_Path, write, LP, [lock(exclusive)]) % Get an exclusive lock
        ),
        (   setup_call_cleanup(
                (   tus_upload_path(Name, Upload_Path),
                    open(Upload_Path, update, UP)
                ),
                (   seek(UP, Offset, bof, _),
                    format(UP, "~s", [Patch]),
                    New_Offset is Offset + Length,

                    set_resource_offset(Name, New_Offset)
                ),
                close(UP)
            ),
            resource_size(Name, Size),
            (   Size = New_Offset
            ->  tus_resource_path(Name, Resource_Path),
                rename_file(Upload_Path, Resource_Path)
            ;   true
            )
        ),
        close(LP)
    ).


tus_client_effective_chunk_size(Options, Chunk) :-
    memberchk(tus_max_size(Max), Options),
    tus_client_chunk_size(Size),
    Chunk is min(Max,Size).

chunk_directive_(Length, Chunk_Size, [Length-0]) :-
    Length =< Chunk_Size,
    !.
chunk_directive_(Length, Chunk_Size, [Chunk_Size-New_Length|Directive]) :-
    Length > Chunk_Size,
    !,
    New_Length is Length - Chunk_Size,
    chunk_directive_(New_Length, Chunk_Size, Directive).

chunk_directive(Length, Chunk_Size, Directive) :-
    chunk_directive_(Length, Chunk_Size, Reversed),
    reverse(Reversed, Directive).

uri_resource(URI, Resource) :-
    split_string(URI, '/', '', List),
    last(List, Resource).

terminal_slash(Atom, Slashed) :-
    split_string(Atom, '/', '', List),
    last(List, Last),
    (   Last = ""
    ->  Atom = Slashed
    ;   atomic_list_concat([Atom, '/'], Slashed)).

resumable_endpoint(Request, Name, Endpoint) :-
    memberchk(protocol(Protocol),Request),
    memberchk(host(Server),Request),
    memberchk(port(Port),Request),
    memberchk(request_uri(Pre_Base),Request),
    terminal_slash(Pre_Base,Base),
    format(atom(Endpoint), "~s://~s:~d~s~s", [Protocol,Server,Port,Base,Name]).

/*
 Server implementation

 Requests are structured according to the prolog http library format.

 Implemented features of the TUS protocol:

 OPTIONS (Discovery)
 POST (Create)*
 HEAD (Find resumption point)
 PATCH (Send chunk)

 * Suggested

*/

% This is a terrible way to get the output stream...
% something is broken - should be set in current_output
http_output_stream(Request, Out) :-
    memberchk(pool(client(_,_,_,Out)), Request).

tus_dispatch(Request) :-
    memberchk(method(Method),Request),
    tus_dispatch(Method,Request).

tus_dispatch(options,Request) :-
    % Options
    !,
    tus_version_list(Version_List),
    tus_max_size(Max_Size),
    tus_extension_list(Extension_List),
    http_output_stream(Request, Out),
    http_status_reply(no_content, Out,
                      ['Tus-Resumable'('1.0.0'),
                       'Tus-Version'(Version_List),
                       'Tus-Max-Size'(Max_Size),
                       'Tus-Extension'(Extension_List)],
                      204).
tus_dispatch(post,Request) :-
    % Create
    !,
    memberchk(upload_length(Length_Atom),Request),
    atom_number(Length_Atom, Length),

    memberchk(upload_metadata(Metadata),Request),
    parse_upload_metadata(Metadata, Struct),

    memberchk(tus_resumable(Version),Request),
    accept_tus_version(Version),

    Struct = filename(File,_Options), % ignoring options for the minute

    create_file_resource(File, Length, Name, Status),
    resumable_endpoint(Request, Name, Endpoint),
    http_output_stream(Request, Out),

    (   Status = exists
    ->  http_status_reply(conflict, Out,
                          ['Tus-Resumable'('1.0.0'),
                           'Location'(Endpoint)],
                          _Code)
    ;   http_status_reply(created(Endpoint), Out,
                          ['Tus-Resumable'('1.0.0'),
                           'Location'(Endpoint)],
                          _Code)).
tus_dispatch(head,Request) :-
    % Next stage.
    !,
    memberchk(request_uri(URI), Request),
    uri_resource(URI, Resource),
    resource_offset(Resource, Offset),
    http_output_stream(Request, Out),
    http_status_reply(ok, Out,
                      ['Tus-Resumable'('1.0.0'),
                       'Upload-Offset'(Offset),
                       'Cache-Control'('no-store')],
                      _Code).
tus_dispatch(patch,Request) :-
    % Next stage.
    !,
    memberchk(request_uri(URI),Request),
    memberchk(content_length(Length),Request),

    memberchk(upload_offset(Offset_Atom),Request),
    atom_number(Offset_Atom, Offset),

    http_read_data(Request, Patch, []),
    uri_resource(URI, Resource),
    patch_resource(Resource, Patch, Offset, Length, New_Offset),
    http_output_stream(Request, Out),
    http_status_reply(no_content, Out,
                      ['Tus-Resumable'('1.0.0'),
                       'Upload-Offset'(New_Offset)],
                      _Code).

/*
 Client implementation

[date('Sat, 23 Jan 2021 22:04:41 GMT'),connection(close),content_type('application/json; charset=UTF-8'),content_length(65)]
*/

tus_process_options([], []).
tus_process_options([tus_extention(X)|Rest_In],[tus_extention(Y)|Rest_Out]) :-
    !,
    split_string(X, ',', '', List),
    maplist(atom_string, Y, List),
    tus_process_options(Rest_In, Rest_Out).
tus_process_options([tus_max_size(X)|Rest_In],[tus_max_size(Y)|Rest_Out]) :-
    !,
    atom_number(X,Y),
    tus_process_options(Rest_In, Rest_Out).
tus_process_options([X|Rest_In],[X|Rest_Out]) :-
    tus_process_options(Rest_In, Rest_Out).

tus_options(Endpoint, Options) :-
    http_get(Endpoint, _, [
                 method(options),
                 reply_header(Pre_Options),
                 status_code(204)
             ]),
    tus_process_options(Pre_Options, Options).

tus_create(Endpoint, File, Length, Resource) :-
    size_file(File, Length),
    parse_upload_metadata(Metadata,filename(File,[])),
    http_get(Endpoint, _, [
                 method(post),
                 request_header('Upload-Length'=Length),
                 request_header('Upload-Metadata'=Metadata),
                 request_header('Tus-Resumable'='1.0.0'),
                 reply_header(Reply_Header),
                 status_code(Status)
             ]),
    (   Status = 409
    ->  throw(error(file_already_exists(File), _))
    ;   memberchk(location(Resource), Reply_Header)).

tus_patch(Endpoint, File, Chunk, Position) :-
    setup_call_cleanup(
        (   open(File, read, Stream),
            seek(Stream, Position, bof, _),
            read_string(Stream, Chunk, String)
        ),
        http_get(Endpoint, _, [
                     method(patch),
                     post(bytes('application/offset+octet-stream', String)),
                     request_header('Content-Length'=Chunk),
                     request_header('Upload-Offset'=Position),
                     request_header('Tus-Resumable'='1.0.0'),
                     status_code(204)
                 ]),
        close(Stream)
    ).

tus_upload(File, Endpoint, Resource) :-
    tus_options(Endpoint, Options),
    tus_create(Endpoint, File, Length, Resource),

    tus_client_effective_chunk_size(Options, Chunk_Size),
    chunk_directive(Length, Chunk_Size, Directive),

    maplist({File, Resource}/[Chunk-Position]>>(
                format(user_error, "Chunk: ~q Position: ~q~n", [Chunk, Position]),
                tus_patch(Resource, File, Chunk, Position)
            ),
            Directive).


:- begin_tests(tus).

spawn_server(URL, Port) :-
    random_between(49152, 65535, Port),
    http_server(http_dispatch, [port(Port), workers(1)]),
    http_handler(root(files), tus_dispatch,
                 [ methods([options,head,post,patch]),
                   prefix
                 ]),
    format(atom(URL), 'http://127.0.0.1:~d/files', [Port]).

kill_server(Port) :-
    http_stop_server(Port,[]).

test(parse_upload_metadata, [
         setup((spawn_server(URL, Port),
                set_tus_options([tus_client_chunk_size(4)]))),
         cleanup(kill_server(Port))
     ]) :-

    File = 'example.txt',
    tmp_file(File, Example),
    open(Example, write, Stream),
    Content = "asdf fdsa yes yes yes",
    format(Stream, '~s', [Content]),
    close(Stream),

    tus_upload(Example, URL, _Resource),

    tus_resource_name(Example, Name),
    tus_resource_path(Name, Resource),
    read_file_to_string(Resource, Result, []),
    writeq(Result), nl,
    Result = Content.

:- end_tests(tus).
