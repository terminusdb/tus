:- module(tus, [set_tus_options/1,         % +Options
                tus_dispatch/2,             % +Method, +Request
                tus_upload/2                % +Method, +URI
               ]).

/** <module> TUS Protocol

Both client and server implementation of the TUS protocol.

*/

:- use_module(library(http/http_server_files)).
:- use_module(library(http/html_write)).
:- use_module(library(http/http_path)).
:- use_module(library(http/html_head)).
:- use_module(library(http/http_parameters)).
:- use_module(library(http/http_json)).
:- use_module(library(http/http_client)).
:- use_module(library(http/http_header)).

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
    memberchk(tus_max_size(Size), Options),
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
tus_storage_path(Path) :-
    tmp_file('tus_storage', Temp),
    make_directory(Temp),
    assertz(tus_storage_path_dynamic(Path)).

tus_extension_list('creation').

accept_tus_version(Version) :-
    member(Version, ['1.0.0']).

/*
File store manipulation utilities.
*/
tus_resource_name(File, Name) :-
    www_form_encode(File, Name).

tus_resource_path(File, Path) :-
    tus_storage_path(Storage),
    tus_resource_name(File, Name),
    atomic_list_concat([Storage, '/', Name], Path).

tus_offset_file('offset').

tus_offset_path(File, Path) :-
    tus_resource_path(File, RPath),
    tus_offset_file(Offset),
    atomic_list_concat([RPath, '/', Offset], Path).

tus_size_file('size').

tus_size_path(File, Path) :-
    tus_resource_path(File, RPath),
    tus_size_file(Size),
    atomic_list_concat([RPath, '/', Size], Path).

tus_upload_file('file').

tus_upload_path(File, Path) :-
    tus_resource_path(File, RPath),
    tus_upload_file(File),
    atomic_list_concat([RPath, '/', File], Path).

resource_offset(File, Offset) :-
    tus_offset_path(File, Offset_File),
    read_file_to_string(Offset_File, Offset_String, []),
    atom_number(Offset_String, Offset).

set_resource_offset(File, Offset) :-
    setup_call_cleanup(
        (   tus_offset_path(File, Offset_Path),
            open(Offset_Path, write, OP)),
        write(OP, Offset),
        close(OP)).

resource_size(File, Offset) :-
    tus_size_path(File, Offset_File),
    read_file_to_string(Offset_File, Offset_String, []),
    atom_number(Offset_String, Offset).

set_resource_size(File, Size) :-
    setup_call_cleanup(
        (   tus_size_path(File, Size_Path),
            open(Size_Path, write, SP)),
        write(SP, Size),
        close(SP)).

create_file_resource(File, Size, Name) :-
    tus_resource_name(File, Name),
    tus_resource_path(File, Resource),
    make_directory(Resource),
    % Size
    set_resource_size(Resource, Size),

    % Offset
    set_resource_offset(Resource, 0),

    % File
    setup_call_cleanup(
        (   tus_upload_path(Resource,File_Path),
            open(File_Path, write, FP)),
        true, % touch
        close(FP)).

patch_resource(File, Patch, Offset, Length, New_Offset) :-
    % sanity check
    (   string_length(Patch, Length)
    ->  true
    ;   throw(error(bad_length(Length)))),

    (   resource_offset(File, Offset)
    ->  true
    ;   throw(error(bad_offset(Offset)))),

    tus_resource_path(File, Resource),
    tus_upload_path(Resource, File_Path),

    setup_call_cleanup(
        open(File_Path, write, Stream, [lock(exclusive)]),
        (
            seek(Stream, Offset, bof, _),
            format(Stream, "~s", [Patch]),
            New_Offset is Offset + Length,

            set_resource_offset(Resource, New_Offset)
        ),
        close(Stream)
    ).

tus_client_effective_chunk_size(Options, Chunk) :-
    memberchk(tus_max_size(Max), Options),
    tus_client_chunk_size(Size),
    Chunk is min(Max,Size).

chunk_directive_(Length, Chunk_Size, [Length-Length]) :-
    Length =< Chunk_Size,
    !.
chunk_directive_(Length, Chunk_Size, [Chunk_Size-Length|Directive]) :-
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
    format(atom(Endpoint), "~s://~s:~s~s/~s", [Protocol,Server,Port,Base,Name]).

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

tus_dispatch(options,_Request) :-
    % Options
    !,
    format("HTTP/1.1 204 No Content~n", []),
    format("Tus-Resumable: ~s~n", []),
    tus_version_list(Version_List),
    format("Tus-Version: ~s~n", [Version_List]),
    tus_max_size(Max_Size),
    format("Tus-Max-Size: ~s~n", [Max_Size]),
    tus_extension_list(Extension_List),
    format("Tus-Extension: ~s~n~n", [Extension_List]).
tus_dispatch(post,Request) :-
    % Create
    !,
    memberchk(upload_length(Length),Request),
    memberchk(upload_metadata(Metadata),Request),
    memberchk(tus_resumable(Version),Request),
    accept_tus_version(Version),
    parse_upload_metadata(Metadata, Struct),
    Struct = filename(File,_Options), % ignoring options for the minute
    create_file_resource(File, Length, Name),
    resumable_endpoint(Request, Name, Endpoint),
    format("HTTP/1.1 201 Created~n", []),
    format("Location: ~s~n",[Endpoint]),
    format("Tus-Resumable: 1.0.0~n~n", []).
tus_dispatch(head,Request) :-
    % Next stage.
    !,
    memberchk(request_uri(URI), Request),
    uri_resource(URI, Resource),
    resource_offset(Resource, Offset),
    format("HTTP/1.1 200 OK~n", []),
    format("Upload-Offset: ~s~n", [Offset]),
    format("Tus-Resumable: 1.0.0~n~n", []).
tus_dispatch(patch,Request) :-
    % Next stage.
    !,
    memberchk(request_uri(URI),Request),
    memberchk(content_length(Length),Request),
    memberchk(upload_offset(Offset),Request),
    http_read_data(Request, Patch, []),
    uri_resource(URI, Resource),
    patch_resource(Resource, Patch, Offset, Length, New_Offset),
    format("HTTP/1.1 204 No Content~n", []),
    format("Upload-Offset: ~s~n", [New_Offset]),
    format("Tus-Resumable: 1.0.0~n~n", []).

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
                 reply_header(Pre_Options)
             ]),
    tus_process_options(Pre_Options, Options).

tus_create(Endpoint, File, Length, Resource) :-
    size_file(File, Length),
    parse_upload_metadata(filename(File,[]), Metadata),
    http_get(Endpoint, Resource, [
                 method(post),
                 request_header('Content-Length'=0),
                 request_header('Upload-Length'=Length),
                 request_header('Upload-Metdata'=Metadata),
                 request_header('Tus-Resumable'='1.0.0')
             ]).

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

tus_upload(File, Endpoint) :-
    tus_options(Endpoint, Options),
    tus_create(Endpoint, File, Length, Resource),

    tus_client_effective_chunk_size(Options, Chunk_Size),
    chunk_directive(Length, Chunk_Size, Directive),

    maplist({File, Resource}/[Chunk-Position]>>(
                tus_patch(Resource, File, Chunk, Position),
                format(user_error, "Chunk: ~q Position: ~q", [Chunk, Position])
            ),
            Directive).


:- begin_tests(tus).

spawn_server(URL, PID) :-
    random_between(49152, 65535, Port),
    http_server(http_dispatch, [port(Port), workers(1)]),
    http_handler(files, tus_dispatch(Method),
                 [ method(Method),
                   methods([options,get,head,post,patch]),
                   prefix
                 ])
    format(atom(URL), 'http://127.0.0.1:~s/files', [Port]).

kill_server(PID) :-
    process_kill(PID),
    process_wait(PID, _).

test(parse_upload_metadata, [
         setup((spawn_server(URL, PID),
                set_tus_options([tus_client_chunk_size(4)])),
         cleanup(kill_server(PID))
     ]) :-
    tmp_file('example', Example),
    open(Example, write, Stream),
    format(Stream, '~s', ['asdf fdsa yes yes yes']),
    close(Stream),

    tus_upload(Example, URL).

:- end_tests(tus).
