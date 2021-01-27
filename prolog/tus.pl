:- module(tus, [set_tus_options/1,          % +Options
                tus_dispatch/1,             % +Request
                tus_dispatch/2,             % +Options, +Request
                tus_dispatch/3,             % +Method, +Options, +Request
                tus_upload/3,               % +File, +Endpoint_URI, +Resource_URI
                tus_upload/4,               % +File, +Endpoint_URI, +Resource_URI,
                                            % +Options
                tus_resume/3,               % +File, +Endpoint_URI, +Resource_URI
                tus_resume/4,               % +File, +Endpoint_URI, +Resource_URI,
                                            % +Options
                tus_uri_resource/2,         % +URI, -Resource
                tus_resource_path/3         % +Resource, -Path, +Options
               ]).

/** <module> TUS Protocol

 Both client and server implementation of the TUS protocol.

 The TUS protocol allows resumable file uploads via HTTP in swipl
 [https://tus.io/](https://tus.io/)

 Server implementation

 Requests are structured according to the prolog http library format.

 Implemented features of the TUS protocol:

 OPTIONS (Discovery)
 POST (Create)*
 HEAD (Find resumption point)
 PATCH (Send chunk)

 * Suggested

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
:- use_module(tus/parse).
:- use_module(tus/utilities).

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

/**
 * set_tus_options(+Options) is det.
 *
 * Sets the global options for the tus server and client.
 *
 * @arg Options Includes the following options:
 * * tus_storage_path(Path): Location of server storage folder.
 * * tus_max_size(Size): Maximum chunk size accepted by the server.
 * * tus_client_chunk_size(Size)): Size of chunks to be sent to the server.
 * * tus_expiry(Expires): Expires after `Expires` seconds.
 */
set_tus_options(Options) :-
    retract_tus_dynamics,
    valid_options(Options, global_tus_option),
    create_prolog_flag(tus_options, Options, []).

global_tus_option(tus_storage_path(_Path)).
global_tus_option(tus_max_size(Size)) :-
    must_be(positive_integer, Size).
global_tus_option(tus_client_chunk_size(Size)) :-
    must_be(positive_integer, Size).
global_tus_option(tus_expiry_seconds(Seconds)) :-
    must_be(positive_integer, Seconds).

tus_default_options(
    [
        tus_max_size(17_179_869_184),
        tus_client_chunk_size(16_777_216),
        tus_expiry_seconds(86400),
        tus_storage_path(_Dummy)
    ]
).

tus_merged_options(Options) :-
    tus_default_options(Defaults),
    (   current_prolog_flag(tus_options, User)
    ->  true
    ;   User = []),
    merge_options(User, Defaults, Options).

get_tus_option(Option) :-
    tus_merged_options(Options),
    option(Option, Options).

:- dynamic tus_storage_path_dynamic/1.

retract_tus_dynamics :-
    retractall(tus_storage_path_dynamic(_)).

/* Tus server constants */
tus_version_list('1.0.0').

tus_max_size(Size) :-
    get_tus_option(tus_max_size(Size)).

tus_client_chunk_size(Size) :-
    get_tus_option(tus_client_chunk_size(Size)).

tus_expiry_seconds(Seconds) :-
    get_tus_option(tus_expiry_seconds(Seconds)).

tus_extension(creation).
tus_extension(expiration).

tus_extension_list(Atom) :-
    findall(Extension,
            tus_extension(Extension),
            Extensions),
    comma_list(Atom, Extensions).

tus_storage_path(Path) :-
    tus_storage_path_dynamic(Path),
    !.
tus_storage_path(Path) :-
    current_prolog_flag(tus_options, Options),
    memberchk(tus_storage_path(Pre_Path), Options),
    terminal_slash(Pre_Path, Path),
    assertz(tus_storage_path_dynamic(Path)),
    !.
tus_storage_path(Temp) :-
    tmp_file('tus_storage', Temp_File),
    make_directory(Temp_File),
    terminal_slash(Temp_File,Temp),
    assertz(tus_storage_path_dynamic(Temp)).

accept_tus_version(Version) :-
    member(Version, ['1.0.0']).

expiration_timestamp(Expiry) :-
    get_time(Time),
    tus_expiry_seconds(Seconds),
    Expiry is Time + Seconds.

/*
File store manipulation utilities.
*/
tus_resource_name(File, Name) :-
    md5_hash(File, Name, []).

/**
 * tus_resource_path(+Resource, -Path, +Options) is det.
 *
 * (Server) Return a fully qualified path for the
 * given resource (assuming fully uploaded).
 *
 * @arg Resource The resource which is referenced
 * @arg Path The file path location of the associated resource
 * @arg Options A list which includes:
 *  * `domain(Domain)`: The domain in which to store the file (to avoid collisions)
 *
 */
tus_resource_path(Resource, Path, Options) :-
    tus_storage_path(Storage),
    option(domain(Domain),Options,'xanadu'),
    atomic_list_concat([Storage, Domain, '.', Resource], Path).

tus_offset_suffix('offset').

tus_offset_path(Resource, Path, Options) :-
    tus_resource_path(Resource, RPath, Options),
    tus_offset_suffix(Offset),
    atomic_list_concat([RPath, '.', Offset], Path).

tus_size_suffix('size').

tus_size_path(Resource, Path, Options) :-
    tus_resource_path(Resource, RPath, Options),
    tus_size_suffix(Size),
    atomic_list_concat([RPath, '.', Size], Path).

tus_upload_suffix('upload').

tus_upload_path(Resource, Path, Options) :-
    tus_resource_path(Resource, RPath, Options),
    tus_upload_suffix(Upload),
    atomic_list_concat([RPath, '.', Upload], Path).

tus_lock_suffix('lock').

tus_lock_path(Resource, Path, Options) :-
    tus_resource_path(Resource, RPath, Options),
    tus_lock_suffix(Lock),
    atomic_list_concat([RPath, '.', Lock], Path).

tus_expiry_suffix('expiry').

tus_expiry_path(Resource, Path, Options) :-
    tus_resource_path(Resource, RPath, Options),
    tus_expiry_suffix(Offset),
    atomic_list_concat([RPath, '.', Offset], Path).

:- meta_predicate fail_on_missing_file(0).
fail_on_missing_file(Goal) :-
    catch(
        call(Goal),
        error(existence_error(source_sink,_),_),
        fail).

path_contents(Offset_File, Offset_String) :-
    fail_on_missing_file(
        read_file_to_string(Offset_File, Offset_String, [])
    ).

resource_offset(Resource, Offset, Options) :-
    tus_offset_path(Resource, Offset_File, Options),
    path_contents(Offset_File, Offset_String),
    atom_number(Offset_String, Offset).

set_resource_offset(Resource, Offset, Options) :-
    setup_call_cleanup(
        (   tus_offset_path(Resource, Offset_Path, Options),
            open(Offset_Path, write, OP)),
        format(OP, "~d", [Offset]),
        close(OP)
    ).

resource_size(Resource, Size, Options) :-
    tus_size_path(Resource, Size_File, Options),
    path_contents(Size_File, Size_String),
    atom_number(Size_String, Size).

set_resource_size(Resource, Size, Options) :-
    setup_call_cleanup(
        (   tus_size_path(Resource, Size_Path, Options),
            open(Size_Path, write, SP)),
        format(SP, "~d", [Size]),
        close(SP)
    ).

resource_expiry(Resource, Expiry, Options) :-
    tus_expiry_path(Resource, Expiry_File, Options),
    path_contents(Expiry_File, Expiry_String),
    atom_number(Expiry_String, Expiry).

set_resource_expiry(Resource, Size, Options) :-
    setup_call_cleanup(
        (   tus_expiry_path(Resource, Size_Path, Options),
            open(Size_Path, write, SP)),
        format(SP, "~q", [Size]),
        close(SP)
    ).

% member(Status, [exists, expires(Expiry)])
create_file_resource(File, _, Name, Status, Options) :-
    tus_resource_name(File, Name),
    tus_resource_path(Name, Resource_Path, Options),
    exists_file(Resource_Path),
    !,
    Status=exists.
create_file_resource(File, Size, Name, Status, Options) :-
    tus_resource_name(File, Name),

    % File
    setup_call_cleanup(
        (   tus_lock_path(Name, Lock_Path, Options),
            open(Lock_Path, write, LP, [lock(exclusive)]) % Get an exclusive lock
        ),
        setup_call_cleanup(
            (   tus_upload_path(Name,File_Path, Options),
                open(File_Path, write, FP)
            ),
            (   % Size
                set_resource_size(Name, Size, Options),

                % Offset
                set_resource_offset(Name, 0, Options),

                % Expires
                expiration_timestamp(Expiry),
                set_resource_expiry(Name, Expiry, Options)
            ),
            close(FP)
        ),
        close(LP)
    ),
    Status=expires(Expiry).

patch_resource(Name, Patch, Offset, Length, New_Offset, Options) :-

    % sanity check
    (   string_length(Patch, Length)
    ->  true
    ;   throw(error(bad_length(Length)))),

    (   resource_offset(Name, Offset, Options)
    ->  true
    ;   throw(error(bad_offset(Offset)))),

    setup_call_cleanup(
        (   tus_lock_path(Name, Lock_Path, Options),
            open(Lock_Path, write, LP, [lock(exclusive)]) % Get an exclusive lock
        ),
        (   setup_call_cleanup(
                (   tus_upload_path(Name, Upload_Path, Options),
                    open(Upload_Path, update, UP, [encoding(octet)])
                ),
                (   seek(UP, Offset, bof, _),
                    format(UP, "~s", [Patch]),
                    New_Offset is Offset + Length,

                    set_resource_offset(Name, New_Offset, Options)
                ),
                close(UP)
            ),
            resource_size(Name, Size, Options),
            (   Size = New_Offset
            ->  tus_resource_path(Name, Resource_Path, Options),
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

chunk_directive(Offset, Length, Chunk_Size, Directive) :-
    Remaining is Length - Offset,
    chunk_directive(Remaining, Chunk_Size, Remaining_Directive),
    maplist({Offset}/[C-P1,C-P2]>>(P2 is P1 + Offset),
            Remaining_Directive, Directive).

/**
 * tus_uri_resource(+Uri, -Resource) is det.
 *
 * Return a resource descriptor from the given URI endpoint
 */
tus_uri_resource(URI, Resource) :-
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

% This is a terrible way to get the output stream...
% something is broken - should be set in current_output
http_output_stream(Request, Out) :-
    memberchk(pool(client(_,_,_,Out)), Request).

tus_dispatch(Request) :-
    tus_dispatch([],Request).

/**
 * tus_dispatch(+Options, +Request) is semidet.
 *
 * Dispatchs various TUS requests to the apropriate handlers.
 *
 * Should be callable from `http_handler/3` with something along the lines of:
 *
 * ``` http_handler(root(files), tus_dispatch,
                [ methods([options,head,post,patch]),
                  prefix
                ])
   ```
 *
 * @arg Options A list with the following flags:
 * * domain(Domain): An organisation/domain/user in which to isolate the file
 *                   uploads. This can be used together with authentication.
 *                   (see tests or README.md)
 * @arg Request is the standard Request object from the http_server
 */
tus_dispatch(Options,Request) :-
    (   memberchk('X-HTTP-Method-Override'(Method), Request)
    ->  true
    ;   memberchk(method(Method),Request)),
    tus_dispatch(Method,Options,Request).

/**
 * tus_dispatch(+Mode, +Request) is semidet.
 *
 * Version of `tus_dispatch/1` which includes explicit mode.
 * The `tus_dispatch/0` version is to be preferred for proper
 * handling of 'X-HTTP-Method_Override'.
 *
 * @arg Mode One of: options, head, post, patch
 * @arg Request is the standard Request object from the http_server
 *
 */
tus_dispatch(options,_Options,Request) :-
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
tus_dispatch(post,Options,Request) :-
    % Create
    !,
    memberchk(upload_length(Length_Atom),Request),
    atom_number(Length_Atom, Length),

    memberchk(upload_metadata(Metadata),Request),
    parse_upload_metadata(Metadata, Struct),

    memberchk(tus_resumable(Version),Request),
    accept_tus_version(Version),

    Struct = filename(File,_Options), % ignoring options for the minute

    create_file_resource(File, Length, Name, Status, Options),
    resumable_endpoint(Request, Name, Endpoint),
    http_output_stream(Request, Out),

    (   Status = exists
    ->  http_status_reply(conflict, Out,
                          ['Tus-Resumable'('1.0.0'),
                           'Location'(Endpoint)],
                          _Code)
    ;   Status = expires(Expiry),
        http_timestamp(Expiry, Expiry_Date),
        http_status_reply(created(Endpoint), Out,
                          ['Tus-Resumable'('1.0.0'),
                           'Upload-Expires'(Expiry_Date),
                           'Location'(Endpoint)],
                          _Code)).
tus_dispatch(head,Options,Request) :-
    % Next stage.
    !,
    memberchk(request_uri(URI), Request),
    tus_uri_resource(URI, Resource),
    http_output_stream(Request, Out),

    (   resource_offset(Resource, Offset, Options),
        resource_size(Resource, Size, Options)
    ->  http_reply(bytes('application/offset+octet-stream',""), Out,
                   ['Tus-Resumable'('1.0.0'),
                    'Upload-Offset'(Offset),
                    'Upload-Length'(Size),
                    'Cache-Control'('no-store')])
    ;   http_status_reply(not_found(URI), Out,
                          ['Tus-Resumable'('1.0.0')],
                          _Code)
    ).
tus_dispatch(patch,Options,Request) :-
    % Next stage.
    !,
    memberchk(request_uri(URI),Request),
    memberchk(content_length(Length),Request),

    memberchk(upload_offset(Offset_Atom),Request),
    atom_number(Offset_Atom, Offset),

    http_read_data(Request, Patch, []),
    tus_uri_resource(URI, Resource),

    http_output_stream(Request, Out),

    (   resource_expiry(Resource, Expiry, Options)
    ->  http_timestamp(Expiry, Expiry_Date),
        (   get_time(Time),
            debug(tus, "Time: ~q Expiry: ~q~n", [Time, Expiry]),
            Time > Expiry
        ->  http_status_reply(not_found(URI), Out,
                              % This should be `gone`, not `not_found`
                              ['Tus-Resumable'('1.0.0'),
                               'Upload-Expires'(Expiry_Date)],
                              _Code)
        ;   patch_resource(Resource, Patch, Offset, Length, New_Offset, Options),
            http_status_reply(no_content, Out,
                              ['Tus-Resumable'('1.0.0'),
                               'Upload-Expires'(Expiry_Date),
                               'Upload-Offset'(New_Offset)],
                              _Code))
    ;   http_status_reply(not_found(URI), Out,
                          ['Tus-Resumable'('1.0.0')],
                          _Code)
    ).

/*
 Client implementation

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

tus_options(Endpoint, Tus_Options, Options) :-
    http_get(Endpoint, _, [
                 method(options),
                 reply_header(Pre_Options),
                 status_code(204)
                 |Options
             ]),
    tus_process_options(Pre_Options, Tus_Options).

tus_create(Endpoint, File, Length, Resource, Options) :-
    tus_create(Endpoint, File, Length, Resource, _, Options).

tus_create(Endpoint, File, Length, Resource, Reply_Header, Options) :-
    size_file(File, Length),
    parse_upload_metadata(Metadata,filename(File,[])),
    http_get(Endpoint, _, [
                 method(post),
                 request_header('Upload-Length'=Length),
                 request_header('Upload-Metadata'=Metadata),
                 request_header('Tus-Resumable'='1.0.0'),
                 reply_header(Reply_Header),
                 status_code(Status)
                 |Options
             ]),
    (   Status = 409
    ->  throw(error(file_already_exists(File), _))
    ;   memberchk(location(Resource), Reply_Header)).

tus_patch(Endpoint, File, Chunk, Position, Options) :-
    tus_patch(Endpoint, File, Chunk, Position, _Reply_Header, Options).

tus_patch(Endpoint, File, Chunk, Position, Reply_Header, Options) :-
    setup_call_cleanup(
        open(File, read, Stream, [encoding(octet)]),
        (   seek(Stream, Position, bof, _),
            read_string(Stream, Chunk, String),
            http_get(Endpoint, _, [
                         method(patch),
                         post(bytes('application/offset+octet-stream', String)),
                         request_header('Upload-Offset'=Position),
                         request_header('Tus-Resumable'='1.0.0'),
                         reply_header(Reply_Header),
                         status_code(204)
                         |Options
                     ])
        ),
        close(Stream)
    ).

tus_head(Resource_URL, Offset, Length, Options) :-
    tus_head(Resource_URL, Offset, Length, _Reply_Header, Options).

tus_head(Resource_URL, Offset, Length, Reply_Header, Options) :-
    http_get(Resource_URL, _, [
                 method(head),
                 request_header('Tus-Resumable'='1.0.0'),
                 reply_header(Reply_Header),
                 status_code(200)
                 |Options
             ]),
    memberchk(upload_offset(Offset_Atom),Reply_Header),
    atom_number(Offset_Atom, Offset),
    (   memberchk(upload_length(Length_Atom),Reply_Header)
    ->  atom_number(Length_Atom, Length)
    ;   Length = unknown
    ).

/**
 * tus_upload(+File, +Endpoint, -Resource_URL, +Options) is semidet.
 *
 * Upload `File` to `Endpoint` returning `Resource_URL`
 *
 * @arg File A fully qualified file path
 * @arg Endpoint The URL of a TUS server
 * @arg Resource_URL The URL which refers to the uploaded resource.
 * @arg Options A list of options sent to http_get/3
 */
tus_upload(File, Endpoint, Resource_URL, Options) :-
    tus_options(Endpoint, Tus_Options, Options),
    tus_create(Endpoint, File, Length, Resource_URL, Options),
    tus_client_effective_chunk_size(Tus_Options, Chunk_Size),
    chunk_directive(Length, Chunk_Size, Directive),

    maplist({File, Resource_URL, Options}/[Chunk-Position]>>(
                debug(tus, "Chunk: ~q Position: ~q~n", [Chunk, Position]),
                tus_patch(Resource_URL, File, Chunk, Position, Options)
            ),
            Directive).

tus_upload(File, Endpoint, Resource_URL) :-
    tus_upload(File, Endpoint, Resource_URL, []).

/**
 * tus_resume(+Endpoint, +Resource_URL, +Options) is semidet.
 *
 * Resume `File` upload to `Endpoint` and `Resource`
 *
 * @arg Endpoint The URL of a TUS server
 * @arg Resource_URL The URL which refers to the uploaded resource.
 * @arg Length Length of the file
 * @arg Options A list of options sent to http_get/3
 */
tus_resume(File, Endpoint, Resource_URL, Options) :-
    tus_options(Endpoint, Tus_Options, Options),
    tus_head(Resource_URL, Offset, Length, Options),
    tus_client_effective_chunk_size(Tus_Options, Chunk_Size),
    chunk_directive(Offset, Length, Chunk_Size, Directive),

    maplist({File, Resource_URL, Options}/[Chunk-Position]>>(
                debug(tus, "Chunk: ~q Position: ~q~n", [Chunk, Position]),
                tus_patch(Resource_URL, File, Chunk, Position, Options)
            ),
            Directive).

tus_resume(File, Endpoint, Resource_URL) :-
    tus_resume(File, Endpoint, Resource_URL, []).

/* Tests */

:- begin_tests(tus).
spawn_server(URL, Port) :-
    random_between(49152, 65535, Port),
    http_server(tus_dispatch, [port(Port), workers(1)]),
    format(atom(URL), 'http://127.0.0.1:~d/files', [Port]).

kill_server(Port) :-
    http_stop_server(Port,[]).

test(send_file, [
         setup((set_tus_options([tus_client_chunk_size(4)]),
                spawn_server(URL, Port))),
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
    tus_resource_path(Name, Resource, []),
    read_file_to_string(Resource, Result, []),

    Result = Content.

test(check_expiry, [
         setup((set_tus_options([tus_client_chunk_size(4)]),
                spawn_server(URL, Port))),
         cleanup(kill_server(Port))
     ]) :-

    File = 'example.txt',
    tmp_file(File, Example),
    open(Example, write, Stream),
    Content = "asdf fdsa yes yes yes",
    format(Stream, '~s', [Content]),
    close(Stream),

    tus_create(URL, Example, _Length, Resource, Reply_Header_Create, []),
    % TODO: This should actually parse as RFC7231
    %       and check the date is in the future.
    memberchk(upload_expires(_Date_String1),
              Reply_Header_Create),

    tus_patch(Resource, Example, 4, 0, Reply_Header_Patch, []),
    memberchk(upload_expires(_Date_String2),
              Reply_Header_Patch).


test(expired_reinitiated, [
         setup((set_tus_options([tus_client_chunk_size(4),
                                 tus_expiry_seconds(1)
                                ]),
                spawn_server(URL, Port))),
         cleanup(kill_server(Port))
     ]) :-

    File = 'example.txt',
    tmp_file(File, Example),
    open(Example, write, Stream),
    Content = "asdf fdsa yes yes yes",
    format(Stream, '~s', [Content]),
    close(Stream),

    tus_create(URL, Example, _Length, Resource, _, []),
    sleep(1),
    catch(
        once(tus_patch(Resource, Example, 4, 0, [])),
        error(existence_error(url,_URL),
              context(_,status(Status,_))),
        memberchk(Status, [404, 410])).

test(resume, [
         setup((set_tus_options([tus_client_chunk_size(4)]),
                spawn_server(URL, Port))),
         cleanup(kill_server(Port))
     ]) :-

    File = 'example.txt',
    tmp_file(File, Example),
    open(Example, write, Stream),
    Content = "asdf fdsa yes yes yes",
    format(Stream, '~s', [Content]),
    close(Stream),

    tus_create(URL, Example, _Length, Resource_URL, _, []),
    tus_patch(Resource_URL, Example, 4, 0, []),

    tus_resume(Example, URL, Resource_URL),

    tus_resource_name(Example, Name),
    tus_resource_path(Name, Resource, []),
    read_file_to_string(Resource, Result, []),

    Result = Content.

/* Authorization

   A test example with domains.

 */
:- use_module(library(http/http_authenticate)).

auth_table(me,pass,shangrila).

fetch_authorization_data(Request, Username, Key) :-
    memberchk(authorization(Text), Request),
    http_authorization_data(Text, basic(Username, Key)).

authorize(Request,Organization) :-
    fetch_authorization_data(Request, Username, Key_Codes),
    atom_codes(Key,Key_Codes),
    auth_table(Username, Key, Organization).

:- meta_predicate auth_wrapper(2,?).
auth_wrapper(Goal,Request) :-
    authorize(Request, Domain),
    call(Goal, [domain(Domain)], Request).

spawn_auth_server(URL, Port) :-
    random_between(49152, 65535, Port),
    http_server(auth_wrapper(tus_dispatch), [port(Port), workers(1)]),
    format(atom(URL), 'http://127.0.0.1:~d/files', [Port]).

test(auth_test, [
         setup((set_tus_options([tus_client_chunk_size(4),
                                 tus_expiry_seconds(1)
                                ]),
                spawn_auth_server(URL, Port))),
         cleanup(kill_server(Port))
     ]) :-

    File = 'example.txt',
    tmp_file(File, Example),
    open(Example, write, Stream),
    Content = "asdf fdsa yes yes yes",
    format(Stream, '~s', [Content]),
    close(Stream),

    tus_upload(Example, URL, _Resource, [authorization(basic(me,pass))]),

    tus_resource_name(Example, Name),
    tus_resource_path(Name, Resource, [domain(shangrila)]),
    read_file_to_string(Resource, Result, []),

    Result = Content.

:- end_tests(tus).
