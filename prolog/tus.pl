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

:- use_module(library(http/http_client)).
:- use_module(library(http/http_header)).
:- use_module(library(http/thread_httpd)).

/* parsing tools */
:- use_module(tus/parse).
:- use_module(tus/utilities).

:- use_module(library(crypto)).

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
tus_extension(checksum).
tus_extension(termination).

tus_extension_list(Atom) :-
    findall(Extension,
            tus_extension(Extension),
            Extensions),
    atomic_list_concat(Extensions, ',', Atom).

tus_checksum_algorithm(md5).
tus_checksum_algorithm(sha1).

tus_checksum_algorithm_list(Atom) :-
    findall(Extension,
            tus_checksum_algorithm(Extension),
            Extensions),
    atomic_list_concat(Extensions, ',', Atom).

tus_storage_path(Path, Options) :-
    memberchk(tus_storage_path(Pre_Path), Options),
    terminal_slash(Pre_Path, Path),
    !.
tus_storage_path(Path, _Options) :-
    tus_storage_path_dynamic(Path),
    !.
tus_storage_path(Path, _Options) :-
    current_prolog_flag(tus_options, Options),
    memberchk(tus_storage_path(Pre_Path), Options),
    terminal_slash(Pre_Path, Path),
    assertz(tus_storage_path_dynamic(Path)),
    !.
tus_storage_path(Temp, _Options) :-
    random_file('tus_storage', Temp_File),
    make_directory(Temp_File),
    terminal_slash(Temp_File,Temp),
    assertz(tus_storage_path_dynamic(Temp)).

accept_tus_version(Version) :-
    member(Version, ['1.0.0']).

expiration_timestamp(Expiry) :-
    get_time(Time),
    tus_expiry_seconds(Seconds),
    Expiry is Time + Seconds.

algorithm_checksum_string(md5, Checksum, String) :-
    md5_hash(String, Checksum, []).
algorithm_checksum_string(sha1, Checksum, String) :-
    crypto_data_hash(String, Checksum_Pre, [algorithm(sha1),
                                            encoding(octet)]),
    Checksum_Pre = Checksum.

algorithm_checksum_string_value(Algorithm, Checksum, String, Value) :-
    when(
        (   ground(Algorithm),
            ground(Checksum)
        ;   ground(Value)),
        atomic_list_concat([Algorithm, Checksum], ' ', Value)
    ),
    algorithm_checksum_string(Algorithm, Checksum, String).

/**
 * tus_checksum(+Upload_Checksum, +String).
 */
tus_checksum(Upload_Checksum,String) :-
    algorithm_checksum_string_value(_Algorithm, _Checksum, String, Upload_Checksum).

tus_algorithm_supported(Upload_Checksum) :-
    atomic_list_concat([Algorithm, _], ' ', Upload_Checksum),
    tus_checksum_algorithm(Algorithm).

tus_generate_checksum_header(String, Header, Tus_Options) :-
    memberchk(tus_checksum_algorithm(Algorithms), Tus_Options),
    member(Algorithm, [sha1,md5]), % in this order of precedence
    memberchk(Algorithm, Algorithms),
    !,
    algorithm_checksum_string_value(Algorithm, _, String, Upload_Checksum),
    Header = [request_header('Upload-Checksum'=Upload_Checksum)].
tus_generate_checksum_header(_, Header, _) :-
    Header = [].

% Should probably also be an option.
tus_max_retries(3).

check_tus_creation(Tus_Options) :-
    memberchk(tus_extension(Extensions), Tus_Options),
    memberchk(creation, Extensions).

check_tus_termination(Tus_Options) :-
    memberchk(tus_extension(Extensions), Tus_Options),
    memberchk(termination, Extensions).

/*
File store manipulation utilities.
*/
tus_resource_name(File, Name) :-
    md5_hash(File, Name, []).

tus_resource_base_path(Resource, Path, Options) :-
    tus_storage_path(Storage, Options),
    option(domain(Domain),Options,'xanadu'),
    atomic_list_concat([Storage, Domain, '.', Resource], Path).

tus_resource_suffix('completed').

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
    tus_resource_base_path(Resource, Base_Path, Options),
    tus_resource_suffix(Completed),
    atomic_list_concat([Base_Path, '/',Completed], Path).

tus_resource_deleted_path(Resource, Deleted_Path, Options) :-
    tus_resource_base_path(Resource, Path, Options),
    atomic_list_concat([Path, '.deleted'], Deleted_Path).

tus_offset_suffix('offset').

tus_offset_path(Resource, Path, Options) :-
    tus_resource_base_path(Resource, RPath, Options),
    tus_offset_suffix(Offset),
    atomic_list_concat([RPath, '/', Offset], Path).

tus_size_suffix('size').

tus_size_path(Resource, Path, Options) :-
    tus_resource_base_path(Resource, RPath, Options),
    tus_size_suffix(Size),
    atomic_list_concat([RPath, '/', Size], Path).

tus_upload_suffix('upload').

tus_upload_path(Resource, Path, Options) :-
    tus_resource_base_path(Resource, RPath, Options),
    tus_upload_suffix(Upload),
    atomic_list_concat([RPath, '/', Upload], Path).

tus_lock_suffix('lock').

tus_lock_path(Resource, Path, Options) :-
    tus_resource_base_path(Resource, RPath, Options),
    tus_lock_suffix(Lock),
    atomic_list_concat([RPath, '/', Lock], Path).

tus_expiry_suffix('expiry').

tus_expiry_path(Resource, Path, Options) :-
    tus_resource_base_path(Resource, RPath, Options),
    tus_expiry_suffix(Offset),
    atomic_list_concat([RPath, '/', Offset], Path).

% turns exception into failure.
try_make_directory(Directory) :-
    catch(
        make_directory(Directory),
        error(existence_error(directory,_),_),
        fail).

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
create_file_resource(File, Size, Name, Status, Options) :-
    tus_resource_name(File, Name),
    tus_resource_base_path(Name, Path, Options),
    (   try_make_directory(Path)
    ->  % File
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
        Status=expires(Expiry)
    ;   Status=exists
    ).

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

delete_resource(Resource, Options) :-
    tus_resource_base_path(Resource, Path, Options),
    tus_resource_deleted_path(Resource, Deleted, Options),
    rename_file(Path, Deleted),
    directory_files(Deleted, All_Files),
    exclude([X]>>(member(X,['.', '..'])), All_Files, Files),
    forall(
        member(File, Files),
        (   atomic_list_concat([Deleted, '/', File],Full_Path),
            delete_file(Full_Path))),
    delete_directory(Deleted).

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

/*
 * Generators for chunk offsets
 */
chunk_directive(Length, Chunk_Size, Current_Offset, Current_Chunk) :-
    chunk_directive(0, Length, Chunk_Size, Current_Offset, Current_Chunk).

chunk_directive(Offset, Length, Chunk_Size, Offset, Current_Chunk) :-
    Offset < Length,
    Current_Chunk is min(Chunk_Size, Length - Offset).
chunk_directive(Offset, Length, Chunk_Size, Current_Offset, Current_Chunk) :-
    Next_Chunk is min(Chunk_Size, Length - Offset),
    Next_Offset is Offset + Next_Chunk,
    Next_Offset < Length,
    chunk_directive(Next_Offset, Length, Chunk_Size, Current_Offset, Current_Chunk).

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

format_headers(_, []).
format_headers(Out, [Term|Rest]) :-
    Term =.. [Atom,Value],
    format(Out, "~s: ~w~n", [Atom, Value]),
    format_headers(Out, Rest).

format_custom_response(Out, checksum_mismatch) :-
    format(Out, "HTTP/1.1 460 Checksum Mismatch~n",[]).
format_custom_response(Out, gone) :-
    format(Out, "HTTP/1.1 410 Gone~n",[]).

custom_status_reply(Custom_Response, Out, Headers) :-
    format_custom_response(Out,Custom_Response),
    format_headers(Out,Headers),
    format(Out,"\r\n",[]).

status_code(created,201).
status_code(no_content,204).
status_code(bad_request,400).
status_code(forbidden,403).
status_code(not_found,404).
status_code(conflict,409).
status_code(gone,410).
status_code(unsupported_media,415).
status_code(bad_checksum,460).

/*
 * Server dispatch
 */

/**
 * tus_dispatch(+Options, +Request) is semidet.
 *
 * See tus_dispatch/2
 *
 */
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
    tus_checksum_algorithm_list(Algorithm_List),
    http_output_stream(Request, Out),
    http_status_reply(no_content, Out,
                      ['Tus-Resumable'('1.0.0'),
                       'Tus-Version'(Version_List),
                       'Tus-Max-Size'(Max_Size),
                       'Tus-Checksum-Algorithm'(Algorithm_List),
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
    % Find position
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
    % Patch next bit
    !,
    memberchk(request_uri(URI),Request),
    memberchk(content_length(Length),Request),

    memberchk(upload_offset(Offset_Atom),Request),
    atom_number(Offset_Atom, Offset),

    http_read_data(Request, Patch, []),

    http_output_stream(Request, Out),
    (   memberchk(upload_checksum(Upload_Checksum),Request),
        \+ tus_checksum(Upload_Checksum,Patch)
    % We have a checksum to check and it doesn't check out.
    ->  (   \+ tus_algorithm_supported(Upload_Checksum)
        % Because the algorithm is unsupported
        ->  http_status_reply(bad_request('Algorithm Unsupported'), Out,
                              ['Tus-Resumable'('1.0.0')],
                              _Code)
        % Because the checksum is wrong
        ;   custom_status_reply(checksum_mismatch, Out,
                                ['Tus-Resumable'('1.0.0')])
        )
    % No checksum, or it checks out.
    ;   tus_uri_resource(URI, Resource),
        (   resource_expiry(Resource, Expiry, Options)
        ->  http_timestamp(Expiry, Expiry_Date),
            (   get_time(Time),
                debug(tus, "Time: ~q Expiry: ~q~n", [Time, Expiry]),
                Time > Expiry
            ->  custom_status_reply(gone, Out,
                                    ['Tus-Resumable'('1.0.0'),
                                     'Upload-Expires'(Expiry_Date)])
            ;   patch_resource(Resource, Patch, Offset, Length, New_Offset, Options),
                http_status_reply(no_content, Out,
                                  ['Tus-Resumable'('1.0.0'),
                                   'Upload-Expires'(Expiry_Date),
                                   'Upload-Offset'(New_Offset)],
                                  _Code))
        ;   http_status_reply(not_found(URI), Out,
                              ['Tus-Resumable'('1.0.0')],
                              _Code)
        )
    ).
tus_dispatch(delete,Options,Request) :-
    % Delete
    memberchk(request_uri(URI),Request),

    tus_uri_resource(URI, Resource),

    http_output_stream(Request, Out),

    (   delete_resource(Resource, Options)
    ->  http_status_reply(no_content, Out,
                          ['Tus-Resumable'('1.0.0')],
                          _Code)
    ;   http_status_reply(not_found(URI), Out,
                              ['Tus-Resumable'('1.0.0')],
                              _Code)
    ).

/*
 Client implementation

*/

tus_process_options([], []).
tus_process_options([tus_checksum_algorithm(X)|Rest_In],[tus_checksum_algorithm(Y)|Rest_Out]) :-
    !,
    atomic_list_concat(Y, ',', X),
    tus_process_options(Rest_In, Rest_Out).
tus_process_options([tus_extension(X)|Rest_In],[tus_extension(Y)|Rest_Out]) :-
    !,
    atomic_list_concat(Y, ',', X),
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

tus_create(Endpoint, File, Length, Resource, Tus_Options, Options) :-
    tus_create(Endpoint, File, Length, Resource, _, Tus_Options, Options).

tus_create(Endpoint, File, Length, Resource, Reply_Header, Tus_Options, Options) :-
    (   check_tus_creation(Tus_Options)
    ->  true
    ;   throw(error(no_creation_extention(Endpoint), _))),

    size_file(File, Length),
    parse_upload_metadata(Metadata,filename(File,[])),
    http_get(Endpoint, Response, [
                 method(post),
                 request_header('Upload-Length'=Length),
                 request_header('Upload-Metadata'=Metadata),
                 request_header('Tus-Resumable'='1.0.0'),
                 reply_header(Reply_Header),
                 status_code(Code)
                 |Options
             ]),
    (   status_code(Status,Code)
    ->  (   Status = created
        ->  memberchk(location(Resource), Reply_Header)
        ;   Status = conflict % file already exists
        ->  throw(error(file_already_exists(File), _))
        ;   throw(error(unhandled_status_code(Code,Response),_)))
    ;   throw(error(unhandled_status_code(Code,Response),_))
    ).

tus_patch(Endpoint, File, Chunk, Position, Tus_Options, Options) :-
    tus_patch(Endpoint, File, Chunk, Position, _Reply_Header, Tus_Options, Options).

tus_patch(Endpoint, File, Chunk, Position, Reply_Header, Tus_Options, Options) :-
    tus_max_retries(Max_Retries),
    between(0,Max_Retries,_Tries),
    tus_patch_(Endpoint, File, Chunk, Position, Reply_Header, Tus_Options, Options),
    !.
tus_patch(Endpoint, _, _, _, _, _, _) :-
    tus_max_retries(Max_Retries),
    throw(error(exceeded_max_retries(Endpoint,Max_Retries),_)).

tus_patch_(Endpoint, File, Chunk, Position, Reply_Header, Tus_Options, Options) :-
    setup_call_cleanup(
        open(File, read, Stream, [encoding(octet)]),
        (   seek(Stream, Position, bof, _),
            read_string(Stream, Chunk, String),
            tus_generate_checksum_header(String, Header, Tus_Options),
            append(Options,Header,HdrExtra),
            http_get(Endpoint, Response, [
                         method(patch),
                         post(bytes('application/offset+octet-stream', String)),
                         request_header('Upload-Offset'=Position),
                         request_header('Tus-Resumable'='1.0.0'),
                         reply_header(Reply_Header),
                         status_code(Code)
                         |HdrExtra
                     ])
        ),
        close(Stream)
    ),
    (   status_code(Status,Code)
    ->  (   Status = no_content % patched
        ->  true
        ;   Status = bad_checksum
        ->  fail % (i.e. retry)
        ;   Status = bad_request % No request algorithm
        ->  throw(error(bad_request(Endpoint), _))
        ;   Status = not_found
        ->  throw(error(not_found(Endpoint), _))
        ;   Status = gone
        ->  throw(error(gone(Endpoint),_))
        ;   Status = forbidden
        ->  throw(error(forbidden(Endpoint),_))
        ;   Status = unsupported_media
        ->  throw(error(unsupported_media,_))
        ;   throw(error(unhandled_status_code(Code,Response),_))
        )
    ;   throw(error(unhandled_status_code(Code,Response),_))
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

tus_delete(Resource_URL, Tus_Options, Options) :-
    tus_delete(Resource_URL, _Reply_Header, Tus_Options, Options).

tus_delete(Resource_URL, Reply_Header, Tus_Options, Options) :-
    (   check_tus_termination(Tus_Options)
    ->  true
    ;   throw(error(no_termination_extention(Resource_URL), _))),

    http_get(Resource_URL, Response, [
                 method(delete),
                 request_header('Tus-Resumable'='1.0.0'),
                 reply_header(Reply_Header),
                 status_code(Code)
                 |Options
             ]),
    (   status_code(Status, Code)
    ->  (   Status = no_content % deleted
        ->  true
        ;   memberchk(Status, [not_found, gone])
        ->  throw(error(resource_does_not_exist(Resource_URL), _))
        ;   Status = forbidden
        ->  throw(error(forbidden(Resource_URL),_))
        ;   throw(error(unhandled_status_code(Code,Response),_))
        )
    ;   throw(error(unhandled_status_code(Code,Response),_))
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
    tus_create(Endpoint, File, Length, Resource_URL, Tus_Options, Options),
    tus_client_effective_chunk_size(Tus_Options, Chunk_Size),
    forall(
        chunk_directive(Length, Chunk_Size, Position, Chunk),
        (   debug(tus, "Chunk: ~q Position: ~q~n", [Chunk, Position]),
            tus_patch(Resource_URL, File, Chunk, Position, Tus_Options, Options)
        )
    ).

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
    forall(
        chunk_directive(Offset, Length, Chunk_Size, Position, Chunk),
        (   debug(tus, "Chunk: ~q Position: ~q~n", [Chunk, Position]),
            tus_patch(Resource_URL, File, Chunk, Position, Tus_Options, Options)
        )
    ).

tus_resume(File, Endpoint, Resource_URL) :-
    tus_resume(File, Endpoint, Resource_URL, []).

/* Tests */

:- begin_tests(tus).


spawn_server(URL, Port, Options) :-
    random_between(49152, 65535, Port),
    http_server(tus_dispatch(Options), [port(Port), workers(1)]),
    format(atom(URL), 'http://127.0.0.1:~d/files', [Port]).

kill_server(Port) :-
    http_stop_server(Port,[]).

test(send_file, [
         setup((set_tus_options([tus_client_chunk_size(4)]),
                random_file(tus_storage_test, Path),
                make_directory(Path),
                Options = [tus_storage_path(Path)],
                spawn_server(URL, Port, Options))),
         cleanup(kill_server(Port))
     ]) :-

    random_file('example_txt_tus', File),
    open(File, write, Stream),
    Content = "asdf fdsa yes yes yes",
    format(Stream, '~s', [Content]),
    close(Stream),

    tus_upload(File, URL, _Resource),

    tus_resource_name(File, Name),
    tus_resource_path(Name, Resource, Options),
    read_file_to_string(Resource, Result, []),

    Result = Content.

test(send_and_delete_file, [
         setup((set_tus_options([tus_client_chunk_size(4)]),
                random_file(tus_storage_test, Path),
                make_directory(Path),
                Options = [tus_storage_path(Path)],
                spawn_server(URL, Port, Options))),
         cleanup(kill_server(Port))
     ]) :-

    random_file('example_txt_tus', File),
    open(File, write, Stream),
    Content = "asdf fdsa yes yes yes",
    format(Stream, '~s', [Content]),
    close(Stream),

    tus_upload(File, URL, Resource),

    tus_resource_name(File, Name),
    tus_resource_path(Name, Resource_Path, Options),
    read_file_to_string(Resource_Path, _Result, []),

    tus_options(URL, Tus_Options, []),
    tus_delete(Resource, Tus_Options, Options),
    tus_resource_base_path(Resource, Base_Path, Options),
    \+ exists_directory(Base_Path).

test(check_expiry, [
         setup((set_tus_options([tus_client_chunk_size(4)]),
                random_file(tus_storage_test, Path),
                make_directory(Path),
                Options = [tus_storage_path(Path)],
                spawn_server(URL, Port, Options))),
         cleanup(kill_server(Port))
     ]) :-

    random_file('example_txt_tus', File),
    open(File, write, Stream),
    Content = "asdf fdsa yes yes yes",
    format(Stream, '~s', [Content]),
    close(Stream),

    tus_options(URL, Tus_Options, []),
    tus_create(URL, File, _Length, Resource, Reply_Header_Create, []),
    % TODO: This should actually parse as RFC7231
    %       and check the date is in the future.
    memberchk(upload_expires(_Date_String1),
              Reply_Header_Create),

    tus_patch(Resource, File, 4, 0, Reply_Header_Patch, Tus_Options, []),
    memberchk(upload_expires(_Date_String2),
              Reply_Header_Patch).

test(expired_reinitiated, [
         setup((set_tus_options([tus_client_chunk_size(4),
                                 tus_expiry_seconds(1)
                                ]),
                random_file(tus_storage_test, Path),
                make_directory(Path),
                Options = [tus_storage_path(Path)],
                spawn_server(URL, Port, Options))),
         cleanup(kill_server(Port)),
         error(gone(Resource),_)
     ]) :-

    random_file('example_txt_tus', File),
    open(File, write, Stream),
    Content = "asdf fdsa yes yes yes",
    format(Stream, '~s', [Content]),
    close(Stream),

    tus_options(URL, Tus_Options, []),
    tus_create(URL, File, _Length, Resource, _, []),
    sleep(1),
    tus_patch(Resource, File, 4, 0, Tus_Options, []).

test(resume, [
         setup((set_tus_options([tus_client_chunk_size(4)]),
                random_file(tus_storage_test, Path),
                make_directory(Path),
                Options = [tus_storage_path(Path)],
                spawn_server(URL, Port, Options))),
         cleanup(kill_server(Port))
     ]) :-

    random_file('example_txt_tus', File),
    open(File, write, Stream),
    Content = "asdf fdsa yes yes yes",
    format(Stream, '~s', [Content]),
    close(Stream),

    tus_options(URL, Tus_Options, []),
    tus_create(URL, File, _Length, Resource_URL, _, []),
    tus_patch(Resource_URL, File, 4, 0, Tus_Options, []),

    tus_resume(File, URL, Resource_URL),

    tus_resource_name(File, Name),
    tus_resource_path(Name, Resource, Options),
    read_file_to_string(Resource, Result, []),

    Result = Content.

test(bad_checksum, [
         setup((set_tus_options([tus_client_chunk_size(4)]),
                random_file(tus_storage_test, Path),
                make_directory(Path),
                Options = [tus_storage_path(Path)],
                spawn_server(URL, Port, Options))),
         cleanup(kill_server(Port)),
         error(exceeded_max_retries(Resource_URL,_Tries),_)
     ]) :-

    random_file('example_txt_tus', File),
    open(File, write, Stream),
    Content = "something else for a change",
    format(Stream, '~s', [Content]),
    close(Stream),

    tus_options(URL, Tus_Options, []),
    tus_create(URL, File, _Length, Resource_URL, _, []),
    tus_patch(Resource_URL, File, 4, 0, Tus_Options,
              [request_header('Upload-Checksum'='sha1 33fd0301077bc24fc6513513c71e288fcecc0c66')]).

test(bad_checksum_algo, [
         setup((set_tus_options([tus_client_chunk_size(4)]),
                random_file(tus_storage_test, Path),
                make_directory(Path),
                Options = [tus_storage_path(Path)],
                spawn_server(URL, Port, Options))),
         cleanup(kill_server(Port)),
         error(bad_request(_),_)
     ]) :-

    random_file('example_txt_tus', File),
    open(File, write, Stream),
    Content = "something else for a change",
    format(Stream, '~s', [Content]),
    close(Stream),

    tus_options(URL, Tus_Options, []),
    tus_create(URL, File, _Length, Resource_URL, _, []),
    tus_patch(Resource_URL, File, 4, 0, Tus_Options,
              [request_header('Upload-Checksum'='scrunchy asdffdsa')]).

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

:- meta_predicate auth_wrapper(2,+,+).
auth_wrapper(Goal,Options,Request) :-
    authorize(Request, Domain),
    call(Goal, [domain(Domain) | Options], Request).

spawn_auth_server(URL, Port, Options) :-
    random_between(49152, 65535, Port),
    http_server(auth_wrapper(tus_dispatch, Options), [port(Port), workers(1)]),
    format(atom(URL), 'http://127.0.0.1:~d/files', [Port]).

test(auth_test, [
         setup((set_tus_options([tus_client_chunk_size(4),
                                 tus_expiry_seconds(1)
                                ]),
                random_file(tus_storage_test, Path),
                make_directory(Path),
                Options = [tus_storage_path(Path)],
                spawn_auth_server(URL, Port, [tus_storage_path(Path)]))),
         cleanup(kill_server(Port))
     ]) :-

    random_file('example_txt_tus', File),
    open(File, write, Stream),
    Content = "asdf fdsa yes yes yes",
    format(Stream, '~s', [Content]),
    close(Stream),

    tus_upload(File, URL, _Resource, [authorization(basic(me,pass))]),

    tus_resource_name(File, Name),
    tus_resource_path(Name, Resource, [domain(shangrila) | Options]),
    read_file_to_string(Resource, Result, []),

    Result = Content.

:- end_tests(tus).
