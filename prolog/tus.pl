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

set_tus_options(Options) :-
    retract_tus_dynamics,
    valid_options(Options, global_tus_option),
    set_test_flag(tus_options, Options).

global_tus_option(tus_storage_path(_Path)).
global_tus_option(tus_max_size(Size)) :-
    must_be(positive_integer, Size).

:- dynamic tus_storage_path_dynamic/1.

retract_tus_dynamics :-
    retractall(tus_storage_path_dynamics(_)).

/* Tus server constants */
tus_version_list('1.0.0').

tus_max_size(Size) :-
    get_test_glag(tus_options, Options),
    memberchk(tus_max_size(Size), Options),
    !.
tus_max_size(17_179_869_184).

tus_extention_list('creation').

tus_storage_path(Path) :-
    tus_storage_path_dynamic(Path),
    !.
tus_storage_path(Path) :-
    get_test_flag(tus_options, Options),
    memberchk(tus_storage_path(Path), Options),
    assertz(tus_storage_path_dynamic(Path)),
    !.
tus_storage_path(Path) :-
    tmp_file('tus_storage', Temp),
    make_directory(Temp),
    assertz(tus_storage_path_dynamic(Path)).

/*
File store manipulation utilities.
*/
tus_offset_file('offset').

tus_offset_path(URI, Path) :-
    tus_resource_path(RPath),
    tus_offset_file(Offset),
    atomic_list_concat([RPath, '/', Offset], Path).

tus_size_file('size').

tus_size_path(URI, Path) :-
    tus_resource_path(RPath),
    tus_size_file(Offset),
    atomic_list_concat([RPath, '/', Offset], Path).

tus_upload_file('file').

tus_upload_path(URI, Path) :-
    tus_resource_path(RPath),
    tus_upload_file(Offset),
    atomic_list_concat([RPath, '/', Offset], Path).

resource_offset(URI, Offset) :-
    tus_resource_path(URI, URI_Storage),
    www_form_encode(URI, Safe),

    tus_offset_path(URI, Offset_File),
    read_file_to_string(Offset_File, Offset_String, []),
    atom_number(Offset_String, Offset).

set_resource_offset(URI, Offset) :-
    setup_call_cleanup(
        (   tus_offset_path(Resource,Offset_Path),
            open(Offset_Path, write, OP)),
        write(OP, Offset),
        close(OP)).

resource_size(URI, Offset) :-
    tus_resource_path(URI, URI_Storage),
    www_form_encode(URI, Safe),

    tus_size_path(URI, Offset_File),
    read_file_to_string(Offset_File, Offset_String, []),
    atom_number(Offset_String, Offset).

set_resource_size(URI, Size) :-
    setup_call_cleanup(
        (   tus_size_path(Resource,Size_Path),
            open(Size_Path, write, SP)),
        write(SP, Size),
        close(SP)).

create_file_resource(URI, Size, Name) :-
    tus_resource_path(URI, Resource),
    make_directory(Resource),
    % Size
    set_resource_size(Resource, Size),

    % Offset
    set_resource_offset(Resource, Offset),

    % File
    setup_call_cleanup(
        (   tus_upload_path(Resource,File_Path),
            open(File_Path, write, FP)),
        true, % touch
        close(FP)).

patch_resource(URI, Patch, Offset, Length, New_Offset) :-
    % sanity check
    (   string_length(Patch, Length)
    ->  true
    ;   throw(error(bad_length(Length)))),

    (   resource_offset(URI, Offset)
    ->  true
    ;   throw(error(bad_offset(Offset)))),

    tus_resource_path(URI, Resource),
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

tus_dispatch(options,Request) :-
    % Options
    !,
    format("HTTP/1.1 204 No Content~n", []),
    format("Tus-Resumable: ~s~n", []),
    tus_version_list(Version_List),
    format("Tus-Version: ~s~n", [Version_List]),
    tus_max_size(Max_Size),
    format("Tus-Max-Size: ~s~n", [Max_Size]),
    tus_extention_list(Extention_List),
    format("Tus-Extension: ~s~n~n", [Extension_List]).
tus_dispatch(post,Request) :-
    % Create
    !,
    memberchk(upload_length(Length),Request),
    memberchk(upload_metadata(Metadata),Request),
    memberchk(tus_resumable(Version),Request),
    accept_tus_version(Version),
    parse_metadata(Metadata, Struct),
    Struct = filename(File,_Options), % ignoring options for the minute
    create_file_resource(File, Name),
    resumable_endpoint(Name, Endpoint),
    format("HTTP/1.1 201 Created~n", []),
    format("Location: ~s~n",[]),
    format("Tus-Resumable: 1.0.0~n~n", []).
tus_dispatch(head,Request) :-
    % Next stage.
    !,
    memberchk(request_uri(URI), Request),
    resource_offset(URI, Offset),
    format("HTTP/1.1 200 OK~n", []),
    format("Upload-Offset: ~s~n", [Offset]),
    format("Tus-Resumable: 1.0.0~n~n", []).
tus_dispatch(patch,Request) :-
    % Next stage.
    !,
    memberchk(request_uri(URI), Request),
    memberchk(content_length(Length)),
    memberchk(upload_offset(Offset)),
    http_read_data(Request, Patch, []),
    patch_resource(URI, Patch, Offset, Length, New_Offset),
    format("HTTP/1.1 204 No Content~n", []),
    format("Upload-Offset: ~s~n", [Offset]),
    format("Tus-Resumable: 1.0.0~n~n", []).
