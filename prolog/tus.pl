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

 Requests are structured according to the prolog http library format.

 Implemented features of the TUS protocol:

 OPTIONS (Discovery)
 POST (Create*)
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
    resource_current_offset(URI, Offset),
    format("HTTP/1.1 200 OK~n", []),
    format("Upload-Offset: ~s~n", [Offset]),
    format("Tus-Resumable: 1.0.0~n~n", []).

resource_current_offset(URI, Offset) :-
    tus_storage_path(Path),
    true.

create_file_resource(File, Name) :-
    % how do we remember what file to move to eventually?
    true.
