:- module(tus, []).

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

/* Tus server constants */
tus_version_list('1.0.0').
tus_max_size(17_179_869_184).
tus_extention_list('creation').

/*

 Requests are structured according to the prolog http library format.

 Implemented features of the TUS protocol:

 Creation*

 * Suggested

*/

tus_dispatch(options,Request) :-
    % Options
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
    memberchk(upload_length(Length),Request),
    memberchk(upload_metadata(Metadata),Request),
    !,
    memberchk(tus_resumable(Version),Request),
    accept_tus_version(Version),
    parse_metadata(Metadata, Struct),
    Struct = filename(File,Options),
    create_file_resource(File, Name),
    resumable_endpoint(Name, Endpoint),
    format("HTTP/1.1 201 Created~n", []),
    format("Location: ~s~n",[]),
    format("Tus-Resumable: 1.0.0~n~n", []).



create_file_resource(File, Name) :-
    % how do we remember what file to move to eventually?
    true.
