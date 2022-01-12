:- module(parse, [
              parse_upload_metadata/2
          ]).

/* parsing */

:- use_module(library(when)).
:- use_module(library(base64)).

assoc_metadata_parts([], []).
assoc_metadata_parts([Key-Value|Rest_A], [Meta|Rest_B]) :-
    when((   ground(Value)
         ;   ground(Value_base64)),
         base64_encoded(Value,Value_base64, [])),
    atomic_list_concat([Key,Value_base64], ' ', Meta),
    !,
    assoc_metadata_parts(Rest_A, Rest_B).
assoc_metadata_parts([Key|Rest_A], [Key|Rest_B]) :-
    assoc_metadata_parts(Rest_A, Rest_B).

parse_upload_metadata(Atom, Assoc) :-
    when(
        (   ground(Assoc)
        ;   ground(Parts)),
        assoc_metadata_parts(Assoc, Parts)
    ),
    atomic_list_concat(Parts, ',', Atom).

:- begin_tests(parse).

test(parse_upload_metadata, []) :-
    String = 'filename d29ybGRfZG9taW5hdGlvbl9wbGFuLnBkZg==,is_confidential',
    parse_upload_metadata(String, Struct),
    Struct = [filename-"world_domination_plan.pdf",is_confidential].

test(parse_upload_metadata_backwards, []) :-
    Struct = [filename-"world_domination_plan.pdf",is_confidential],
    parse_upload_metadata(String, Struct),
    String = 'filename d29ybGRfZG9taW5hdGlvbl9wbGFuLnBkZg==,is_confidential'.

test(parse_upload_metadata_backwards_empty, []) :-
    Struct = [filename-"world_domination_plan.pdf"],
    parse_upload_metadata(String, Struct),
    String = 'filename d29ybGRfZG9taW5hdGlvbl9wbGFuLnBkZg=='.

:- end_tests(parse).

