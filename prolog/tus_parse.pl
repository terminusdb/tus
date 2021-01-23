:- module(tus_parse, [
              parse_upload_metadata/2
          ]).

/* parsing */
%:- use_module(library(dcg/basics)).

char_from_range(H,First,Last,[H|T],T) :-
	H >= First, H =< Last.

any(Code,List,[Code|T], T) :-
    memberchk(Code,List).

any_but(Code,List,[Code|T], T) :-
    \+ memberchk(Code,List).

digit(Code) --> char_from_range(Code,0'0,0'9).

alpha_upper(H) --> char_from_range(H,0'A,0'Z).
alpha_lower(H) --> char_from_range(H,0'a,0'z).

alpha(H) --> alpha_upper(H).
alpha(H) --> alpha_lower(H).

file_codes([Code|Codes]) -->
    digit(Code),
    !,
    file_codes(Codes).
file_codes([Code|Codes]) -->
    alpha(Code),
    !,
    file_codes(Codes).
file_codes([Code|Codes]) -->
    any(Code, [43, 61, 47]), % +,=,/
    !,
    file_codes(Codes).
file_codes([]) -->
    [].

file(File) -->
    file_codes(File_Codes),
    { atom_codes(File_64,File_Codes),
      base64_encoded(File,File_64, [])
    }.

upload_metadata(filename(File,Options)) -->
    "filename", " ",
    file(File),
    file_options(Options).

eos([],[]).

next_option_codes([]) -->
    eos.
next_option_codes([H|T]) -->
    any_but(H,[0' ,0',]),
    next_option_codes(T).

next_option(Option) -->
    next_option_codes(Codes),
    { atom_codes(Option,Codes)}.

file_options([Option|Remainder]) -->
    ",",
    next_option(Option),
    file_options(Remainder).
file_options([]) -->
    [].

parse_upload_metadata(Metadata, Metadata_Struct) :-
     atom_codes(Metadata, Codes),
     once(phrase(upload_metadata(Metadata_Struct), Codes)).

:- begin_tests(parse).

test(parse_upload_metadata, []) :-
    String = 'filename d29ybGRfZG9taW5hdGlvbl9wbGFuLnBkZg==,is_confidential',
    parse_upload_metadata(String, Struct),
    Struct = filename("world_domination_plan.pdf",[is_confidential]).

:- end_tests(parse).

