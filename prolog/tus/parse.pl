:- module(parse, [
              parse_upload_metadata/2
          ]).

/* parsing */

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
    { when((   ground(File)
           ;   ground(File_64)),
           base64_encoded(File,File_64, [])),
      when((   ground(File_Codes)
           ;   ground(File_64)),
           atom_codes(File_64,File_Codes))
    },
    file_codes(File_Codes).

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
    { when((   ground(Option)
           ;   ground(Codes)),
           atom_codes(Option,Codes)) },
    next_option_codes(Codes).

file_options([Option|Remainder]) -->
    ",",
    next_option(Option),
    file_options(Remainder).
file_options([]) -->
    [].

parse_upload_metadata(Metadata, Metadata_Struct) :-
    when((   ground(Metadata)
         ;   ground(Codes)),
         atom_codes(Metadata, Codes)),
    once(phrase(upload_metadata(Metadata_Struct), Codes)).

:- begin_tests(parse).

test(parse_upload_metadata, []) :-
    String = 'filename d29ybGRfZG9taW5hdGlvbl9wbGFuLnBkZg==,is_confidential',
    parse_upload_metadata(String, Struct),
    Struct = filename("world_domination_plan.pdf",[is_confidential]).

test(parse_upload_metadata_backwards, []) :-
    Struct = filename("world_domination_plan.pdf",[is_confidential]),
    parse_upload_metadata(String, Struct),
    String = 'filename d29ybGRfZG9taW5hdGlvbl9wbGFuLnBkZg==,is_confidential'.

test(parse_upload_metadata_backwards_empty, []) :-
    Struct = filename("world_domination_plan.pdf",[]),
    parse_upload_metadata(String, Struct),
    String = 'filename d29ybGRfZG9taW5hdGlvbl9wbGFuLnBkZg=='.

:- end_tests(parse).

