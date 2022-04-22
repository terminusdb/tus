:- module(utilities, [
              random_string/1,
              random_file/2
          ]).

:- use_module(library(random)).

/**
 * random_string(String) is det.
 */
random_string(String) :-
    Size is 2 ** (20 * 8),
    random_between(0, Size, Num),
    format(string(String), '~36r', [Num]).

random_file(Prefix, Filename) :-
    random_string(RandomString),
    atomic_list_concat([Prefix, RandomString], Tmp),
    tmp_file(Tmp, Filename).
