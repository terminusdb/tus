:- module(utilities, [
              comma_list/2,
              random_file/2
          ]).

intersperse(Item, List, Output) :-
    (   List == []
    ->  Output = []
    ;   List = [X| Xs],
        intersperse_(Xs, X, Item, Output)
    ).

intersperse_([], X, _, [X]).
intersperse_([Y| Xs], X, Item, [X, Item| Tail]) :-
    intersperse_(Xs, Y, Item, Tail).

comma_list(Atom, List) :-
    atomic_list_concat(List, ',', Atom).

/**
 * random_string(String) is det.
 */
random_string(String) :-
    Size is 2 ** (20 * 8),
    random(0, Size, Num),
    format(string(String), '~36r', [Num]).

random_file(Prefix, Filename) :-
    random_string(RandomString),
    atomic_list_concat([Prefix, RandomString], Tmp),
    tmp_file(Tmp, Filename).
