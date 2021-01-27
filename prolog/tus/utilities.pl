:- module(utilities, [
              comma_list/2
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
    var(Atom),
    !,
    intersperse(',', List, Interspersed),
    atomic_list_concat(Interspersed, Atom).
comma_list(Atom, List) :-
    split_string(Atom, ',', '', List_Strings),
    maplist(atom_string, List, List_Strings).
