:- module(utilities, [
              random_string/1,
              random_file/2,
              commands/1
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

/*
 * xfy_list(Op, Term, List) is det.
 *
 * Folds a functor over a list.
 */
xfy_list(Op, Term, [Left|List]) :-
    Term =.. [Op, Left, Right],
    xfy_list(Op, Right, List),
    !.
xfy_list(_, Term, [Term]).

determinise_goals([], []).
determinise_goals([Goal|Goals], [New_Goal|New_Goals]) :-
    New_Goal =
    (   call(Goal)
    ->  true
    ;   throw(error(goal_failed_deterministic_contract(Goal)))
    ),
    determinise_goals(Goals,New_Goals).

:- meta_predicate commands(:).
commands(Module_Goals) :-
    strip_module(Module_Goals, Module, Goals),
    Goals = {Ands},
    xfy_list(',', Ands, And_List),
    determinise_goals(And_List,Goal_List),
    xfy_list(',',New_Goals,Goal_List),
    call(Module:New_Goals).
