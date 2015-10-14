%%% Add erlang apache license here as a lot of this code
%%% is copy pasta

-module('crypto2').
-on_load(on_load/0).

%% API exports
-export([
         hash_init/1,
         hash_update/2,
         hash_final/1
        ]).

%%====================================================================
%% API functions
%%====================================================================

hash_init(sha256) ->
    sha256_init().

hash_update(_Context, _Data) -> "Undefined".
hash_final(_Context) -> "Undefined".

%%====================================================================
%% Internal functions
%%====================================================================

%on_load() ->
  %case code:priv_dir(crypto2) of
    %Path when is_list(Path) ->
      %erlang:load_nif(filename:join(Path, "crypto2"));
  %end.

on_load() ->
  case code:priv_dir(crypto2) of
    Path when is_list(Path) ->
      erlang:load_nif(filename:join(Path, "crypto2"), []);
    _ ->
      {error, "Could not find library"}
  end.

sha256_init() -> "Undefined".
