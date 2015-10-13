%%% Add erlang apache license here as a lot of this code
%%% is copy pasta

-module('crypto2').
-on_load(on_load/0).

%% API exports
-export([
         sha256/1
        ]).

%%====================================================================
%% API functions
%%====================================================================

sha256(String) ->
  sha256_nif(list_to_binary(String)).

%%====================================================================
%% Internal functions
%%====================================================================

%on_load() ->
  %case code:priv_dir(crypto2) of
    %Path when is_list(Path) ->
      %erlang:load_nif(filename:join(Path, "crypto2"));
  %end.

sha256_nif(_Data) -> "Undefined".

on_load() ->
  case code:priv_dir(crypto2) of
    Path when is_list(Path) ->
      erlang:load_nif(filename:join(Path, "crypto2"), []);
    _ ->
      {error, "Could not find library"}
  end.
