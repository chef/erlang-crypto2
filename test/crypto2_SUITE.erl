%%
%% %CopyrightBegin%
%%
%% Copyright Ericsson AB 1999-2013. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
%% %CopyrightEnd%
%%

-module(crypto2_SUITE).
-include_lib("common_test/include/ct.hrl").
-compile(export_all).

all() -> [{group, sha},
          {group, sha256},
          {group, sha512},
          rand_bytes
         ].

groups() -> [{sha, [], [hash]},
             {sha256, [], [hash]},
             {sha512, [], [hash]}
            ].

hash() ->
    [{doc, "Test all different hash functions"}].
hash(Config) when is_list(Config) ->
    {Type, MsgsLE, Digests} = proplists:get_value(hash, Config),
    Msgs = lazy_eval(MsgsLE),
    [LongMsg | _] = lists:reverse(Msgs),
    Inc = iolistify(LongMsg),
    [IncrDigest | _] = lists:reverse(Digests),
    hash(Type, Msgs, Digests),
    hash(Type, lists:map(fun iolistify/1, Msgs), Digests),
    hash_increment(Type, Inc, IncrDigest).

%%-------------------------------------------------------------------
%init_per_suite(Config) ->
    %%crypto:start(),
    %Config.

%end_per_suite(_Config) ->
    %application:stop(crypto).

%%-------------------------------------------------------------------
init_per_group(GroupName, Config) ->
    group_config(GroupName, Config).

end_per_group(_GroupName, Config) ->
    Config.

init_per_testcase(info, Config) ->
    Config;
init_per_testcase(_Name,Config) ->
    Config.

end_per_testcase(info, Config) ->
    Config;
end_per_testcase(_Name,Config) ->
    Config.

group_config(sha = Type, Config) ->
    Msgs = [rfc_4634_test1(), rfc_4634_test2_1(),long_msg()],
    Digests = rfc_4634_sha_digests() ++ [long_sha_digest()],
    [{hash, {Type, Msgs, Digests}} | Config];
group_config(sha256 = Type, Config) ->
    Msgs =   [rfc_4634_test1(), rfc_4634_test2_1(), long_msg()],
    Digests = rfc_4634_sha256_digests() ++ [long_sha256_digest()],
    [{hash, {Type, Msgs, Digests}} | Config];
group_config(sha512 = Type, Config) ->
    Msgs =  [rfc_4634_test1(), rfc_4634_test2(), long_msg()],
    Digests = rfc_4634_sha512_digests() ++ [long_sha512_digest()],
    [{hash, {Type, Msgs, Digests}} | Config];
group_config(_, Config) ->
    Config.
%%--------------------------------------------------------------------
hexstr2bin(S) ->
    list_to_binary(hexstr2list(S)).

hexstr2list([X,Y|T]) ->
    [mkint(X)*16 + mkint(Y) | hexstr2list(T)];
hexstr2list([]) ->
    [].
mkint(C) when $0 =< C, C =< $9 ->
    C - $0;
mkint(C) when $A =< C, C =< $F ->
    C - $A + 10;
mkint(C) when $a =< C, C =< $f ->
    C - $a + 10.

hash(_, [], []) ->
    ok;
hash(Type, [Msg | RestMsg], [Digest| RestDigest]) ->
    case crypto2:hash(Type, Msg) of
	Digest ->
	    hash(Type, RestMsg, RestDigest);
	Other ->
	    ct:fail({{crypto2, hash, [Type, Msg]}, {expected, Digest}, {got, Other}})
    end.

hash_increment(Type, Increments, Digest) ->
    State = crypto2:hash_init(Type),
    case hash_increment(State, Increments) of
	Digest ->
	    ok;
	Other ->
	    ct:fail({{crypto2, "hash_init/update/final", [Type, Increments]}, {expected, Digest}, {got, Other}})  
    end.

hash_increment(State, []) ->
    crypto2:hash_final(State);
hash_increment(State0, [Increment | Rest]) ->
    State = crypto2:hash_update(State0, Increment),
    hash_increment(State, Rest).

iolistify(<<"Test With Truncation">>)->
    %% Do not iolistify as it spoils this special case
    <<"Test With Truncation">>;
iolistify(Msg) when is_binary(Msg) ->
    Length = erlang:byte_size(Msg),
    Split = Length div 2,
    List0 = binary_to_list(Msg),
   case lists:split(Split, List0) of
       {[Element | List1], List2} ->
	   [[Element], List1, List2];
       {List1, List2}->
	   [List1, List2]
   end;
iolistify(Msg) ->
    iolistify(list_to_binary(Msg)).


lazy_eval(F) when is_function(F) -> F();
lazy_eval(Lst)  when is_list(Lst) -> lists:map(fun lazy_eval/1, Lst);
lazy_eval(Tpl) when is_tuple(Tpl) -> list_to_tuple(lists:map(fun lazy_eval/1, tuple_to_list(Tpl)));
lazy_eval(Term) -> Term.

rfc_4634_test1() ->
    <<"abc">>.
rfc_4634_test2_1() ->
    <<"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq">>.
rfc_4634_test2_2a() ->
    <<"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn">>.
rfc_4634_test2_2b() ->
    <<"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu">>.
rfc_4634_test2() ->
    A2 =rfc_4634_test2_2a(),
    B2 = rfc_4634_test2_2b(),
    <<A2/binary, B2/binary>>.

rfc_4634_sha_digests()->
     [hexstr2bin("A9993E364706816ABA3E25717850C26C9CD0D89D"),
      hexstr2bin("84983E441C3BD26EBAAE4AA1F95129E5E54670F1")].

rfc_4634_sha256_digests() ->
    [
     hexstr2bin("BA7816BF8F01CFEA4141"
		"40DE5DAE2223B00361A396177A9CB410FF61F20015AD"),
     hexstr2bin("248D6A61D20638B8"
		"E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1")
    ].

rfc_4634_sha512_digests() ->
    [hexstr2bin("DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA2"
		"0A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD"
		"454D4423643CE80E2A9AC94FA54CA49F"),
     hexstr2bin("8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909")].


long_msg() ->
    fun() -> lists:duplicate(1000000, $a) end.

long_sha_digest() ->
    hexstr2bin("34aa973c" "d4c4daa4" "f61eeb2b" "dbad2731" "6534016f").

long_sha256_digest() ->
    hexstr2bin("cdc76e5c" "9914fb92" "81a1c7e2" "84d73e67" "f1809a48" "a497200e" "046d39cc" "c7112cd0").

long_sha512_digest() ->
    hexstr2bin("e718483d0ce76964" "4e2e42c7bc15b463" "8e1f98b13b204428" "5632a803afa973eb"
	       "de0ff244877ea60a" "4cb0432ce577c31b" "eb009c5c2c49aa2e" "4eadb217ad8cc09b").

rand_bytes(_Config) ->
    10 = byte_size(crypto2:rand_bytes(10)),
    20 = byte_size(crypto2:strong_rand_bytes(20)).
