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

all() -> [{group, md5},
          {group, sha},
          {group, sha256},
          {group, sha512},
          {group, rsa},
          rand_bytes
         ].

groups() -> [{md5, [], [hash]},
             {sha, [], [hash]},
             {sha256, [], [hash]},
             {sha512, [], [hash]},
             {rsa, [], [sign_verify, public_encrypt]}
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

public_encrypt() ->
     [{doc, "Test public_encrypt/decrypt and private_encrypt/decrypt functions. "}].
public_encrypt(Config) when is_list(Config) ->
    Params = proplists:get_value(pub_priv_encrypt, Config),
    lists:foreach(fun do_public_encrypt/1, Params),
    lists:foreach(fun do_private_encrypt/1, Params).

sign_verify() ->
     [{doc, "Sign/verify digital signatures"}].
sign_verify(Config) when is_list(Config) ->
    SignVerify = proplists:get_value(sign_verify, Config),
    lists:foreach(fun do_sign_verify/1, SignVerify).

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

group_config(md5 = Type, Config) ->
    Msgs = rfc_1321_msgs(),
    Digests = rfc_1321_md5_digests(),
    [{hash, {Type, Msgs, Digests}} | Config];
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
group_config(rsa = Type, Config) ->
    Msg = rsa_plain(),
    PublicS = rsa_public_stronger(),
    PrivateS = rsa_private_stronger(),
    SignVerify = sign_verify_tests(Type, Msg, PublicS, PrivateS),
    MsgPubEnc = <<"7896345786348 Asldi">>,
    PubPrivEnc = [{rsa, PublicS, PrivateS, MsgPubEnc, rsa_pkcs1_padding},
                  no_padding()
                 ],
    [{sign_verify, SignVerify}, {pub_priv_encrypt, PubPrivEnc} | Config];
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

rsa_plain() ->
    <<"7896345786348756234 Hejsan Svejsan, erlang crypto debugger"
      "09812312908312378623487263487623412039812 huagasd">>.

rsa_public_stronger() ->
    [65537, 24629450921918866883077380602720734920775458960049554761386137065662137652635369332143446151320538248280934442179850504891395344346514465469955766163141133564033962851182759993807898821114734943339732032639891483186089941567854227407119560631150779000222837755424893038740314247760600374970909894211201220612920040986106639419467243909950276018045907029941478599124238353052062083560294570722081552510960894164859765695309596889747541376908786225647625736062865138957717982693312699025417086612046330464651009693307624955796202070510577399561730651967517158452930742355327167632521808183383868100102455048819375344881].

rsa_private_stronger() ->
    rsa_public_stronger() ++ [13565232776562604620467234237694854016819673873109064019820773052201665024482754648718278717031083946624786145611240731564761987114634269887293030432042088547345315212418830656522115993209293567218379960177754901461542373481136856927955012596579314262051109321754382091434920473734937991286600905464814063189230779981494358415076362038786197620360127262110530926733754185204773610295221669711309000953136320804528874719105049753061737780710448207922456570922652651354760939379096788728229638142403068102990416717272880560951246813789730402978652924934794503277969128609831043469924881848849409122972426787999886557185].

sign_verify_tests(Type, Msg, PublicS, PrivateS) ->
    sign_verify_tests(Type, [sha256, sha512], Msg, PublicS, PrivateS).

sign_verify_tests(Type, Hashs, Msg, Public, Private) ->
    lists:foldl(fun(Hash, Acc) ->
                        [{Type, Hash,  Public, Private, Msg}|Acc]
                end, [], Hashs).

do_sign_verify({Type, Hash, Public, Private, Msg}) ->
    Signature = crypto2:sign(Type, Hash, Msg, Private),
    case crypto2:verify(Type, Hash, Msg, Signature, Public) of
        true ->
            negative_verify(Type, Hash, Msg, <<10,20>>, Public);
        false ->
            ct:fail({{crypto, verify, [Type, Hash, Msg, Signature, Public]}})
    end.

negative_verify(Type, Hash, Msg, Signature, Public) ->
    case crypto2:verify(Type, Hash, Msg, Signature, Public) of
        true ->
            ct:fail({{crypto, verify, [Type, Hash, Msg, Signature, Public]}, should_fail});
        false ->
            ok
    end.

do_public_encrypt({Type, Public, Private, Msg, Padding}) ->
    PublicEcn = (catch crypto2:public_encrypt(Type, Msg, Public, Padding)),
    case crypto2:private_decrypt(Type, PublicEcn, Private, Padding) of
        Msg ->
            ok;
        Other ->
            ct:fail({{crypto, private_decrypt, [Type, PublicEcn, Private, Padding]}, {expected, Msg}, {got, Other}})
    end.

do_private_encrypt({Type, Public, Private, Msg, Padding}) ->
    PrivEcn = (catch crypto2:private_encrypt(Type, Msg, Private, Padding)),
    case crypto2:public_decrypt(rsa, PrivEcn, Public, Padding) of
        Msg ->
            ok;
        Other ->
            ct:fail({{crypto, public_decrypt, [Type, PrivEcn, Public, Padding]}, {expected, Msg}, {got, Other}})
    end.

no_padding() ->
    Public = [_, Mod] = rsa_public_stronger(),
    Private = rsa_private_stronger(),
    MsgLen = erlang:byte_size(int_to_bin(Mod)),
    Msg = list_to_binary(lists:duplicate(MsgLen, $X)),
    {rsa, Public, Private, Msg, rsa_no_padding}.

int_to_bin(X) when X < 0 -> int_to_bin_neg(X, []);
int_to_bin(X) -> int_to_bin_pos(X, []).

int_to_bin_pos(0,Ds=[_|_]) ->
    list_to_binary(Ds);
int_to_bin_pos(X,Ds) ->
    int_to_bin_pos(X bsr 8, [(X band 255)|Ds]).

int_to_bin_neg(-1, Ds=[MSB|_]) when MSB >= 16#80 ->
    list_to_binary(Ds);
int_to_bin_neg(X,Ds) ->
    int_to_bin_neg(X bsr 8, [(X band 255)|Ds]).

rfc_1321_msgs() ->
    [<<"">>, 
     <<"a">>,
     <<"abc">>, 
     <<"message digest">>,
     <<"abcdefghijklmnopqrstuvwxyz">>,
     <<"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789">>,
     <<"12345678901234567890123456789012345678901234567890123456789012345678901234567890">>
    ].

rfc_1321_md5_digests() ->
    [hexstr2bin("d41d8cd98f00b204e9800998ecf8427e"),
     hexstr2bin("0cc175b9c0f1b6a831c399e269772661"),
     hexstr2bin("900150983cd24fb0d6963f7d28e17f72"),
     hexstr2bin("f96b697d7cb7938d525a2f31aaf161d0"),
     hexstr2bin("c3fcd3d76192e4007dfb496cca67e13b"),
     hexstr2bin("d174ab98d277d9f5a5611c2c9f419d9f"),
     hexstr2bin("57edf4a22be3c955ac49da2e2107b67a")].
