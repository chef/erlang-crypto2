%%% Add erlang apache license here as a lot of this code
%%% is copy pasta

-module('crypto2').
-on_load(on_load/0).

%% API exports
-export([
         hash/2,
         hash_init/1,
         hash_update/2,
         hash_final/1,
         public_encrypt/4,
         private_decrypt/4,
         private_encrypt/4,
         public_decrypt/4,
         rand_bytes/1,
         strong_rand_bytes/1,
         sign/4,
         verify/5
        ]).

%%====================================================================
%% API functions
%%====================================================================

hash(md5, Data) ->
    erlang:md5(Data);
hash(Type, Data) ->
    Context = hash_update(hash_init(Type), Data),
    hash_final(Context).

hash_init(md5) ->
    {md5_bif, erlang:md5_init()};
hash_init(sha) ->
    sha1_init();
hash_init(sha256) ->
    sha256_init();
hash_init(sha512) ->
    sha512_init().

hash_update({md5_bif, Context}, Data) ->
    {md5_bif, erlang:md5_update(Context, Data)};
hash_update(Context, Data) -> 
    hash_update_nif(Context, Data).

hash_final({md5_bif, Context}) ->
    erlang:md5_final(Context);
hash_final(Context) ->
    hash_final_nif(Context).

public_encrypt(rsa, BinMesg, Key, Padding) ->
    case rsa_public_crypt(BinMesg,  map_ensure_int_as_bin(Key), Padding, true) of
        error ->
            erlang:error(encrypt_failed, [BinMesg,Key, Padding]);
        Sign -> Sign
    end.

%% Binary, Key = [E,N,D]
private_decrypt(rsa, BinMesg, Key, Padding) ->
    case rsa_private_crypt(BinMesg, map_ensure_int_as_bin(Key), Padding, false) of
        error ->
            erlang:error(decrypt_failed, [BinMesg,Key, Padding]);
        Sign -> Sign
    end.

%% Binary, Key = [E,N,D]
private_encrypt(rsa, BinMesg, Key, Padding) ->
    case rsa_private_crypt(BinMesg, map_ensure_int_as_bin(Key), Padding, true) of
        error ->
            erlang:error(encrypt_failed, [BinMesg,Key, Padding]);
        Sign -> Sign
    end.

%% Binary, Key = [E,N]
public_decrypt(rsa, BinMesg, Key, Padding) ->
    case rsa_public_crypt(BinMesg, map_ensure_int_as_bin(Key), Padding, false) of
        error ->
            erlang:error(decrypt_failed, [BinMesg,Key, Padding]);
        Sign -> Sign
    end.

rand_bytes(NumBytes) ->
    case rand_bytes_nif(NumBytes) of
        error -> erlang:error(low_entropy);
        Data -> Data
    end.

strong_rand_bytes(NumBytes) ->
    rand_bytes(NumBytes).

sign(rsa, DigestType, {digest, Digest}, Key) when is_binary(Digest) ->
    case rsa_sign(DigestType, Digest, map_ensure_int_as_bin(Key)) of
        error -> erlang:error(badkey, [DigestType, Digest, Key]);
        Sign -> Sign
    end;
sign(rsa, DigestType, Msg, Key) when is_binary(Msg) ->
    sign(rsa, DigestType, {digest, hash(DigestType, Msg)}, Key).

verify(rsa, DigestType, {digest, Digest}, Signature, Key) ->
    rsa_verify(DigestType, Digest, Signature, map_ensure_int_as_bin(Key));
verify(rsa, DigestType, Msg, Signature, Key) ->
    verify(rsa, DigestType, {digest, hash(DigestType, Msg)}, Signature, Key).

%%====================================================================
%% Internal functions
%%====================================================================

on_load() ->
  case code:priv_dir(crypto2) of
    Path when is_list(Path) ->
      erlang:load_nif(filename:join(Path, "crypto2"), []);
    _ ->
      {error, "Could not find library"}
  end.

%%%%%%%%%%%%%%%%%%%%%%% from crypto.erl %%%%%%%%%%%%%%%%%%%%%%
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

map_ensure_int_as_bin([H|_]=List) when is_integer(H) ->
    lists:map(fun(E) -> int_to_bin(E) end, List);
map_ensure_int_as_bin(List) ->
    List.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

sha1_init() -> "Undefined".
sha256_init() -> "Undefined".
sha512_init() -> "Undefined".
hash_update_nif(_,_) -> "Undefined".
hash_final_nif(_) -> "Undefined".
rand_bytes_nif(_NumBytes) -> "Undefined".
rsa_sign(_,_,_) -> "Undefined".
rsa_verify(_,_,_,_) -> "Undefined".
rsa_public_crypt(_,_,_,_) -> "Undefined".
rsa_private_crypt(_,_,_,_) -> "Undefined".
