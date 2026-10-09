-module(fast_pbkdf2).
-on_load(load/0).
-nifs([pbkdf2_block/5]).

%% Taken from unexported crypto:sha3().
-type sha3() :: sha3_224 | sha3_256 | sha3_384 | sha3_512.
-type sha_type() :: crypto:sha1() | crypto:sha2() | sha3().

-export([pbkdf2/4, pbkdf2/5]).

%% The block index is encoded in 32 bits, see RFC 8018, section 5.2.
-define(MAX_BLOCK_INDEX, 16#FFFFFFFF).

%%% @doc
%%% This function calculates the pbkdf2 algorithm where dkLen is simply assumed to be that
%%% of the underlying hash function, a sane default.
-spec pbkdf2(sha_type(), binary(), binary(), pos_integer()) -> binary() | {error, atom()}.
pbkdf2(Hash, Password, Salt, IterationCount) ->
    pbkdf2_block(Hash, Password, Salt, IterationCount, 1).

%%% @doc
%%% This function allows to customise the desired dkLen parameter for pbkdf2.
%%% As in RFC 8018, it returns `{error, derived_key_too_long}' when dkLen exceeds
%%% (2^32 - 1) * hLen, where hLen is the output length of the hash function.
-spec pbkdf2(sha_type(), binary(), binary(), pos_integer(), pos_integer()) ->
    binary() | {error, atom()}.
pbkdf2(Hash, Password, Salt, IterationCount, DkLen) when is_integer(DkLen), DkLen > 0 ->
    case hash_length(Hash) of
        undefined ->
            {error, bad_hash};
        HLen when DkLen > ?MAX_BLOCK_INDEX * HLen ->
            {error, derived_key_too_long};
        _ ->
            pbkdf2(Hash, Password, Salt, IterationCount, DkLen, 1, [], 0)
    end;
pbkdf2(_Hash, _Password, _Salt, _IterationCount, _DkLen) ->
    {error, bad_derived_key_length}.

%%%===================================================================
%%% Helper function
%%%===================================================================
pbkdf2(_Hash, _Password, _Salt, _IterationCount, DkLen, _BlockIndex, Acc, Len) when Len >= DkLen ->
    Bin = iolist_to_binary(lists:reverse(Acc)),
    binary:part(Bin, 0, DkLen);
pbkdf2(Hash, Password, Salt, IterationCount, DkLen, BlockIndex, Acc, Len) ->
    case pbkdf2_block(Hash, Password, Salt, IterationCount, BlockIndex) of
        {error, Reason} -> {error, Reason};
        Block ->
            pbkdf2(Hash, Password, Salt, IterationCount, DkLen, BlockIndex + 1,
                   [Block | Acc],
                   byte_size(Block) + Len)
    end.

-spec hash_length(sha_type()) -> pos_integer() | undefined.
hash_length(sha) -> 20;
hash_length(sha224) -> 28;
hash_length(sha256) -> 32;
hash_length(sha384) -> 48;
hash_length(sha512) -> 64;
hash_length(sha3_224) -> 28;
hash_length(sha3_256) -> 32;
hash_length(sha3_384) -> 48;
hash_length(sha3_512) -> 64;
hash_length(_) -> undefined.

%%%===================================================================
%%% NIF
%%%===================================================================
-spec pbkdf2_block(sha_type(), binary(), binary(), pos_integer(), pos_integer()) ->
    binary() | {error, atom()}.
pbkdf2_block(_Hash, _Password, _Salt, _IterationCount, _BlockIndex) ->
    erlang:nif_error(not_loaded).

-spec load() -> any().
load() ->
    code:ensure_loaded(crypto),
    PrivDir = case code:priv_dir(?MODULE) of
                  {error, _} ->
                      EbinDir = filename:dirname(code:which(?MODULE)),
                      AppPath = filename:dirname(EbinDir),
                      filename:join(AppPath, "priv");
                  Path ->
                      Path
              end,
    erlang:load_nif(filename:join(PrivDir, ?MODULE_STRING), none).
