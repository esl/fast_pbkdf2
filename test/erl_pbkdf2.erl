-module(erl_pbkdf2).

-export([pbkdf2/5, pbkdf2_oneblock/4]).

%% Taken from unexported crypto:sha3().
-type sha3() :: sha3_224 | sha3_256 | sha3_384 | sha3_512.
-type sha_type() :: crypto:sha1() | crypto:sha2() | sha3().

-spec pbkdf2(sha_type(), binary(), binary(), pos_integer(), pos_integer()) -> binary().
pbkdf2(Sha, Password, Salt, IterationCount, DkLen) ->
    #{size := HLen} = crypto:hash_info(Sha),
    Blocks = [pbkdf2_block(Sha, Password, Salt, IterationCount, BlockIndex)
              || BlockIndex <- lists:seq(1, (DkLen + HLen - 1) div HLen)],
    binary:part(iolist_to_binary(Blocks), 0, DkLen).

-spec pbkdf2_oneblock(sha_type(), binary(), binary(), pos_integer()) -> binary().
pbkdf2_oneblock(Sha, Password, Salt, IterationCount) ->
    pbkdf2_block(Sha, Password, Salt, IterationCount, 1).

-spec pbkdf2_block(sha_type(), binary(), binary(), pos_integer(), pos_integer()) -> binary().
pbkdf2_block(Sha, Password, Salt, 1, BlockIndex) ->
    crypto_hmac(Sha, Password, <<Salt/binary, BlockIndex:32>>);
pbkdf2_block(Sha, Password, Salt, IterationCount, BlockIndex)
  when is_integer(IterationCount), IterationCount > 1 ->
    U1 = crypto_hmac(Sha, Password, <<Salt/binary, BlockIndex:32>>),
    mask(U1, iteration(Sha, Password, U1, IterationCount - 1)).

-spec iteration(sha_type(), binary(), binary(), non_neg_integer()) -> binary().
iteration(Sha, Password, UPrev, 1) ->
    crypto_hmac(Sha, Password, UPrev);
iteration(Sha, Password, UPrev, IterationCount) ->
    U = crypto_hmac(Sha, Password, UPrev),
    mask(U, iteration(Sha, Password, U, IterationCount - 1)).

-spec mask(binary(), binary()) -> binary().
mask(Key, Data) ->
    KeySize = size(Key) * 8,
    <<A:KeySize>> = Key,
    <<B:KeySize>> = Data,
    C = A bxor B,
    <<C:KeySize>>.

-ifdef(OTP_RELEASE).
-if(?OTP_RELEASE >= 23).
crypto_hmac(Sha, Bin1, Bin2) ->
    crypto:mac(hmac, Sha, Bin1, Bin2).
-else.
crypto_hmac(Sha, Bin1, Bin2) ->
    crypto:hmac(Sha, Bin1, Bin2).
-endif.
-else.
crypto_hmac(Sha, Bin1, Bin2) ->
    crypto:hmac(Sha, Bin1, Bin2).
-endif.
