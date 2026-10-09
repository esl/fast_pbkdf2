-module(pbkdf2_SUITE).

%% API
-export([all/0,
         groups/0,
         init_per_suite/1,
         end_per_suite/1,
         init_per_group/2,
         end_per_group/2,
         init_per_testcase/2,
         end_per_testcase/2]).

%% test cases
-export([
         erlang_and_nif_are_equivalent_sha1/1,
         erlang_and_nif_are_equivalent_sha224/1,
         erlang_and_nif_are_equivalent_sha256/1,
         erlang_and_nif_are_equivalent_sha384/1,
         erlang_and_nif_are_equivalent_sha512/1,
         erlang_and_nif_are_equivalent_sha3_224/1,
         erlang_and_nif_are_equivalent_sha3_256/1,
         erlang_and_nif_are_equivalent_sha3_384/1,
         erlang_and_nif_are_equivalent_sha3_512/1
        ]).
-export([
         test_vector_sha1_1/1,
         test_vector_sha1_2/1,
         test_vector_sha1_3/1,
         test_vector_sha1_4/1,
         test_vector_sha1_5/1,
         test_vector_sha1_6/1,
         test_vector_sha256_1/1,
         test_vector_sha256_2/1,
         test_vector_sha256_3/1,
         test_vector_sha256_4/1,
         test_vector_sha256_5/1,
         test_vector_sha256_6/1,
         test_vector_sha256_7/1,
         test_vector_sha256_8/1
        ]).
-export([
         bad_hashes/1,
         bad_iteration_counts/1,
         large_iteration_counts_are_accepted/1,
         bad_derived_key_lengths/1,
         derived_key_too_long/1
        ]).
-export([
         killed_callers_do_not_leak/1
        ]).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

all() ->
    [
     {group, equivalents},
     {group, test_vectors},
     {group, bad_arguments},
     {group, resources}
    ].

groups() ->
    [
     {equivalents, [parallel],
      [
       erlang_and_nif_are_equivalent_sha1,
       erlang_and_nif_are_equivalent_sha224,
       erlang_and_nif_are_equivalent_sha256,
       erlang_and_nif_are_equivalent_sha384,
       erlang_and_nif_are_equivalent_sha512,
       erlang_and_nif_are_equivalent_sha3_224,
       erlang_and_nif_are_equivalent_sha3_256,
       erlang_and_nif_are_equivalent_sha3_384,
       erlang_and_nif_are_equivalent_sha3_512
      ]},
     {test_vectors, [parallel],
      [
       test_vector_sha1_1,
       test_vector_sha1_2,
       test_vector_sha1_3,
       test_vector_sha1_4,
       test_vector_sha1_5,
       test_vector_sha1_6,
       test_vector_sha256_1,
       test_vector_sha256_2,
       test_vector_sha256_3,
       test_vector_sha256_4,
       test_vector_sha256_5,
       test_vector_sha256_6,
       test_vector_sha256_7,
       test_vector_sha256_8
      ]},
     {bad_arguments, [parallel],
      [
       bad_hashes,
       bad_iteration_counts,
       large_iteration_counts_are_accepted,
       bad_derived_key_lengths,
       derived_key_too_long
      ]},
     {resources, [],
      [
       killed_callers_do_not_leak
      ]}
    ].

%%%===================================================================
%%% Overall setup/teardown
%%%===================================================================
init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

%%%===================================================================
%%% Group specific setup/teardown
%%%===================================================================
init_per_group(_Groupname, Config) ->
    Config.

end_per_group(_Groupname, _Config) ->
    ok.

%%%===================================================================
%%% Testcase specific setup/teardown
%%%===================================================================
init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%%===================================================================
%%% Individual Test Cases (from groups() definition)
%%%===================================================================

erlang_and_nif_are_equivalent_sha1(_Config) ->
    crypto_and_erlang_and_nif_are_equivalent_(sha).

erlang_and_nif_are_equivalent_sha224(_Config) ->
    crypto_and_erlang_and_nif_are_equivalent_(sha224).

erlang_and_nif_are_equivalent_sha256(_Config) ->
    crypto_and_erlang_and_nif_are_equivalent_(sha256).

erlang_and_nif_are_equivalent_sha384(_Config) ->
    crypto_and_erlang_and_nif_are_equivalent_(sha384).

erlang_and_nif_are_equivalent_sha512(_Config) ->
    crypto_and_erlang_and_nif_are_equivalent_(sha512).

erlang_and_nif_are_equivalent_sha3_224(_Config) ->
    erlang_and_nif_are_equivalent_(sha3_224).

erlang_and_nif_are_equivalent_sha3_256(_Config) ->
    erlang_and_nif_are_equivalent_(sha3_256).

erlang_and_nif_are_equivalent_sha3_384(_Config) ->
    erlang_and_nif_are_equivalent_(sha3_384).

erlang_and_nif_are_equivalent_sha3_512(_Config) ->
    erlang_and_nif_are_equivalent_(sha3_512).

crypto_and_erlang_and_nif_are_equivalent_(Sha) ->
    Prop = ?FORALL({Pass, Salt, Count},
                   {password(Sha), binary(), range(1,20000)},
                   begin
                       #{size := KeyLen} = crypto:hash_info(Sha),
                       This = fast_pbkdf2:pbkdf2(Sha, Pass, Salt, Count),
                       PureErl = erl_pbkdf2:pbkdf2_oneblock(Sha, Pass, Salt, Count),
                       LibCrypto = crypto:pbkdf2_hmac(Sha, Pass, Salt, Count, KeyLen),
                       This =:= PureErl andalso This =:= LibCrypto
                   end),
    ?assert(proper:quickcheck(Prop, proper_opts())),
    PropDkLen = ?FORALL({Pass, Salt, Count, DkLen},
                        {password(Sha), binary(), range(1,1000), dk_len(Sha)},
                        begin
                            This = fast_pbkdf2:pbkdf2(Sha, Pass, Salt, Count, DkLen),
                            PureErl = erl_pbkdf2:pbkdf2(Sha, Pass, Salt, Count, DkLen),
                            LibCrypto = crypto:pbkdf2_hmac(Sha, Pass, Salt, Count, DkLen),
                            This =:= PureErl andalso This =:= LibCrypto
                        end),
    ?assert(proper:quickcheck(PropDkLen, proper_opts())).

erlang_and_nif_are_equivalent_(Sha) ->
    Prop = ?FORALL({Pass, Salt, Count},
                   {password(Sha), binary(), range(1,20000)},
                   begin
                       This = fast_pbkdf2:pbkdf2(Sha, Pass, Salt, Count),
                       PureErl = erl_pbkdf2:pbkdf2_oneblock(Sha, Pass, Salt, Count),
                       This =:= PureErl
                   end),
    ?assert(proper:quickcheck(Prop, proper_opts())),
    PropDkLen = ?FORALL({Pass, Salt, Count, DkLen},
                        {password(Sha), binary(), range(1,1000), dk_len(Sha)},
                        begin
                            This = fast_pbkdf2:pbkdf2(Sha, Pass, Salt, Count, DkLen),
                            PureErl = erl_pbkdf2:pbkdf2(Sha, Pass, Salt, Count, DkLen),
                            This =:= PureErl
                        end),
    ?assert(proper:quickcheck(PropDkLen, proper_opts())).

%% Passwords longer than the block size of the hash are hashed before being used as HMAC keys,
%% so generate passwords of up to twice the block size, and right around the block size.
password(Sha) ->
    #{block_size := BlockSize} = crypto:hash_info(Sha),
    ?LET(Len,
         oneof([range(0, 2 * BlockSize), range(BlockSize - 1, BlockSize + 1)]),
         binary(Len)).

%% Derived keys of up to four blocks, not necessarily a multiple of the hash length.
dk_len(Sha) ->
    #{size := HashLen} = crypto:hash_info(Sha),
    range(1, 4 * HashLen).

proper_opts() ->
    [verbose, long_result,
     {start_size, 2}, {max_size, 128},
     {numtests, 500}, {numworkers, erlang:system_info(schedulers_online)}].


%% Taken from the official RFC https://www.ietf.org/rfc/rfc6070.txt

test_vector_sha1_1(_Config) ->
    {P,S,It,DkLen,Result} = {<<"password">>,<<"salt">>,1,20,
     base16:decode(<<"0c60c80f961f0e71f3a9b524af6012062fe037a6">>)},
    ?assertEqual(Result, fast_pbkdf2:pbkdf2(sha, P, S, It, DkLen)).

test_vector_sha1_2(_Config) ->
    {P,S,It,DkLen,Result} = {<<"password">>,<<"salt">>,2,20,
     base16:decode(<<"ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957">>)},
    ?assertEqual(Result, fast_pbkdf2:pbkdf2(sha, P, S, It, DkLen)).

test_vector_sha1_3(_Config) ->
    {P,S,It,DkLen,Result} = {<<"password">>,<<"salt">>,4096,20,
     base16:decode(<<"4b007901b765489abead49d926f721d065a429c1">>)},
    ?assertEqual(Result, fast_pbkdf2:pbkdf2(sha, P, S, It, DkLen)).

test_vector_sha1_4(_Config) ->
    {P,S,It,DkLen,Result} = {<<"password">>,<<"salt">>,16777216,20,
     base16:decode(<<"eefe3d61cd4da4e4e9945b3d6ba2158c2634e984">>)},
    ?assertEqual(Result, fast_pbkdf2:pbkdf2(sha, P, S, It, DkLen)).

test_vector_sha1_5(_Config) ->
    {P,S,It,DkLen,Result} = {<<"passwordPASSWORDpassword">>,<<"saltSALTsaltSALTsaltSALTsaltSALTsalt">>,4096,25,
     base16:decode(<<"3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038">>)},
    ?assertEqual(Result, fast_pbkdf2:pbkdf2(sha, P, S, It, DkLen)).

test_vector_sha1_6(_Config) ->
    {P,S,It,DkLen,Result} = {<<"pass\0word">>,<<"sa\0lt">>,4096,16,
     base16:decode(<<"56fa6aa75548099dcc37d7f03425e0c3">>)},
    ?assertEqual(Result, fast_pbkdf2:pbkdf2(sha, P, S, It, DkLen)).


%% Taken from https://stackoverflow.com/a/5136918/8853275
test_vector_sha256_1(_Config) ->
    {P,S,It,DkLen,Result} = {<<"password">>, <<"salt">>, 1, 32,
     base16:decode(<<"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b">>)},
    ?assertEqual(Result, fast_pbkdf2:pbkdf2(sha256, P, S, It, DkLen)).

test_vector_sha256_2(_Config) ->
    {P,S,It,DkLen,Result} = {<<"password">>, <<"salt">>, 2, 32,
     base16:decode(<<"ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43">>)},
    ?assertEqual(Result, fast_pbkdf2:pbkdf2(sha256, P, S, It, DkLen)).

test_vector_sha256_3(_Config) ->
    {P,S,It,DkLen,Result} = {<<"password">>, <<"salt">>, 4096, 32,
     base16:decode(<<"c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a">>)},
    ?assertEqual(Result, fast_pbkdf2:pbkdf2(sha256, P, S, It, DkLen)).

test_vector_sha256_4(_Config) ->
    {P,S,It,DkLen,Result} = {<<"password">>, <<"salt">>, 16777216, 32,
     base16:decode(<<"cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46">>)},
    ?assertEqual(Result, fast_pbkdf2:pbkdf2(sha256, P, S, It, DkLen)).

test_vector_sha256_5(_Config) ->
    {P,S,It,DkLen,Result} = {<<"passwordPASSWORDpassword">>,<<"saltSALTsaltSALTsaltSALTsaltSALTsalt">>,4096,40,
     base16:decode(<<"348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9">>)},
    ?assertEqual(Result, fast_pbkdf2:pbkdf2(sha256, P, S, It, DkLen)).

test_vector_sha256_6(_Config) ->
    {P,S,It,DkLen,Result} = {<<"pass\0word">>, <<"sa\0lt">>, 4096, 16,
     base16:decode(<<"89b69d0516f829893c696226650a8687">>)},
    ?assertEqual(Result, fast_pbkdf2:pbkdf2(sha256, P, S, It, DkLen)).

%% Taken from the official RFC https://www.rfc-editor.org/rfc/rfc7914#section-11
test_vector_sha256_7(_Config) ->
    {P,S,It,DkLen,Result} = {<<"passwd">>, <<"salt">>, 1, 64,
     base16:decode(<<"55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
                     "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783">>)},
    ?assertEqual(Result, fast_pbkdf2:pbkdf2(sha256, P, S, It, DkLen)).

test_vector_sha256_8(_Config) ->
    {P,S,It,DkLen,Result} = {<<"Password">>, <<"NaCl">>, 80000, 64,
     base16:decode(<<"4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
                     "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d">>)},
    ?assertEqual(Result, fast_pbkdf2:pbkdf2(sha256, P, S, It, DkLen)).

bad_hashes(_Config) ->
    ?assertEqual({error, bad_hash}, fast_pbkdf2:pbkdf2(md5, <<"p">>, <<"s">>, 1)),
    ?assertEqual({error, bad_hash}, fast_pbkdf2:pbkdf2(md5, <<"p">>, <<"s">>, 1, 16)).

bad_iteration_counts(_Config) ->
    [begin
         ?assertEqual({error, bad_iteration_count},
                      fast_pbkdf2:pbkdf2(sha, <<"p">>, <<"s">>, It)),
         ?assertEqual({error, bad_iteration_count},
                      fast_pbkdf2:pbkdf2(sha, <<"p">>, <<"s">>, It, 40))
     end || It <- [0, -1, 1 bsl 32, 1.0, one]].

%% Iteration counts are only limited to 32 bits, so this computation would take very long,
%% we just check that it gets started.
large_iteration_counts_are_accepted(_Config) ->
    {Pid, Ref} = spawn_monitor(
                   fun() -> fast_pbkdf2:pbkdf2(sha, <<"p">>, <<"s">>, 16#FFFFFFFF) end),
    wait_until_yielded(Pid),
    exit(Pid, kill),
    receive {'DOWN', Ref, process, Pid, killed} -> ok end.

bad_derived_key_lengths(_Config) ->
    [?assertEqual({error, bad_derived_key_length},
                  fast_pbkdf2:pbkdf2(sha, <<"p">>, <<"s">>, 1, DkLen))
     || DkLen <- [0, -1, 20.0, twenty]].

%% RFC 8018, section 5.2, step 1
derived_key_too_long(_Config) ->
    ?assertEqual({error, derived_key_too_long},
                 fast_pbkdf2:pbkdf2(sha, <<"p">>, <<"s">>, 1, (1 bsl 32 - 1) * 20 + 1)),
    ?assertEqual({error, derived_key_too_long},
                 fast_pbkdf2:pbkdf2(sha3_512, <<"p">>, <<"s">>, 1, (1 bsl 32 - 1) * 64 + 1)).


%% A process killed while the NIF is yielding must not leak the state of its computation.
%% Every leaked computation holds a few hundred bytes, so a leak across all these kills
%% is well above the noise of the node's binary memory.
killed_callers_do_not_leak(_Config) ->
    Hashes = [sha, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512],
    Before = settled_binary_memory(),
    [kill_mid_computation(Hash) || Hash <- Hashes, _ <- lists:seq(1, 200)],
    assert_binary_memory_settles(Before, 10).

kill_mid_computation(Hash) ->
    {Pid, Ref} = spawn_monitor(
                   fun() -> fast_pbkdf2:pbkdf2(Hash, <<"password">>, <<"salt">>, 1 bsl 30) end),
    wait_until_yielded(Pid),
    exit(Pid, kill),
    receive {'DOWN', Ref, process, Pid, killed} -> ok end.

%% Once the NIF has rescheduled itself, the process reports one of the scheduled functions,
%% which are the only functions of arity 1 in the module.
wait_until_yielded(Pid) ->
    case erlang:process_info(Pid, current_function) of
        {current_function, {fast_pbkdf2, _, 1}} -> ok;
        {current_function, _} -> erlang:yield(), wait_until_yielded(Pid);
        undefined -> ct:fail({exited_before_yielding, Pid})
    end.

assert_binary_memory_settles(Before, Retries) ->
    After = settled_binary_memory(),
    case After - Before < 64 * 1024 of
        true -> ct:pal("Binary memory before ~p, after ~p", [Before, After]);
        false when Retries > 0 -> assert_binary_memory_settles(Before, Retries - 1);
        false -> ct:fail({binary_memory_grew, Before, After})
    end.

settled_binary_memory() ->
    [erlang:garbage_collect(Pid) || Pid <- processes()],
    timer:sleep(100),
    erlang:memory(binary).
