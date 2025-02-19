# Fast PBKDF2

[![Hex pm](https://img.shields.io/hexpm/v/fast_pbkdf2.svg)](https://hex.pm/packages/fast_pbkdf2)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/fast_pbkdf2/)
[![Downloads](https://img.shields.io/hexpm/dt/fast_pbkdf2.svg)](https://hex.pm/packages/fast_pbkdf2)
[![GitHub Actions](https://github.com/esl/fast_pbkdf2/workflows/ci/badge.svg?branch=main)](https://github.com/esl/fast_pbkdf2/actions?query=workflow%3Aci+branch%3Amain)
[![Codecov](https://codecov.io/gh/esl/fast_pbkdf2/branch/main/graph/badge.svg)](https://codecov.io/gh/esl/fast_pbkdf2)
[![License](https://img.shields.io/hexpm/l/fast_pbkdf2.svg)](https://github.com/esl/fast_pbkdf2/blob/main/LICENSE)

`fast_pbkdf2` is an Erlang implementation of [PBKDF2][PBKDF2], where the algorithm is a carefully-optimised NIF that uses timeslicing and nif scheduling to respect the latency properties of the BEAM.

## Building
`fast_pbkdf2` is a rebar3-compatible OTP application, that uses the [port_compiler](https://github.com/blt/port_compiler) for the C part of the code.

Building is as easy as `rebar3 compile`, and using it in your projects as
```erlang
{deps,
 [{fast_pbkdf2, "~> 2.0"}]}.
{provider_hooks,
 [{pre,
   [{compile, {pc, compile}},
    {clean, {pc, clean}}]}]}.
```

## Using

```erlang
DerivedPassword = fast_pbkdf2:pbkdf2(Hash, Password, Salt, IterationCount)
```
where `Hash` is the underlying hash function chosen as described by
```erlang
-type sha_type() :: crypto:sha1() | crypto:sha2().
```

### Custom `dkLen`
If what you desire is PBKDF2 with custom `dkLen`(I assume that if that is what you want, then you know your RFC), in a way that allows you to request longer derived keys, you may use `fast_pbkdf2:pbkdf2_block/5` with a given block index and do the indexing and chunking yourself, or use `fast_pbkdf2:pbkdf2/5` for the full algorithm. However, it doesn't really add much more entropy to the derived key to use outputs larger than the output of the underlying hash, so you might as well, use `pbkdf2` where dkLen is that of the hash's output, which is the same than `pbkdf2_block` with index `1`, which is simply the `pbkdf2/4` function.

## Performance

### The problem
PBKDF2 is a challenge derivation method, that is, it forces the client to compute a challenge in order to derive the desired password. But when the server implementation is slower than that of an attacker, it makes the server vulnerable to DoS by hogging itself with computations. We could see that on the CI and load-testing pipelines of [MongooseIM][MIM] for example.

### The solution
Is partial. We don't expect to have the fastest implementation, as that would be purely C code on GPUs, so unfortunately an attacker will pretty much always have better chances there. _But_ we can make the computation cheap enough for us that other computations —like the load of a session establishment— will be more relevant than that of the challenge; and also that other defence mechanisms like IP blacklisting or traffic shaping, will fire in good time.

### The outcome
On average it's 30% faster than the pure OpenSSL implementation, which `crypto:pbkdf2_hmac/5` calls without yielding, and 10x times faster (and x3N less memory, where N is the iteration count!) than a pure erlang equivalent (you can compare using the provided module in `./benchmarks/bench.ex`).

## Credit where credit is due
The initial algorithm and optimisations were taken from Joseph Birr-Pixton's
[fastpbkdf2](https://github.com/ctz/fastpbkdf2)'s repository.

## Read more:
* Password-Based Cryptography Specification (PBKDF2): [RFC8018](https://tools.ietf.org/html/rfc8018#section-5.2)
* HMAC: [RFC2104](https://datatracker.ietf.org/doc/html/rfc2104)
* SHAs and HMAC-SHA: [RFC6234](https://datatracker.ietf.org/doc/html/rfc6234)

[MIM]: https://github.com/esl/MongooseIM
[PBKDF2]: https://tools.ietf.org/html/rfc8018#section-5.2
