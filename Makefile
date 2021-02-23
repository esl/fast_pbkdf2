.PHONY: rel deps test

all: deps compile

compile: rebar3
	./rebar3 compile

deps: rebar3
	./rebar3 get-deps

clean: rebar3
	./rebar3 clean

test-deps: rebar3
	./rebar3 get-deps

test-compile: rebar3 test-deps
	./rebar3 as test compile

test: test-compile
	./rebar3 as test ct

codecov: _build/test/cover/ct.coverdata
	./rebar3 as test codecov analyze

gcov: test-compile
	gcov -o c_src fast_pbkdf2

rebar3:
	wget https://github.com/erlang/rebar3/releases/download/3.13.2/rebar3 &&\
	chmod u+x rebar3

dialyzer: rebar3
	./rebar3 dialyzer
