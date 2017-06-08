#!/usr/bin/env perl
use strict;
use warnings;
use Test::RandomCheck;
use Test::RandomCheck::Generator;
use Test::More;

BEGIN { use_ok 'SOPS::Value' };

my $expected = "foo";
my $key = "f" x 32;
my $message = "ENC[AES256_GCM,data:oYyi,iv:MyIDYbT718JRr11QtBkcj3Dwm4k1aCGZBVeZf0EyV8o=,tag:t5z2Z023Up0kxwCgw1gNxg==,type:str]";

is(SOPS::Value->parse($message)->decrypt($key, "bar:"), $expected);
isnt(SOPS::Value->parse($message)->decrypt($key, ""), $expected);

my $str_and_path = concat(string(), string());
my $int_and_path = concat(integer(), string());
my $bool_and_path = concat(enum(JSON->false, JSON->true), string());

my $check = sub { 
    my ($value, $path) = @_;

    my $new_value = SOPS::Value->parse(
        SOPS::Value->encrypt($value, $key, $path)->to_string,
    )->decrypt($key, $path);
    is($new_value, $value, "value: $value");
};

random_ok { $check->(@_) } $str_and_path;
random_ok { $check->(@_) } $int_and_path;
random_ok { $check->(@_) } $bool_and_path;

done_testing;
