#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;

unless ($ENV{AUTHOR_TESTING} or $ENV{RELEASE_TESTING}) {
    plan skip_all => 'these tests are for testing by the author';
}

unless (eval { use Test::Signature; 1 }) {
    plan skip_all => 'Test::Signature is required for this test';
}

signature_ok();
done_testing;
