#!/usr/bin/perl

# test dependencies on individual curves in tests
# - build
# - run test suite
#
# Usage: tests/scripts/curves.pl

use warnings;
use strict;

-d 'library' && -d 'include' && -d 'tests' or die "Must be run from root\n";

my $sed_cmd = 's/^#define \(POLARSSL_ECP_DP.*_ENABLED\)/\1/p';
my $config_h = 'include/polarssl/config.h';
my @curves = split( /\s+/, `sed -n -e '$sed_cmd' $config_h` );

my $test = system( "grep -i cmake Makefile >/dev/null" ) ? 'check' : 'test';

system( "cp $config_h $config_h.bak" ) and die;
sub abort {
    system( "mv $config_h.bak $config_h" ) and warn "$config_h not restored\n";
    die $_[0];
}

for my $curve (@curves) {
    system( "cp $config_h.bak $config_h" ) and die "$config_h not restored\n";
    system( "make clean" ) and die;

    print "\n******************************************\n";
    print "* Testing without curve: $curve\n";
    print "******************************************\n";

    system( "scripts/config.pl unset $curve" )
        and abort "Failed to disable $curve\n";

    system( "make polarssl" ) and abort "Failed to build lib: $curve\n";
    system( "cd tests && make" ) and abort "Failed to build tests: $curve\n";
    system( "make $test" ) and abort "Failed test suite: $curve\n";

}

system( "mv $config_h.bak $config_h" ) and die "$config_h not restored\n";
system( "make clean" ) and die;
exit 0;
