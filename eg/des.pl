#!/usr/bin/perl

use lib '../blib/lib';

use Getopt::Std;
use Crypt::CBC;
use strict vars;

my %options;

getopts('edk:i:o:',\%options) || die <<USAGE;
Usage: des.pl [options] file1 file2 file3...
    DES encrypt/decrypt files using Cipher Block Chaining mode.

     It is compatible with files encrypted using 
    "openssl enc -des-cbc -md md5".
Options:
       -e        encrypt (default)
       -d        decrypt
       -k 'key'  provide key on command line
       -i file   input file
       -o file   output file
USAGE
    ;

@ARGV = $options{'i'} if $options{'i'};
push(@ARGV,'-') unless @ARGV;
open (STDOUT,">$options{'o'}") || die "$options{'o'}: $!"
    if $options{'o'};

my $key = $options{'k'} || get_key();
# DES used by default
my $cipher = Crypt::CBC->new(-key   => $key,
			     -cipher=> 'DES',
			     -salt  => 1) || die "Couldn't create CBC object";  
my $decrypt = $options{'d'} and !$options{'e'};
$cipher->start($decrypt ? 'decrypt' : 'encrypt');

my $in;
while (@ARGV) {
    my $file = shift @ARGV;
    open(ARGV,$file) || die "$file: $!";
    print $cipher->crypt($in) while read(ARGV,$in,1024);
    close ARGV;
}
print $cipher->finish;

sub get_key {
    local($|) = 1;
    local(*TTY);
    open(TTY,"/dev/tty");
    my ($key1,$key2);
    system "stty -echo </dev/tty";
    do {
	print STDERR "DES key: ";
        chomp($key1 = <TTY>);
	print STDERR "\r\nRe-type key: ";
        chomp($key2 = <TTY>);
        print STDERR "\r\n";
        print STDERR "The two keys don't match. Try again.\r\n"
            unless $key1 eq $key2;
    } until $key1 eq $key2;
    system "stty echo </dev/tty";
    close(TTY);
    $key1;
}
