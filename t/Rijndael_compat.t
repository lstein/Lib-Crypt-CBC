#!/usr/local/bin/perl

use strict;
use lib '..','../blib/lib','.','./blib/lib';

my ($i, $j, $test_data);

eval "use Crypt::Rijndael";
if ($@) {
    warn "Crypt::Rijndael not installed\n";
    print "1..0\n";
    exit;
}

print "1..32\n";

sub test {
    local($^W) = 0;
    my($num, $true,$msg) = @_;
    print($true ? "ok $num\n" : "not ok $num $msg\n");
}

sub pad {
   my ($s,$decrypt) = @_;
   if ($decrypt eq 'd') {
     $s =~ s/10*$//s;
   } else {
      $s .= '1' . ('0' x (16 - length($s) % 16 - 1) );
   }
   return $s;
}

$test_data = <<END;
Mary had a little lamb,
Its fleece was black as coal,
And everywere that Mary went,
That lamb would dig a hole.
END
    ;

eval "use Crypt::CBC";

test(1,!$@,"Couldn't load module");
test(2,$i = Crypt::CBC->new({key => 'a' x 16, 
                             cipher => 'Rijndael',
                             iv => 'f' x 16,
                             regenerate_key => 0,
                             prepend_iv => 0,
                             padding => 'oneandzeroes'
                           }),
                           "Couldn't create new object");
test(3,$j = Crypt::Rijndael->new('a' x 16, Crypt::Rijndael->MODE_CBC),
                           "Couldn't create new object");
test(4,$j->set_iv('f' x 16));

test(5,$i->encrypt($test_data) == $j->encrypt($test_data),"Encrypt doesn't match");

test(6,$i->decrypt($i->encrypt($test_data)) eq $j->decrypt($j->encrypt($test_data)),"Decrypt doesn't match");

# now try various truncations of the whole
for (my $c=1;$c<=7;$c++) {
  substr($test_data,-$c) = '';  # truncate
  test(6+$c,$i->decrypt($i->encrypt($test_data)) eq &pad($j->decrypt($j->encrypt(&pad($test_data,'e'))),'d'),"Decrypt doesn't match" );
}


# now try various short strings
for (my $c=0;$c<=18;$c++) {
  $test_data = 'i' x $c;
  test(14+$c,$i->decrypt($i->encrypt($test_data)) eq &pad($j->decrypt($j->encrypt(&pad($test_data,'e'))),'d'),"Decrypt doesn't match" );
}

