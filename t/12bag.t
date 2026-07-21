# SPDX-FileCopyrightText: SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# BagOfPatterns (the tf-idf closest-match model). Self-contained: a text that is (almost) a full copy
# of one license pattern must rank that pattern first. Covers count-limiting, dump/load and never
# crashing on hostile input. The exhaustive parity check vs the previous engine is in xt/differential.t.
use strict;
use warnings;
use Test::More;
use Test::Deep;
use Cavil::Matcher;
use File::Temp qw(tempdir);

sub slurp { open my $fh, '<:raw', $_[0] or die $!; local $/; my $c = <$fh>; close $fh; $c }

my %patterns;
for my $fn (glob('t/fixtures/licenses/04license.*.pattern')) {
  $fn =~ m/\.(\d+)\.pattern$/ or next;
  $patterns{$1} = slurp($fn);
}
my $bag = Cavil::Matcher::init_bag_of_patterns;
$bag->set_patterns({%patterns});

# Each of these fixture texts is essentially the body of one known pattern, so the bag must pick it.
my %TOP = (1 => 1, 5 => 13, 12 => 29);
for my $num (sort { $a <=> $b } keys %TOP) {
  my $best = $bag->best_for(slurp("t/fixtures/licenses/04license.$num.txt"), 1);
  is($best->[0]{pattern}, $TOP{$num}, "fixture $num resembles pattern $TOP{$num} most");
  cmp_ok($best->[0]{match}, '>', 0.9, "fixture $num scores a strong match");
}

# Count limiting: at most N results, ordered by descending score.
my $top3 = $bag->best_for(slurp('t/fixtures/licenses/04license.1.txt'), 3);
cmp_ok(scalar @$top3, '<=', 3, 'best_for respects the count limit');
ok($top3->[0]{match} >= $top3->[-1]{match}, 'results are ordered by descending score');

# dump / load round-trip ranks identically.
my $dir  = tempdir(CLEANUP => 1);
my $file = "$dir/bag";
ok($bag->dump($file), 'bag dump reports success');
my $loaded = Cavil::Matcher::init_bag_of_patterns;
ok($loaded->load($file), 'bag load succeeds');
for my $num (sort { $a <=> $b } keys %TOP) {
  my $text = slurp("t/fixtures/licenses/04license.$num.txt");
  cmp_deeply($loaded->best_for($text, 3), $bag->best_for($text, 3), "reloaded bag ranks fixture $num identically");
}

# Loading a missing file fails cleanly; hostile inputs never crash.
is($loaded->load("$dir/missing"), 0, 'loading a missing bag returns false');
for my $text ('', 'x', "binary\x00text", join('', map { chr(int(rand(256))) } 1 .. 2000)) {
  ok(ref($bag->best_for($text, 3)) eq 'ARRAY', 'best_for survives hostile/edge input');
}

# Asking for zero (or, via the XS boundary, a negative) result count returns nothing - never UB.
is_deeply($bag->best_for('permission is hereby granted',  0), [], 'best_for(count=0) returns empty');
is_deeply($bag->best_for('permission is hereby granted', -1), [], 'best_for(negative count) returns empty');

# The cache is a versioned, CRC-checked format: truncated / wrong-magic / wrong-version / corrupt
# files are all rejected, and a rejected load must leave any existing model intact (not wipe it).
my $sample = slurp('t/fixtures/licenses/04license.1.txt');
my $before = $loaded->best_for($sample, 1);
ok(@$before, 'model matches before a bad load');
my $good = slurp($file);

sub write_bytes { my ($p, $b) = @_; open my $o, '>:raw', $p or die $!; print {$o} $b; close $o; $p }

# Truncated payload (valid header, partial body): CRC fails.
is($loaded->load(write_bytes("$dir/truncated", substr($good, 0, 48))), 0, 'truncated bag rejected');

# Not a bag at all (wrong magic).
is($loaded->load(write_bytes("$dir/garbage", 'not a bag file, just some bytes here at all')),
  0, 'wrong-magic bag rejected');

# Valid magic but a flipped payload byte fails the CRC.
my $corrupt = $good;
substr($corrupt, length($corrupt) - 1, 1) = chr(ord(substr($corrupt, length($corrupt) - 1, 1)) ^ 0xFF);
is($loaded->load(write_bytes("$dir/corrupt", $corrupt)), 0, 'flipped payload byte fails CRC');

cmp_deeply($loaded->best_for($sample, 1), $before, 'the existing model is intact after every failed load');

done_testing();
