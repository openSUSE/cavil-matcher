# SPDX-FileCopyrightText: SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Segment mechanics at the engine level: multi-segment union, tombstones, and the versioned/validated
# on-disk format. A corrupt or hostile segment file must be rejected, never mis-read or crashed on.
use strict;
use warnings;
use Test::More;
use Test::Deep;
use Cavil::Matcher;
use File::Temp qw(tempdir);

my $dir = tempdir(CLEANUP => 1);

sub slurp          { open my $fh, '<', $_[0] or die $!; local $/; my $c = <$fh>; close $fh; $c }
sub sorted_matches { [sort { $a->[0] <=> $b->[0] || $a->[1] <=> $b->[1] } @{$_[0]}] }

# Load a handful of real patterns.
my %pat;
for my $fn (glob('t/fixtures/licenses/04license.*.pattern')) {
  $fn =~ m/\.(\d+)\.pattern$/ or next;
  $pat{$1} = slurp($fn);
}
my @ids = sort { $a <=> $b } keys %pat;

# --- Reference: one matcher with every pattern ---------------------------------------------------
my $all = Cavil::Matcher::init_matcher();
$all->add_pattern($_, Cavil::Matcher::parse_tokens($pat{$_})) for @ids;

# --- Split the same patterns across two compiled segments ----------------------------------------
my $half = int(@ids / 2);
my $ma   = Cavil::Matcher::init_matcher();
$ma->add_pattern($_, Cavil::Matcher::parse_tokens($pat{$_})) for @ids[0 .. $half - 1];
my $seg_a = "$dir/a.seg";
ok($ma->dump($seg_a), 'compiled segment A');

my $mb = Cavil::Matcher::init_matcher();
$mb->add_pattern($_, Cavil::Matcher::parse_tokens($pat{$_})) for @ids[$half .. $#ids];
my $seg_b = "$dir/b.seg";
ok($mb->dump($seg_b), 'compiled segment B');

my $multi = Cavil::Matcher::init_matcher();
ok($multi->attach($seg_a), 'attach segment A');
ok($multi->attach($seg_b), 'attach segment B');

# Union of two segments equals the single all-patterns matcher (compared as sets).
for my $fn (sort glob('t/fixtures/licenses/04license.*.txt')) {
  cmp_deeply(
    sorted_matches($multi->find_matches($fn)),
    sorted_matches($all->find_matches($fn)),
    "two-segment union equals single matcher for $fn"
  );
}

# --- Tombstones: drop one pattern id; its matches vanish, others remain --------------------------
# Pick a pattern id that actually matches somewhere.
my ($victim, $victim_file);
for my $fn (sort glob('t/fixtures/licenses/04license.*.txt')) {
  for my $m (@{$all->find_matches($fn)}) { ($victim, $victim_file) = ($m->[0], $fn); last; }
  last if $victim;
}
ok($victim, "found a matching pattern id ($victim) to tombstone");

my $tomb = Cavil::Matcher::init_matcher();
$tomb->attach($seg_a);
$tomb->attach($seg_b);
$tomb->set_tombstones([$victim]);
my @still = grep { $_->[0] == $victim } @{$tomb->find_matches($victim_file)};
is(scalar @still, 0, 'tombstoned pattern produces no matches');

# The real invariant: tombstoning a pattern yields exactly the same result as a corpus that never
# contained it - because tombstones are filtered *before* overlap resolution, removing a match can
# correctly reveal smaller matches it used to suppress. Compare against a matcher built without the
# victim across every fixture (as sets).
my $without = Cavil::Matcher::init_matcher();
$without->add_pattern($_, Cavil::Matcher::parse_tokens($pat{$_})) for grep { $_ != $victim } @ids;
for my $fn (sort glob('t/fixtures/licenses/04license.*.txt')) {
  cmp_deeply(
    sorted_matches($tomb->find_matches($fn)),
    sorted_matches($without->find_matches($fn)),
    "tombstoning $victim equals a corpus without it for $fn"
  );
}

# --- Format safety: corrupt segments are rejected, never mis-read or crashed on -------------------
my $good = slurp($seg_a);

sub attach_bytes {
  my $bytes = shift;
  my $f     = "$dir/corrupt.$$." . int(rand(1e9));
  open my $fh, '>', $f or die $!;
  binmode $fh;
  print {$fh} $bytes;
  close $fh;
  my $m  = Cavil::Matcher::init_matcher();
  my $ok = $m->attach($f);
  unlink $f;
  return $ok;
}

is(attach_bytes($good), 1, 'a valid segment attaches');

my $bad_magic = $good;
substr($bad_magic, 0, 1) = 'X';
is(attach_bytes($bad_magic), 0, 'wrong magic rejected');

my $bad_version = $good;
substr($bad_version, 8, 4) = pack('L', 999);
is(attach_bytes($bad_version), 0, 'wrong format version rejected');

my $bad_crc = $good;
substr($bad_crc, length($bad_crc) - 1, 1) = chr((ord(substr($bad_crc, length($bad_crc) - 1, 1)) ^ 0xFF));
is(attach_bytes($bad_crc), 0, 'flipped payload byte fails CRC');

is(attach_bytes(substr($good, 0, 20)),                                0, 'truncated file rejected');
is(attach_bytes(''),                                                  0, 'empty file rejected');
is(attach_bytes('not a segment at all, just random text bytes here'), 0, 'garbage file rejected');

# A matcher whose only segment failed to attach simply finds nothing (no crash).
my $none = Cavil::Matcher::init_matcher();
$none->attach("$dir/does-not-exist.seg");
cmp_deeply($none->find_matches('t/fixtures/licenses/04license.1.txt'), [], 'missing segment => no matches, no crash');

done_testing();
