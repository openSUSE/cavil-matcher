# SPDX-FileCopyrightText: SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Cavil scans an entire Linux distribution, including binary blobs, malware test corpora and malformed
# samples. The matcher must NEVER crash on any input. A C++ crash would abort this process, so simply
# reaching done_testing() (with sane return values along the way) is the assertion.
use strict;
use warnings;
use Test::More;
use Cavil::Matcher;
use File::Temp qw(tempdir);

srand(42);    # deterministic "random" inputs
my $dir = tempdir(CLEANUP => 1);

# A matcher with a few real-ish patterns, including a skip-heavy (pathological) one.
my $m = Cavil::Matcher::init_matcher();
$m->add_pattern(1, Cavil::Matcher::parse_tokens('permission is hereby granted'));
$m->add_pattern(2, Cavil::Matcher::parse_tokens('copyright $SKIP30 all rights reserved'));
$m->add_pattern(3, Cavil::Matcher::parse_tokens('a $SKIP99 b $SKIP99 c $SKIP99 d'));

sub write_file {
  my ($name, $bytes) = @_;
  my $f = "$dir/$name";
  open my $fh, '>', $f or die $!;
  binmode $fh;
  print {$fh} $bytes;
  close $fh;
  return $f;
}

sub scan_ok {
  my ($name, $bytes) = @_;
  my $f   = write_file($name, $bytes);
  my $res = $m->find_matches($f);
  ok(ref $res eq 'ARRAY', "find_matches survived: $name");
  unlink $f;
}

# --- Hostile scan inputs -------------------------------------------------------------------------
scan_ok('empty',        '');
scan_ok('all_nul',      "\x00" x 4096);
scan_ok('embedded_nul', "permission is\x00hereby granted\ncopyright foo\x00bar all rights reserved\n");
scan_ok('random_bin',   join('', map { chr(int(rand(256))) } 1 .. 20000));
scan_ok('no_newline',   ('a ' x 500_000));                                                # ~1MB single line, no newline
scan_ok('long_token',   ('x' x 100_000) . "\n");
scan_ok('high_bytes',   join('', map { chr(128 + int(rand(128))) } 1 .. 20000) . "\n");
scan_ok('crlf_soup',    ("permission\r\nis\r\nhereby\r\ngranted\r\n" x 100));
scan_ok('null_lines',   ("\x00\n" x 5000));

# Millions of tokens to exercise the sliding-window eviction path.
{
  my $big = '';
  $big .= "tok$_ " for 1 .. 200_000;
  scan_ok('window_eviction', $big);
}

# Scanning a directory path (not a regular file) must not crash.
my $res = $m->find_matches($dir);
ok(ref $res eq 'ARRAY', 'scanning a directory path does not crash');

# --- Hostile inputs to the text primitives -------------------------------------------------------
for my $bytes ('', "\x00\x00", join('', map { chr(int(rand(256))) } 1 .. 5000), ('z' x 50_000)) {
  ok(ref(Cavil::Matcher::parse_tokens($bytes)) eq 'ARRAY', 'parse_tokens survives hostile input');
  ok(ref(Cavil::Matcher::normalize($bytes)) eq 'ARRAY',    'normalize survives hostile input');
  my $h = Cavil::Matcher::init_hash(0, 0);
  $h->add($bytes);
  ok(length($h->hex) == 32, 'hash survives hostile input');
}

# --- Hostile inputs to the bag -------------------------------------------------------------------
my $bag = Cavil::Matcher::init_bag_of_patterns;
$bag->set_patterns({1 => 'permission is hereby granted', 2 => "binary\x00pattern", 3 => ''});
ok(ref($bag->best_for(join('', map { chr(int(rand(256))) } 1 .. 3000), 3)) eq 'ARRAY',
  'bag->best_for survives hostile input');
ok(ref($bag->best_for('', 3)) eq 'ARRAY', 'bag->best_for survives empty input');

# --- Skip fan-out DoS backstop -------------------------------------------------------------------
# A pattern with several wide $SKIP wildcards can fan out combinatorially against a crafted file. A
# rare first anchor ("startmarker") means only one start position enters the deep walk, and the file
# feeds every skip offset with the continuation token - so without the per-start work budget this
# would run ~99^4 steps and effectively hang. The budget must bound it and return promptly.
{
  my $sm = Cavil::Matcher::init_matcher;
  $sm->add_pattern(1, Cavil::Matcher::parse_tokens('startmarker $SKIP99 xx $SKIP99 xx $SKIP99 xx $SKIP99 xx'));
  my $f     = write_file('skip_fanout', 'startmarker ' . ('xx ' x 450));
  my $start = time;
  my $res   = $sm->find_matches($f);
  my $secs  = time - $start;
  unlink $f;
  ok(ref $res eq 'ARRAY', 'skip-heavy pattern returns instead of hanging');
  cmp_ok($secs, '<', 20, 'skip fan-out is bounded by the work budget');
}

pass('reached end without crashing');
done_testing();
