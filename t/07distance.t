# SPDX-FileCopyrightText: SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# distance() is a token-level Levenshtein over normalize() output. Self-contained: a pinned value on
# the fixtures, identity, and robustness on degenerate input.
use strict;
use warnings;
use Test::More;
use Cavil::Matcher;

sub slurp { open my $fh, '<:raw', $_[0] or die $!; local $/; my $c = <$fh>; close $fh; $c }

my $p1 = Cavil::Matcher::normalize(slurp('t/fixtures/text/07close.p1'));
my $p2 = Cavil::Matcher::normalize(slurp('t/fixtures/text/07close.p2'));

is(Cavil::Matcher::distance($p1, $p2), 4, 'pinned distance between the two close fixtures');
is(Cavil::Matcher::distance($p1, $p1), 0, 'distance to self is zero');

# Never crash on empty / single-token inputs (av_len is -1 for an empty array).
for my $pair (
  [[],                               []],
  [Cavil::Matcher::normalize(''),    Cavil::Matcher::normalize('word')],
  [Cavil::Matcher::normalize('one'), Cavil::Matcher::normalize('two words here')]
  )
{
  my $d = Cavil::Matcher::distance($pair->[0], $pair->[1]);
  ok(defined $d && $d >= 0, 'distance stays sane on degenerate input');
}

done_testing();
