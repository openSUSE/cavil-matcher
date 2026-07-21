# SPDX-FileCopyrightText: SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later

package Cavil::Matcher;

use strict;
use warnings;

our $VERSION = '0.01';

require XSLoader;
XSLoader::load('Cavil::Matcher', $VERSION);

package Cavil::Matcher::Hash;

# 128-bit digest as a 32-character hex string, matching the previous engine byte-for-byte so stored
# snippet and line checksums stay valid.
sub hex {
  my $self = shift;
  my $hash = $self->hash128;
  return sprintf('%016x%016x', $hash->[0], $hash->[1]);
}

sub hash64 {
  my $self = shift;
  return $self->hash128->[0];
}

1;

__END__

=encoding utf8

=head1 NAME

Cavil::Matcher - Next-generation license pattern matcher for Cavil

=head1 SYNOPSIS

  use Cavil::Matcher;

  my $m = Cavil::Matcher::init_matcher;
  $m->add_pattern(1, Cavil::Matcher::parse_tokens('Permission is hereby granted $SKIP30 to deal'));
  my $matches = $m->find_matches('source/file.c');   # [[pattern_id, start_line, end_line], ...]

=head1 DESCRIPTION

C<Cavil::Matcher> turns source files into license and keyword matches for
L<Cavil|https://github.com/openSUSE/cavil>. It keeps the proven token-hash prefix-tree algorithm of its
predecessor, L<Spooky::Patterns::XS>, but stores the compiled patterns as immutable, memory-mapped
B<segments> described by a small B<manifest>, so that adding or removing a pattern never rebuilds the whole
cache and index workers share one physical copy of the data per host.

The tokenizer and hashing are a frozen C++ core, bit-for-bit compatible with the previous engine; the segment
lifecycle is pure Perl (see L<Cavil::Matcher::Index> and L<Cavil::Matcher::Manifest>). For the design and
rationale see F<docs/Architecture.md>.

=head1 FUNCTIONS

=head2 init_matcher

  my $matcher = Cavil::Matcher::init_matcher;

Create a new matching engine (a L</Cavil::Matcher::Engine>).

=head2 parse_tokens

  my $tokens = Cavil::Matcher::parse_tokens($pattern_text);

Tokenize pattern text into the arrayref of token hashes that L</add_pattern> expects. C<$SKIP<n>> wildcards
(match up to I<n> arbitrary words, I<n> up to 99) are recognised here; a pattern may not begin or end with a
skip.

=head2 normalize

  my $rows = Cavil::Matcher::normalize($text);   # [[line, token, hash], ...]

Tokenize arbitrary text, returning each token with its line number and hash.

=head2 distance

  my $edits = Cavil::Matcher::distance($norm_a, $norm_b);

Token-level Levenshtein distance between two L</normalize> results.

=head2 read_lines

  my $rows = Cavil::Matcher::read_lines($file, \%wanted_lines);   # [[line, value, text], ...]

Return the requested lines of a file as raw (undecoded) bytes. B<Note:> C<%wanted_lines> is consumed -
each line found is deleted from the hash (an early-exit optimization), so pass a fresh hash if you need
to reuse it.

=head2 init_hash

  my $hash = Cavil::Matcher::init_hash($seed1, $seed2);

Create a streaming 128-bit content hash (a L</Cavil::Matcher::Hash>).

=head2 init_bag_of_patterns

  my $bag = Cavil::Matcher::init_bag_of_patterns;

Create a tf-idf "closest match" model (a L</Cavil::Matcher::Bag>).

=head1 Cavil::Matcher::Engine

The matching engine returned by L</init_matcher>.

=over 2

=item add_pattern($id, $tokens)

Add a pattern (from L</parse_tokens>) to the in-memory delta segment.

=item find_matches($file)

Scan a file and return the resolved matches as C<[[pattern_id, start_line, end_line], ...]>.

=item dump($file) / load($file)

Write the in-memory patterns to a compiled segment file / replace the engine's state with a single mmapped
segment file.

=item attach($file)

Memory-map an additional compiled segment into the active set. Returns false (without dying) on a missing or
invalid file.

=item set_tombstones(\@pattern_ids)

Drop these pattern ids from results before overlap resolution.

=item set_generation($n)

Record the manifest generation this engine was built from (for reproducibility).

=back

=head1 Cavil::Matcher::Hash

Streaming content hash from L</init_hash>: C<add($bytes)>, C<hash128> (C<[hi, lo]>), C<hex> (32-char string)
and C<hash64>.

=head1 Cavil::Matcher::Bag

tf-idf closest-match model from L</init_bag_of_patterns>: C<set_patterns(\%id_to_text)>,
C<best_for($text, $count)>, C<dump($file)> and C<load($file)>. C<dump> and C<load> return true on
success; a failed C<load> (missing/truncated file) leaves the model unchanged.

=head1 SEE ALSO

L<Cavil::Matcher::Index>, L<Cavil::Matcher::Manifest>, L<https://github.com/openSUSE/cavil>.

=head1 COPYRIGHT AND LICENSE

Copyright (C) SUSE LLC. This is free software, licensed under GPL-2.0-or-later.

=cut

