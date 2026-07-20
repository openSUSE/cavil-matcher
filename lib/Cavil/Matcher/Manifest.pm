# SPDX-FileCopyrightText: SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# The manifest is the small, human-readable JSON file that names the active segments of an index, the
# set of tombstoned pattern ids, and a monotonic generation counter. It is pure Perl on purpose: this
# is policy, not the hot path, and it is where a new developer should be able to see the whole state of
# an index at a glance. Writes are atomic (temp + rename) so a reader never sees a half-written file.

package Cavil::Matcher::Manifest;

use strict;
use warnings;
use v5.20;
use feature 'signatures';
no warnings 'experimental::signatures';

use Cpanel::JSON::XS ();
use Carp 'croak';

use constant FORMAT_VERSION => 1;

sub new ($class, %args) {
  croak 'dir required' unless defined $args{dir};
  my $dir  = $args{dir};
  my $self = bless {dir => $dir, file => "$dir/manifest.json"}, $class;
  $self->{data} = $self->_read;
  return $self;
}

sub _default {
  return {format_version => FORMAT_VERSION, generation => 0, segments => [], tombstones => []};
}

# A manifest that cannot be read or parsed, or that carries an unknown format version, is treated as
# empty rather than fatal - the index simply rebuilds. Never dies on a bad file.
sub _read ($self) {
  return _default() unless -r $self->{file};
  my $json = do {
    open my $fh, '<:raw', $self->{file} or return _default();    # uncoverable branch true (unreadable after stat)
    local $/;
    <$fh>;
  };
  my $data = eval { Cpanel::JSON::XS->new->decode($json) };
  return _default() unless ref $data eq 'HASH' && ($data->{format_version} // 0) == FORMAT_VERSION;
  $data->{generation} = 0  unless defined $data->{generation};
  $data->{segments}   = [] unless ref $data->{segments} eq 'ARRAY';
  $data->{tombstones} = [] unless ref $data->{tombstones} eq 'ARRAY';
  return $data;
}

sub data       ($self) { $self->{data} }
sub generation ($self) { $self->{data}{generation} }
sub segments   ($self) { $self->{data}{segments} }
sub tombstones ($self) { $self->{data}{tombstones} }

sub bump ($self) { return ++$self->{data}{generation} }

sub add_segment ($self, %entry) {
  push @{$self->{data}{segments}},
    {file => $entry{file}, checksum => $entry{checksum}, pattern_count => $entry{pattern_count} // 0};
  return $self;
}

sub set_segments ($self, @segs) {
  $self->{data}{segments} = [@segs];
  return $self;
}

sub add_tombstones ($self, @ids) {
  my %seen = map { $_ => 1 } @{$self->{data}{tombstones}};
  push @{$self->{data}{tombstones}}, grep { !$seen{$_}++ } @ids;
  return $self;
}

sub clear_tombstones ($self) {
  $self->{data}{tombstones} = [];
  return $self;
}

# Atomic write: encode, write to a temp file, then rename over the real one.
sub save ($self) {
  my $json = Cpanel::JSON::XS->new->canonical->pretty->encode($self->{data});
  my $tmp  = "$self->{file}.tmp.$$";
  open my $fh, '>:raw', $tmp or croak "cannot write manifest: $!";     # uncoverable branch true (I/O error)
  print {$fh} $json or croak "cannot write manifest: $!";              # uncoverable branch true (I/O error)
  close $fh         or croak "cannot write manifest: $!";              # uncoverable branch true (I/O error)
  rename $tmp, $self->{file} or croak "cannot rename manifest: $!";    # uncoverable branch true (I/O error)
  return $self;
}

1;
