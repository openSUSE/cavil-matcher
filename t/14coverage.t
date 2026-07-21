# SPDX-FileCopyrightText: SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Exercises the error and edge paths of the pure-Perl lifecycle layer (Index + Manifest): argument
# validation, no-op guards, compaction failure, corrupt/missing segments and manifests. These are the
# resilience behaviours that keep indexing a whole distribution from ever dying.
use strict;
use warnings;
use Test::More;
use Test::Deep;
use Cavil::Matcher;
use Cavil::Matcher::Index;
use Cavil::Matcher::Manifest;
use File::Temp qw(tempdir);
use File::Spec;

my $sample = [[1, 'permission is hereby granted free of charge']];

# --- Index construction -------------------------------------------------------------------------
eval { Cavil::Matcher::Index->new };
like($@, qr/dir required/, 'Index->new without dir croaks');

my $root  = tempdir(CLEANUP => 1);
my $afile = "$root/a-file";
open my $ftmp, '>', $afile or die $!;
close $ftmp;
eval { Cavil::Matcher::Index->new(dir => $afile) };
like($@, qr/not a directory/, 'Index->new on a plain file croaks');

my $newdir = "$root/created";
ok(!-d $newdir, 'target dir does not exist yet');
my $idx = Cavil::Matcher::Index->new(dir => $newdir);
ok(-d $newdir, 'Index->new creates a missing dir');
is($idx->dir, $newdir, 'dir() accessor');

# --- No-op guards -------------------------------------------------------------------------------
is($idx->add_segment([]),    0, 'add_segment([]) is a no-op at generation 0');
is($idx->add_segment(undef), 0, 'add_segment(undef) is a no-op');
is($idx->tombstone(),        0, 'tombstone() with no ids is a no-op');
is($idx->merge(undef),       1, 'merge(undef) builds an empty base at generation 1');

# --- Compile failures croak (force by colliding the target name with a directory) ----------------
my $d2   = tempdir(CLEANUP => 1);
my $idx2 = Cavil::Matcher::Index->new(dir => $d2);
mkdir "$d2/seg-0000000001.seg";
eval { $idx2->add_segment($sample) };
like($@, qr/failed to compile segment/, 'add_segment croaks when the segment file cannot be written');

my $d3   = tempdir(CLEANUP => 1);
my $idx3 = Cavil::Matcher::Index->new(dir => $d3);
mkdir "$d3/base-0000000001.seg";
eval { $idx3->merge($sample) };
like($@, qr/failed to compile base segment/, 'merge croaks when the base file cannot be written');

# --- matcher() resilience: missing / checksum-mismatch / attach-fail segments --------------------
my $d4   = tempdir(CLEANUP => 1);
my $idx4 = Cavil::Matcher::Index->new(dir => $d4);
$idx4->add_segment($sample);    # a real segment at generation 1
my ($real_seg) = glob "$d4/seg-*.seg";

# Append a manifest entry for a segment that is not on disk.
my $man = Cavil::Matcher::Manifest->new(dir => $d4);
$man->add_segment(file => 'ghost.seg', checksum => 'deadbeef');
$man->save;

my @warns;
{
  local $SIG{__WARN__} = sub { push @warns, $_[0] };
  $idx4->matcher;    # non-quiet
}
ok((grep {/ghost\.seg missing/} @warns), 'warns about a missing segment (non-quiet)');

@warns = ();
{
  local $SIG{__WARN__} = sub { push @warns, $_[0] };
  $idx4->matcher(quiet => 1);
}
is(scalar @warns, 0, 'quiet suppresses the missing-segment warning');

# Corrupt the real segment so its bytes no longer match the manifest checksum.
open my $cf, '>>:raw', $real_seg or die $!;
print {$cf} 'zzzz';
close $cf;
@warns = ();
{
  local $SIG{__WARN__} = sub { push @warns, $_[0] };
  $idx4->matcher;
}
ok((grep {/checksum mismatch/} @warns), 'warns on a checksum mismatch');

# A segment whose manifest checksum is empty skips the checksum check but still fails validation.
my $d5   = tempdir(CLEANUP => 1);
my $idx5 = Cavil::Matcher::Index->new(dir => $d5);
open my $junk, '>:raw', "$d5/junk.seg" or die $!;
print {$junk} 'not a valid compiled segment';
close $junk;
my $m5 = Cavil::Matcher::Manifest->new(dir => $d5);
$m5->add_segment(file => 'junk.seg', checksum => '');    # empty checksum => pattern_count defaults to 0 too
$m5->save;
@warns = ();
my $eng5;
{
  local $SIG{__WARN__} = sub { push @warns, $_[0] };
  $eng5 = $idx5->matcher;
}
ok((grep {/junk\.seg failed validation/} @warns), 'warns when a segment fails to attach');
cmp_deeply($eng5->find_matches('t/fixtures/licenses/04license.1.txt'),
  [], 'index with only a bad segment finds nothing');

@warns = ();
{
  local $SIG{__WARN__} = sub { push @warns, $_[0] };
  $idx5->matcher(quiet => 1);
}
is(scalar @warns, 0, 'quiet suppresses the attach-failure warning');

# A manifest entry with no checksum at all (e.g. an older manifest) skips the integrity check and
# still attaches a valid segment.
my $d7   = tempdir(CLEANUP => 1);
my $idx7 = Cavil::Matcher::Index->new(dir => $d7);
$idx7->add_segment($sample);
my ($seg7) = glob "$d7/seg-*.seg";
my $m7 = Cavil::Matcher::Manifest->new(dir => $d7);
$m7->add_segment(file => (File::Spec->splitpath($seg7))[2], checksum => undef);
$m7->save;
ok(ref $idx7->matcher(quiet => 1)->find_matches('t/fixtures/licenses/04license.1.txt') eq 'ARRAY',
  'segment with an undefined checksum still attaches');

# --- Manifest edge cases ------------------------------------------------------------------------
eval { Cavil::Matcher::Manifest->new };
like($@, qr/dir required/, 'Manifest->new without dir croaks');

my $d6 = tempdir(CLEANUP => 1);
sub write_manifest { open my $fh, '>:raw', "$d6/manifest.json" or die $!; print {$fh} $_[0]; close $fh }

write_manifest('{"format_version":999,"generation":7}');
is(Cavil::Matcher::Manifest->new(dir => $d6)->generation, 0, 'wrong format version reads as empty');

write_manifest('{"generation":5}');    # missing format_version
is(Cavil::Matcher::Manifest->new(dir => $d6)->generation, 0, 'missing format version reads as empty');

write_manifest('{"format_version":1,"segments":[]}');    # valid, but no generation key
is(Cavil::Matcher::Manifest->new(dir => $d6)->generation, 0, 'missing generation defaults to 0');

write_manifest('{"format_version":1,"generation":2,"segments":"nope","tombstones":"nope"}');
my $mm = Cavil::Matcher::Manifest->new(dir => $d6);
is($mm->generation, 2, 'generation preserved from a valid manifest');
ok(ref $mm->data eq 'HASH', 'data() accessor');
is_deeply($mm->segments,   [], 'non-array segments normalized to []');
is_deeply($mm->tombstones, [], 'non-array tombstones normalized to []');

$mm->add_segment(file => 'x.seg', checksum => 'abc');    # no pattern_count -> defaults to 0
is($mm->segments->[0]{pattern_count}, 0, 'pattern_count defaults to 0');

$mm->add_tombstones(1, 2, 3);
$mm->add_tombstones(2, 3, 4);                            # duplicates ignored
is_deeply([sort { $a <=> $b } @{$mm->tombstones}], [1, 2, 3, 4], 'tombstone ids de-duplicated');

# A structurally-malformed manifest (non-hash segments, unsafe/traversal filenames, ref checksums,
# bad pattern_count, non-integer generation, non-scalar tombstones) must be sanitized, not fatal.
write_manifest(<<'JSON');
{"format_version":1,"generation":"not-a-number",
 "segments":["a-string-not-a-hash",
             {"file":"../evil.seg"},
             {"file":"sub/dir.seg"},
             {"file":null},
             {"file":[]},
             {"file":""},
             {"file":"a..b.seg"},
             {"file":"weird.seg","checksum":{"x":1},"pattern_count":"nan"},
             {"file":"good-seg.seg","checksum":"abc","pattern_count":"5"},
             {"file":"bare.seg"},
             {"file":"countref.seg","pattern_count":{}}],
 "tombstones":[1,2,{"x":1},null,"7",4294967297,"99999999999",-5,3.5]}
JSON
my $bad = Cavil::Matcher::Manifest->new(dir => $d6);
is($bad->generation,         0, 'non-integer generation sanitized to 0');
is(scalar @{$bad->segments}, 4, 'only safe, well-formed segment entries survive');
is_deeply(
  $bad->segments,
  [
    {file => 'weird.seg',    checksum => '',    pattern_count => 0},
    {file => 'good-seg.seg', checksum => 'abc', pattern_count => 5},
    {file => 'bare.seg',     checksum => '',    pattern_count => 0},
    {file => 'countref.seg', checksum => '',    pattern_count => 0}
  ],
  'segment fields coerced (ref/empty/traversal names dropped; ref checksum -> "", bad count -> 0)'
);
is_deeply(
  [@{$bad->tombstones}],
  [1, 2, '7'],
  'tombstones sanitized: refs, undef, out-of-range (>uint32), negative and non-integer ids dropped'
);

# Generation given as a non-scalar is also sanitized rather than fatal.
write_manifest('{"format_version":1,"generation":{"x":1}}');
is(Cavil::Matcher::Manifest->new(dir => $d6)->generation, 0, 'non-scalar generation sanitized to 0');

# And the reader (matcher) must not die on it - it degrades to the well-formed (here: missing) segments.
my $bad_idx = Cavil::Matcher::Index->new(dir => $d6);
my $eng     = eval { $bad_idx->matcher(quiet => 1) };
ok(!$@, 'matcher() survives a malformed manifest');
cmp_deeply($eng->find_matches('t/fixtures/licenses/04license.1.txt'), [], 'malformed-manifest index finds nothing');

done_testing();
