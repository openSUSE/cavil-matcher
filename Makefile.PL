# SPDX-FileCopyrightText: SUSE LLC
# SPDX-License-Identifier: GPL-2.0-or-later

use strict;
use warnings;
use ExtUtils::MakeMaker;

# C++ core lives under src/; the XS shim (Matcher.xs) at the top marshals between Perl and it.
my @cpp = qw(SpookyV2.cpp tokenizer.cc segment.cc matcher.cc bag.cc bindings.cc);
my @obj = ('$(BASEEXT)$(OBJ_EXT)');    # the compiled XS shim (Matcher$(OBJ_EXT))
for my $src (@cpp) {
  (my $o = $src) =~ s/\.(?:cc|cpp)$/\$(OBJ_EXT)/;
  push @obj, "src/$o";
}

WriteMakefile(
  NAME             => 'Cavil::Matcher',
  VERSION_FROM     => 'lib/Cavil/Matcher.pm',
  ABSTRACT_FROM    => 'lib/Cavil/Matcher.pm',
  AUTHOR           => 'Sebastian Riedel <sriedel@suse.com>',
  LICENSE          => 'gpl_2',
  MIN_PERL_VERSION => '5.020',

  CC     => 'g++',
  LD     => 'g++',
  XSOPT  => '-C++',
  INC    => '-Isrc',
  DEFINE => '-O2 -Wall -Wno-unused-value -Wno-format-security -std=c++17',
  OBJECT => join(' ', @obj),

  CONFIGURE_REQUIRES => {'ExtUtils::MakeMaker' => '7.12'},
  PREREQ_PM          => {'Cpanel::JSON::XS'    => '4.09'},
  TEST_REQUIRES      => {'Test::More'          => '0.98', 'Test::Deep' => 0},

  META_MERGE => {
    'meta-spec'    => {version => 2},
    dynamic_config => 0,
    resources      => {
      repository => {
        type => 'git',
        url  => 'https://github.com/openSUSE/cavil-matcher.git',
        web  => 'https://github.com/openSUSE/cavil-matcher'
      },
      bugtracker => {web => 'https://github.com/openSUSE/cavil-matcher/issues'},
      license    => ['https://www.gnu.org/licenses/old-licenses/gpl-2.0.html'],
    },
    prereqs => {runtime => {recommends => {'Spooky::Patterns::XS' => 0}}},
  },

  clean  => {FILES => 'cover_db'},
  depend => {
    'src/bindings$(OBJ_EXT)'  => 'src/bindings.h src/tokenizer.h src/segment.h src/matcher.h src/bag.h src/SpookyV2.h',
    'src/matcher$(OBJ_EXT)'   => 'src/matcher.h src/segment.h src/tokenizer.h',
    'src/segment$(OBJ_EXT)'   => 'src/segment.h src/tokenizer.h',
    'src/tokenizer$(OBJ_EXT)' => 'src/tokenizer.h src/SpookyV2.h',
    'src/bag$(OBJ_EXT)'       => 'src/bag.h src/tokenizer.h',
  },
);

# GNU make pattern rules to compile the C++ core in src/ using MakeMaker's own compiler flags, so the
# object files land next to their sources instead of cluttering the top level.
sub MY::postamble {
  return <<'MAKE';
src/%$(OBJ_EXT) : src/%.cc
	$(CCCMD) $(CCCDLFLAGS) "-I$(PERL_INC)" $(PASTHRU_DEFINE) $(DEFINE) -o $@ $<

src/%$(OBJ_EXT) : src/%.cpp
	$(CCCMD) $(CCCDLFLAGS) "-I$(PERL_INC)" $(PASTHRU_DEFINE) $(DEFINE) -o $@ $<
MAKE
}
