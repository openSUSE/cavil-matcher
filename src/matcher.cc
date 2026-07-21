// SPDX-FileCopyrightText: SUSE LLC
// SPDX-License-Identifier: GPL-2.0-or-later

#include "matcher.h"

#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// Same safety limit as the previous engine: lines longer than this are read in chunks by fgets, so a
// giant single-line file never overflows the buffer.
static const int MAX_LINE_SIZE = 8000;

MappedFile::~MappedFile() {
  if (_data && _data != MAP_FAILED) munmap((void*)_data, _size);
  if (_fd >= 0) close(_fd);
}

bool MappedFile::map(const std::string& path) {
  _fd = open(path.c_str(), O_RDONLY);
  if (_fd < 0) return false;
  struct stat st;
  if (fstat(_fd, &st) != 0 || st.st_size <= 0) {
    close(_fd);
    _fd = -1;
    return false;
  }
  void* p = mmap(nullptr, (size_t)st.st_size, PROT_READ, MAP_SHARED, _fd, 0);
  if (p == MAP_FAILED) {
    close(_fd);
    _fd = -1;
    return false;
  }
  _data = static_cast<const char*>(p);
  _size = (size_t)st.st_size;
  return true;
}

void Matcher::clear() {
  _build       = BuildTrie();
  _build_dirty = false;
  _build_segment = Segment();
  _segments.clear();
  _maps.clear();
  _tombstones.clear();
}

void Matcher::add_pattern(uint32_t id, const std::vector<uint64_t>& tokens) {
  _build.add_pattern(id, tokens);
  _build_dirty = true;
}

void Matcher::set_tombstones(const std::vector<uint32_t>& ids) {
  _tombstones.clear();
  for (uint32_t id : ids) _tombstones.insert(id);
}

bool Matcher::attach(const std::string& path) {
  auto mf = std::make_unique<MappedFile>();
  if (!mf->map(path)) return false;
  auto seg = std::make_unique<Segment>();
  if (!seg->open(mf->data(), mf->size())) return false;
  _maps.push_back(std::move(mf));
  _segments.push_back(std::move(seg));
  return true;
}

bool Matcher::dump(const std::string& path) {
  std::vector<char> buf = _build.compile(_generation);
  FILE*             f   = fopen(path.c_str(), "wb");
  if (!f) return false;
  bool ok = fwrite(buf.data(), 1, buf.size(), f) == buf.size();
  if (fclose(f) != 0) ok = false;
  return ok;
}

bool Matcher::load(const std::string& path) {
  clear();
  return attach(path);
}

void Matcher::collect_active(std::vector<const Segment*>& out) {
  if (_build_dirty) {
    _build_segment.open_owned(_build.compile(_generation));
    _build_dirty = false;
  }
  if (_build_segment.valid()) out.push_back(&_build_segment);
  for (auto& s : _segments)
    if (s->valid()) out.push_back(s.get());
}

// If either the start or the end of one region is within the other.
static bool match_overlap(int s1, int e1, int s2, int e2) {
  if (s1 >= s2 && s1 <= e2) return true;
  if (e1 >= s2 && e1 <= e2) return true;
  return false;
}

std::vector<ResolvedMatch> Matcher::find_matches(const std::string& path) {
  std::vector<ResolvedMatch> result;

  std::vector<const Segment*> segs;
  collect_active(segs);
  if (segs.empty()) return result;

  int64_t longest = 1;
  for (const Segment* s : segs)
    if (s->longest_pattern() > longest) longest = s->longest_pattern();

  FILE* input = fopen(path.c_str(), "r");
  if (!input) return result;

  std::vector<RawMatch> ms;
  char                  line[MAX_LINE_SIZE];
  int                   linenumber   = 1;
  TokenList             ts;
  int                   token_offset = 0;

  // Line numbers count physical newlines, not read chunks. fgets stops at the first newline or when
  // the buffer fills, so a physical line longer than the buffer arrives in several chunks; we advance
  // the line number only on the chunk that actually ended with a newline, so all pieces of one long
  // line share one (correct) number. Memory stays bounded - we keep reading fixed-size chunks rather
  // than slurping whole lines, so a pathological single line cannot exhaust memory. (This intentionally
  // differs from the previous engine, which counted chunks; it fixes wrong line numbers on long lines.)
  while (fgets(line, sizeof(line) - 1, input)) {
    size_t chunk_len = strlen(line);
    bool   line_end  = chunk_len > 0 && line[chunk_len - 1] == '\n';
    tokenizer().tokenize(ts, line, linenumber);
    if (line_end) ++linenumber;
    if ((int64_t)ts.size() > longest * 100) {
      int erasing = (int)ts.size() - (int)longest - 1;
      if (erasing > 0) {
        for (int i = 0; i < erasing; ++i)
          for (const Segment* s : segs) s->find_tokens(ts, ms, token_offset, i);
        ts.erase(ts.begin(), ts.begin() + erasing);
        token_offset += erasing;
      }
    }
  }
  fclose(input);

  for (int i = 0; i < (int)ts.size(); ++i)
    for (const Segment* s : segs) s->find_tokens(ts, ms, token_offset, i);

  // Drop tombstoned patterns before resolution, so a tombstoned (possibly longer) match can never
  // suppress a genuine one.
  if (!_tombstones.empty()) {
    std::vector<RawMatch> kept;
    kept.reserve(ms.size());
    for (const RawMatch& m : ms)
      if (_tombstones.find(m.pattern) == _tombstones.end()) kept.push_back(m);
    ms.swap(kept);
  }

  // Frozen overlap resolution: the longer match wins; on an exact tie the higher (newer) pattern id
  // wins, on the assumption that newer patterns are the more specific ones.
  while (!ms.empty()) {
    RawMatch best = ms.front();
    for (const RawMatch& it : ms) {
      if (best.matched < it.matched || (best.matched == it.matched && best.pattern < it.pattern)) best = it;
    }
    result.push_back({best.pattern, best.sline, best.eline});
    std::vector<RawMatch> rest;
    rest.reserve(ms.size());
    for (const RawMatch& it : ms) {
      if (!match_overlap(it.start, it.start + it.matched - 1, best.start, best.start + best.matched - 1))
        rest.push_back(it);
    }
    ms.swap(rest);
  }

  return result;
}
