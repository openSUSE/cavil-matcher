// SPDX-FileCopyrightText: SUSE LLC
// SPDX-License-Identifier: GPL-2.0-or-later

#include "segment.h"

#include <cstring>
#include <iostream>

// ---------------------------------------------------------------------------
// CRC32 (IEEE, reflected) - small table-based implementation, no dependencies.
// ---------------------------------------------------------------------------
uint32_t cavil_crc32(const void* data, size_t len) {
  static uint32_t table[256];
  static bool     ready = false;
  if (!ready) {
    for (uint32_t i = 0; i < 256; ++i) {
      uint32_t c = i;
      for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
      table[i] = c;
    }
    ready = true;
  }
  const uint8_t* p   = static_cast<const uint8_t*>(data);
  uint32_t       crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < len; ++i) crc = table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
  return crc ^ 0xFFFFFFFFu;
}

// ---------------------------------------------------------------------------
// BuildTrie
// ---------------------------------------------------------------------------
BuildTrie::BuildTrie() { _nodes.emplace_back(); }    // node 0 = root

void BuildTrie::add_pattern(uint32_t id, const std::vector<uint64_t>& tokens) {
  if (tokens.empty()) {
    std::cerr << "cavil-matcher: add failed for id " << id << " (empty pattern)" << std::endl;
    return;
  }

  uint32_t current = 0;
  for (uint64_t tok : tokens) {
    if (tok <= (uint64_t)MAX_SKIP) {
      uint8_t val = (uint8_t)tok;
      auto    it  = _nodes[current].skips.find(val);
      if (it == _nodes[current].skips.end()) {
        uint32_t next = (uint32_t)_nodes.size();
        _nodes.emplace_back();
        _nodes[current].skips[val] = next;
        current                    = next;
      } else {
        current = it->second;
      }
    } else {
      auto it = _nodes[current].children.find(tok);
      if (it == _nodes[current].children.end()) {
        uint32_t next = (uint32_t)_nodes.size();
        _nodes.emplace_back();
        _nodes[current].children[tok] = next;
        current                       = next;
      } else {
        current = it->second;
      }
    }
  }

  if (_nodes[current].pid)
    std::cerr << "cavil-matcher: id " << id << " overwrites " << _nodes[current].pid << std::endl;
  _nodes[current].pid = id;

  if ((int64_t)tokens.size() > _longest) _longest = (int64_t)tokens.size();
  _pattern_count++;
}

std::vector<char> BuildTrie::compile(uint64_t generation) const {
  uint32_t node_count  = (uint32_t)_nodes.size();
  uint32_t child_count = 0;
  uint32_t skip_count  = 0;
  for (const auto& n : _nodes) {
    child_count += (uint32_t)n.children.size();
    skip_count += (uint32_t)n.skips.size();
  }

  size_t nodes_bytes = (size_t)node_count * sizeof(FlatNode);
  size_t child_bytes = (size_t)child_count * sizeof(FlatChild);
  size_t skip_bytes  = (size_t)skip_count * sizeof(FlatSkip);
  size_t total       = sizeof(SegmentHeader) + nodes_bytes + child_bytes + skip_bytes;

  std::vector<char> buf(total, 0);
  char*             p          = buf.data();
  SegmentHeader*    h          = reinterpret_cast<SegmentHeader*>(p);
  FlatNode*         nodes      = reinterpret_cast<FlatNode*>(p + sizeof(SegmentHeader));
  FlatChild*        children   = reinterpret_cast<FlatChild*>(p + sizeof(SegmentHeader) + nodes_bytes);
  FlatSkip*         skips      = reinterpret_cast<FlatSkip*>(p + sizeof(SegmentHeader) + nodes_bytes + child_bytes);

  uint32_t ci = 0, si = 0;
  for (uint32_t i = 0; i < node_count; ++i) {
    const BuildNode& bn = _nodes[i];
    nodes[i].pid        = bn.pid;
    nodes[i].child_start = ci;
    nodes[i].child_len   = (uint32_t)bn.children.size();
    for (const auto& kv : bn.children) {    // std::map iterates sorted by hash
      children[ci].hash       = kv.first;
      children[ci].child_node = kv.second;
      children[ci].pad        = 0;
      ci++;
    }
    nodes[i].skip_start = si;
    nodes[i].skip_len   = (uint32_t)bn.skips.size();
    for (const auto& kv : bn.skips) {
      skips[si].child_node = kv.second;
      skips[si].skip_value = kv.first;
      skips[si].pad[0] = skips[si].pad[1] = skips[si].pad[2] = 0;
      si++;
    }
  }

  memcpy(h->magic, SEGMENT_MAGIC, 8);
  h->format_version = SEGMENT_FORMAT_VERSION;
  h->flags          = 0;
  h->generation     = generation;
  h->longest_pattern = _longest;
  h->node_count     = node_count;
  h->child_count    = child_count;
  h->skip_count     = skip_count;
  h->pattern_count  = _pattern_count;
  h->reserved       = 0;
  h->payload_crc32  = cavil_crc32(p + sizeof(SegmentHeader), total - sizeof(SegmentHeader));

  return buf;
}

// ---------------------------------------------------------------------------
// Segment (read side)
// ---------------------------------------------------------------------------
bool Segment::open_owned(std::vector<char>&& buf) {
  _owned = std::move(buf);
  return open(_owned.data(), _owned.size());
}

bool Segment::open(const char* data, size_t len) {
  _valid  = false;
  _base   = data;
  _len    = len;
  _header = nullptr;

  if (!data || len < sizeof(SegmentHeader)) return false;
  const SegmentHeader* h = reinterpret_cast<const SegmentHeader*>(data);
  if (memcmp(h->magic, SEGMENT_MAGIC, 8) != 0) return false;
  if (h->format_version != SEGMENT_FORMAT_VERSION) return false;
  if (h->node_count < 1) return false;    // root must exist

  size_t nodes_bytes = (size_t)h->node_count * sizeof(FlatNode);
  size_t child_bytes = (size_t)h->child_count * sizeof(FlatChild);
  size_t skip_bytes  = (size_t)h->skip_count * sizeof(FlatSkip);
  size_t total       = sizeof(SegmentHeader) + nodes_bytes + child_bytes + skip_bytes;
  if (total < sizeof(SegmentHeader) || total > len) return false;    // overflow / truncation

  if (cavil_crc32(data + sizeof(SegmentHeader), total - sizeof(SegmentHeader)) != h->payload_crc32) return false;

  const FlatNode*  nodes    = reinterpret_cast<const FlatNode*>(data + sizeof(SegmentHeader));
  const FlatChild* children = reinterpret_cast<const FlatChild*>(data + sizeof(SegmentHeader) + nodes_bytes);
  const FlatSkip*  skips = reinterpret_cast<const FlatSkip*>(data + sizeof(SegmentHeader) + nodes_bytes + child_bytes);

  // Validate every index/range once, so the scan can trust the structure completely.
  for (uint32_t i = 0; i < h->node_count; ++i) {
    const FlatNode& n = nodes[i];
    if ((size_t)n.child_start + n.child_len > h->child_count) return false;
    if ((size_t)n.skip_start + n.skip_len > h->skip_count) return false;
    for (uint32_t c = 0; c < n.child_len; ++c) {
      const FlatChild& fc = children[n.child_start + c];
      if (fc.child_node >= h->node_count) return false;
      if (c > 0 && !(children[n.child_start + c - 1].hash < fc.hash)) return false;    // must be sorted asc
    }
    for (uint32_t s = 0; s < n.skip_len; ++s) {
      if (skips[n.skip_start + s].child_node >= h->node_count) return false;
    }
  }

  _header   = h;
  _nodes    = nodes;
  _children = children;
  _skips    = skips;
  _valid    = true;
  return true;
}

uint32_t Segment::find_child(uint32_t node, uint64_t hash) const {
  const FlatNode& n  = _nodes[node];
  uint32_t        lo = n.child_start;
  uint32_t        hi = n.child_start + n.child_len;
  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2;
    uint64_t h   = _children[mid].hash;
    if (h == hash) return _children[mid].child_node;
    if (h < hash)
      lo = mid + 1;
    else
      hi = mid;
  }
  return SEG_NONE;
}

// Per-start work budget. A pattern may contain $SKIP wildcards, and each skip node fans out up to its
// width, so a pathological (or adversarially targeted) pattern could recurse combinatorially. Real
// patterns and files stay many orders of magnitude below this cap - the developer differential over the
// full corpus would fail if the budget ever truncated a genuine match - so this only ever bounds a
// crafted fan-out, keeping a scan of hostile input responsive instead of hanging.
static const long SKIP_WORK_BUDGET = 5000000;

void Segment::check_token_matches(const TokenList& tokens, std::vector<RawMatch>& ms, int tokenlist_offset,
                                  int tokenlist_index, unsigned int offset, uint32_t node, long& budget) const {
  if (offset >= tokens.size()) return;
  if (--budget < 0) return;    // work budget exhausted; stop exploring (adversarial skip fan-out guard)

  while (node != SEG_NONE) {
    if (offset >= tokens.size()) {
      uint32_t pid = _nodes[node].pid;
      if (pid) {
        RawMatch m;
        m.start   = tokenlist_offset + tokenlist_index;
        m.matched = (int)offset - tokenlist_index;
        m.sline   = tokens[tokenlist_index].linenumber;
        m.eline   = tokens[offset - 1].linenumber;
        m.pattern = pid;
        ms.push_back(m);
      }
      return;
    }

    const FlatNode& n = _nodes[node];
    for (uint32_t s = 0; s < n.skip_len; ++s) {
      const FlatSkip& sk = _skips[n.skip_start + s];
      for (int i = 1; i <= sk.skip_value; ++i)
        check_token_matches(tokens, ms, tokenlist_offset, tokenlist_index, offset + i, sk.child_node, budget);
    }

    if (n.pid) {
      RawMatch m;
      m.start   = tokenlist_offset + tokenlist_index;
      m.matched = (int)offset - tokenlist_index;
      m.sline   = tokens[tokenlist_index].linenumber;
      m.eline   = tokens[offset - 1].linenumber;
      m.pattern = n.pid;
      ms.push_back(m);
    }

    node = find_child(node, tokens[offset].hash);
    offset++;
  }
}

void Segment::find_tokens(const TokenList& tokens, std::vector<RawMatch>& ms, int tokenlist_offset,
                          int index) const {
  if (!_valid) return;
  if (index < 0 || (size_t)index >= tokens.size()) return;
  uint32_t start = find_child(0, tokens[index].hash);
  if (start == SEG_NONE) return;
  long budget = SKIP_WORK_BUDGET;    // fresh per-start budget; real matches never approach it
  check_token_matches(tokens, ms, tokenlist_offset, index, (unsigned int)index + 1, start, budget);
}
