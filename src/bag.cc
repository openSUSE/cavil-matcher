// SPDX-FileCopyrightText: SUSE LLC
// SPDX-License-Identifier: GPL-2.0-or-later

#include "bag.h"
#include "tokenizer.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>

void Bag::tokenize(const std::string& str, std::map<uint64_t, uint64_t>& localwords) const {
  std::vector<char> copy(str.begin(), str.end());
  copy.push_back('\0');
  TokenList t;
  tokenizer().tokenize(t, copy.data(), 1);
  for (const auto& tok : t) localwords[tok.hash] = 1;    // count a word once per document
}

double Bag::tf_idf(const std::map<uint64_t, uint64_t>& words, std::vector<TfIdf>& out) const {
  double square_sum = 0;
  for (const auto& it : words) {
    auto   idf_it = _idfs.find(it.first);
    double idf    = idf_it == _idfs.end() ? 0.0 : idf_it->second;
    double value  = it.second * idf;
    square_sum += value * value;
    out.push_back({it.first, value});
  }
  std::sort(out.begin(), out.end());
  return sqrt(square_sum);
}

double Bag::compare2(const std::vector<TfIdf>& snippet, const Pattern& pattern) const {
  double sum = 0;
  auto   it1 = pattern.tf_idfs.begin();
  auto   it2 = snippet.begin();
  while (it1 != pattern.tf_idfs.end() && it2 != snippet.end()) {
    if (it1->hash == it2->hash) {
      sum += it1->value * it2->value;
      ++it1;
      ++it2;
    } else if (it1->hash > it2->hash) {
      ++it2;
    } else {
      ++it1;
    }
  }
  return pattern.square_sum > 0 ? sum / pattern.square_sum : 0;
}

void Bag::set_patterns(const std::vector<std::pair<uint64_t, std::string>>& patterns) {
  _idfs.clear();
  _patterns.clear();

  std::map<uint64_t, uint64_t>              words;
  std::vector<std::map<uint64_t, uint64_t>> wordcounts;
  std::vector<uint64_t>                     indexes;

  for (const auto& kv : patterns) {
    std::map<uint64_t, uint64_t> localwords;
    tokenize(kv.second, localwords);
    indexes.push_back(kv.first);
    wordcounts.push_back(localwords);
    for (const auto& w : localwords) words[w.first]++;
  }

  for (const auto& w : words) _idfs[w.first] = log(double(indexes.size()) / w.second);

  for (size_t i = 0; i < indexes.size(); ++i) {
    Pattern p;
    p.index      = indexes[i];
    p.square_sum = tf_idf(wordcounts[i], p.tf_idfs);
    _patterns.push_back(std::move(p));
  }
}

std::vector<Bag::Hit> Bag::best_for(const std::string& snippet, unsigned int count) const {
  std::map<uint64_t, uint64_t> localwords;
  tokenize(snippet, localwords);

  std::vector<TfIdf> tfidf;
  double             square_sum = tf_idf(localwords, tfidf);

  double           highscore = -1;
  std::vector<Hit> hits;
  for (const auto& p : _patterns) {
    double match = compare2(tfidf, p);
    if (match > highscore) {
      hits.push_back({p.index, match});
      std::sort(hits.begin(), hits.end(), [](const Hit& a, const Hit& b) { return a.match > b.match; });
      if (hits.size() > count) {
        hits.resize(count);
        highscore = hits.back().match;
      }
    }
  }

  for (auto& h : hits) {
    double m = square_sum > 0 ? int(h.match * 10000 / square_sum) / 10000.0 : 0.0;
    h.match  = m;
  }
  return hits;
}

void Bag::dump(const std::string& path) const {
  FILE* file = fopen(path.c_str(), "wb");
  if (!file) return;

  uint64_t count = _idfs.size();
  fwrite(&count, sizeof(count), 1, file);
  for (const auto& it : _idfs) {
    uint64_t f1 = it.first;
    double   f2 = it.second;
    fwrite(&f1, sizeof(f1), 1, file);
    fwrite(&f2, sizeof(f2), 1, file);
  }

  count = _patterns.size();
  fwrite(&count, sizeof(count), 1, file);
  for (const auto& p : _patterns) {
    uint64_t f1 = p.index;
    fwrite(&f1, sizeof(f1), 1, file);
    double f2 = p.square_sum;
    fwrite(&f2, sizeof(f2), 1, file);
    uint64_t c = p.tf_idfs.size();
    fwrite(&c, sizeof(c), 1, file);
    for (const auto& t : p.tf_idfs) {
      uint64_t h = t.hash;
      double   v = t.value;
      fwrite(&h, sizeof(h), 1, file);
      fwrite(&v, sizeof(v), 1, file);
    }
  }
  fclose(file);
}

bool Bag::load(const std::string& path) {
  FILE* file = fopen(path.c_str(), "rb");
  if (!file) return false;

  bool     ok    = true;
  uint64_t count = 0;
  if (fread(&count, sizeof(count), 1, file) != 1) {
    fclose(file);
    return false;
  }

  _idfs.clear();
  while (count-- && ok) {
    uint64_t f1 = 0;
    double   f2 = 0;
    if (fread(&f1, sizeof(f1), 1, file) != 1 || fread(&f2, sizeof(f2), 1, file) != 1) {
      ok = false;
      break;
    }
    _idfs[f1] = f2;
  }

  _patterns.clear();
  if (ok && fread(&count, sizeof(count), 1, file) != 1) ok = false;
  while (ok && count--) {
    Pattern  p;
    uint64_t f1 = 0;
    double   f2 = 0;
    uint64_t f3 = 0;
    if (fread(&f1, sizeof(f1), 1, file) != 1 || fread(&f2, sizeof(f2), 1, file) != 1
        || fread(&f3, sizeof(f3), 1, file) != 1) {
      ok = false;
      break;
    }
    p.index      = f1;
    p.square_sum = f2;
    while (f3-- && ok) {
      uint64_t h = 0;
      double   v = 0;
      if (fread(&h, sizeof(h), 1, file) != 1 || fread(&v, sizeof(v), 1, file) != 1) {
        ok = false;
        break;
      }
      p.tf_idfs.push_back({h, v});
    }
    _patterns.push_back(std::move(p));
  }

  fclose(file);
  return ok;
}
