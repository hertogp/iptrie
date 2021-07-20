# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## changed
- Merged [#1](https://github.com/hertogp/iptrie/pull/1) misc doc changes
- Pulled in `Pfx` 0.5.0
- Pulled in `Radix` 0.2.0
- Updated deps with new versions of `Pfx` and `Radix`
- `Iptrie.delete/2` only deletes a single prefix, now `Iptrie.drop/2` is available
- `Iptrie.filter/2` user callback now takes a `t:Pfx.t/0` instead of bitstring radix key
- `Iptrie.get/2` no longer gets a list of prefixes, just 1 prefix at a time
- `Iptrie.keys/2` returns keys for a single type only
- `Iptrie.reduce/3` user callback now takes a `t:Pfx.t/0` instead of bitstring radix key
- `Iptrie.reduce/4` takes a single type only, not a list of types
- `Iptrie.reduce/4` user callback now takes a `t:Pfx.t/0` instead of bitstring radix key
- `Iptrie.to_list/2` returns prefix,value-pairs for a single type only
- `Iptrie.values/2` returns values for a single radix tree type only

## added
- `Iptrie.count/1`, return count of all entries in an Iptrie
- `Iptrie.count/2`, return count of entries for given `type`
- `Iptrie.drop/2`, drop some prefixes from the Iptrie
- `Iptrie.empty?/1`, says if a given Iptrie is empty or not
- `Iptrie.empty?/2`, says if a particular radix tree of `type` is empty or not
- `Iptrie.get/3`, gets a prefix or returns default if prefix was not found
- `Iptrie.has_prefix?/2`, says whether given prefix is present in an Iptrie
- `Iptrie.has_type?/2`, says whether or not trie has a given type
- `Iptrie.merge/2`, merges two Iptrie's
- `Iptrie.merge/3`, merges two Iptrie's with conflict resolution
- `Iptrie.pop/3`, returns popped pfx,val and new trie
- `Iptrie.radix/2`, get a radix tree by type from an Iptrie, or a new empty one
- `Iptrie.split/3`, split one trie into two (optionally using lpm)
- `Iptrie.take/3`, return new Iptrie contains just the given keys
- `Iptrie.types/1`, returns a list of available types or maxlen's in the trie


## v0.3.0 - 2021-07-06

### added
- `Iptrie.fetch/2`, `Iptrie.fetch!/2`
- `Iptrie.find/2`, `Iptrie.find!/2`
- `Iptrie.filter/2`

## v0.2.0 - 2021-07-05

### added
- `Iptrie.radix/2`
- `Iptrie.reduce/3`, `Iptrie.reduce/4`
- `Iptrie.to_list/1`, `Iptrie.to_list/2`

## v0.1.0 - 2021-07-05

- Initial public version
