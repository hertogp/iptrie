# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## changed
- Updated dependencies Radix, `Pfx` to use `>=` instead of `~>`
- Merged [#1](https://github.com/hertogp/iptrie/pull/1) misc doc changes
- Pulled in `Pfx` 0.5.0
- Pulled in `Radix` 0.2.0

## added

TODO:
- Iptrie.count/1, return count of entries in the different radix trees
- Iptrie.update/4, to update values in one go
- Iptrie.take/3, return new Iptrie contains just the given keys
- Iptrie.split/3, split one trie into two (optionally using lpm)
- Iptrie.merge/2, merges two Iptrie's
- Iptrie.merge/3, merges two Iptrie's with conflict resolution
- Iptrie.drop/2, drop some prefixes from the Iptrie
- Iptrie.pop/3, returns popped pfx,val and new trie
- Iptrie.dot/3, wraps Radix.dot
- Iptrie.empty?/2, says if a particular (or all) radix trees are empty


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
