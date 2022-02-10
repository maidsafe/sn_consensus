# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## [1.11.0](https://github.com/maidsafe/sn_membership/compare/v1.10.1...v1.11.0) (2022-02-10)


### Features

* return VoteResponse from Membership::handle_signed_vote API ([4a9fb0d](https://github.com/maidsafe/sn_membership/commit/4a9fb0de4907ffff48c021b52c021b24c8be8781))

### [1.10.1](https://github.com/maidsafe/sn_membership/compare/v1.10.0...v1.10.1) (2022-02-10)

## [1.10.0](https://github.com/maidsafe/sn_membership/compare/v1.9.0...v1.10.0) (2022-02-09)


### Features

* aggregated signed decisions are now produced on decision ([fa34abd](https://github.com/maidsafe/sn_membership/commit/fa34abd728a237a2668a3387d7ac1ee2edfd6083))
* include signed proposals in SuperMajority ballot ([55b2ff5](https://github.com/maidsafe/sn_membership/commit/55b2ff53fb660f929818702a51b4521d40526cd0))

## [1.9.0](https://github.com/maidsafe/sn_membership/compare/v1.8.1...v1.9.0) (2022-02-03)


### Features

* **agg-sig:** move to blsttc::PublicKeySet from Set<PublicKeyShare> ([7084a31](https://github.com/maidsafe/sn_membership/commit/7084a31ce849b09589941e2d254079619df008cd))

### [1.8.1](https://github.com/maidsafe/sn_membership/compare/v1.8.0...v1.8.1) (2022-02-01)


### Bug Fixes

* **tests:** fix nodes who voted check; avoid panic in leave proposal ([dc3bddd](https://github.com/maidsafe/sn_membership/commit/dc3bddd47df6d3e49d62a6e6064e4bcd45b86c70))

## [1.8.0](https://github.com/maidsafe/sn_membership/compare/v1.7.0...v1.8.0) (2022-02-01)


### Features

* add tests and fix handover issue when consensus is reached ([592c2f8](https://github.com/maidsafe/sn_membership/commit/592c2f8cde021fb6370a81ef035e557aae20272d))
* generic consensus module (tests wip) ([765fa0a](https://github.com/maidsafe/sn_membership/commit/765fa0a8470a3ef5b52b3dd57dd01f24ea38bf43))
* handover wrapper ([f6d5348](https://github.com/maidsafe/sn_membership/commit/f6d534873d937d1479e17b867a5a2f3bd5189ce1))
* improve handle vote response ([2729ecd](https://github.com/maidsafe/sn_membership/commit/2729ecdcd7fb13de85821a49e09ed4262db6e711))
* move validation back to consensus with pre-check for proposals ([92392a6](https://github.com/maidsafe/sn_membership/commit/92392a69aabb1a193fd56cd52e735b8dfcd68863))


### Bug Fixes

* tests and gen handling in membership ([728f0d9](https://github.com/maidsafe/sn_membership/commit/728f0d92e2953eeee15bccf26daa87f2981b90cc))

## [1.7.0](https://github.com/maidsafe/sn_membership/compare/v1.6.0...v1.7.0) (2022-01-26)


### Features

* split code in different files ([8006212](https://github.com/maidsafe/sn_membership/commit/800621209a74b607fccea100d5f67aa5e0c79df1))

## [1.6.0](https://github.com/maidsafe/sn_membership/compare/v1.5.0...v1.6.0) (2022-01-25)


### Features

* handle_signed_vote now returns an Option<SignedVote> ([a8bf63a](https://github.com/maidsafe/sn_membership/commit/a8bf63a97cf907a17833c5569b14913b66b4ea0a))


### Bug Fixes

* **ci:** we don't have feature flags for crypto backends anymore ([e12dddd](https://github.com/maidsafe/sn_membership/commit/e12dddd8423f6857f57ef1f46e1f031fefa989c7))

## [1.5.0](https://github.com/maidsafe/sn_membership/compare/v1.4.0...v1.5.0) (2022-01-20)


### Features

* **static-elders:** most tests passing, still a few failing ([ab02464](https://github.com/maidsafe/sn_membership/commit/ab02464aa6e2d6d7860991a2abcd35a177504f9a))


### Bug Fixes

* **consensus:** only prevent voting a SM if we had already sent a SM ([f4b5a4b](https://github.com/maidsafe/sn_membership/commit/f4b5a4b8b9cb4ad0c7ca0b2cfb2fc33116fc12c8))
* **tests:** fix two issues with test cases causing false positives ([2e8a011](https://github.com/maidsafe/sn_membership/commit/2e8a011df931847ffc7a1891a1b98b7f81316ff1))
* **tests:** tests are now passing with the new static elders change ([83be4a1](https://github.com/maidsafe/sn_membership/commit/83be4a1412090d066a7a2bbe74c24129b138f27c))

## [1.4.0](https://github.com/maidsafe/brb_membership/compare/v1.3.0...v1.4.0) (2022-01-04)


### Features

* **prop_testing:** better rng seeds: more than 256 variations ([92174ab](https://github.com/maidsafe/brb_membership/commit/92174ab8d239f976ba6c67a808d0104fdd928447))

## [1.3.0](https://github.com/maidsafe/brb_membership/compare/v1.2.0...v1.3.0) (2022-01-04)


### Features

* **bad_crypto:** stub slow cryptography functions with a fast one ([0447710](https://github.com/maidsafe/brb_membership/commit/0447710d0fffc2a2e7f28c16dd9af43102fde567))
* **tests:** added bft_consensus property tests ([d14f974](https://github.com/maidsafe/brb_membership/commit/d14f974afd488eb8e60a83e091490418a3dc3e26))


### Bug Fixes

* **validation:** validate vote & no special case for  p_gen == gen ([f9e5248](https://github.com/maidsafe/brb_membership/commit/f9e5248e095e57a79441ead5a6b8c546e31cab87))

## [1.2.0](https://github.com/maidsafe/brb_membership/compare/v1.1.1...v1.2.0) (2021-12-29)


### Features

* **api:** additinal general purpose public APIs ([b284b42](https://github.com/maidsafe/brb_membership/commit/b284b42ee6ec169dd6fafefcda2ae45a2e8475eb))

### [1.1.1](https://github.com/maidsafe/brb_membership/compare/v1.1.0...v1.1.1) (2021-12-22)

## [1.1.0](https://github.com/maidsafe/brb_membership/compare/v1.0.12...v1.1.0) (2021-12-21)


### Features

* **blsttc:** add support for blsttc ([0524047](https://github.com/maidsafe/brb_membership/commit/0524047047506898373853698c77268c2fc19cf7))

### [1.0.12](https://github.com/maidsafe/brb_membership/compare/v1.0.11...v1.0.12) (2021-12-21)

### [1.0.11](https://github.com/maidsafe/brb_membership/compare/v1.0.10...v1.0.11) (2021-12-20)

### [1.0.10](https://github.com/maidsafe/brb_membership/compare/v1.0.9...v1.0.10) (2021-06-14)

### [1.0.9](https://github.com/maidsafe/brb_membership/compare/v1.0.8...v1.0.9) (2021-05-31)

### [1.0.8](https://github.com/maidsafe/brb_membership/compare/v1.0.7...v1.0.8) (2021-03-03)

### [1.0.7](https://github.com/maidsafe/brb_membership/compare/v1.0.6...v1.0.7) (2021-02-25)

### [1.0.6](https://github.com/maidsafe/brb_membership/compare/v1.0.5...v1.0.6) (2021-02-09)

### [1.0.5](https://github.com/maidsafe/brb_membership/compare/v1.0.4...v1.0.5) (2021-02-09)

### [1.0.4](https://github.com/maidsafe/brb_membership/compare/v1.0.3...v1.0.4) (2021-01-20)

### [1.0.3](https://github.com/maidsafe/brb_membership/compare/v1.0.2...v1.0.3) (2021-01-20)

### [1.0.2](https://github.com/maidsafe/brb_membership/compare/v1.0.1...v1.0.2) (2021-01-19)

### 1.0.1 (2021-01-19)

### [0.1.0](https://github.com/maidsafe/sn_launch_tool/compare/v0.1.0...v0.1.0) (2021-01-07)
* Initial implementation
