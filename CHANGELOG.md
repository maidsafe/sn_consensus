# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## [3.2.0](https://github.com/maidsafe/sn_consensus/compare/v3.1.4...v3.2.0) (2023-01-30)


### Features

* **abba:** simulated network test showing failure to terminate ([922cc86](https://github.com/maidsafe/sn_consensus/commit/922cc868b97aa058462f66c876d2d5134e9ef7d2))
* **mvba:** implementing Protocol VBA for multi-valued validated Byzantine agreement. ([71d80af](https://github.com/maidsafe/sn_consensus/commit/71d80af90fadbc47f5448a68333a7fec139578e5))
* **mvba:** introducing outgoing type ([d8d5216](https://github.com/maidsafe/sn_consensus/commit/d8d5216cfc3c7ed4ad3102b975bad0af285e70e3))
* **vcbc:** defining proposal ([6a75d37](https://github.com/maidsafe/sn_consensus/commit/6a75d3763b4c73d781b04f2bc0681945b9b59fbe))
* **vcbc:** implementing c-request and c-answer messages ([f3de8ad](https://github.com/maidsafe/sn_consensus/commit/f3de8ada663a2b5d196e94acb61c913f3d29ad4e))
* agreement in two-round with weaker validity assumption ([a887138](https://github.com/maidsafe/sn_consensus/commit/a8871388f373e9ac40d2e5d8af1a496dc825513c))
* implementing abba, implementing pre-vote phase (WIP) ([f7f57ac](https://github.com/maidsafe/sn_consensus/commit/f7f57ac548f8881f3be186bf7e80ffaac6f52fe9))
* implementing abba, pre-procesing phase (WIP) ([ce2ba78](https://github.com/maidsafe/sn_consensus/commit/ce2ba78ff4b94cbe156b6a0eeaaf67214cd2accb))
* implementing main-vote justification ([e30b04a](https://github.com/maidsafe/sn_consensus/commit/e30b04afb5123dfd5365edd783569721a5a04580))
* implementing pre-vote justification (r==1) ([1b035e8](https://github.com/maidsafe/sn_consensus/commit/1b035e8d7779a7c0d451749301e8fb044b0367c0))
* implementing pre-vote justification (r>1) ([48a20f4](https://github.com/maidsafe/sn_consensus/commit/48a20f490317e6cd0b629676ed45413d5608536c))


### Bug Fixes

* **abba:** ignore the incoming messages if we have decided ([09ec7bd](https://github.com/maidsafe/sn_consensus/commit/09ec7bdcf2bf34c6eb148b6fd1d01548633678cc))
* **vcbc:** remove unwraps in reading delivered values ([578e88d](https://github.com/maidsafe/sn_consensus/commit/578e88d306d0c539cf2e5e581a721fecfa580be3))
* adding target to the bundle ([443d283](https://github.com/maidsafe/sn_consensus/commit/443d28314dded6368eceb58dbcf5eed31b1fde84))
* an issue on getting round votes ([5632f2c](https://github.com/maidsafe/sn_consensus/commit/5632f2c8e1a35f655f123f3a794417a543e1ff4b))
* check the zero value ([c02469c](https://github.com/maidsafe/sn_consensus/commit/c02469cccc509f5d421d7ec08acece8b8a04fd4f))
* clippy and format issues ([9aa8605](https://github.com/maidsafe/sn_consensus/commit/9aa8605a277aadaae9297e48d1af19fc2b6c2f5e))
* fixing a broken test (still one test is failing) ([95f4603](https://github.com/maidsafe/sn_consensus/commit/95f460305c2bb2c7d66c20e9df5fef14fe9a5e93))
* fixing a broken tests and add new test for double vote ([bada652](https://github.com/maidsafe/sn_consensus/commit/bada652939b94a0bfd5d6da49c98ff6c5da91d7f))
* fixing clippy issues ([54ab0b0](https://github.com/maidsafe/sn_consensus/commit/54ab0b095235f5b1b779ebdf56bc9516fd8107ef))
* fixing conflict decisions by halting consensus on True agreement ([9d701d7](https://github.com/maidsafe/sn_consensus/commit/9d701d73c99e0aac587d67bd5bd45ce69ecf8da8))
* fixing linting issues ([9236913](https://github.com/maidsafe/sn_consensus/commit/92369135468737163320f21b89d441989a7094ea))
* fixing tests, clippy and fmt issues ([3917a02](https://github.com/maidsafe/sn_consensus/commit/3917a0245ac13724a5eb5fddbd0598abc7b76160))
* integrating consensus protocols ([452b7df](https://github.com/maidsafe/sn_consensus/commit/452b7df338474b6eccede106dbeb21a0844efab4))
* make sure the absent value set correct and fixing 'CHECK FOR DECISION' stage ([e93d7d0](https://github.com/maidsafe/sn_consensus/commit/e93d7d000d6d3f98879acdd3595c98d3b8f1e0d2))
* make sure the the honest parties won't double vote ([561c06c](https://github.com/maidsafe/sn_consensus/commit/561c06ca511bc0e59b15844391a289cb15e2b5fb))
* returning option for the decided value, rather than unwrap it ([557d4f5](https://github.com/maidsafe/sn_consensus/commit/557d4f5d96c85d3788c0963918d8f5697cbde1d0))
* some coments for unsynced messages ([bfb2398](https://github.com/maidsafe/sn_consensus/commit/bfb2398512a8cc3e000fc35ec090c2792be13641))
* **abba:** add strong termination to resolve the termination failure ([9364ebb](https://github.com/maidsafe/sn_consensus/commit/9364ebbcd24bcf18e0d25cd36dcee05eda236919))
* **abba:** adding proposer ID for messages ([d52f9a9](https://github.com/maidsafe/sn_consensus/commit/d52f9a942aa5b38c16bc645bebeb8974dabd950f))
* **abba:** fix consensus failure by adding check for justification in pre-vote messages ([de476d3](https://github.com/maidsafe/sn_consensus/commit/de476d3581280e8f8181c605230de70cd2dfe094))
* **abba:** remove justification from decision action ([80d8f2a](https://github.com/maidsafe/sn_consensus/commit/80d8f2a85ab6e5a7b3fe4c2cb2f86dd0d89bf80c))
* **mvba:** improving the protocol by replacing the proposal by its digest ([d1fe112](https://github.com/maidsafe/sn_consensus/commit/d1fe112af7ef1f2350b51cb00133771a68f89880))
* **mvba:** removing old code ([7339703](https://github.com/maidsafe/sn_consensus/commit/7339703e9ae82a406bfdc687c7ee33f2fa6edc1a))
* using c-final message for the first round ([1b566f0](https://github.com/maidsafe/sn_consensus/commit/1b566f040cce7ced125dd0efeff8b24445810354))
* weaker validity and justification for main votes ([bb0484d](https://github.com/maidsafe/sn_consensus/commit/bb0484d284f9d0daee74303c467de79c8ff55b17))

## [3.2.0](https://github.com/maidsafe/sn_consensus/compare/v3.1.4...v3.2.0) (2023-01-25)


### Features

* **abba:** simulated network test showing failure to terminate ([922cc86](https://github.com/maidsafe/sn_consensus/commit/922cc868b97aa058462f66c876d2d5134e9ef7d2))
* **mvba:** implementing Protocol VBA for multi-valued validated Byzantine agreement. ([71d80af](https://github.com/maidsafe/sn_consensus/commit/71d80af90fadbc47f5448a68333a7fec139578e5))
* **mvba:** introducing outgoing type ([d8d5216](https://github.com/maidsafe/sn_consensus/commit/d8d5216cfc3c7ed4ad3102b975bad0af285e70e3))
* **vcbc:** defining proposal ([6a75d37](https://github.com/maidsafe/sn_consensus/commit/6a75d3763b4c73d781b04f2bc0681945b9b59fbe))
* **vcbc:** implementing c-request and c-answer messages ([f3de8ad](https://github.com/maidsafe/sn_consensus/commit/f3de8ada663a2b5d196e94acb61c913f3d29ad4e))
* agreement in two-round with weaker validity assumption ([a887138](https://github.com/maidsafe/sn_consensus/commit/a8871388f373e9ac40d2e5d8af1a496dc825513c))
* implementing abba, implementing pre-vote phase (WIP) ([f7f57ac](https://github.com/maidsafe/sn_consensus/commit/f7f57ac548f8881f3be186bf7e80ffaac6f52fe9))
* implementing abba, pre-procesing phase (WIP) ([ce2ba78](https://github.com/maidsafe/sn_consensus/commit/ce2ba78ff4b94cbe156b6a0eeaaf67214cd2accb))
* implementing main-vote justification ([e30b04a](https://github.com/maidsafe/sn_consensus/commit/e30b04afb5123dfd5365edd783569721a5a04580))
* implementing pre-vote justification (r==1) ([1b035e8](https://github.com/maidsafe/sn_consensus/commit/1b035e8d7779a7c0d451749301e8fb044b0367c0))
* implementing pre-vote justification (r>1) ([48a20f4](https://github.com/maidsafe/sn_consensus/commit/48a20f490317e6cd0b629676ed45413d5608536c))


### Bug Fixes

* **vcbc:** remove unwraps in reading delivered values ([578e88d](https://github.com/maidsafe/sn_consensus/commit/578e88d306d0c539cf2e5e581a721fecfa580be3))
* adding target to the bundle ([443d283](https://github.com/maidsafe/sn_consensus/commit/443d28314dded6368eceb58dbcf5eed31b1fde84))
* an issue on getting round votes ([5632f2c](https://github.com/maidsafe/sn_consensus/commit/5632f2c8e1a35f655f123f3a794417a543e1ff4b))
* check the zero value ([c02469c](https://github.com/maidsafe/sn_consensus/commit/c02469cccc509f5d421d7ec08acece8b8a04fd4f))
* clippy and format issues ([9aa8605](https://github.com/maidsafe/sn_consensus/commit/9aa8605a277aadaae9297e48d1af19fc2b6c2f5e))
* fixing a broken test (still one test is failing) ([95f4603](https://github.com/maidsafe/sn_consensus/commit/95f460305c2bb2c7d66c20e9df5fef14fe9a5e93))
* fixing a broken tests and add new test for double vote ([bada652](https://github.com/maidsafe/sn_consensus/commit/bada652939b94a0bfd5d6da49c98ff6c5da91d7f))
* fixing clippy issues ([54ab0b0](https://github.com/maidsafe/sn_consensus/commit/54ab0b095235f5b1b779ebdf56bc9516fd8107ef))
* fixing conflict decisions by halting consensus on True agreement ([9d701d7](https://github.com/maidsafe/sn_consensus/commit/9d701d73c99e0aac587d67bd5bd45ce69ecf8da8))
* fixing linting issues ([9236913](https://github.com/maidsafe/sn_consensus/commit/92369135468737163320f21b89d441989a7094ea))
* fixing tests, clippy and fmt issues ([3917a02](https://github.com/maidsafe/sn_consensus/commit/3917a0245ac13724a5eb5fddbd0598abc7b76160))
* integrating consensus protocols ([452b7df](https://github.com/maidsafe/sn_consensus/commit/452b7df338474b6eccede106dbeb21a0844efab4))
* make sure the absent value set correct and fixing 'CHECK FOR DECISION' stage ([e93d7d0](https://github.com/maidsafe/sn_consensus/commit/e93d7d000d6d3f98879acdd3595c98d3b8f1e0d2))
* make sure the the honest parties won't double vote ([561c06c](https://github.com/maidsafe/sn_consensus/commit/561c06ca511bc0e59b15844391a289cb15e2b5fb))
* returning option for the decided value, rather than unwrap it ([557d4f5](https://github.com/maidsafe/sn_consensus/commit/557d4f5d96c85d3788c0963918d8f5697cbde1d0))
* some coments for unsynced messages ([bfb2398](https://github.com/maidsafe/sn_consensus/commit/bfb2398512a8cc3e000fc35ec090c2792be13641))
* **abba:** add strong termination to resolve the termination failure ([9364ebb](https://github.com/maidsafe/sn_consensus/commit/9364ebbcd24bcf18e0d25cd36dcee05eda236919))
* **abba:** adding proposer ID for messages ([d52f9a9](https://github.com/maidsafe/sn_consensus/commit/d52f9a942aa5b38c16bc645bebeb8974dabd950f))
* **abba:** fix consensus failure by adding check for justification in pre-vote messages ([de476d3](https://github.com/maidsafe/sn_consensus/commit/de476d3581280e8f8181c605230de70cd2dfe094))
* **abba:** remove justification from decision action ([80d8f2a](https://github.com/maidsafe/sn_consensus/commit/80d8f2a85ab6e5a7b3fe4c2cb2f86dd0d89bf80c))
* **mvba:** improving the protocol by replacing the proposal by its digest ([d1fe112](https://github.com/maidsafe/sn_consensus/commit/d1fe112af7ef1f2350b51cb00133771a68f89880))
* **mvba:** removing old code ([7339703](https://github.com/maidsafe/sn_consensus/commit/7339703e9ae82a406bfdc687c7ee33f2fa6edc1a))
* using c-final message for the first round ([1b566f0](https://github.com/maidsafe/sn_consensus/commit/1b566f040cce7ced125dd0efeff8b24445810354))
* weaker validity and justification for main votes ([bb0484d](https://github.com/maidsafe/sn_consensus/commit/bb0484d284f9d0daee74303c467de79c8ff55b17))

## [3.2.0](https://github.com/maidsafe/sn_consensus/compare/v3.1.4...v3.2.0) (2023-01-24)


### Features

* **abba:** simulated network test showing failure to terminate ([922cc86](https://github.com/maidsafe/sn_consensus/commit/922cc868b97aa058462f66c876d2d5134e9ef7d2))
* **mvba:** implementing Protocol VBA for multi-valued validated Byzantine agreement. ([71d80af](https://github.com/maidsafe/sn_consensus/commit/71d80af90fadbc47f5448a68333a7fec139578e5))
* **mvba:** introducing outgoing type ([d8d5216](https://github.com/maidsafe/sn_consensus/commit/d8d5216cfc3c7ed4ad3102b975bad0af285e70e3))
* **vcbc:** defining proposal ([6a75d37](https://github.com/maidsafe/sn_consensus/commit/6a75d3763b4c73d781b04f2bc0681945b9b59fbe))
* **vcbc:** implementing c-request and c-answer messages ([f3de8ad](https://github.com/maidsafe/sn_consensus/commit/f3de8ada663a2b5d196e94acb61c913f3d29ad4e))
* agreement in two-round with weaker validity assumption ([a887138](https://github.com/maidsafe/sn_consensus/commit/a8871388f373e9ac40d2e5d8af1a496dc825513c))
* implementing abba, implementing pre-vote phase (WIP) ([f7f57ac](https://github.com/maidsafe/sn_consensus/commit/f7f57ac548f8881f3be186bf7e80ffaac6f52fe9))
* implementing abba, pre-procesing phase (WIP) ([ce2ba78](https://github.com/maidsafe/sn_consensus/commit/ce2ba78ff4b94cbe156b6a0eeaaf67214cd2accb))
* implementing main-vote justification ([e30b04a](https://github.com/maidsafe/sn_consensus/commit/e30b04afb5123dfd5365edd783569721a5a04580))
* implementing pre-vote justification (r==1) ([1b035e8](https://github.com/maidsafe/sn_consensus/commit/1b035e8d7779a7c0d451749301e8fb044b0367c0))
* implementing pre-vote justification (r>1) ([48a20f4](https://github.com/maidsafe/sn_consensus/commit/48a20f490317e6cd0b629676ed45413d5608536c))


### Bug Fixes

* adding target to the bundle ([443d283](https://github.com/maidsafe/sn_consensus/commit/443d28314dded6368eceb58dbcf5eed31b1fde84))
* an issue on getting round votes ([5632f2c](https://github.com/maidsafe/sn_consensus/commit/5632f2c8e1a35f655f123f3a794417a543e1ff4b))
* check the zero value ([c02469c](https://github.com/maidsafe/sn_consensus/commit/c02469cccc509f5d421d7ec08acece8b8a04fd4f))
* clippy and format issues ([9aa8605](https://github.com/maidsafe/sn_consensus/commit/9aa8605a277aadaae9297e48d1af19fc2b6c2f5e))
* fixing a broken test (still one test is failing) ([95f4603](https://github.com/maidsafe/sn_consensus/commit/95f460305c2bb2c7d66c20e9df5fef14fe9a5e93))
* fixing a broken tests and add new test for double vote ([bada652](https://github.com/maidsafe/sn_consensus/commit/bada652939b94a0bfd5d6da49c98ff6c5da91d7f))
* fixing clippy issues ([54ab0b0](https://github.com/maidsafe/sn_consensus/commit/54ab0b095235f5b1b779ebdf56bc9516fd8107ef))
* fixing conflict decisions by halting consensus on True agreement ([9d701d7](https://github.com/maidsafe/sn_consensus/commit/9d701d73c99e0aac587d67bd5bd45ce69ecf8da8))
* fixing linting issues ([9236913](https://github.com/maidsafe/sn_consensus/commit/92369135468737163320f21b89d441989a7094ea))
* fixing tests, clippy and fmt issues ([3917a02](https://github.com/maidsafe/sn_consensus/commit/3917a0245ac13724a5eb5fddbd0598abc7b76160))
* integrating consensus protocols ([452b7df](https://github.com/maidsafe/sn_consensus/commit/452b7df338474b6eccede106dbeb21a0844efab4))
* make sure the absent value set correct and fixing 'CHECK FOR DECISION' stage ([e93d7d0](https://github.com/maidsafe/sn_consensus/commit/e93d7d000d6d3f98879acdd3595c98d3b8f1e0d2))
* make sure the the honest parties won't double vote ([561c06c](https://github.com/maidsafe/sn_consensus/commit/561c06ca511bc0e59b15844391a289cb15e2b5fb))
* returning option for the decided value, rather than unwrap it ([557d4f5](https://github.com/maidsafe/sn_consensus/commit/557d4f5d96c85d3788c0963918d8f5697cbde1d0))
* some coments for unsynced messages ([bfb2398](https://github.com/maidsafe/sn_consensus/commit/bfb2398512a8cc3e000fc35ec090c2792be13641))
* **abba:** add strong termination to resolve the termination failure ([9364ebb](https://github.com/maidsafe/sn_consensus/commit/9364ebbcd24bcf18e0d25cd36dcee05eda236919))
* **abba:** adding proposer ID for messages ([d52f9a9](https://github.com/maidsafe/sn_consensus/commit/d52f9a942aa5b38c16bc645bebeb8974dabd950f))
* **abba:** fix consensus failure by adding check for justification in pre-vote messages ([de476d3](https://github.com/maidsafe/sn_consensus/commit/de476d3581280e8f8181c605230de70cd2dfe094))
* **abba:** remove justification from decision action ([80d8f2a](https://github.com/maidsafe/sn_consensus/commit/80d8f2a85ab6e5a7b3fe4c2cb2f86dd0d89bf80c))
* **mvba:** improving the protocol by replacing the proposal by its digest ([d1fe112](https://github.com/maidsafe/sn_consensus/commit/d1fe112af7ef1f2350b51cb00133771a68f89880))
* **mvba:** removing old code ([7339703](https://github.com/maidsafe/sn_consensus/commit/7339703e9ae82a406bfdc687c7ee33f2fa6edc1a))
* using c-final message for the first round ([1b566f0](https://github.com/maidsafe/sn_consensus/commit/1b566f040cce7ced125dd0efeff8b24445810354))
* weaker validity and justification for main votes ([bb0484d](https://github.com/maidsafe/sn_consensus/commit/bb0484d284f9d0daee74303c467de79c8ff55b17))

## [3.2.0](https://github.com/maidsafe/sn_consensus/compare/v3.1.4...v3.2.0) (2022-12-15)


### Features

* **abba:** simulated network test showing failure to terminate ([922cc86](https://github.com/maidsafe/sn_consensus/commit/922cc868b97aa058462f66c876d2d5134e9ef7d2))
* agreement in two-round with weaker validity assumption ([a887138](https://github.com/maidsafe/sn_consensus/commit/a8871388f373e9ac40d2e5d8af1a496dc825513c))
* implementing abba, implementing pre-vote phase (WIP) ([f7f57ac](https://github.com/maidsafe/sn_consensus/commit/f7f57ac548f8881f3be186bf7e80ffaac6f52fe9))
* implementing abba, pre-procesing phase (WIP) ([ce2ba78](https://github.com/maidsafe/sn_consensus/commit/ce2ba78ff4b94cbe156b6a0eeaaf67214cd2accb))
* implementing main-vote justification ([e30b04a](https://github.com/maidsafe/sn_consensus/commit/e30b04afb5123dfd5365edd783569721a5a04580))
* implementing pre-vote justification (r==1) ([1b035e8](https://github.com/maidsafe/sn_consensus/commit/1b035e8d7779a7c0d451749301e8fb044b0367c0))
* implementing pre-vote justification (r>1) ([48a20f4](https://github.com/maidsafe/sn_consensus/commit/48a20f490317e6cd0b629676ed45413d5608536c))


### Bug Fixes

* **abba:** add strong termination to resolve the termination failure ([9364ebb](https://github.com/maidsafe/sn_consensus/commit/9364ebbcd24bcf18e0d25cd36dcee05eda236919))
* **abba:** remove justification from decision action ([80d8f2a](https://github.com/maidsafe/sn_consensus/commit/80d8f2a85ab6e5a7b3fe4c2cb2f86dd0d89bf80c))
* an issue on getting round votes ([5632f2c](https://github.com/maidsafe/sn_consensus/commit/5632f2c8e1a35f655f123f3a794417a543e1ff4b))
* check the zero value ([c02469c](https://github.com/maidsafe/sn_consensus/commit/c02469cccc509f5d421d7ec08acece8b8a04fd4f))
* fixing a broken test (still one test is failing) ([95f4603](https://github.com/maidsafe/sn_consensus/commit/95f460305c2bb2c7d66c20e9df5fef14fe9a5e93))
* fixing a broken tests and add new test for double vote ([bada652](https://github.com/maidsafe/sn_consensus/commit/bada652939b94a0bfd5d6da49c98ff6c5da91d7f))
* fixing linting issues ([9236913](https://github.com/maidsafe/sn_consensus/commit/92369135468737163320f21b89d441989a7094ea))
* make sure the absent value set correct and fixing 'CHECK FOR DECISION' stage ([e93d7d0](https://github.com/maidsafe/sn_consensus/commit/e93d7d000d6d3f98879acdd3595c98d3b8f1e0d2))
* using c-final message for the first round ([1b566f0](https://github.com/maidsafe/sn_consensus/commit/1b566f040cce7ced125dd0efeff8b24445810354))
* weaker validity and justification for main votes ([bb0484d](https://github.com/maidsafe/sn_consensus/commit/bb0484d284f9d0daee74303c467de79c8ff55b17))

## [3.2.0](https://github.com/maidsafe/sn_consensus/compare/v3.1.4...v3.2.0) (2022-12-13)


### Features

* agreement in two-round with weaker validity assumption ([a887138](https://github.com/maidsafe/sn_consensus/commit/a8871388f373e9ac40d2e5d8af1a496dc825513c))
* implementing abba, implementing pre-vote phase (WIP) ([f7f57ac](https://github.com/maidsafe/sn_consensus/commit/f7f57ac548f8881f3be186bf7e80ffaac6f52fe9))
* implementing abba, pre-procesing phase (WIP) ([ce2ba78](https://github.com/maidsafe/sn_consensus/commit/ce2ba78ff4b94cbe156b6a0eeaaf67214cd2accb))
* implementing main-vote justification ([e30b04a](https://github.com/maidsafe/sn_consensus/commit/e30b04afb5123dfd5365edd783569721a5a04580))
* implementing pre-vote justification (r==1) ([1b035e8](https://github.com/maidsafe/sn_consensus/commit/1b035e8d7779a7c0d451749301e8fb044b0367c0))
* implementing pre-vote justification (r>1) ([48a20f4](https://github.com/maidsafe/sn_consensus/commit/48a20f490317e6cd0b629676ed45413d5608536c))


### Bug Fixes

* an issue on getting round votes ([5632f2c](https://github.com/maidsafe/sn_consensus/commit/5632f2c8e1a35f655f123f3a794417a543e1ff4b))
* check the zero value ([c02469c](https://github.com/maidsafe/sn_consensus/commit/c02469cccc509f5d421d7ec08acece8b8a04fd4f))
* fixing a broken test (still one test is failing) ([95f4603](https://github.com/maidsafe/sn_consensus/commit/95f460305c2bb2c7d66c20e9df5fef14fe9a5e93))
* fixing a broken tests and add new test for double vote ([bada652](https://github.com/maidsafe/sn_consensus/commit/bada652939b94a0bfd5d6da49c98ff6c5da91d7f))
* fixing linting issues ([9236913](https://github.com/maidsafe/sn_consensus/commit/92369135468737163320f21b89d441989a7094ea))
* make sure the absent value set correct and fixing 'CHECK FOR DECISION' stage ([e93d7d0](https://github.com/maidsafe/sn_consensus/commit/e93d7d000d6d3f98879acdd3595c98d3b8f1e0d2))
* using c-final message for the first round ([1b566f0](https://github.com/maidsafe/sn_consensus/commit/1b566f040cce7ced125dd0efeff8b24445810354))
* weaker validity and justification for main votes ([bb0484d](https://github.com/maidsafe/sn_consensus/commit/bb0484d284f9d0daee74303c467de79c8ff55b17))

## [3.2.0](https://github.com/maidsafe/sn_consensus/compare/v3.1.4...v3.2.0) (2022-12-07)


### Features

* agreement in two-round with weaker validity assumption ([a887138](https://github.com/maidsafe/sn_consensus/commit/a8871388f373e9ac40d2e5d8af1a496dc825513c))
* implementing abba, implementing pre-vote phase (WIP) ([f7f57ac](https://github.com/maidsafe/sn_consensus/commit/f7f57ac548f8881f3be186bf7e80ffaac6f52fe9))
* implementing abba, pre-procesing phase (WIP) ([ce2ba78](https://github.com/maidsafe/sn_consensus/commit/ce2ba78ff4b94cbe156b6a0eeaaf67214cd2accb))
* implementing main-vote justification ([e30b04a](https://github.com/maidsafe/sn_consensus/commit/e30b04afb5123dfd5365edd783569721a5a04580))
* implementing pre-vote justification (r==1) ([1b035e8](https://github.com/maidsafe/sn_consensus/commit/1b035e8d7779a7c0d451749301e8fb044b0367c0))
* implementing pre-vote justification (r>1) ([48a20f4](https://github.com/maidsafe/sn_consensus/commit/48a20f490317e6cd0b629676ed45413d5608536c))


### Bug Fixes

* an issue on getting round votes ([5632f2c](https://github.com/maidsafe/sn_consensus/commit/5632f2c8e1a35f655f123f3a794417a543e1ff4b))
* check the zero value ([c02469c](https://github.com/maidsafe/sn_consensus/commit/c02469cccc509f5d421d7ec08acece8b8a04fd4f))
* fixing a broken test (still one test is failing) ([95f4603](https://github.com/maidsafe/sn_consensus/commit/95f460305c2bb2c7d66c20e9df5fef14fe9a5e93))
* fixing a broken tests and add new test for double vote ([bada652](https://github.com/maidsafe/sn_consensus/commit/bada652939b94a0bfd5d6da49c98ff6c5da91d7f))
* fixing linting issues ([9236913](https://github.com/maidsafe/sn_consensus/commit/92369135468737163320f21b89d441989a7094ea))
* make sure the absent value set correct and fixing 'CHECK FOR DECISION' stage ([e93d7d0](https://github.com/maidsafe/sn_consensus/commit/e93d7d000d6d3f98879acdd3595c98d3b8f1e0d2))
* using c-final message for the first round ([1b566f0](https://github.com/maidsafe/sn_consensus/commit/1b566f040cce7ced125dd0efeff8b24445810354))
* weaker validity and justification for main votes ([bb0484d](https://github.com/maidsafe/sn_consensus/commit/bb0484d284f9d0daee74303c467de79c8ff55b17))

## [3.2.0](https://github.com/maidsafe/sn_consensus/compare/v3.1.4...v3.2.0) (2022-12-07)


### Features

* agreement in two-round with weaker validity assumption ([a887138](https://github.com/maidsafe/sn_consensus/commit/a8871388f373e9ac40d2e5d8af1a496dc825513c))
* implementing abba, implementing pre-vote phase (WIP) ([f7f57ac](https://github.com/maidsafe/sn_consensus/commit/f7f57ac548f8881f3be186bf7e80ffaac6f52fe9))
* implementing abba, pre-procesing phase (WIP) ([ce2ba78](https://github.com/maidsafe/sn_consensus/commit/ce2ba78ff4b94cbe156b6a0eeaaf67214cd2accb))
* implementing main-vote justification ([e30b04a](https://github.com/maidsafe/sn_consensus/commit/e30b04afb5123dfd5365edd783569721a5a04580))
* implementing pre-vote justification (r==1) ([1b035e8](https://github.com/maidsafe/sn_consensus/commit/1b035e8d7779a7c0d451749301e8fb044b0367c0))
* implementing pre-vote justification (r>1) ([48a20f4](https://github.com/maidsafe/sn_consensus/commit/48a20f490317e6cd0b629676ed45413d5608536c))


### Bug Fixes

* an issue on getting round votes ([5632f2c](https://github.com/maidsafe/sn_consensus/commit/5632f2c8e1a35f655f123f3a794417a543e1ff4b))
* check the zero value ([c02469c](https://github.com/maidsafe/sn_consensus/commit/c02469cccc509f5d421d7ec08acece8b8a04fd4f))
* fixing a broken test (still one test is failing) ([95f4603](https://github.com/maidsafe/sn_consensus/commit/95f460305c2bb2c7d66c20e9df5fef14fe9a5e93))
* fixing a broken tests and add new test for double vote ([bada652](https://github.com/maidsafe/sn_consensus/commit/bada652939b94a0bfd5d6da49c98ff6c5da91d7f))
* fixing linting issues ([9236913](https://github.com/maidsafe/sn_consensus/commit/92369135468737163320f21b89d441989a7094ea))
* make sure the absent value set correct and fixing 'CHECK FOR DECISION' stage ([e93d7d0](https://github.com/maidsafe/sn_consensus/commit/e93d7d000d6d3f98879acdd3595c98d3b8f1e0d2))
* using c-final message for the first round ([1b566f0](https://github.com/maidsafe/sn_consensus/commit/1b566f040cce7ced125dd0efeff8b24445810354))
* weaker validity and justification for main votes ([bb0484d](https://github.com/maidsafe/sn_consensus/commit/bb0484d284f9d0daee74303c467de79c8ff55b17))

### [3.1.4](https://github.com/maidsafe/sn_consensus/compare/v3.1.3...v3.1.4) (2022-11-14)


### Bug Fixes

* add comment noting that threshold should match n+t+1/2 ([3007d7b](https://github.com/maidsafe/sn_consensus/commit/3007d7bdcf3186fce5ecb0484b9cc033095eb264))

### [3.1.3](https://github.com/maidsafe/sn_consensus/compare/v3.1.2...v3.1.3) (2022-11-08)

### [3.1.2](https://github.com/maidsafe/sn_consensus/compare/v3.1.1...v3.1.2) (2022-07-20)


### Bug Fixes

* post rebase merge conflict ([88c58ed](https://github.com/maidsafe/sn_consensus/commit/88c58edac570683ba1cecd6b4d1ecbce65f03938))

### [3.1.1](https://github.com/maidsafe/sn_consensus/compare/v3.1.0...v3.1.1) (2022-07-20)

## [3.1.0](https://github.com/maidsafe/sn_consensus/compare/v3.0.0...v3.1.0) (2022-06-23)


### Features

* **decision:** impl partial-ord, ord on Decision ([906b9c6](https://github.com/maidsafe/sn_consensus/commit/906b9c64a39115e4b7ef08fe7d3a0ec7131943d2))

## [3.0.0](https://github.com/maidsafe/sn_consensus/compare/v2.1.1...v3.0.0) (2022-06-21)


### ⚠ BREAKING CHANGES

* **decision:** Decisions hold signature over full proposal set
rather than individual proposals

### Features

* **decision:** Sign proposal set rather than individual proposals ([fa48612](https://github.com/maidsafe/sn_consensus/commit/fa486124c0fe26d4111ecb04e622607d43836565))

### [2.1.1](https://github.com/maidsafe/sn_consensus/compare/v2.1.0...v2.1.1) (2022-06-14)

## [2.1.0](https://github.com/maidsafe/sn_consensus/compare/v2.0.0...v2.1.0) (2022-06-06)


### Features

* **serde:** make decision serde ([59b866a](https://github.com/maidsafe/sn_consensus/commit/59b866a96a605f1f12959295369c69e3887fd603))

## [2.0.0](https://github.com/maidsafe/sn_consensus/compare/v1.17.1...v2.0.0) (2022-05-24)


### ⚠ BREAKING CHANGES

* **versions:** move validations to vote struct

* **versions:** forgot to mark last commits as breaking changes ([8ae1e4c](https://github.com/maidsafe/sn_consensus/commit/8ae1e4cb82e20afb7125da6fa769d6ec70b1bec7))

### [1.17.1](https://github.com/maidsafe/sn_consensus/compare/v1.17.0...v1.17.1) (2022-05-18)


### Bug Fixes

* **decision:** validate all votes in decision are from same gen ([91d896c](https://github.com/maidsafe/sn_consensus/commit/91d896c057f5b6b8dd0e74413a0031143c340173))

## [1.17.0](https://github.com/maidsafe/sn_consensus/compare/v1.16.1...v1.17.0) (2022-05-18)


### Features

* **decision:** add byzantine fault checks to decision validation ([e5c5f8d](https://github.com/maidsafe/sn_consensus/commit/e5c5f8dc6aba12293caa402868a403b266dfe571))
* **decision:** flesh out decision validation ([dd0fb7d](https://github.com/maidsafe/sn_consensus/commit/dd0fb7d5fe0849b7848ad3a5c39b30061f58557d))
* **tests:** add decision validation as a part of the test harness ([7ff642e](https://github.com/maidsafe/sn_consensus/commit/7ff642e71b349665aa019a4ca6b13487f2897fe9))

### [1.16.1](https://github.com/maidsafe/sn_consensus/compare/v1.16.0...v1.16.1) (2022-05-17)

## [1.16.0](https://github.com/maidsafe/sn_consensus/compare/v1.15.1...v1.16.0) (2022-03-28)


### Features

* **traits:** derive Clone, PartialEq, and Eq on Consensus ([e96a150](https://github.com/maidsafe/sn_consensus/commit/e96a150426b813650933e1b9c74bedd1b9110f6f))

### [1.15.1](https://github.com/maidsafe/sn_consensus/compare/v1.15.0...v1.15.1) (2022-03-09)

## [1.15.0](https://github.com/maidsafe/sn_membership/compare/v1.14.0...v1.15.0) (2022-03-08)


### Features

* **perf:** early out if we've already validated a vote ([aecbed2](https://github.com/maidsafe/sn_membership/commit/aecbed2517f80218b68594821f6bc5f4df8bd1b7))
* cache processed votes by their signature ([e8a7998](https://github.com/maidsafe/sn_membership/commit/e8a79987df71e6aa1c35375e3f013d5ba5576bb7))


### Bug Fixes

* add back explanation for keeping faulty voter ids ([75a09d0](https://github.com/maidsafe/sn_membership/commit/75a09d009bb3515c17c084ec9a72bb4006ce2bd4))
* add explicit struct for super_majority count summary ([e5931ac](https://github.com/maidsafe/sn_membership/commit/e5931ac22dd214a6eef7eff69b4cf161acdc6622))
* get super-majority proposals from winning candidate ([38dedc7](https://github.com/maidsafe/sn_membership/commit/38dedc7be298c093230dbb5aa6815ed777e4e0bd))
* handover anti-entropy returns decision vote if we've decided ([840b579](https://github.com/maidsafe/sn_membership/commit/840b579b6dc5bf2f3af61011f4d6112963608f0a))
* handover tests now log with env_logger ([111ee6c](https://github.com/maidsafe/sn_membership/commit/111ee6cad411dbdd48a318fc5d8b89826fcd5427))
* impl SignedVote::candidate + rename known_faulty to faulty_ids ([29b6568](https://github.com/maidsafe/sn_membership/commit/29b6568ab67e8fdbe78ea56defd07bb5223974a6))
* log vote before checking for decision ([db4b23b](https://github.com/maidsafe/sn_membership/commit/db4b23be8574ce74aff038726dfda155a264706e))
* move to a final broadcast on decision ([d53df88](https://github.com/maidsafe/sn_membership/commit/d53df88be7ed62fff7e4f695a4c98ad3abc4f0a5))
* recursively check votes for faults ([20d95d7](https://github.com/maidsafe/sn_membership/commit/20d95d73851d708c7dea5b09551c32cdc78c0e35))
* test_have_we_seen_this_vote_before signs votes properly ([13b6eb3](https://github.com/maidsafe/sn_membership/commit/13b6eb39f86caca87f33b7d62242b0150c6c2543))

## [1.14.0](https://github.com/maidsafe/sn_membership/compare/v1.13.0...v1.14.0) (2022-03-02)


### Features

* **prop_bft_consensus:** take n_action as input instead of from rng ([939bfca](https://github.com/maidsafe/sn_membership/commit/939bfcaa45d510cf20c1980209a00e15c2e66b88))
* **tests:** add env_logger to tests ([ce86f15](https://github.com/maidsafe/sn_membership/commit/ce86f153e0929b6f27cf6dab9ba6808c4e053c80))
* test_membership_bft_consensus_qc3 ([a583900](https://github.com/maidsafe/sn_membership/commit/a583900aa5a6b9bc546edcf1af16622fde5287a9))
* test_membership_interpreter_qc4 ([af209ad](https://github.com/maidsafe/sn_membership/commit/af209ad7553524a33d4fd84f070b668ea15fba8c))


### Bug Fixes

* add new test checking that faulty votes are not counted ([28d762f](https://github.com/maidsafe/sn_membership/commit/28d762fa15937d0edf3b8c3969264a0d54c4652f))
* build_super_majority_vote takes faults as input ([c5652f0](https://github.com/maidsafe/sn_membership/commit/c5652f0d3b652db07b8b673e3d8a35fcf343190c))
* filter out faulty votes when counting candidates ([d543b4d](https://github.com/maidsafe/sn_membership/commit/d543b4d4da88e8f5c8bbeefe86f2c33d40eb80f2))
* recursively handle vote when casting; keep consensus history ([bd5a766](https://github.com/maidsafe/sn_membership/commit/bd5a7663e3b63d9c627afe2a1f32eb08e52525e2))
* remove unneccessary anti_entropy calls that may mask errors ([f1ae81e](https://github.com/maidsafe/sn_membership/commit/f1ae81edda25f069718ddbe5ae68c79608c99355))
* remove unused dependencies ([602662a](https://github.com/maidsafe/sn_membership/commit/602662a9f7f518b313a117f2cb895e6c5e39432a))
* **naming:** singular candidate/super-majority in VoteCount methods ([64d97f5](https://github.com/maidsafe/sn_membership/commit/64d97f51648dd66910bd1a5aaeb72f402cf45d6b))
* **tests:** simplify bft_qc1 test case ([fd18675](https://github.com/maidsafe/sn_membership/commit/fd18675d4fd8620d72a20fdcd6cde1660eb13db7))
* don't log signed voted in sn_membership ([1c2da5f](https://github.com/maidsafe/sn_membership/commit/1c2da5f7daa4e33214136267c1169bcef2215175))
* drop votes from faulty voters ([73625aa](https://github.com/maidsafe/sn_membership/commit/73625aaa96bda5bc6351609a357c70ea593dfbb9))
* idempotency check and no-op when we've both terminated ([88ae8f3](https://github.com/maidsafe/sn_membership/commit/88ae8f31e6f53c64b85af1bb140425050398159d))
* simplify votes when making decision ([9058262](https://github.com/maidsafe/sn_membership/commit/9058262bdebaf4a01d178b0d169c6bd32fa3d073))
* undecided consensus is kept in it's own field to remove unwraps ([b3e99f3](https://github.com/maidsafe/sn_membership/commit/b3e99f3bac3e3aa9230c8dd5a71245e92da08a0f))
* update tests ([56efb6f](https://github.com/maidsafe/sn_membership/commit/56efb6fe341fcb415e265c479d7cf64b6f8f1a37))
* use count_votes instead of proposals to decide if a merge vote is productive ([bfbcbaf](https://github.com/maidsafe/sn_membership/commit/bfbcbaf2f6df7c256233a2c643846e48d6d479c8))
* when adopting decision, use faults from signed vote rather than our ([41dcecc](https://github.com/maidsafe/sn_membership/commit/41dcecc63d2bfcb3a518181358b3c9c15505e2df))
* **consensus:** derive Clone, PartialEq/Eq on Decision, VoteResponse ([b17dc9d](https://github.com/maidsafe/sn_membership/commit/b17dc9d7621f202926ed7c153bee5629fa3a630d))
* **handle_signed_vote:** handle_signed_vote reads gen from vote ([c06ca78](https://github.com/maidsafe/sn_membership/commit/c06ca780a38b8b87d458481c4b3c791104adcb0b))
* **logging:** move more logging to log::info ([27bd4ab](https://github.com/maidsafe/sn_membership/commit/27bd4ab5d1532728e3fd2eacc52661f50881be4a))
* **vote counting:** count each voters proposals only once ([47572e3](https://github.com/maidsafe/sn_membership/commit/47572e38c559d820d2e05cabe606dcc15b5ce5b5))

## [1.13.0](https://github.com/maidsafe/sn_membership/compare/v1.12.0...v1.13.0) (2022-02-23)


### Features

* **fault-detection:** introduce fault detection ([4b8108c](https://github.com/maidsafe/sn_membership/commit/4b8108c2a1ef0bb44a722fcac15ec4c2a7f336fa))


### Bug Fixes

* **fault_detection:** accept network decisions even when faulty ([ec0ffb4](https://github.com/maidsafe/sn_membership/commit/ec0ffb4b0d4ad2ef32feaf13d719312281ee856f))
* **tests:** drain_queued_packets after segregated elder comes online ([bbc9670](https://github.com/maidsafe/sn_membership/commit/bbc967071a691058b3def32c9b17c2a5a7c5fc28))
* **tests:** ensure that one_faulty_node test is deciding on `1` ([660eff9](https://github.com/maidsafe/sn_membership/commit/660eff96a1608b2814bcc9dac233073d4f32e232))
* when adopting a vote, use merge rather than copy proposal ([02cea8e](https://github.com/maidsafe/sn_membership/commit/02cea8ed3d683236d91a9875a0fb329f80ab295d))

## [1.12.0](https://github.com/maidsafe/sn_membership/compare/v1.11.0...v1.12.0) (2022-02-15)


### Features

* check for smsm before splits ([ffa97f5](https://github.com/maidsafe/sn_membership/commit/ffa97f51ae6923058156a7b7ceca7ea543c6d7c3))
* final broadcast when receiving new votes after termination ([0d502f9](https://github.com/maidsafe/sn_membership/commit/0d502f9b1b17f9c97131ec551033c5345708389f))
* strict supersedes func ([e0f2265](https://github.com/maidsafe/sn_membership/commit/e0f2265d225ee654ba3b456ec47c14075aa5c53a))


### Bug Fixes

* adapt catch up broadcast to sig shares ([edb0aeb](https://github.com/maidsafe/sn_membership/commit/edb0aeb8ec59da44120de20e7651070891c03a74))
* infinite loop issue, add one faulty node test ([ef9c24e](https://github.com/maidsafe/sn_membership/commit/ef9c24ec92772de9f9e0637792bdad192b29867b))
* swich to new votes from voter instead of new props, fix conflicting votes issues ([7c33f45](https://github.com/maidsafe/sn_membership/commit/7c33f4586be7a2a52257c5761d0c1712d4a2be06))
* upgrade test to keyshares ([a092f49](https://github.com/maidsafe/sn_membership/commit/a092f49861833e07f0406f6508977d843c6500de))

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
