// ## Propose state
//
// A validated Byzantine agreement protocol is activated by a message of the form
// $$(ID, in, v-propose, v, π)$$,
// where $$v ∈ \{0, 1\}^∗$$ and $$π ∈ \{0, 1\}^∗$$ . When this occurs, we say &&P_i$$
// proposes $$v$$ validated by $$π$$ for transaction $$ID$$.
//
// ## Broadcast state
//
// Each party $$P_i$$ c-broadcasts (Consistent Broadcast) the value that it proposes to
// all other parties using verifiable authenticated consistent broadcast. This ensures that all
// honest parties obtain the same proposal value for any particular party, even if the sender
// is corrupted.
