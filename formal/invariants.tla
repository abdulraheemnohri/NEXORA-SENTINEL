---------------- MODULE invariants ----------------
EXTENDS Naturals
CONSTANTS L0, L1
VARIABLES autonomy, killSwitch, unknownInteraction, proposalExecuted
Init == /\ autonomy = L0 /\ killSwitch = TRUE /\ unknownInteraction = TRUE /\ proposalExecuted = FALSE
SafetyInvariant == autonomy \in {L0, L1}
KillSwitchInvariant == killSwitch = TRUE => proposalExecuted = FALSE
UnknownInteractionInvariant == unknownInteraction = TRUE => proposalExecuted = FALSE
ProposalIsNotMutation == proposalExecuted = FALSE
=============================================================================
