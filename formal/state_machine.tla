---------------- MODULE state_machine ----------------
EXTENDS Naturals
CONSTANTS Specified, Registered, Implemented, Tested, Shadowed, Approved, Enabled
VARIABLES state, killSwitch, signedApproval
States == {Specified, Registered, Implemented, Tested, Shadowed, Approved, Enabled}
Init == /\ state = Specified /\ killSwitch = TRUE /\ signedApproval = FALSE
Advance == \/ /\ state = Specified /\ state' = Registered /\ UNCHANGED <<killSwitch, signedApproval>>
          \/ /\ state = Registered /\ state' = Implemented /\ UNCHANGED <<killSwitch, signedApproval>>
          \/ /\ state = Implemented /\ state' = Tested /\ UNCHANGED <<killSwitch, signedApproval>>
          \/ /\ state = Tested /\ state' = Shadowed /\ UNCHANGED <<killSwitch, signedApproval>>
Approve == /\ state = Shadowed /\ state' = Approved /\ signedApproval' = TRUE /\ UNCHANGED killSwitch
Enable == /\ state = Approved /\ signedApproval /\ ~killSwitch /\ state' = Enabled /\ UNCHANGED <<killSwitch, signedApproval>>
ClearStop == /\ killSwitch /\ killSwitch' = FALSE /\ UNCHANGED <<state, signedApproval>>
EngageStop == /\ ~killSwitch /\ killSwitch' = TRUE /\ UNCHANGED <<state, signedApproval>>
Next == Advance \/ Approve \/ Enable \/ ClearStop \/ EngageStop
Safety == state \in States
EnableInvariant == state = Enabled => signedApproval
ExecutionAllowed == state = Enabled /\ ~killSwitch
StopInvariant == ExecutionAllowed => ~killSwitch
Spec == Init /\ [][Next]_<<state, killSwitch, signedApproval>>
=============================================================================
