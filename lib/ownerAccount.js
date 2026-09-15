/* The one account this deployment's single-tenant paths belong to.

   THE LITERAL LIVES HERE AND NOWHERE ELSE IN THE APPLICATION. It used to be
   typed out three times under three names — SCORING_ACCOUNT_ID in
   leadRadar.js, CAPTURE_OWNER_ID and OUTREACH_CREDENTIAL_OWNER_ID in
   server.js — because server.js requires leadRadar.js and so leadRadar.js
   could not require it back. Each copy was correct and each was a place the
   next edit could miss. This module breaks the cycle: both files require it,
   neither requires the other for this value, and the three names survive as
   aliases so that every call site still says WHICH of the three unrelated
   jobs it is doing.

   The three jobs, kept distinct on purpose (see the comment at each alias):
     SCORING_ACCOUNT_ID          whose Anthropic key pays for lead scoring
     CAPTURE_OWNER_ID            who a public landing-page capture is attributed to
     OUTREACH_CREDENTIAL_OWNER_ID  whose Bluesky login and Mastodon token the
                                 send path posts from, and therefore the only
                                 account Lead Radar and the Sales Agent's lead
                                 views are enabled for

   They are one value today because there is one customer. They will stop
   being one value on the day there are two, and on that day each alias gets
   its own source and this file goes.

   NOT USED BY scripts/checkRunResidue.js, and that is deliberate. That file
   keeps its own OWNER_ACCOUNT_ID so its refusal to delete the owner's rows
   cannot be moved by an edit to the application's idea of who the owner is.
   A safeguard derived from the thing it guards is not a safeguard.
   scripts/checkLeadRadarOwnerGate.js asserts the two agree, so they cannot
   drift apart unnoticed either. */

const OWNER_ACCOUNT_ID = "ea887c6e-e278-4a15-b7e9-cd78a9949b78";

module.exports = { OWNER_ACCOUNT_ID: OWNER_ACCOUNT_ID };
