#! VULNERABLE travel-agent — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant bookTrip irreversible

let raw = fetch<web>
commit { bookTrip(raw) }  # tainted -> tool: REJECTED
