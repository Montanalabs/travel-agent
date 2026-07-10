#! Travel-booking agent — untrusted a request can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires bookTrip — the travel-booking agent sink
#! @effect io
#! @irreversible
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant bookTrip irreversible

type TripKind = Flight | HotelT | CarT
type Decision = BookTrip(TripKind) | DeclineTrip

let raw = fetch<web>  # UNTRUSTED a request — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
commit { bookTrip(d) }  # act on the trusted decision only
