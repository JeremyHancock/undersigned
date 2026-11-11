# What should a service be able to check when an agent acts for someone?

*Design notes for [undersigned](../README.md).*

When an AI agent calls an API on my behalf, the API sees a bearer token. The
token says some client was given some scopes at some point. It does not say
what I approved, whether this particular request is inside it, or whether I
have changed my mind since. The service takes all of that on trust from
whoever issued the token.

That was tolerable when the client was an app with a fixed set of things it
did. It is less comfortable when the client decides at run time what to do
next.

## Two bad options

The obvious fix is to ask the person. Every write, a prompt. I built that
first, in a project called AgentCafe, and it does not survive contact with
real use: a person approving their fifteenth request of the day is no longer
reading them.

The other option is to approve once and let the agent do anything the scope
allows. That is where most integrations are today.

What I wanted was the arrangement people already use with each other: "you can
do these things, up to this much, until the end of the month; ask me about
anything bigger." An envelope.

## The envelope

A **standing grant** names a set of actions, a risk ceiling, an optional
budget and an expiry. Inside it the agent acts without prompting anyone.

Some things never fit inside. Each action has a risk tier, and anything rated
high or critical cannot be covered by a standing grant at all; the library
refuses to construct one. Those actions **punch through** to a single-use
grant, approved for one request and pinned to its method, URL and body.

So the person sees two kinds of prompt: an occasional "here is the envelope",
and a rare "this one is serious, look at it". Everything else is silent.

## Who signs what

In the first version, the broker (the party that shows the approval page)
signed a statement that I had approved. A service receiving it learned that
the broker said so.

That is weaker than it sounds. Anyone who steals the broker's signing key can
mint approvals for every user.

In undersigned, the grant is a small JSON document, and my passkey signs its
digest: the SHA-256 of the canonical document is used as the WebAuthn
challenge. The service pins my passkey's public key when my account is linked,
and checks that signature itself. A stolen broker key can still sign requests
inside grants I have already made. It cannot make new ones.

The broker still signs each request, because I am not there when the agent
acts. Each request carries a 30-second token and an HTTP message signature
over the method, URL, body digest and token. Change any of them and the
service refuses it.

## What the review broke

I had the code reviewed adversarially before calling it done. The reviewer
could not forge, replay or cross-use anything. It broke the design anyway.

The budget was enforced on an `amount` field. The agent supplied that amount
when asking the broker for a signature, and the service read it back out of
the signed token. Both sides were faithfully enforcing a number chosen by the
party being limited. Fifty writes went through a three-a-day budget, every one
of them correctly signed.

The same shape appeared twice more. A proof for a low-risk action could be
presented at a high-risk endpoint, because nothing tied the action named in
the proof to the route serving the request. And "pinned to this exact request"
pinned only the body, which for a delete is often empty.

The signatures were fine. What they covered was self-declared.

The fix is a rule I now think of as the actual design: **each side decides for
itself what a request is.** The broker and the service each hold their own
catalog saying how risky an action is and what it costs. The service says
which action an endpoint performs. A proof that disagrees is refused. Nothing
about risk or cost travels from the party being constrained to the party
doing the constraining.

## What it does not prove

- **That I read what I signed.** The approval page belongs to the broker. My
  passkey signs a digest; it has no way to show me the document. WebAuthn has
  a mechanism for binding displayed text to a signature only for payments.
- **Anything before account linking.** The service learns my public key at
  linking time, usually through the broker. That moment is trusted.
- **That I was present for a given request.** Under a standing grant I signed
  the envelope, not the request.

These are stated in the README as well, because a credential that overstates
itself is worse than none.

## Where this sits

Payments already has this idea. Google's [AP2](https://ap2-protocol.org/)
calls the signed approval a mandate, and the card networks have their own
versions. I could not find an adopted equivalent for actions that are not
payments, though the gap is being worked on from several directions:

- A [FIDO Alliance working group](https://fidoalliance.org/fido-alliance-to-develop-standards-for-trusted-ai-agent-interactions/)
  formed in April 2026 lists verifiable user instructions among its topics.
- Individual IETF drafts cover parts of it, including
  [authorization receipts](https://www.ietf.org/archive/id/draft-schrock-ep-authorization-receipts-01.html),
  [delegation receipts](https://datatracker.ietf.org/doc/draft-nelson-agent-delegation-receipts/)
  and [AAuth](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-10.html).
- [OAuth Transaction Tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/)
  carry a similar short-lived token, but only inside one trust domain.

undersigned is not a proposal to add to that list. It is a working example of
one combination I did not find elsewhere: an envelope the person grants and
signs, enforced independently by the service, with punch-through for what
does not belong in an envelope. It reuses existing standards for every piece
that has one (RFC 9421, 9530, 9396, 8785, 8417, 8935) and mints two
identifiers where none exists.

## What is missing

Persistence, key rotation, an approval page worth trusting, and a second
implementation in another language to show the wire format is not an accident
of this one. The review was one pass by an AI reviewer, not an audit.

*The envelope and joint-verification ideas come from AgentCafe. This library
was written with Claude Code, which wrote most of the code and ran the
review.*
