---
title: "Batched Token Issuance Protocol"
abbrev: Batched Tokens
docname: draft-ietf-privacypass-batched-tokens-latest
category: std

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: R. Robert
    name: Raphael Robert
    org: Phoenix R&D
    email: ietf@raphaelrobert.com
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare
    email: caw@heapingbits.net

--- abstract

This document specifies a variant of the Privacy Pass issuance protocol that
allows for batched issuance of tokens. This allows clients to request more than
one token at a time and for issuers to isse more than one token at a time.

--- middle

# Introduction

This document specifies a variant of the Privacy Pass issuance protocol (as
defined in {{!ARCH=I-D.ietf-privacypass-architecture}}) that allows for batched
issuance of tokens. This allows clients to request more than one token at a time
and for issuers to isse more than one token at a time.

The base Privacy Pass issuance protocol
{{!ISSUANCE=I-D.ietf-privacypass-protocol}} defines stateless anonymous tokens,
which can either be publicly verifiable or not. While it is possible to run
multiple instances of the issuance protocol in parallel, e.g., over a
multiplexed transport such as HTTP/3 {{?HTTP3=RFC9114}}, the cost of doing so
scales linearly with the number of instances.

This variant builds upon the privately verifiable issuance protocol that uses
VOPRF {{!OPRF=I-D.irtf-cfrg-voprf}}, and allows for batched issuance of tokens.
This allows clients to request more than one token at a time and for issuers to
issue more than one token at a time. In effect, batched issuance performance
scales better than linearly.

This issuance protocol registers the batched token type ({{iana-token-type}}),
to be used with the PrivateToken HTTP authentication scheme defined in
{{!AUTHSCHEME=I-D.ietf-privacypass-auth-scheme}}.

# Motivation

Privately Verifiable Tokens (as defines in
{{!ISSUANCE=I-D.ietf-privacypass-protocol}}) offer a simple way to unlink the
issuance from the redemption. The base protocol however only allows for a single
token to be issued at a time for every challenge. In some cases, especially
where a large number of clients need to fetch a large number of tokens, this may
introduce performance bottlenecks. The Batched Token Issuance Protocol improves
upon the basic Privately Verifiable Token issuance protocol in the following key
ways:

1. Issuing multiple tokens at once in response to a single TokenChallenge,
   thereby reducing the size of the proofs required for multiple tokens.
1. Improving server and client issuance efficiency by amortizing the cost of the
   VOPRF proof generation and verification, respectively.

# Client-to-Issuer Request {#client-to-issuer-request}

Except where specified otherwise, the client follows the same protocol as
described in {{ISSUANCE, Section 5.1}}.

The Client first creates a context as follows:

~~~
client_context = SetupVOPRFClient(ciphersuiteID, pkI)
~~~

`ciphersuiteID` is the ciphersuite identifier from {{OPRF}} corresponding
to the ciphersuite being used for this token version. SetupVOPRFClient is
defined in {{OPRF, Section 3.2}}.

`Nr` denotes the number of tokens the clients wants to request. For every token,
the Client then creates an issuance request message for a random value `nonce`
with the input challenge and Issuer key identifier as described below:

~~~
nonce_i = random(32)
challenge_digest = SHA256(challenge)
token_input = concat(token_type, nonce_i, challenge_digest, token_key_id)
blind_i, blinded_element_i = client_context.Blind(token_input)
~~~

`token_type` corresponds to the 2-octet integer in the challenge.

The above is repeated for each token to be requested. Importantly, a fresh nonce
MUST be sampled each time.

The Client then creates a TokenRequest structured as follows:

~~~tls
struct {
    uint8_t blinded_element[Ne];
} BlindedElement;

struct {
   uint16_t token_type;
   uint8_t truncated_token_key_id;
   BlindedElement blinded_elements<0..2^16-1>;
} TokenRequest;
~~~

The structure fields are defined as follows:

- "token_type" is a 2-octet integer, which matches the type in the challenge.

- "truncated_token_key_id" is the least significant byte of the `token_key_id`
  in network byte order (in other words, the last 8 bits of `token_key_id`).

- "blinded_elements" is a list of `Nr` serialized elements, each of length `Ne`
  bytes and computed as `SerializeElement(blinded_element_i)`, where
  blinded_element_i is the i-th output sequence of `Blind` invocations above. Ne
  is as defined in {{OPRF, Section 4}}.

Upon receipt of the request, the Issuer validates the following conditions:

- The TokenRequest contains a supported token_type equal to one of the batched
  token types defined in this document.
- The TokenRequest.truncated_token_key_id corresponds to a key ID of a Public
  Key owned by the issuer.
- Nr, as determined based on the size of TokenRequest.blinded_elements, is
  less than or equal to the number of tokens that the issuer can issue in a
  single batch.

If any of these conditions is not met, the Issuer MUST return an HTTP 400 error
to the client.

# Issuer-to-Client Response {#issuer-to-client-response}

Except where specified otherwise, the client follows the same protocol as
described in {{ISSUANCE, Section 5.2}}.

Upon receipt of a TokenRequest, the Issuer tries to deseralize the i-th element
of TokenRequest.blinded_elements using DeserializeElement from {{Section 2.1 of
OPRF}}, yielding `blinded_element_i` of type `Element`. If this fails for any of
the TokenRequest.blinded_elements values, the Issuer MUST return an HTTP 400
error to the client. Otherwise, if the Issuer is willing to produce a token to
the Client, the issuer forms a list of `Element` values, denoted
`blinded_elements`, and computes a blinded response as follows:

~~~
server_context = SetupVOPRFServer(ciphersuiteID, skI, pkI)
evaluated_elements, proof = server_context.BlindEvaluateBatch(skI, blinded_elements)
~~~

`ciphersuiteID` is the ciphersuite identifier from {{OPRF}} corresponding
to the ciphersuite being used for this token version. SetupVOPRFServer is
defined in {{OPRF, Section 3.2}}. The issuer uses a list of
blinded elements to compute in the proof generation step. The
`BlindEvaluateBatch` function is a batch-oriented version of the `BlindEvaluate`
function described in {{OPRF, Section 3.3.2}}. The description of
`BlindEvaluateBatch` is below.

~~~
Input:

  Element blindedElements[Nr]

Output:

  Element evaluatedElements[Nr]
  Proof proof

Parameters:

  Group G
  Scalar skS
  Element pkS

def BlindEvaluateBatch(blindedElements):
  evaluatedElements = []
  for blindedElement in blindedElements:
    evaluatedElements.append(skS * blindedElement)

  proof = GenerateProof(skS, G.Generator(), pkS,
                        blindedElements, evaluatedElements)
  return evaluatedElements, proof
~~~

The Issuer then creates a TokenResponse structured as follows:

~~~tls
struct {
    uint8_t evaluated_element[Ne];
} EvaluatedElement;

struct {
   EvaluatedElement evaluated_elements<0..2^16-1>;
   uint8_t evaluated_proof[Ns + Ns];
} TokenResponse;
~~~

The structure fields are defined as follows:

- "evaluated_elements" is a list of `Nr` serialized elements, each of length
  `Ne` bytes and computed as `SerializeElement(evaluate_element_i)`, where
  evaluate_element_i is the i-th output of `BlindEvaluate`.

- "evaluated_proof" is the (Ns+Ns)-octet serialized proof, which is a pair of
  Scalar values, computed as `concat(SerializeScalar(proof[0]),
  SerializeScalar(proof[1]))`, where Ns is as defined in {{OPRF, Section 4}}.

# Finalization {#finalization}

Upon receipt, the Client handles the response and, if successful, deserializes
the body values TokenResponse.evaluate_response and
TokenResponse.evaluate_proof, yielding `evaluated_elements` and `proof`. If
deserialization of either value fails, the Client aborts the protocol.
Otherwise, the Client processes the response as follows:

~~~
authenticator_values = client_context.FinalizeBatch(token_input, blind, evaluated_elements, blinded_elements, proof)
~~~

The `FinalizeBatch` function is a batched variant of the `Finalize` function as
defined in {{OPRF, Section 3.3.2}}. `FinalizeBatch` accepts lists of evaluated
elements and blinded elements as input parameters, and is implemented as
described below:

~~~
Input:

  PrivateInput input
  Scalar blind
  Element evaluatedElements[Nr]
  Element blindedElements[Nr]
  Proof proof

Output:

  opaque output[Nh * Nr]

Parameters:

  Group G
  Element pkS

Errors: VerifyError

def FinalizeBatch(input, blind, evaluatedElements, blindedElements, proof):
  if VerifyProof(G.Generator(), pkS, blindedElements,
                 evaluatedElements, proof) == false:
    raise VerifyError

  output = nil
  for evaluatedElement in evaluatedElements:
    N = G.ScalarInverse(blind) * evaluatedElement
    unblindedElement = G.SerializeElement(N)
    hashInput = I2OSP(len(input), 2) || input ||
                I2OSP(len(unblindedElement), 2) || unblindedElement ||
                "Finalize"
    output = concat(output, Hash(hashInput))

  return output
~~~

If this succeeds, the Client then constructs `Nr` Token values as follows, where
`authenticator` is the i-th Nh-byte length slice of `authenticator_values` that
corresponds to `nonce`, the i-th nonce that was sampled in
{{client-to-issuer-request}}:

~~~
struct {
    uint16_t token_type;
    uint8_t nonce[32];
    uint8_t challenge_digest[32];
    uint8_t token_key_id[32];
    uint8_t authenticator[Nh];
} Token;
~~~

If the FinalizeBatch function fails, the Client aborts the protocol.

# Security considerations {#security-considerations}

Implementors SHOULD be aware of the security considerations described in {{OPRF,
Section 6.2.3}} and implement mitigation mechanisms. Application can mitigate
this issue by limiting the number of clients and limiting the number of token
requests per client per key.

# IANA considerations

## Token Type {#iana-token-type}

This document updates the "Token Type" Registry ({{AUTHSCHEME}}) with the
following value:

| Value  | Name                                        | Publicly Verifiable | Public Metadata | Private Metadata | Nk  | Reference        |
|:-------|:--------------------------------------------|:--------------------|:----------------|:-----------------|:----|:-----------------|
| 0xF901 | Batched Token VOPRF (P-384, SHA-384) | N                   | N               | N                | 32  | This document    |
| 0xF91A | Batched Token VOPRF (ristretto255, SHA-512) | N                   | N               | N                | 32  | This document    |
{: #aeadid-values title="Token Types"}
