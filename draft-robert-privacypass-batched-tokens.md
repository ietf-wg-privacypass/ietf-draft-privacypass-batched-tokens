---
title: "Batched Token Issuance Protocol"
abbrev: Batched Tokens
docname: draft-robert-privacypass-batched-tokens-latest
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: R. Robert
    name: Raphael Robert
    org:
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

The base Privacy Pass issuance protocol {{!ISSUANCE=I-D.ietf-privacypass-protocol}}
defines stateless anonymous tokens, which can either be publicly verifiable
or not.

This variant build upon the privately verifiable issuance protocol that uses
VOPRF {{!OPRF=I-D.irtf-cfrg-voprf}}, and allows for batched issuance of tokens.
This allows clients to request more than one token at a time and for issuers to
isse more than one token at a time.

This issuance protocol registers the batched token type
({{iana-token-type}}), to be used with the PrivateToken HTTP authentication
scheme defined in {{!AUTHSCHEME=I-D.ietf-privacypass-auth-scheme}}.

# Motivation

Privately Verifiable Tokens (as defines in
{{!ISSUANCE=I-D.ietf-privacypass-protocol}}) offer a siple way to unlink the
issuance from the redemption. The base protocol however only allows for a single
token to be issued at a time for every challenge. In some cases, this is not
sufficient for good unlikability, especially when the redemption happens shortly
after the issuance. The Batched Token Issuance Protocol allows for multiple aims
to improve the situation by

 - Issuing multiple tokens at a time for a single challenge
 - Making the issuance more efficient by amortizing the cost of the VOPRF proof generation.


# Client-to-Issuer Request {#client-to-issuer-request}

Except where specified otherwise, the client follows the same protocol as described in
{{ISSUANCE, Section 5.1}}.

The Client first creates a context as follows:

~~~
client_context = SetupVOPRFClient(0x0001, pkI)
~~~

Here, 0x0001 is the two-octet identifier corresponding to the
OPRF(ristretto255, SHA-512) ciphersuite in {{OPRF}}. SetupVOPRFClient
is defined in {{OPRF, Section 3.2}}.

`Nr` denotes the number of tokens the clients wants to request. For every token,
the Client then creates an issuance request message for a random value `nonce`
with the input challenge and Issuer key identifier as described below:

~~~
nonce = random(32)
challenge_digest = SHA256(challenge)
token_input = concat(0x0003, nonce, challenge_digest, key_id)
blind, blinded_element = client_context.Blind(token_input)
~~~

The above is repeated for each token to be requested.

The Client then creates a TokenRequest structured as follows:

~~~tls
struct {
    uint8_t blinded_element[Ne];
} BlindedElement;

struct {
   uint16_t token_type = 0x0003;
   uint8_t token_key_id;
   BlindedElement blinded_element[Nr];
} TokenRequest;
~~~

The structure fields are defined as follows:

- "token_type" is a 2-octet integer, which matches the type in the challenge.

- "token_key_id" is the least significant byte of the `key_id` in network byte order (in other words, the last 8 bits of `key_id`).

- "blinded_element" is the Ne-octet blinded message defined above, computed as
  `SerializeElement(blinded_element)`. Ne is as defined in {{OPRF, Section 4}}.

Upon receipt of the request, the Issuer validates the following conditions:

- The TokenRequest contains a supported token_type.
- The TokenRequest.token_key_id corresponds to a key ID of a Public Key owned by the issuer.
- The TokenRequest.blinded_request is of the correct size.
- Nr is less than or equal to the number of tokens that the issuer can issue.

If any of these conditions is not met, the Issuer MUST return an HTTP 400 error
to the client.

Upon receipt of a TokenRequest, the Issuer tries to deseralize TokenRequest.blinded_element[i]
using DeserializeElement from {{Section 2.1 of OPRF}}, yielding `blinded_element`.
If this fails, the Issuer MUST return an HTTP 400 error to the client. Otherwise, if the
Issuer is willing to produce a token to the Client, the Issuer completes the issuance
flow by computing a blinded response as follows:

# Issuer-to-Client Response {#issuer-to-client-response}

Except where specified otherwise, the client follows the same protocol as described in
{{ISSUANCE, Section 5.2}}.

~~~
server_context = SetupVOPRFServer(0x0001, skI, pkI)
evaluated_elements, proof = server_context.BlindEvaluateBatch(skI, blinded_element)
~~~

SetupVOPRFServer is defined in {{OPRF, Section 3.2}}. The issuer uses a list of
blinded elements to compute in the proof generation step, the `BlindEvaluate`
function described in {{OPRF, Section 3.3.2}} is amended in the folowing way:

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
   EvaluatedElement evaluated_elements[Nr];
   uint8_t evaluated_proof[Ns + Ns];
} TokenResponse;
~~~

The structure fields are defined as follows:

- "evaluated_element" is the Ne-octet evaluated element, computed as
  `SerializeElement(evaluate_element)`.

- "evaluated_proof" is the (Ns+Ns)-octet serialized proof, which is a pair of
  Scalar values, computed as `concat(SerializeScalar(proof[0]),
  SerializeScalar(proof[1]))`, where Ns is as defined in {{OPRF, Section 4}}.

# Finalization {#finalization}

Upon receipt, the Client handles the response and, if successful, deserializes
the body values TokenResponse.evaluate_response and TokenResponse.evaluate_proof,
yielding `evaluated_elements` and `proof`. If deserialization of either value fails,
the Client aborts the protocol. Otherwise, the Client processes the response as
follows:

~~~
authenticator_values = client_context.FinalizeBatch(token_input, blind, evaluated_elements, blinded_elements, proof)
~~~

The FinalizeBatch function is similar to the Finalize function is defined in
{{OPRF, Section 3.3.2}}, but accepts lists of evaluated elements and blinded
elements as input parameters:

~~~
Input:

  PrivateInput input
  Scalar blind
  Element evaluatedElements[Nr]
  Element blindedElements[Nr]
  Proof proof

Output:

  opaque outputs[Nh][Nr]

Parameters:

  Group G
  Element pkS

Errors: VerifyError

def FinalizeBatch(input, blind, evaluatedElements, blindedElements, proof):
  if VerifyProof(G.Generator(), pkS, blindedElements,
                 evaluatedElements, proof) == false:
    raise VerifyError

  outputs = []
  for evaluatedElement in evaluatedElements:
    N = G.ScalarInverse(blind) * evaluatedElement
    unblindedElement = G.SerializeElement(N)
    hashInput = I2OSP(len(input), 2) || input ||
                I2OSP(len(unblindedElement), 2) || unblindedElement ||
                "Finalize"
    outputs.append(Hash(hashInput))

  return outputs
~~~

If this succeeds, the Client then constructs a Token as follows, where
`authenticator` is the element of `autheticator_values` that corresponds to the
nonce was sampled in {{client-to-issuer-request}} and that the client wants to
redeem:

~~~
struct {
    uint16_t token_type = 0x0003
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

This document updates the "Token Type" Registry ({{AUTHSCHEME}}) with the following value:

| Value  | Name                                        | Publicly Verifiable | Public Metadata | Private Metadata | Nk  | Reference        |
|:-------|:--------------------------------------------|:--------------------|:----------------|:-----------------|:----|:-----------------|
| 0x0003 | Batched Token VOPRF (ristretto255, SHA-512) | N                   | N               | N                | 32  | This document    |
{: #aeadid-values title="Token Types"}
