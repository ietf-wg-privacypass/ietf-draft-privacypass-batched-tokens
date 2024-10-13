---
title: "Batched Token Issuance Protocol"
abbrev: Batched Tokens
docname: draft-ietf-privacypass-batched-tokens-latest
submissiontype: IETF
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
one token at a time and for issuers to issue more than one token at a time.

--- middle

# Change Log:

RFC EDITOR PLEASE DELETE THIS SECTION.

draft-02

- Renaming TokenRequest to BatchTokenRequest and TokenResponse to
  BatchTokenResponse
- IANA: Media types for BatchTokenRequest and BatchTokenResponse
- IANA: Expand Token Type registry entry
- Various editorial fixes

draft-01

- Initial WG document version

# Introduction

This document specifies a variant of the Privacy Pass issuance protocol (as
defined in {{!ARCH=I-D.ietf-privacypass-architecture}}) that allows for batched
issuance of tokens. This allows clients to request more than one token at a time
and for issuers to issue more than one token at a time.

The base Privacy Pass issuance protocol
{{!ISSUANCE=I-D.ietf-privacypass-protocol}} defines stateless anonymous tokens,
which can either be publicly verifiable or not. While it is possible to run
multiple instances of the issuance protocol in parallel, e.g., over a
multiplexed transport such as HTTP/3 {{?HTTP3=RFC9114}}, the cost of doing so
scales linearly with the number of instances.

This variant of the issuance protocol builds upon the privately verifiable
issuance protocol in {{ISSUANCE}} that uses VOPRF {{!OPRF=I-D.irtf-cfrg-voprf}},
and allows for batched issuance of tokens. This allows clients to request more
than one token at a time and for issuers to issue more than one token at a
time. In effect, batched issuance performance scales better than linearly.

The token type for this issuance protocol is the same as in the non-batched
issuance protocol. This is because the underlying cryptographic protocol is
the same. As a result, the batched issuance protocol in this document only
works with token types that support batching.

This batched issuance protocol registers one new token type ({{iana-token-type}}),
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
token_input = concat(token_type, nonce_i, challenge_digest,
                token_key_id)
blind_i, blinded_element_i = client_context.Blind(token_input)
~~~

`token_type` corresponds to the 2-octet integer in the challenge.

The above is repeated for each token to be requested. Importantly, a fresh nonce
MUST be sampled each time.

The Client then creates a BatchTokenRequest structured as follows:

~~~tls
struct {
    uint8_t blinded_element[Ne];
} BlindedElement;

struct {
   uint16_t token_type;
   uint8_t truncated_token_key_id;
   BlindedElement blinded_elements<0..2^16-1>;
} BatchTokenRequest;
~~~

The structure fields are defined as follows:

- "token_type" is a 2-octet integer, which matches the type in the challenge.

- "truncated_token_key_id" is the least significant byte of the `token_key_id`
  in network byte order (in other words, the last 8 bits of `token_key_id`).

- "blinded_elements" is a list of `Nr` serialized elements, each of length `Ne`
  bytes and computed as `SerializeElement(blinded_element_i)`, where
  blinded_element_i is the i-th output sequence of `Blind` invocations above. Ne
  is as defined in {{OPRF, Section 4}}.

The Client then generates an HTTP POST request to send to the Issuer Request
URL, with the BatchTokenRequest as the content. The media type for this request
is "application/private-token-batch-request". An example request for the Issuer
Request URL "https://issuer.example.net/request" is shown below.

~~~
POST /request HTTP/1.1
Host: issuer.example.net
Accept: application/private-token-batch-response
Content-Type: application/private-token-batch-request
Content-Length: <Length of BatchTokenRequest>

<Bytes containing the BatchTokenRequest>
~~~

# Issuer-to-Client Response {#issuer-to-client-response}

Except where specified otherwise, the client follows the same protocol as
described in {{ISSUANCE, Section 5.2}}.

Upon receipt of the request, the Issuer validates the following conditions:

- The BatchTokenRequest contains a supported token_type equal to one of the batched
  token types defined in this document.
- The BatchTokenRequest.truncated_token_key_id corresponds to a key ID of a Public
  Key owned by the issuer.
- Nr, as determined based on the size of BatchTokenRequest.blinded_elements, is
  less than or equal to the number of tokens that the issuer can issue in a
  single batch.

If any of these conditions is not met, the Issuer MUST return an HTTP 400 error
to the client.

The Issuer then tries to deseralize the i-th element
of BatchTokenRequest.blinded_elements using DeserializeElement from {{Section 2.1 of
OPRF}}, yielding `blinded_element_i` of type `Element`. If this fails for any of
the BatchTokenRequest.blinded_elements values, the Issuer MUST return an HTTP 400
error to the client. Otherwise, if the Issuer is willing to produce a token to
the Client, the issuer forms a list of `Element` values, denoted
`blinded_elements`, and computes a blinded response as follows:

~~~
server_context = SetupVOPRFServer(ciphersuiteID, skI, pkI)
evaluated_elements, proof =
  server_context.BlindEvaluateBatch(skI, blinded_elements)
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

The Issuer then creates a BatchTokenResponse structured as follows:

~~~tls
struct {
    uint8_t evaluated_element[Ne];
} EvaluatedElement;

struct {
   EvaluatedElement evaluated_elements<0..2^16-1>;
   uint8_t evaluated_proof[Ns + Ns];
} BatchTokenResponse;
~~~

The structure fields are defined as follows:

- "evaluated_elements" is a list of `Nr` serialized elements, each of length
  `Ne` bytes and computed as `SerializeElement(evaluate_element_i)`, where
  evaluate_element_i is the i-th output of `BlindEvaluate`.

- "evaluated_proof" is the (Ns+Ns)-octet serialized proof, which is a pair of
  Scalar values, computed as `concat(SerializeScalar(proof[0]),
  SerializeScalar(proof[1]))`, where Ns is as defined in {{OPRF, Section 4}}.

The Issuer generates an HTTP response with status code 200 whose content
consists of TokenResponse, with the content type set as
"application/private-token-batch-response".

~~~
HTTP/1.1 200 OK
Content-Type: application/private-token-batch-response
Content-Length: <Length of BatchTokenResponse>

<Bytes containing the BatchTokenResponse>
~~~

# Finalization {#finalization}

Upon receipt, the Client handles the response and, if successful, deserializes
the body values TokenResponse.evaluate_response and
TokenResponse.evaluate_proof, yielding `evaluated_elements` and `proof`. If
deserialization of either value fails, the Client aborts the protocol.
Otherwise, the Client processes the response as follows:

~~~
authenticator_values = client_context.FinalizeBatch(token_input, blind,
                         evaluated_elements, blinded_elements, proof)
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

def FinalizeBatch(input, blind,
  evaluatedElements, blindedElements, proof):
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

If this succeeds, the Client then constructs `Nr` Token values, where
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

If the FinalizeBatch function fails, the Client aborts the protocol. Token
verification works exactly as specified in {{ISSUANCE}}.

# Security considerations {#security-considerations}

Implementors SHOULD be aware of the security considerations described in {{OPRF,
Section 6.2.3}} and implement mitigation mechanisms. Application can mitigate
this issue by limiting the number of clients and limiting the number of token
requests per client per key.

# IANA considerations

This section contains IANA codepoint allocation requests.

## Token Type {#iana-token-type}

This document updates the "Token Type" Registry ({{AUTHSCHEME}}) with the
following entry:

* Value: 0xF91A
* Name: VOPRF (ristretto255, SHA-512)
* Token Structure: As defined in {{Section 2.2 of AUTHSCHEME}}
* Token Key Encoding: Serialized using SerializeElement from {{Section 2.1 of OPRF}}
* TokenChallenge Structure: As defined in {{Section 2.1 of AUTHSCHEME}}
* Publicly Verifiable: N
* Public Metadata: N
* Private Metadata: N
* Nk: 32
* Nid: 32
* Reference: {{ISSUANCE, Section 5}}
* Notes: None

## Media Types

The following entries should be added to the IANA "media types"
registry:

- "application/private-token-batch-request"
- "application/private-token-batch-response"

The templates for these entries are listed below and the
reference should be this RFC.

### "application/private-token-batch-request" media type

Type name:

: application

Subtype name:

: private-token-request

Required parameters:

: N/A

Optional parameters:

: N/A

Encoding considerations:

: "binary"

Security considerations:

: see {{security-considerations}}

Interoperability considerations:

: N/A

Published specification:

: this specification

Applications that use this media type:

: Applications that want to issue or facilitate issuance of Privacy Pass tokens,
  including Privacy Pass issuer applications themselves.

Fragment identifier considerations:

: N/A

Additional information:

: <dl spacing="compact">
  <dt>Magic number(s):</dt><dd>N/A</dd>
  <dt>Deprecated alias names for this type:</dt><dd>N/A</dd>
  <dt>File extension(s):</dt><dd>N/A</dd>
  <dt>Macintosh file type code(s):</dt><dd>N/A</dd>
  </dl>

Person and email address to contact for further information:

: see Authors' Addresses section

Intended usage:

: COMMON

Restrictions on usage:

: N/A

Author:

: see Authors' Addresses section

Change controller:

: IETF
{: spacing="compact"}

### "application/private-token-batch-response" media type

Type name:

: application

Subtype name:

: private-token-response

Required parameters:

: N/A

Optional parameters:

: N/A

Encoding considerations:

: "binary"

Security considerations:

: see {{security-considerations}}

Interoperability considerations:

: N/A

Published specification:

: this specification

Applications that use this media type:

: Applications that want to issue or facilitate issuance of Privacy Pass tokens,
  including Privacy Pass issuer applications themselves.

Fragment identifier considerations:

: N/A

Additional information:

: <dl spacing="compact">
  <dt>Magic number(s):</dt><dd>N/A</dd>
  <dt>Deprecated alias names for this type:</dt><dd>N/A</dd>
  <dt>File extension(s):</dt><dd>N/A</dd>
  <dt>Macintosh file type code(s):</dt><dd>N/A</dd>
  </dl>

Person and email address to contact for further information:

: see Authors' Addresses section

Intended usage:

: COMMON

Restrictions on usage:

: N/A

Author:

: see Authors' Addresses section

Change controller:

: IETF
{: spacing="compact"}
