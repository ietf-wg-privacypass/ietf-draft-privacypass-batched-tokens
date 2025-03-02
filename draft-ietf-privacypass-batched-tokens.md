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
 -
    ins: T. Meunier
    name: Thibault Meunier
    org: Cloudflare Inc.
    email: ot-ietf@thibault.uk

--- abstract

This document specifies two variants of the Privacy Pass issuance protocol that
allow for batched issuance of tokens. These allow clients to request more than
one token at a time and for issuers to issue more than one token at a time.

--- middle

# Change Log:

RFC EDITOR PLEASE DELETE THIS SECTION.

draft-04

 - Rename the issuance variants
 - Clarify media types
 - Make generic issuance more generic byt prefixing requests & responses with token type

draft-03

- Arbitrary token types
- Error code 400 aligned with RFC9578 and replaced by error code 422

draft-02

- Renaming TokenRequest to BatchTokenRequest and TokenResponse to
  BatchTokenResponse
- IANA: Media types for BatchTokenRequest and BatchTokenResponse
- IANA: Expand Token Type registry entry
- Various editorial fixes

draft-01

- Initial WG document version

# Introduction

This document specifies two variants of Privacy Pass issuance protocols (as
defined in {{!RFC9576}}) that allow for batched issuance of tokens. This allows
clients to request more than one token at a time and for issuers to issue more
than one token at a time.

The base Privacy Pass issuance protocol {{!RFC9578}} defines stateless anonymous
tokens, which can either be publicly verifiable or not. While it is possible to
run multiple instances of the issuance protocol in parallel, e.g., over a
multiplexed transport such as HTTP/3 {{?HTTP3=RFC9114}} or by orchestrating
multiple HTTP requests, these ad-hoc solutions vary based on transport protocol
support. In addition, in some cases, they cannot take advantage of cryptographic
optimizations.

The first variant of the issuance protocol builds upon the privately verifiable
issuance protocol in {{RFC9578}} that uses VOPRF {{!OPRF=RFC9497}}, and allows
for batched issuance of tokens and amortizes the cost of zero knowledge proofs.
This allows clients to request more than one token at a time and for issuers to
issue more than one token at a time. In effect, private batched issuance
performance scales better than linearly.

The second variant of the issuance protocol introduces a new Client-Issuer
communication method, which allows for batched issuance of generic token
types. This allows clients to request more than one token at a time and for
issuers to issue more than one token at a time. This variant has no other effect
than batching requests and responses and the issuance performance remains
linear.

This document registers a new token type ({{iana-token-type}}) that can either
be used with the Privately Verifiable Issuance Protocol as defined in
{{RFC9578}}, or with the Amortized Privately Verifiable Batch Issuance Protocol
defined below.

## Terminology

{::boilerplate bcp14-tagged}

# Motivation

Privacy Pass tokens (as defined in {{RFC9576}} and {{!RFC9578}}) are unlinkable
during issuance and redemption. The basic issuance protocols defined in
{{RFC9578}}, however, only allow for a single token to be issued at a time for
every challenge. In some cases, especially where a large number of clients need
to fetch a large number of tokens, this may introduce performance bottlenecks.

Amortized Privately Verifiable Token Issuance {{amortized-batch}} improves upon
the basic Privately Verifiable Token issuance protocol in the following key ways:

1. Issuing multiple tokens at once in response to a single TokenChallenge,
   thereby reducing the size of the proofs required for multiple tokens.
2. Improving server and client issuance efficiency by amortizing the cost of the
   VOPRF proof generation and verification, respectively.

Generic Token Batch Issuance {{generic-batch}} allows for a single
GenericBatchTokenRequest to be sent that encompasses multiple token requests.
This improves upon the basic issuance protocols defined in {{RFC9578}} in the following key ways:

1. Issuing multiple tokens at once of the same type with different keys.
2. Issuing multiple tokens at once of different types.

# Presentation Language

This document uses the TLS presentation language {{!RFC8446}} to describe the
structure of protocol messages.  In addition to the base syntax, it uses two
additional features: the ability for fields to be optional and the ability for
vectors to have variable-size length headers.

## Optional Value {#optional-value}

An optional value is encoded with a presence-signaling octet, followed by the
value itself if present.  When decoding, a presence octet with a value other
than 0 or 1 MUST be rejected as malformed.

~~~ tls-presentation
struct {
    uint8 present;
    select (present) {
        case 0: struct{};
        case 1: T value;
    };
} optional<T>;
~~~

## Variable-Size Vector Length Headers

In the TLS presentation language, vectors are encoded as a sequence of encoded
elements prefixed with a length.  The length field has a fixed size set by
specifying the minimum and maximum lengths of the encoded sequence of elements.

In this document, there are several vectors whose sizes vary over significant
ranges.  So instead of using a fixed-size length field, it uses a variable-size
length using a variable-length integer encoding based on the one described in
{{Section 16 of ?RFC9000}}. They differ only in that the one here requires a
minimum-size encoding. Instead of presenting min and max values, the vector
description simply includes a `V`. For example:

~~~ tls-presentation
struct {
    uint32 fixed<0..255>;
    opaque variable<V>;
} StructWithVectors;
~~~

# Amortized Privately Verifiable Token Batch Issuance {#amortized-batch}

This section describes a batched issuance protocol for select token types,
including 0x0001 (defined in {{RFC9578}}) and 0x0005 (defined in this document).
This variant is more efficient than Generic Token Batch Issuance defined below.
It does so by requiring the same key to be used by all token requests.

## Client-to-Issuer Request {#client-to-issuer-request}

Except where specified otherwise, the client follows the same protocol as
described in {{RFC9578, Section 5.1}}.

The Client first creates a context as follows:

~~~
client_context = SetupVOPRFClient(ciphersuiteID, pkI)
~~~

`ciphersuiteID` is the ciphersuite identifier from {{OPRF}} corresponding to the
ciphersuite being used for this token version. SetupVOPRFClient is defined in
{{OPRF, Section 3.2}}.

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
   BlindedElement blinded_elements<V>;
} AmortizedBatchTokenRequest;
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
URL, with the AmortizedBatchTokenRequest as the content. The media type for this
request MUST be "application/private-token-amortized-batch-request". If not, the
Issuer responds with status code 415. An example request for the Issuer Request
URL "https://issuer.example.net/request" is shown below.

~~~
POST /request HTTP/1.1
Host: issuer.example.net
Accept: application/private-token-amortized-batch-response
Content-Type: application/private-token-amortized-batch-request
Content-Length: <Length of AmortizedBatchTokenRequest>

<Bytes containing the AmortizedBatchTokenRequest>
~~~

## Issuer-to-Client Response {#issuer-to-client-response}

Except where specified otherwise, the client follows the same protocol as
described in {{RFC9578, Section 5.2}}.

Upon receipt of the request, the Issuer validates the following conditions:

- The AmortizedBatchTokenRequest contains a supported token_type of the
  privatley verifiable token kind.
- The AmortizedBatchTokenRequest.truncated_token_key_id corresponds to a key ID
  of a Public Key owned by the issuer.
- Nr, as determined based on the size of
  AmortizedBatchTokenRequest.blinded_elements, is less than or equal to the
  number of tokens that the issuer can issue in a single batch.

If any of these conditions is not met, the Issuer MUST return an HTTP 422
(Unprocessable Content) error to the client.

The Issuer then tries to deseralize the i-th element of
AmortizedBatchTokenRequest.blinded_elements using DeserializeElement from
{{Section 2.1 of OPRF}}, yielding `blinded_element_i` of type `Element`. If this
fails for any of the AmortizedBatchTokenRequest.blinded_elements values, the
Issuer MUST return an HTTP 422 (Unprocessable Content) error to the client.
Otherwise, if the Issuer is willing to produce a token to the Client, the issuer
forms a list of `Element` values, denoted `blinded_elements`, and computes a
blinded response as follows:

~~~
server_context = SetupVOPRFServer(ciphersuiteID, skI, pkI)
evaluated_elements, proof =
  server_context.BlindEvaluateBatch(skI, blinded_elements)
~~~

`ciphersuiteID` is the ciphersuite identifier from {{OPRF}} corresponding to the
ciphersuite being used for this token version. SetupVOPRFServer is defined in
{{OPRF, Section 3.2}}. The issuer uses a list of blinded elements to compute in
the proof generation step. The `BlindEvaluateBatch` function is a batch-oriented
version of the `BlindEvaluate` function described in {{OPRF, Section 3.3.2}}.
The description of `BlindEvaluateBatch` is below.

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

The Issuer then creates a AmortizedBatchTokenResponse structured as follows:

~~~tls
struct {
    uint8_t evaluated_element[Ne];
} EvaluatedElement;

struct {
   EvaluatedElement evaluated_elements<V>;
   uint8_t evaluated_proof[Ns + Ns];
} AmortizedBatchTokenResponse;
~~~

The structure fields are defined as follows:

- "evaluated_elements" is a list of `Nr` serialized elements, each of length
  `Ne` bytes and computed as `SerializeElement(evaluate_element_i)`, where
  evaluate_element_i is the i-th output of `BlindEvaluate`.

- "evaluated_proof" is the (Ns+Ns)-octet serialized proof, which is a pair of
  Scalar values, computed as `concat(SerializeScalar(proof[0]),
  SerializeScalar(proof[1]))`, where Ns is as defined in {{OPRF, Section 4}}.

The Issuer MUST generate an HTTP response with status code 200 whose content
consists of AmortizedBatchTokenResponse, with the content type set as
"application/private-token-amorrized-batch-response". Clients MUST ignore the
response if the status code is not 200 or if the content type is not
"application/private-token-amortized-batch-response".

~~~
HTTP/1.1 200 OK
Content-Type: application/private-token-amortized-batch-response
Content-Length: <Length of AmortizedBatchTokenResponse>

<Bytes containing the AmortizedBatchTokenResponse>
~~~

## Finalization {#finalization}

Upon receipt, the Client handles the response and, if successful, deserializes
the body values AmortizedBatchTokenResponse.evaluate_response and
AmortizedBatchTokenResponse.evaluate_proof, yielding `evaluated_elements` and
`proof`. If deserialization of either value fails, the Client aborts the
protocol. Otherwise, the Client processes the response as follows:

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
verification works exactly as specified in {{RFC9578}}.

# Generic Token Batch Issuance {#generic-batch}

This section describes an issuance protocol mechanism for issuing multiple
tokens in one round trip between Client and Issuer. An generic batch token
request can contain token requests for any token type.

## Client-to-Issuer Request {#generic-client-to-issuer-request}

The Client first generates all of the individual TokenRequest structures that
are intended to be batched together. This request creation follows the protocol
describing issuance, such as {{RFC9578, Section 5.1}} or {{RFC9578, Section 6.1}}.

The Client then creates a GenericBatchedTokenRequest structure as follows:

~~~tls
struct {
   uint16_t token_type;
   select (token_type) {
      case (0x0001): /* Type VOPRF(P-384, SHA-384), RFC 9578 */
         TokenRequest token_request;
      case (0x0002): /* Type Blind RSA (2048-bit), RFC 9578 */
          TokenRequest token_request;
      case (0x0005): /* Type VOPRF(ristretto255, SHA-512), RFC 9578 */
          TokenRequest token_request;
   }
} GenericTokenRequest;

struct {
  GenericTokenRequest generic_token_requests<V>;
} GenericBatchTokenRequest
~~~

The structure fields are defined as follows:

- GenericBatchTokenRequest's "token_type" is a 2-octet integer. The rest of the
  structure follows with the TokenRequest based on that type. A TokenRequest
  with a token type not defined in {{RFC9578}} MAY.

- "token_requests" is an array of GenericTokenRequest satisfying the above
  constraint.

The Client then generates an HTTP POST request to send to the Issuer Request
URL, with the GenericBatchTokenRequest as the content. The media type for this
request MUST be "application/private-token-generic-batch-request". If not, the
Issuer responds with status code 415. An example request for the Issuer Request
URL "https://issuer.example.net/request" is shown below.

~~~
POST /request HTTP/1.1
Host: issuer.example.net
Accept: application/private-token-generic-batch-response
Content-Type: application/private-token-generic-batch-request
Content-Length: <Length of GenericBatchTokenRequest>

<Bytes containing the GenericBatchTokenRequest>
~~~

## Issuer-to-Client Response {#generic-issuer-to-client-response}

Upon receipt of the request, the Issuer validates the following conditions:

- The Content-Type is application/private-token-generic-batch-request as
  registered with IANA.

If this condition is not met, the Issuer MUST return an HTTP 422 (Unprocessable
Content) error to the client.

The Issuer then tries to deserialize the first 2 bytes of the i-th element of
GenericBatchTokenRequest.token_requests. If this is not a token type registered
with IANA, the Issuer MUST return an HTTP 422 (Unprocessable Content) error to
the client. The issuer creates a GenericBatchTokenResponse structured as follows:

~~~tls
struct {
  uint16_t token_type;
  select (token_type) {
    case (0x0001): /* Type VOPRF(P-384, SHA-384), RFC 9578 */
      uint8_t evaluated_msg[Ne];
      uint8_t evaluated_proof[Ns + Ns];
    case (0x0002): /* Type Blind RSA (2048-bit), RFC 9578 */
      uint8_t blind_sig[Nk];
  }
} TokenResponse;

struct {
  optional<TokenResponse> token_response; /* Defined by token_type */
} OptionalTokenResponse;

struct {
  OptionalTokenResponse token_responses<V>;
} GenericBatchTokenResponse
~~~

GenericBatchTokenResponse.token_responses is a variable-size vector of
OptionalTokenResponses. OptionalTokenResponse.token_response is an optional
TokenResponse (as specified in {{optional-value}}) , where an absence of
TokenResponse indicates that the Issuer failed or refused to issue the
associated TokenRequest.

The Issuer MUST generate an HTTP response with status code 200 whose content
consists of TokenResponse, with the content type set as
"application/private-token-generic-batch-response". Clients MUST ignore the
response if the status code is not 200 or if the content type is not
"application/private-token-generic-batch-response".

~~~
HTTP/1.1 200 OK
Content-Type: application/private-token-generic-batch-response
Content-Length: <Length of GenericBatchTokenResponse>

<Bytes containing the GenericBatchTokenResponse>
~~~

If the Issuer issues some but not all tokens, it MUST return an HTTP 206 error
to the client and continue processing subsequent requests.
For instance, an Issuer MAY return an HTTP 206 error if requests for tokens of
the same token type refer to more than one `truncated_token_key_id`.

If the Issuer decides not to issue any tokens, it MUST return an HTTP 400 to the
client.


## Finalization {#generic-finalization}

The Client tries to deserialize the i-th element of
GenericBatchTokenResponse.token_responses using the protocol associated to
GenericBatchTokenRequest.token_type. If the element has a size of 0, the Client MUST
ignore this token, and continue processing the next token. The Client finalizes
each deserialized TokenResponse using the matching TokenRequest according to the
corresponding finalization procedure defined by the token type.

# Security considerations {#security-considerations}

## Amortized Privately Verifiable Token Batch Issuance

Implementors SHOULD be aware of the security considerations described in {{OPRF,
Section 6.2.3}} and implement mitigation mechanisms. Application can mitigate
this issue by limiting the number of clients and limiting the number of token
requests per client per key.

## Generic Token Batch Issuance

Implementors SHOULD be aware of the inherent linear cost of this token type. An
Issuer MAY ignore TokenRequest if the number of tokens per request past a limit.

# IANA considerations

This section contains IANA codepoint allocation requests.

## Token Type {#iana-token-type}

This document updates the "Token Type" Registry ({{!AUTHSCHEME=RFC9577}}) with the
following entry:

* Value: 0x0005 (suggested)
* Name: VOPRF (ristretto255, SHA-512)
* Token Structure: As defined in {{Section 2.2 of AUTHSCHEME}}
* Token Key Encoding: Serialized using SerializeElement from {{Section 2.1 of
  OPRF}}
* TokenChallenge Structure: As defined in {{Section 2.1 of AUTHSCHEME}}
* Publicly Verifiable: N
* Public Metadata: N
* Private Metadata: N
* Nk: 32
* Nid: 32
* Change controller: IETF
* Reference: {{RFC9578, Section 5}}
* Notes: None

## Media Types

The following entries should be added to the IANA "media types" registry:

- "application/private-token-amortized-batch-request"
- "application/private-token-amortized-batch-response"
- "application/private-token-generic-batch-request"
- "application/private-token-generic-batch-response"

The templates for these entries are listed below and the reference should be
this RFC.

### "application/private-token-amortized-batch-request" media type

Type name:

: application

Subtype name:

: private-token-amortized-batch-request

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

: Applications that want to issue or facilitate issuance of Privacy Pass
  Amortized Privately Verifiable tokens as defined in {{amortized-batch}},
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

### "application/private-token-amortized-batch-response" media type

Type name:

: application

Subtype name:

: private-token-amortized-batch-response

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

: Applications that want to issue or facilitate issuance of Privacy Pass
  Amortized Privately Verifiable tokens as defined in {{amortized-batch}},
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

### "application/private-token-generic-batch-request" media type

Type name:

: application

Subtype name:

: private-token-generic-batch-request

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

: Applications that want to issue or facilitate issuance of Privacy Pass
  Generic tokens as defined in {{generic-batch}},
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

### "application/private-token-generic-batch-response" media type

Type name:

: application

Subtype name:

: private-token-generic-batch-response

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

: Applications that want to issue or facilitate issuance of Privacy Pass
  Generic tokens as defined in {{generic-batch}},
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

--- back

# Test Vectors

This section includes test vectors for the two issuance protocols
specified in this document. {{test-vectors-batched-voprf}} contains test vectors
for batched token issuance protocol (0x0005), and {{test-vectors-arbitrary-batched}} contains
test vectors for arbitrary batched token issuance protocol.

## Issuance Protocol 3 - VOPRF (ristretto255, SHA-512) {#test-vectors-batched-voprf}

The test vector below lists the following values:

- skS: The Issuer Private Key, serialized using SerializeScalar from
  {{Section 2.1 of OPRF}} and represented as a hexadecimal string.
- pkS: The Issuer Public Key, serialized according to the encoding in {{iana-token-type}}.
- token_challenge: A randomly generated TokenChallenge structure, represented
  as a hexadecimal string.
- nonces: An array of 32-byte client nonces generated according to {{client-to-issuer-request}},
  represented as a hexadecimal string.
- blinds: An array of blinds used when computing the OPRF blinded message, serialized
  using SerializeScalar from {{Section 2.1 of OPRF}} and represented as a
  hexadecimal string.
- token_request: The BatchedTokenRequest message constructed according to
  {{client-to-issuer-request}}, represented as a hexadecimal string.
- token_response: The BatchedTokenResponse message constructed according to
  {{issuer-to-client-response}}, represented as a hexadecimal string.
- tokens: An array of output Tokens from the protocol, represented as a hexadecimal
  string.

~~~
// Test vector 1:
skS:
91f04a2caea9a854cd351b68d58132a6afa65d4dbee00fd55715d553d744820e
pkS:
909b2a8c70e4f70c4acafc87f027d41fb1ac59f7ed62845a8ef5cda4300b5e2c
token_challenge: 0005000e6973737565722e6578616d706c65208278149d30
94c9138347d7a2bcbf1188a262a10b1a5696c41549eabed84c129d000e6f72696
7696e2e6578616d706c65
nonces:
  - 62dd654dffc63bbe3721648eb5bd26f10e7e1851b7dc4e4047cc8cc042d46
  8dc
  - 49625ad9fae71ef46bfc59f09cd74d96bd6fe82c24a4f69efb78662addd2a
  320
  - b76d2192812dbdad0579b00ab61a9cec66e1ecdaaac07c36dd5b70bfae3a0
  bb3
blinds:
  - 6efdd3f587b7a0a50e49ababf7cbc908b345f1425e0b8d43b3452eb592b26
  f05
  - a10eed1297b917e6d807866410307f611386858a1bfb528a70c96d14ead9a
  10b
  - 5291910b64461416cac41e11ceaae17db031c5f1fd36c070f2a74b6f66a44
  704
token_request: 00052d406044d05bfbb5643c595765bd6e0cfdc87714d73a43
a0b7e1fe4ef5a9388e86d97ea45908db7f5dad5573a439ac85262f2c7aed0dfea
10f666cc2a7bd79027cef351e6aa090f165739bd3a07d0f456157e8d93db0c7e0
5603bd995936cc98c6321b
token_response: 4060a2740f4d68e9450a975233ceaeaa1d0feadb97ec39346
3ac783c37af8a9b2829e2cd06c01504b39737bd06ac041910e270c18cf6800243
fc1187035c9cd88d45c8d7d3153dd911f6e5724cb0def59739a1674e2ae4ca1ca
f1e5f11e686457140e4850db347edb252aa4b1004f237318f6079413b0693605c
f591b7291d8cff0b659bb5ee237374bc76b5836e5d9535e0c4bb39c73dcaf0597
340c768a6eab002
tokens:
  - 000562dd654dffc63bbe3721648eb5bd26f10e7e1851b7dc4e4047cc8cc04
  2d468dcead0d1e696ccbef94da0dd33e0e265d97a8015532f429d968fa41fb0
  af0cb385ba9dc18997fcf0439475b67cb5a534250d2d25f9c402f5b4f17d9c2
  d37049f2d072877130cee8e7e5d701807193c2768ee9a15726ea564a2bd9f95
  1f2acb90780f177fc8f5a3a8e1248a2854430223634b0aac66f9fb2f609ac5a
  4ee223b2024
  - 000549625ad9fae71ef46bfc59f09cd74d96bd6fe82c24a4f69efb78662ad
  dd2a320ead0d1e696ccbef94da0dd33e0e265d97a8015532f429d968fa41fb0
  af0cb385ba9dc18997fcf0439475b67cb5a534250d2d25f9c402f5b4f17d9c2
  d37049f2da61b154984bda262b0581883dd386c1c2ea772190cc81d807f239a
  404218f724dadc0cb5527c05ba7cae6d5580c713d5b303853812dd2c0f1ae2c
  a9d8de43e67
  - 0005b76d2192812dbdad0579b00ab61a9cec66e1ecdaaac07c36dd5b70bfa
  e3a0bb3ead0d1e696ccbef94da0dd33e0e265d97a8015532f429d968fa41fb0
  af0cb385ba9dc18997fcf0439475b67cb5a534250d2d25f9c402f5b4f17d9c2
  d37049f2d61df6682b5bf4f9cc8023e6ea6925767f838b0102c06422d160421
  8eb9fcc8f6de083de3f007fa046ded66366e9c7735181fc6c342e03c736f3d7
  ba2c11925a1

// Test vector 2:
skS:
3435c4a17cec27459c6761248b4768b6a580a1ee2cd58ac31fca4af85a171208
pkS:
f448c01ff45ee2140d7fa97a4c5944df4aa862408e5134bfc468d40072b9537d
token_challenge: 0005000e6973737565722e6578616d706c6500000e6f7269
67696e2e6578616d706c65
nonces:
  - 97c7bc12d1eeba7c26ee40a120948d31ac622e51347669a908e36ef5fe280
  bc9
  - 5375bf400d7302584be4328f16c385989dfea8d16d9fc18156edaa167043a
  446
  - 43341e4a06021cbce77c21039b6cae3dc8b7194c2f35c991e94157e7fd214
  9f8
blinds:
  - 41a0baf5b0f33d80be266b014eda0825e7ce10769de0e777faf3e6b673005
  e05
  - 7012a8096a1711f7160bbc11cf6150c8e7f844d955d90d196a2ccdabee3bd
  005
  - be2be22c3b0ddad6edac10fb2201a7b1388d534ca0cf3e03c749c3c65d86a
  90d
token_request: 00056d40604a4d4d2c54280ab82e7d81277916d12c058f13fc
2e6ae94d4066dc61087c102f149f790c28f6382f5c8ad67fa6af8e1be1f771ab2
d2281a09b515c483dba85049e3f9e6761c65f748270e5809b1f992cf1d1834266
b4e1a3cd389bd78f68124a
token_response: 4060b6259e46d25a8bf48f25f673c2a0f80c84c6013d2859e
ec86eb865e26af64f48b48f7c92a124e2051414ac40c5cadadb8a55f0f28bc00d
6be8373cd22b1b391da6afde766f7e2dc0b2d4d9e7c23fc50a22b5d9028ca633a
7bdfe4e3bf67d257ada56c9d8723db2220a4f4190c8541d8e8552ad34b30d9a65
c94347a96a6af00d4b65b5b210471bb4413e184ac5ec98d246f3966132d7bf437
8b0810ae588a307
tokens:
  - 000597c7bc12d1eeba7c26ee40a120948d31ac622e51347669a908e36ef5f
  e280bc969b53830c9e88ce2285efc18a8bdc36d2225a41c4afdd0ce1337411f
  9e7ec0ae5560277b39ac96f35076570711615a322cb2f8f3674e64e173873fd
  9f6d6b16deb93ae2e8cf5b447d11bb667e0badb5b191da9639649ab9a4946d1
  e59cf2b2fd2df8de212a34442c1ed4e43108d2fb5f317fb207d902beeb210b8
  f2f66a132eb
  - 00055375bf400d7302584be4328f16c385989dfea8d16d9fc18156edaa167
  043a44669b53830c9e88ce2285efc18a8bdc36d2225a41c4afdd0ce1337411f
  9e7ec0ae5560277b39ac96f35076570711615a322cb2f8f3674e64e173873fd
  9f6d6b16d5ad6aef9f83b53ee1817cb0b0aac120683fbb3cb2c1e86adde52c5
  33098cc2906bde25974eb9b62132031eea4c8037a187b84a2d406b79e55b8ed
  f7f9b84810b
  - 000543341e4a06021cbce77c21039b6cae3dc8b7194c2f35c991e94157e7f
  d2149f869b53830c9e88ce2285efc18a8bdc36d2225a41c4afdd0ce1337411f
  9e7ec0ae5560277b39ac96f35076570711615a322cb2f8f3674e64e173873fd
  9f6d6b16de487d2826e4e90e2e2fa24df0fdb89ca90ba900b78fb126553d77a
  4bb11ac5fbd909511a35c53ca45841ceb32bfcfe27a17fbdff9b942c0aa8fed
  22b88d79d28

// Test vector 3:
skS:
d53e857d8c589ee11a175a4d880e498d0433e439a72c6ac7f8222873dfd89e03
pkS:
7255025c90d76238ced53cc4473787ea167a7017ae0c1d63e864d599ae5db452
token_challenge: 0005000e6973737565722e6578616d706c65000017666f6f
2e6578616d706c652c6261722e6578616d706c65
nonces:
  - 2607568322aa05f59b5a01ac87c3b55ad11e9bbbe60102af0c5c17f6b99be
  c02
  - 9a934eb5a70436aed6afdcf2460242912ddeeea160b39839bc233de6a3246
  b2f
  - 7555220de2ac527a9c2fa2e10ad239543e2e846245e6a76a7283d1996a878
  251
blinds:
  - 8504535ffbcad52af25c847250d33a4ba3eec29e79b282956d5b68348eee0
  802
  - d85fac3d7203ca80792f8f9299420aa0f93564297fc1c6f2d8713f5181747
  60e
  - f3bdcf1cb48cb0c10018d25bbe4138580cd90c9a0b78e3684b219e0329d0d
  609
token_request: 00055c406046c5f2c875f41a6e75e579186b9f6b0c60fcc156
1cb31227a0212a6fb122a138724033cc8d9f03aab1ce5df56fd241dbdbfb4c5ea
6cedc82d8e95da3e3da804e000ad869035bfb0d673522d0bd94b8ee75a5b79f8e
77d66107804aaf73fb863b
token_response: 406070c40700200f461cad7d144d352cf99aeef2958f75442
3bf04e92eeec2a6c11b74ce8cc8fb24780d1d4c67bd74e57ada3901a2dddfc3ef
088ebbdd45daa54b3ff0563e59dc3f4f13fc574058c907468714113e6bc2dc421
c05432d757d518e553df0b206dc7268c08ca9bc03f67bd1ed92c7b3ee62bd404d
9c17dd69066deb0477506b8a404ad27474f71142db91e549dc0d76c44e099e3f9
6b71bf292e72a01
tokens:
  - 00052607568322aa05f59b5a01ac87c3b55ad11e9bbbe60102af0c5c17f6b
  99bec028a73b15843d93251b73e17d484d3e5467e6db28a74a042d83a311005
  dfdb9c61af60e2f82acdafaa9d3c6b8debb3b1b4385b3357f0cf60441f97901
  91fb9865c82d2beaae48321c6e376f3190dbf2389b2d717481ec73734dd246f
  397a217f0894eff9ef4ad3f110bf265285148a657b20c00457cd03edc1f3d6e
  6268862e2de
  - 00059a934eb5a70436aed6afdcf2460242912ddeeea160b39839bc233de6a
  3246b2f8a73b15843d93251b73e17d484d3e5467e6db28a74a042d83a311005
  dfdb9c61af60e2f82acdafaa9d3c6b8debb3b1b4385b3357f0cf60441f97901
  91fb9865ca959e4e6015c1c5b877ec82aaf5d1bbf4fa4b58b684b2c1b590264
  99c998768cb87b17f32fcc8dbf04509e37d72810fea6e4330341deecb2d6fa4
  7d974208947
  - 00057555220de2ac527a9c2fa2e10ad239543e2e846245e6a76a7283d1996
  a8782518a73b15843d93251b73e17d484d3e5467e6db28a74a042d83a311005
  dfdb9c61af60e2f82acdafaa9d3c6b8debb3b1b4385b3357f0cf60441f97901
  91fb9865c7258d95e545f122c90e331633177409277dd59fd78e4b51b88165f
  fa778b1ad019af5ee8dff21fe58fa0e31fd4a2ab0512b4ea9c487acccdca544
  fa33294fbf0

// Test vector 4:
skS:
7f52844968e3b9ebeb82f8930bc02af1ae35a91e9d699949a629f351e7b3c00d
pkS:
182d797eaec74157c6911f105fc7d99fb08d567e3da7bfefd50340594c603345
token_challenge: 0005000e6973737565722e6578616d706c65000000
nonces:
  - f8534e3448df368adde4bb0609b58799425372e25359922d9382491d35525
  1bd
  - 4d8c92091880c44bc24d5396ecaa68140f65ed3498a72d940bb651b3a952b
  bfc
  - e1f48c0ca3847ede3309e4b13cbb9edbbd65e3bfec548ba80b3193f96336f
  d84
blinds:
  - 903382c558a850f936d8a74e4ad54ea540b451240b8b75ae65852b78e4545
  e03
  - 477e6b85f1380a627627e37d07466023f73bbe60dd6de2d47c9c6f8805a73
  509
  - dffd7898231d883e1b2367f97077d868c2d5dc0d454ac2aa74ce077133cf2
  b06
token_request: 0005dc406062beaa14db5c4d720329060e48228969458db99f
f6c9a67a8fa2652f4da1b751daeb2ca361e24b610585e52c7a98ddc10c381d988
aa93ddb490024690884471e8a8d702f17f62b60ea43b0299586d4f01d800c6ace
c318c921b27c3457358750
token_response: 406000e8ca4ba785a65ee67460c8ca95e31a4e29b86cdda7d
3bdb59ecc471dd08501dc73c0f433876b3bddb6a251f06a056b928e0ce9202d14
a34c7454b1bae7a164e6191c065b9387302241f89a636f742ea754b17adba4979
7b0ec60c0690bde4b5cbc1307ff1766a3997897939c5bf404ff7396462f408497
d78f4a4f2b73610d0a827e4f85a1995b9a7bab72cd982ae8c52d7a994584a177a
03d4e1de4118608
tokens:
  - 0005f8534e3448df368adde4bb0609b58799425372e25359922d9382491d3
  55251bdb2174d8c51b010f2f8d73a85a8595138f02c4082a27c5348a4767945
  6d9e350fba3d0d2cdfdcfa32ba7e5a520cfeaf05057cacfc374fd400493067c
  1e85e79dc070ae23afc8d8a81e448a4abf0a8e4f0cf2c285d9c7d6707f0b817
  3fdd9a007159c5351e191937d22aa58dba713f541d2ad54e9b25af63b68a0e1
  060b0a9611f
  - 00054d8c92091880c44bc24d5396ecaa68140f65ed3498a72d940bb651b3a
  952bbfcb2174d8c51b010f2f8d73a85a8595138f02c4082a27c5348a4767945
  6d9e350fba3d0d2cdfdcfa32ba7e5a520cfeaf05057cacfc374fd400493067c
  1e85e79dc0cd9ef54f8d9a456634af013b7da99e4c52cec576c283ee64a92cb
  b9a5289ce76d492c423f1213b6b3bc7d15c0ecc15a3f663f1b99b59b7667b3a
  8a4d1d7794d
  - 0005e1f48c0ca3847ede3309e4b13cbb9edbbd65e3bfec548ba80b3193f96
  336fd84b2174d8c51b010f2f8d73a85a8595138f02c4082a27c5348a4767945
  6d9e350fba3d0d2cdfdcfa32ba7e5a520cfeaf05057cacfc374fd400493067c
  1e85e79dc9a05c3e96f3abd4e4ea700eb67c95816f76ea423dada2d699a7f92
  328cd9be5d83e8f77974e930d4eee806599efa0d6f3c37749337d1223901a8b
  60e1bbf991f

// Test vector 5:
skS:
5f6b12eaa6bc82618be24bacad324ddf88bb2ed80ea05e1c09c78ebb33ca2f04
pkS:
0af469e5ebe48eaf5ecc30d2a33e715f15aa18f65c72ba7f729331b1f4fb847e
token_challenge: 0005000e6973737565722e6578616d706c65208278149d30
94c9138347d7a2bcbf1188a262a10b1a5696c41549eabed84c129d0000
nonces:
  - 68286e9d5a447f04dadb444fe70c01e89f14305d444a462e5a38b154b6102
  961
  - 921f1cd630b4c1c975a077caee796afcd2bc91dac0891e131ae0744cee4a7
  595
  - 58f3e3da23295d741fc9209b2e01f486ffc5bb4cd9e01b52e2ec22d881062
  eb5
blinds:
  - c494912581ce9ef0e5cb5a45be546c7df5bafa223b9f84188a5bf0bad72b3
  607
  - d91de980016f7dfa0b26f303f46bdabd70d23c57720a8236117aa04ec5cbf
  e0a
  - 0fb91d23a8bd9cc34d154be0fb25b522f8d90da3aacee22abc0823586c6cd
  50c
token_request: 00058140603a1d1b2e8a9d73b19dbaad85e8c53611dba68236
273a876b85e36310f68bc71b1ed45cf7ce982516f6fd79047fd2fa974a04661c9
dc015ec44c48f3a8f421104ec506f251d8d3d0738397f4751078ba1bbbf34d9a6
06962900517108e9935759
token_response: 4060085b0ebcdc26bc0c86908f5faa30b009188e199972cb3
fadbe144bb5cda0bb5a209313fcce1bb4727fe4829e220470d6edce2f119d206b
0fc94208e3dfbfb612d44fb3af8afced1d6efbf7a81f0087e8e1c9384f3a70153
164445f60ab134a5dd3e48dfe1d0ce4a2ccac03c74d5ba6c6c854241019693bd1
e0ccb94458a4600a07ea62971534362965c8ff6cc4c956b849547f656f7d5ce3f
cc0fcd626b34809
tokens:
  - 000568286e9d5a447f04dadb444fe70c01e89f14305d444a462e5a38b154b
  610296176ee4d34d93248d8759177310d19ff8690ccc42f86793cdac0698466
  c3c70da43a9b33fc1983a678ae21c1d544a7340ba7a82a180a9b34ae30db22b
  9ef18a981589c0784cba583bb7c1d2ee684982f706150e8c1901f6dde04abee
  94bbffff08d43131a2a596bca267038ad065a091977014e26af3bef97023122
  bcee8394f71
  - 0005921f1cd630b4c1c975a077caee796afcd2bc91dac0891e131ae0744ce
  e4a759576ee4d34d93248d8759177310d19ff8690ccc42f86793cdac0698466
  c3c70da43a9b33fc1983a678ae21c1d544a7340ba7a82a180a9b34ae30db22b
  9ef18a981fe4d8af90b00fa6324d754e9d318344b86a491d49d03da598c440e
  9bd84ca5484c98f4b9c8a431e3e54dc36bea34a0b15fc9b527337e49a33ebf6
  48b133101c7
  - 000558f3e3da23295d741fc9209b2e01f486ffc5bb4cd9e01b52e2ec22d88
  1062eb576ee4d34d93248d8759177310d19ff8690ccc42f86793cdac0698466
  c3c70da43a9b33fc1983a678ae21c1d544a7340ba7a82a180a9b34ae30db22b
  9ef18a98133451aefec7d96d9fa9015f8c4f36145f0d46e6d0b1848e54120a7
  c531fdab5fdb6687c0b9cb797bbe08ff19779fd420d366b54525dec516d60ba
  d56ad1b7968
~~~


## Issuance Protocol Arbitrary Batched {#test-vectors-arbitrary-batched}

The test vector below lists the following values:

- issuance: An array of parameters required to generate TokenRequest batched
  in the current test vector. This is sharded by a parameter type which is
  the protocol token type, represented as a hexadecimal string.
  Depending on the type, issuance contains different information

  type 0x0001
  - skS: The Issuer Private Key, serialized using SerializeScalar from
    {{Section 2.1 of OPRF}} and represented as a hexadecimal string.
  - pkS: The Issuer Public Key, serialized according to the encoding in {{RFC9578, Section 8.2.1}}.
  - token_challenge: A randomly generated TokenChallenge structure, represented
    as a hexadecimal string.
  - nonce: The 32-byte client nonce generated according to {{RFC9578, Section 5}},
    represented as a hexadecimal string.
  - blind: The blind used when computing the OPRF blinded message, serialized
    using SerializeScalar from {{Section 2.1 of OPRF}} and represented as a
    hexadecimal string.
  - token: The output Token from the protocol, represented as a hexadecimal
    string.

  type 0x0002
  - skS: The PEM-encoded PKCS#8 RSA Issuer Private Key used for signing tokens,
    represented as a hexadecimal string.
  - pkS: The Issuer Public Key, serialized according to the encoding in {{RFC9578, Section 8.2.2}}.
  - token_challenge: A randomly generated TokenChallenge structure, represented
    as a hexadecimal string.
  - nonce: The 32-byte client nonce generated according to {{RFC9578, Section 6}},
    represented as a hexadecimal string.
  - blind: The blind used when computing the blind RSA blinded message,
    represented as a hexadecimal string.
  - salt: The randomly generated 48-byte salt used when encoding the blinded
    token request message, represented as a hexadecimal string.
  - token: The output Token from the protocol, represented as a hexadecimal
    string.

  type 0x0005
  - skS: The Issuer Private Key, serialized using SerializeScalar from
  {{Section 2.1 of OPRF}} and represented as a hexadecimal string.
  - pkS: The Issuer Public Key, serialized according to the encoding in {{iana-token-type}}.
  - token_challenge: A randomly generated TokenChallenge structure, represented
    as a hexadecimal string.
  - nonces: An array of 32-byte client nonces generated according to {{client-to-issuer-request}},
    represented as a hexadecimal string.
  - blinds: An array of blinds used when computing the OPRF blinded message, serialized
    using SerializeScalar from {{Section 2.1 of OPRF}} and represented as a
    hexadecimal string.
  - tokens: An array of output Tokens from the protocol, represented as a hexadecimal
    string.

- token_request: The BatchedTokenRequest message constructed according to
  {{arbitrary-client-to-issuer-request}}, represented as a hexadecimal string.
- token_response: The BatchedTokenResponse message constructed according to
  {{arbitrary-issuer-to-client-response}}, represented as a hexadecimal string.


Note to implementers:
Arbitrary batched token is an issuance protocol that does not define
a token type. You should decide which test vectors is required for
your implementation. The batch for each test vector is the following

- Test vector 1: [0x0001]
- Test vector 2: [0x0002]
- Test vector 3: [0x0001, 0x0001]
- Test vector 4: [0x0002, 0x0002]
- Test vector 5: [0x0001, 0x0002]
- Test vector 6: [0x0005]
- Test vector 7: [0x0001, 0x0002, 0x0005]

~~~
// Test vector 1:
issuance:
  - type: 0001
    skS: 39b0d04d3732459288fc5edb89bb02c2aa42e06709f201d6c518871d
    518114910bee3c919bed1bbffe3fc1b87d53240a
    pkS: 02d45bf522425cdd2227d3f27d245d9d563008829252172d34e48469
    290c21da1a46d42ca38f7beabdf05c074aee1455bf
    token_challenge: 0001000e6973737565722e6578616d706c65205de58a
    52fcdaef25ca3f65448d04e040fb1924e8264acfccfc6c5ad451d582b3000
    e6f726967696e2e6578616d706c65
    nonce: 002fcb69084915aebc7351fd162d42d27f4d7501ad84c1a7af0ddc
    48a79603b9
    blind: 7af11792239827ece48fe23c20ccab78fc10140a43e9feab011e24
    2ae28e4c7fd560a936e2f58423d95fbdfeb8d49f23
    token: 0001002fcb69084915aebc7351fd162d42d27f4d7501ad84c1a7af
    0ddc48a79603b9501370b494089dc462802af545e63809581ee6ef57890a1
    2105c28368169514bf260d0792bf7f46c9866a6d37c3032d8714415f87f5f
    6903d7fb071e253be2f4275769493214541edfbbadc2cae7a428f6c10d0e9
    efa43867c41bcec2e41ff9f74a3eafa14fe96783f22c5404ce47977
token_request: 3600340001f4021f95990d2a11db9cf6e2908d25013d9822f4
23ad5795f36bcd6a008fdaf6aa7b6b3e8c76bdc226f1954f856072628aff
token_response: 409300910323910adecb239d61115cba8fdf8ed62bc54f8be
67a49b1b029af651f85b230538c98ec3b5afce1cfdcbeac225ab8d800cd4d73e6
ffce40a89cd058121aa438b426a107ff4991de4532a117f83bcba485c0a3db951
5a366f5341b3265dd19062b3412daa651850fa17fe80d58118c97909115c8fbed
0e91d3995c67fc6f5469eb0b320b475be8aa6827e9b23cfb9bed85

// Test vector 2:
issuance:
  - type: 0002
    skS: 2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d0a
    4d494945765149424144414e42676b71686b6947397730424151454641415
    343424b63776767536a41674541416f49424151444c477531726170583173
    6334420a4f6b7a38717957355379356b6f6a41303543554b66717444774e3
    8366a424b5a4f76457245526b49314c527876734d6453327961326333616b
    4745714c756b440a556a35743561496b3172417643655844644e445034423
    25055707851436e6969396e6b492b6d677257697444444948713861397931
    37586e6c5079596f784f530a646f6558563835464f314a752b62397336356
    d586d34516a7551394559614971383371724450567a50335758712b524e4d
    636379323269686763624c766d42390a6a41355334475666325a6c7478595
    4736f4c364872377a58696a4e39463748627165676f753967654b524d5846
    45352f2b4a3956595a634a734a624c756570480a544f72535a4d4948502b5
    358514d4166414f454a4547426d6d4430683566672f43473475676a79486e
    4e51383733414e4b6a55716d3676574574413872514c620a4530742b496c7
    06641674d4241414543676745414c7a4362647a69316a506435384d6b562b
    434c6679665351322b7266486e7266724665502f566344787275690a32703
    16153584a596962653645532b4d622f4d4655646c485067414c7731785134
    57657266366336444373686c6c784c57535638477342737663386f3647503
    20a6359366f777042447763626168474b556b5030456b62395330584c4a57
    634753473561556e484a585237696e7834635a6c666f4c6e7245516536685
    578734d710a6230644878644844424d644766565777674b6f6a4f6a70532f
    39386d4555793756422f3661326c7265676c766a632f326e4b434b7459373
    744376454716c47460a787a414261577538364d435a342f5131334c762b42
    6566627174493973715a5a776a7264556851483856437872793251564d515
    751696e57684174364d7154340a53425354726f6c5a7a7772716a65384d50
    4a393175614e4d6458474c63484c49323673587a76374b53514b426751447
    66377735055557641395a325a583958350a6d49784d54424e6445467a5662
    5550754b4b413179576e31554d444e63556a71682b7a652f376b337946786
    b68305146333162713630654c393047495369414f0a354b4f574d39454b6f
    2b7841513262614b314d664f5931472b386a7a42585570427339346b35335
    3383879586d4b366e796467763730424a385a6835666b55710a5732306f53
    62686b686a5264537a48326b52476972672b5553774b426751445a4a4d6e7
    279324578612f3345713750626f737841504d69596e6b354a415053470a79
    327a305a375455622b7548514f2f2b78504d376e433075794c494d44396c6
    1544d48776e3673372f4c62476f455031575267706f59482f4231346b2f52
    6e360a667577524e3632496f397463392b41434c745542377674476179332
    b675277597453433262356564386c4969656774546b656130683075445352
    7841745673330a6e356b796132513976514b4267464a75467a4f5a742b746
    7596e576e51554567573850304f494a45484d45345554644f637743784b72
    48527239334a6a7546320a453377644b6f546969375072774f59496f614a5
    468706a50634a62626462664b792b6e735170315947763977644a724d6156
    774a6376497077563676315570660a56744c61646d316c6b6c76707173364
    74e4d386a6e4d30587833616a6d6d6e66655739794758453570684d727a4c
    4a6c394630396349324c416f4742414e58760a75675658727032627354316
    f6b6436755361427367704a6a5065774e526433635a4b397a306153503144
    544131504e6b7065517748672f2b36665361564f487a0a794178447339683
    55272627852614e6673542b7241554837783153594456565159564d685552
    62546f5a6536472f6a716e544333664e6648563178745a666f740a306c6f4
    d4867776570362b53494d436f6565325a6374755a5633326c634961663972
    62484f633764416f47416551386b3853494c4e4736444f413331544535500
    a6d3031414a49597737416c5233756f2f524e61432b78596450553354736b
    75414c78786944522f57734c455142436a6b46576d6d4a41576e515544746
    26e594e0a536377523847324a36466e72454374627479733733574156476f
    6f465a6e636d504c50386c784c79626c534244454c79615a762f624173506
    c4d4f39624435630a4a2b4e534261612b6f694c6c31776d4361354d43666c
    633d0a2d2d2d2d2d454e442050524956415445204b45592d2d2d2d2d0a
    pkS: 30820152303d06092a864886f70d01010a3030a00d300b0609608648
    016503040202a11a301806092a864886f70d010108300b060960864801650
    3040202a2030201300382010f003082010a0282010100cb1aed6b6a95f5b1
    ce013a4cfcab25b94b2e64a23034e4250a7eab43c0df3a8c12993af12b111
    908d4b471bec31d4b6c9ad9cdda90612a2ee903523e6de5a224d6b02f09e5
    c374d0cfe01d8f529c500a78a2f67908fa682b5a2b430c81eaf1af72d7b5e
    794fc98a3139276879757ce453b526ef9bf6ceb99979b8423b90f4461a22a
    f37aab0cf5733f7597abe44d31c732db68a181c6cbbe607d8c0e52e0655fd
    9996dc584eca0be87afbcd78a337d17b1dba9e828bbd81e291317144e7ff8
    9f55619709b096cbb9ea474cead264c2073fe49740c01f00e109106066983
    d21e5f83f086e2e823c879cd43cef700d2a352a9babd612d03cad02db134b
    7e225a5f0203010001
    token_challenge: 0002000e6973737565722e6578616d706c65205de58a
    52fcdaef25ca3f65448d04e040fb1924e8264acfccfc6c5ad451d582b3000
    e6f726967696e2e6578616d706c65
    nonce: ac1d751d865d2f767fc1e72c769e9dea056b7e53bf5940b019ccbb
    a2f2165348
    blind: 2c1e7ccac7291776568b6653fef546e244133080fb8645e7a605c1
    242a8b733b8d746ba56ff83ca118657fdc9eded496e25e081a163597999dd
    fc38815b39bfe78c31dd5f0833b771b9cf63c4bea00edef6c877d804294dc
    8cf3d3ec7e806defaa05c6934e82eddc8c4dce7a8005b36b04f9851e27fd6
    10bea714fef28f2a6dd58ed1c0577f1d6460ea7f0118557133b54adb09eb7
    7a323f164ba8d3619dba6388ae10c5500d445b7d17b53e75c1e90dd7883bd
    948dc5a0bc900004c036877e921ebcb33e1ed3c0c62205a1957cefd5af8d1
    0c0c62eefb2fccdb44cd4eda8b2bcc89355a59c7f59401e9c93fb0332d293
    5311bee35f150d1176a091e8d08331f
    token: 0002ac1d751d865d2f767fc1e72c769e9dea056b7e53bf5940b019
    ccbba2f2165348820fc64e2630a0d5166c36696b663ff34518338263383ec
    92b3347ea30bddae4ca572f8982a9ca248a3056186322d93ca147266121dd
    eb5632c07f1f71cd27080c0cde249784a45798253ff6839a6c56dde5a1971
    1efcdd8e2dc301f4c6588ce7528438c1f071e3ccfe3b5eaf858fc2f24a907
    9da67f39ef339fea3632eb493eec7bb6c1f89fd98b13de04d302def518c7d
    bc8ca37f85044d19ee913885426ab6a5a90d32b8aa5e52775065ea6b9d03d
    60a2581a14d467eb273936718fd57d8b0bb30b8ee58c30b4895da5a6b1d03
    809ee8fee9c442f0a53cb9c54f117558eee44adb5bfb150a67c4ba73028f3
    2dee0e977e6f6ed1b4f6ce0b1092a8e137db637f57d1f30a845fe88f26ab5
    d158fbf8b18dd2797e3eded54e17ba2f34ef45770f429bc4d9ddbfb61aa6c
    ed311987c3ca276d7abf2d97e294947b4e22bbfd5848
token_request: 410501030002087c3a797d55ccf004e036f7074d503988719e
2fc4c3a0323235ea7841ec63e76223fc83ee922e6af12e225e5a1248b1fe61994
addc4a56f34aae3d803a6cd51f6edf34abf8b47d72ea1db52906cbd5019020fa8
e3c46f12112ea810387be35932ad0f86af6a4d0bfec75936c8cc1e04d6a5719e6
20e7bc535b20641ce62f2abcfe5898409200bf03f2be5450c3b650b18a9c1569e
5d506aa0e5fad7946ff3ecc2d6649c919c121e4f77065e453be423810586f2d2a
722aecfc0a256160840fa0fd58bb7fb77e9208301cf2d665d070afa22679409d2
50e5dd7e7e8bac0d7c9fd6671644e4b84e56ef00bae4cc5f920ee5ea361493499
76c59ca1572ce3fce81f3
token_response: 4102010038debdd8072bf0b191f78a97902a818e682000525
971bafd89f54afc9322b5b185fcaa881b7e3fcf3b574de7209ded8edfa0352ec9
f7f7246cb2f7104cf5feff89adc60969e044db15a0aae3e6551a633102d47c360
a0857a5a32020417fdf224368f72a2fc4a0949d81b6f2a60f1dd10c513135455a
bc9a2f7d677764b8cdafecbcdccb9c076161fbb67562698c427c8dfd5db5f95a8
57996038c6bfa52d0b063fd58f7654532731c4502dfe18ecea2fe14ba79b7a6ff
eea33a41ff34e798f27bcdcdb0b039084bceda42e5975737a05026df97cc5ffe4
01ad57ef417c06c3eecd9cf20c5c56629e28d674a3fb147de258e5500932b478a
99b963dc3dcd0ae4

// Test vector 3:
issuance:
  - type: 0001
    skS: 39b0d04d3732459288fc5edb89bb02c2aa42e06709f201d6c518871d
    518114910bee3c919bed1bbffe3fc1b87d53240a
    pkS: 02d45bf522425cdd2227d3f27d245d9d563008829252172d34e48469
    290c21da1a46d42ca38f7beabdf05c074aee1455bf
    token_challenge: 0001000e6973737565722e6578616d706c65205de58a
    52fcdaef25ca3f65448d04e040fb1924e8264acfccfc6c5ad451d582b3000
    e6f726967696e2e6578616d706c65
    nonce: c041ea6cf602fb388d426f3d0d408b849ead0b0f0cfb802b2b59d2
    c2dcb6419f
    blind: 8f969916bb5d863ec9ad2ff4237d7d03a5e694fcd0cebed4a990d6
    f93c1302fa0a06a76839a0e572e653286b0d7fd940
    token: 0001c041ea6cf602fb388d426f3d0d408b849ead0b0f0cfb802b2b
    59d2c2dcb6419f501370b494089dc462802af545e63809581ee6ef57890a1
    2105c28368169514bf260d0792bf7f46c9866a6d37c3032d8714415f87f5f
    6903d7fb071e253be2f498da273d1988eb6b91927be723efd32d81f4b23d7
    48b8c516a393b6e92d6bc889a9e73f509c8a41335a7ee5b5172f778
  - type: 0001
    skS: 39efed331527cc4ddff9722ab5cd35aeafe7c27520b0cfa2eedbdc29
    8dc3b12bc8298afcc46558af1e2eeacc5307d865
    pkS: 038017e005904c6146b37109d6c2a72b95a183aaa9ed951b8d8fb1ed
    9033f68033284d175e7df89849475cd67a86bfbf4e
    token_challenge: 0001000e6973737565722e6578616d706c6500000e6f
    726967696e2e6578616d706c65
    nonce: d2bab5fe6ddef27226adbda8192237c066d4dab6a75e38a5f4b527
    ff354efb20
    blind: 882173caa0e757dcf0d970118a3d973db0efe7e8f91ea4c34a4287
    6d625b466c1c9cacd692dffb00972a7b4710462ddb
    token: 0001d2bab5fe6ddef27226adbda8192237c066d4dab6a75e38a5f4
    b527ff354efb20c994f7d5cdc2fb970b13d4e8eb6e6d8f9dcdaa65851fb09
    1025dfe134bd5a62a116477bc9e1a205cca95d0c92335ca7a3e71063b2ac0
    20bdd231c66097f12333a401894b93fd026a1534b263bbc7637bd76ba6a2a
    a750e87b9c2f4412000c4d544b2f96de263ca95ecc2343ca593565b
token_request: 406c00340001f40331287b4b3b4b265ef39254d59e088cf5cc
35511917378d613ae1a163fb17cd3742e612e900083b16401da9e1c3419da6003
400013303fc75d24d23d3a4a860881204e4767fa7e456521021b8100489dee02e
4a1d032f0e1e2f18dfac91b54dcdf6560523cf97
token_response: 4126009102410385cbc9117c135b31bcb2b104e3bc0b264f7
551c40c711b359125bdc69c9e8bd0b857de3ba68d59448b0413e5d37feb0685c0
b5150b67bd277cfe02ecb9d313db526d456cb58756afd751ca2e765ce3e89bfb2
c81bb9e918dda22ec4cbcde0d44b9b2ba8a9c8dab15ed5414f5a841cb6a193983
e5a3feb97cf9b7c8d20f8703a4e9a54bfc1acd7d9a8fb93b560f830091027008d
a9ccf876b87516c6afe6ebbc72f18ecd617bd91f50888053eba0a94807cb88130
d1a5386ef152948fbf18d63ef4a3931d063b55a517ae26a85b4faee9fc90a416a
fa91fc95f3de8fabcd461bc32ce423f19108183e235c1c903819a312ca5589366
86b4c5f93bfc6fa848d1628a6bc5510d3258d765bfcf3db5fd1a88830d04602cd
1a9b9c277615b722207528f

// Test vector 4:
issuance:
  - type: 0002
    skS: 2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d0a
    4d494945765149424144414e42676b71686b6947397730424151454641415
    343424b63776767536a41674541416f49424151444c477531726170583173
    6334420a4f6b7a38717957355379356b6f6a41303543554b66717444774e3
    8366a424b5a4f76457245526b49314c527876734d6453327961326333616b
    4745714c756b440a556a35743561496b3172417643655844644e445034423
    25055707851436e6969396e6b492b6d677257697444444948713861397931
    37586e6c5079596f784f530a646f6558563835464f314a752b62397336356
    d586d34516a7551394559614971383371724450567a50335758712b524e4d
    636379323269686763624c766d42390a6a41355334475666325a6c7478595
    4736f4c364872377a58696a4e39463748627165676f753967654b524d5846
    45352f2b4a3956595a634a734a624c756570480a544f72535a4d4948502b5
    358514d4166414f454a4547426d6d4430683566672f43473475676a79486e
    4e51383733414e4b6a55716d3676574574413872514c620a4530742b496c7
    06641674d4241414543676745414c7a4362647a69316a506435384d6b562b
    434c6679665351322b7266486e7266724665502f566344787275690a32703
    16153584a596962653645532b4d622f4d4655646c485067414c7731785134
    57657266366336444373686c6c784c57535638477342737663386f3647503
    20a6359366f777042447763626168474b556b5030456b62395330584c4a57
    634753473561556e484a585237696e7834635a6c666f4c6e7245516536685
    578734d710a6230644878644844424d644766565777674b6f6a4f6a70532f
    39386d4555793756422f3661326c7265676c766a632f326e4b434b7459373
    744376454716c47460a787a414261577538364d435a342f5131334c762b42
    6566627174493973715a5a776a7264556851483856437872793251564d515
    751696e57684174364d7154340a53425354726f6c5a7a7772716a65384d50
    4a393175614e4d6458474c63484c49323673587a76374b53514b426751447
    66377735055557641395a325a583958350a6d49784d54424e6445467a5662
    5550754b4b413179576e31554d444e63556a71682b7a652f376b337946786
    b68305146333162713630654c393047495369414f0a354b4f574d39454b6f
    2b7841513262614b314d664f5931472b386a7a42585570427339346b35335
    3383879586d4b366e796467763730424a385a6835666b55710a5732306f53
    62686b686a5264537a48326b52476972672b5553774b426751445a4a4d6e7
    279324578612f3345713750626f737841504d69596e6b354a415053470a79
    327a305a375455622b7548514f2f2b78504d376e433075794c494d44396c6
    1544d48776e3673372f4c62476f455031575267706f59482f4231346b2f52
    6e360a667577524e3632496f397463392b41434c745542377674476179332
    b675277597453433262356564386c4969656774546b656130683075445352
    7841745673330a6e356b796132513976514b4267464a75467a4f5a742b746
    7596e576e51554567573850304f494a45484d45345554644f637743784b72
    48527239334a6a7546320a453377644b6f546969375072774f59496f614a5
    468706a50634a62626462664b792b6e735170315947763977644a724d6156
    774a6376497077563676315570660a56744c61646d316c6b6c76707173364
    74e4d386a6e4d30587833616a6d6d6e66655739794758453570684d727a4c
    4a6c394630396349324c416f4742414e58760a75675658727032627354316
    f6b6436755361427367704a6a5065774e526433635a4b397a306153503144
    544131504e6b7065517748672f2b36665361564f487a0a794178447339683
    55272627852614e6673542b7241554837783153594456565159564d685552
    62546f5a6536472f6a716e544333664e6648563178745a666f740a306c6f4
    d4867776570362b53494d436f6565325a6374755a5633326c634961663972
    62484f633764416f47416551386b3853494c4e4736444f413331544535500
    a6d3031414a49597737416c5233756f2f524e61432b78596450553354736b
    75414c78786944522f57734c455142436a6b46576d6d4a41576e515544746
    26e594e0a536377523847324a36466e72454374627479733733574156476f
    6f465a6e636d504c50386c784c79626c534244454c79615a762f624173506
    c4d4f39624435630a4a2b4e534261612b6f694c6c31776d4361354d43666c
    633d0a2d2d2d2d2d454e442050524956415445204b45592d2d2d2d2d0a
    pkS: 30820152303d06092a864886f70d01010a3030a00d300b0609608648
    016503040202a11a301806092a864886f70d010108300b060960864801650
    3040202a2030201300382010f003082010a0282010100cb1aed6b6a95f5b1
    ce013a4cfcab25b94b2e64a23034e4250a7eab43c0df3a8c12993af12b111
    908d4b471bec31d4b6c9ad9cdda90612a2ee903523e6de5a224d6b02f09e5
    c374d0cfe01d8f529c500a78a2f67908fa682b5a2b430c81eaf1af72d7b5e
    794fc98a3139276879757ce453b526ef9bf6ceb99979b8423b90f4461a22a
    f37aab0cf5733f7597abe44d31c732db68a181c6cbbe607d8c0e52e0655fd
    9996dc584eca0be87afbcd78a337d17b1dba9e828bbd81e291317144e7ff8
    9f55619709b096cbb9ea474cead264c2073fe49740c01f00e109106066983
    d21e5f83f086e2e823c879cd43cef700d2a352a9babd612d03cad02db134b
    7e225a5f0203010001
    token_challenge: 0002000e6973737565722e6578616d706c65205de58a
    52fcdaef25ca3f65448d04e040fb1924e8264acfccfc6c5ad451d582b3000
    e6f726967696e2e6578616d706c65
    nonce: d048052b9c98942d8d46ace50d159b5df7b46735f0d3616c6d2ce3
    b227208f2e
    blind: 7f359a786c569fbdd453619013405dd160d33b48cc8cc9576d66df
    ce029692e34198d4b7fb71f094074b28e216e8f53f32a52a23738cb3f0e0d
    1ea9eabd7814b04805df5233470d6528d15da4a63c04b77dec53b1c95b9d5
    606ab1cdb41f05dd60fe8d6d58bcd3b0a14a90c0c47d11622dc5dee22924a
    36cdfae932ffd27db61f57995c67c9ccd55ae7bf7244e667b98a0fee4afef
    d133a943bed6cfc26d24b7230ba5390f0bcd60450a06062734a231e16e21a
    275f6cba202a82fe478713ede84f495379ac4df60252dd3f0771fc288def6
    fdc55be97d50ace4fd51c96204040ee1d38ecf16af6716f2b18f9d4a1cb44
    6dc99b96235902759b889d8ffee5cca
    token: 0002d048052b9c98942d8d46ace50d159b5df7b46735f0d3616c6d
    2ce3b227208f2e820fc64e2630a0d5166c36696b663ff34518338263383ec
    92b3347ea30bddae4ca572f8982a9ca248a3056186322d93ca147266121dd
    eb5632c07f1f71cd270818b266714eaf4d02fe00e119d2747e031ac44ef21
    58e21b2b1ab3e3c154155b6a26a9c09f4cb59f7155f5e08b6caf21330e777
    c5ba4114374a0078dbdc4c7bf3bcf5beb617e660eec88749db4437938e9c6
    9f99e46c9337d854ecc17a8e8ca46e2958ac75ea8cc568fa75771342c901b
    c1afe2654e8639ef3ef85ddfdf2ce0e78a649d74e009154ade51dffd7ad32
    49f938eb181043cac973b799fb4943bf0274bc3ef414d0491edb41f254fec
    369101d7fd46763a53aee7f12ae52b9d79a29d3300c1d1c74e9eb06d99cb8
    9f5442c9286042126fa93209c2c6ed1e4a3d0da9b1e69050a0b099a17b2e3
    6f85bc86664287ec17b46b4e18f1558805cfb437aa65
  - type: 0002
    skS: 2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d0a
    4d494945765149424144414e42676b71686b6947397730424151454641415
    343424b63776767536a41674541416f49424151444c477531726170583173
    6334420a4f6b7a38717957355379356b6f6a41303543554b66717444774e3
    8366a424b5a4f76457245526b49314c527876734d6453327961326333616b
    4745714c756b440a556a35743561496b3172417643655844644e445034423
    25055707851436e6969396e6b492b6d677257697444444948713861397931
    37586e6c5079596f784f530a646f6558563835464f314a752b62397336356
    d586d34516a7551394559614971383371724450567a50335758712b524e4d
    636379323269686763624c766d42390a6a41355334475666325a6c7478595
    4736f4c364872377a58696a4e39463748627165676f753967654b524d5846
    45352f2b4a3956595a634a734a624c756570480a544f72535a4d4948502b5
    358514d4166414f454a4547426d6d4430683566672f43473475676a79486e
    4e51383733414e4b6a55716d3676574574413872514c620a4530742b496c7
    06641674d4241414543676745414c7a4362647a69316a506435384d6b562b
    434c6679665351322b7266486e7266724665502f566344787275690a32703
    16153584a596962653645532b4d622f4d4655646c485067414c7731785134
    57657266366336444373686c6c784c57535638477342737663386f3647503
    20a6359366f777042447763626168474b556b5030456b62395330584c4a57
    634753473561556e484a585237696e7834635a6c666f4c6e7245516536685
    578734d710a6230644878644844424d644766565777674b6f6a4f6a70532f
    39386d4555793756422f3661326c7265676c766a632f326e4b434b7459373
    744376454716c47460a787a414261577538364d435a342f5131334c762b42
    6566627174493973715a5a776a7264556851483856437872793251564d515
    751696e57684174364d7154340a53425354726f6c5a7a7772716a65384d50
    4a393175614e4d6458474c63484c49323673587a76374b53514b426751447
    66377735055557641395a325a583958350a6d49784d54424e6445467a5662
    5550754b4b413179576e31554d444e63556a71682b7a652f376b337946786
    b68305146333162713630654c393047495369414f0a354b4f574d39454b6f
    2b7841513262614b314d664f5931472b386a7a42585570427339346b35335
    3383879586d4b366e796467763730424a385a6835666b55710a5732306f53
    62686b686a5264537a48326b52476972672b5553774b426751445a4a4d6e7
    279324578612f3345713750626f737841504d69596e6b354a415053470a79
    327a305a375455622b7548514f2f2b78504d376e433075794c494d44396c6
    1544d48776e3673372f4c62476f455031575267706f59482f4231346b2f52
    6e360a667577524e3632496f397463392b41434c745542377674476179332
    b675277597453433262356564386c4969656774546b656130683075445352
    7841745673330a6e356b796132513976514b4267464a75467a4f5a742b746
    7596e576e51554567573850304f494a45484d45345554644f637743784b72
    48527239334a6a7546320a453377644b6f546969375072774f59496f614a5
    468706a50634a62626462664b792b6e735170315947763977644a724d6156
    774a6376497077563676315570660a56744c61646d316c6b6c76707173364
    74e4d386a6e4d30587833616a6d6d6e66655739794758453570684d727a4c
    4a6c394630396349324c416f4742414e58760a75675658727032627354316
    f6b6436755361427367704a6a5065774e526433635a4b397a306153503144
    544131504e6b7065517748672f2b36665361564f487a0a794178447339683
    55272627852614e6673542b7241554837783153594456565159564d685552
    62546f5a6536472f6a716e544333664e6648563178745a666f740a306c6f4
    d4867776570362b53494d436f6565325a6374755a5633326c634961663972
    62484f633764416f47416551386b3853494c4e4736444f413331544535500
    a6d3031414a49597737416c5233756f2f524e61432b78596450553354736b
    75414c78786944522f57734c455142436a6b46576d6d4a41576e515544746
    26e594e0a536377523847324a36466e72454374627479733733574156476f
    6f465a6e636d504c50386c784c79626c534244454c79615a762f624173506
    c4d4f39624435630a4a2b4e534261612b6f694c6c31776d4361354d43666c
    633d0a2d2d2d2d2d454e442050524956415445204b45592d2d2d2d2d0a
    pkS: 30820152303d06092a864886f70d01010a3030a00d300b0609608648
    016503040202a11a301806092a864886f70d010108300b060960864801650
    3040202a2030201300382010f003082010a0282010100cb1aed6b6a95f5b1
    ce013a4cfcab25b94b2e64a23034e4250a7eab43c0df3a8c12993af12b111
    908d4b471bec31d4b6c9ad9cdda90612a2ee903523e6de5a224d6b02f09e5
    c374d0cfe01d8f529c500a78a2f67908fa682b5a2b430c81eaf1af72d7b5e
    794fc98a3139276879757ce453b526ef9bf6ceb99979b8423b90f4461a22a
    f37aab0cf5733f7597abe44d31c732db68a181c6cbbe607d8c0e52e0655fd
    9996dc584eca0be87afbcd78a337d17b1dba9e828bbd81e291317144e7ff8
    9f55619709b096cbb9ea474cead264c2073fe49740c01f00e109106066983
    d21e5f83f086e2e823c879cd43cef700d2a352a9babd612d03cad02db134b
    7e225a5f0203010001
    token_challenge: 0002000e6973737565722e6578616d706c6500000e6f
    726967696e2e6578616d706c65
    nonce: e19b922c28bb1d83c548a1ab081bf7ef686d85c9d851e468127c10
    c84ac472e4
    blind: ae88e1a9175cadeb95ef6e66ea3845ad8ee7dfbde76f8281d7ded5
    3c0a5f7c2f6c159d76a0638429ec00238b9601ca4c8df5115b15c0f6dcfea
    01ef6c02fd8e15b47412b81eedd31deace7a290597467d347354ed9144792
    f5a27d636b861713dc4963c5ca0df8f3cd24988e6693c2db11313b6024993
    d8ef29795e8189e43226df8b36112f4d4a29477b556009818358a357c882c
    cffd547593767b804d727ffcaa903aac13417d8fb19d7cfcf300f19953feb
    81cd440a2e814786efa8675ef656dcc9f643c82e141555bc0ba58a66871c4
    6b7cf36208f1d5c6b9a36342b791d4e96e6620b4b791e2d693912c877dd65
    7325f5c43cae93874112533ce9197cc
    token: 0002e19b922c28bb1d83c548a1ab081bf7ef686d85c9d851e46812
    7c10c84ac472e411e15c91a7c2ad02abd66645802373db1d823bea80f08d4
    52541fb2b62b5898bca572f8982a9ca248a3056186322d93ca147266121dd
    eb5632c07f1f71cd27086bd916ec83e023ac3be3e3f490786890780a78ba4
    720d1911498c216023c4602da9584b827651b27787e07fa4f2d6551ece490
    7f20b49369abb835936ea6059afcfb22bdc2296f112ea0f5a1a9642279093
    417261e4209a140c3bbc65af8e83dc0726f03711708a02447f1da7bf6fa2c
    bae31cc209a3ab86af929827ce17189b44dea4deb03ef8ce9bd64cc374c1e
    131d4e6844c4c36b6ef04c3eea4a5ce4556aabb60d2e60930f5b61cdcc475
    71f4b5ac4c4e4db1238ecf8733933debca94c2be90e6813106da141730687
    06ac5e5b1dd15b1b1c1d95158252c9f3278705aa6a614402904c163675f3c
    f8d6ca031590e60c8f62dd874900caa626740b093d0d
token_request: 420a0103000208b3fca93ee371f99a7ad75b5afd37879a0488
f96628bc1ce4446412478cca7a3e2d8f9b8bd67e6e073bad587a787a4957a66a6
b0c742c390b5036c68c4058b4e5160badad76ffaa5783def3237db2ba402a0eae
fb975df85f1fe1aadeb944e005a78dc5e97ef480f2337c8cdc02e7116bfdd600f
416cf47972096ae8e5cbd7494d95891553d6a0846a6bb5bd98086c9e99af0912f
635e113ec9dbe574f8bb1b6147b6010adf08ef551d3573e1817acccc7f8e69481
5a13a34e57d6d51c7728be8f1cf910499a22a71fc68742ae8ba8e40e3283f400f
fc56808bdf158bfc31aab8c4d9b6ae45b93ea8e0b49c881022a118643c0905e52
3702ab4f140e4e2d7e2ef0103000208a0c0cabe6b96809222d5137638cac4588e
0b206e49ce65f70ca0b72fe3aac07e9d87b608d52e87acd85041f7eb52c6742c0
647cfbdf7d3b34495f9df626b4408ab3761d1f3774610c6ac6175350ca2620715
de246ab742e6ee0e093e746e7c51490b9c50201f4d2a47475437afd89eb70aabf
4120aa4c4150c0e12084d770a5643a91700779d29a23eed2cafef97bcc44c6411
6c89aeffa5d168406612abb2ef842c3c77d51aeac0ad8742671534e3a211e8bc1
f18ab88abbdc8b4573c70aa3c1b22079d1a3f747a406a768cf220c6592b5e79b8
9e0346ec4585d070a2ef003aa86c3575020934ab457b8c9c6482fdb48c9ba192b
e374cc6f17fbb7f164b05a8
token_response: 420401001095ef43eca604db7927ca6d0ef545adab7beea9e
bb1fcbcb163421ef28e5a2ab53a186299559247ec62b406b92beae8078e96a4f9
e8735307f2a41a71363c6169b7c7da8351c0b6e788eed5c2eb3f78341767beb1b
3dc93c4fb96aca4f13c0912f975c8d0efebb15b75ac2065aed23eb08cb8be3266
ff11ce7a0818ac494b22a7fe84b16a855b74d1247a225ab699c530a9a507efe79
64bd14f0cd6c5d7542085ca764ef77f05e61642ad439cda9bacf75b986823a312
56e4dbc757221865b0e482c13910af7efadc265922cf943df7374ac9f1d079fbd
68df421e5d7f55ab3efa49f402f5cdae224e1b55925d8d5ccb5088a7d2ef1a735
f40763310c353ace010022e06469d9cfd000d2b1b3c0d186fbd6241e65955521a
c9149760abf94afbf96254649103996f8eab95d506d21f40b193029a6d3ae80eb
8ea453e5595a125003caf989e2e16cca2af4df767c9e492ea113cac1daecc9e22
ec3ee8abcf5c87039e2a870445e73f4a641099f9761290ee7842a24cf99352375
8fb2fe1e08236d02907b874586f731745db03c005894828d56a900772be15bb43
106595b05c6d8ad660a14692ba22c4c4c38248bf3f640e1d70a8519316bc449b4
a533301a536042e3db400cd78ed83f4279f6e19bcc4e11f0ee68e38e59be4c18f
3e804efbb249493359360ed806b76a25c55a2a5208121aad80a8e22d914125b20
b06b16acd3d5

// Test vector 5:
issuance:
  - type: 0001
    skS: 39b0d04d3732459288fc5edb89bb02c2aa42e06709f201d6c518871d
    518114910bee3c919bed1bbffe3fc1b87d53240a
    pkS: 02d45bf522425cdd2227d3f27d245d9d563008829252172d34e48469
    290c21da1a46d42ca38f7beabdf05c074aee1455bf
    token_challenge: 0001000e6973737565722e6578616d706c65205de58a
    52fcdaef25ca3f65448d04e040fb1924e8264acfccfc6c5ad451d582b3000
    e6f726967696e2e6578616d706c65
    nonce: 1eafc2a8c2eccd5d26cf0a16a664c0575be11d8b696e56be576ae6
    419480bd98
    blind: 91cafa35931c8be2cc4fc382b918dfa5e507e6c653c26407c39c04
    dc9d00fb810b3bd951e53bc4c47bcf356663780a91
    token: 00011eafc2a8c2eccd5d26cf0a16a664c0575be11d8b696e56be57
    6ae6419480bd98501370b494089dc462802af545e63809581ee6ef57890a1
    2105c28368169514bf260d0792bf7f46c9866a6d37c3032d8714415f87f5f
    6903d7fb071e253be2f4f76a86bdbf962d587eecc0208d8cd1beda796e2d0
    ff2ace3703c1e598b9b38e9aefe4eeac5a4dbbbfe4c8dc03fd64a46
  - type: 0002
    skS: 2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d0a
    4d494945765149424144414e42676b71686b6947397730424151454641415
    343424b63776767536a41674541416f49424151444c477531726170583173
    6334420a4f6b7a38717957355379356b6f6a41303543554b66717444774e3
    8366a424b5a4f76457245526b49314c527876734d6453327961326333616b
    4745714c756b440a556a35743561496b3172417643655844644e445034423
    25055707851436e6969396e6b492b6d677257697444444948713861397931
    37586e6c5079596f784f530a646f6558563835464f314a752b62397336356
    d586d34516a7551394559614971383371724450567a50335758712b524e4d
    636379323269686763624c766d42390a6a41355334475666325a6c7478595
    4736f4c364872377a58696a4e39463748627165676f753967654b524d5846
    45352f2b4a3956595a634a734a624c756570480a544f72535a4d4948502b5
    358514d4166414f454a4547426d6d4430683566672f43473475676a79486e
    4e51383733414e4b6a55716d3676574574413872514c620a4530742b496c7
    06641674d4241414543676745414c7a4362647a69316a506435384d6b562b
    434c6679665351322b7266486e7266724665502f566344787275690a32703
    16153584a596962653645532b4d622f4d4655646c485067414c7731785134
    57657266366336444373686c6c784c57535638477342737663386f3647503
    20a6359366f777042447763626168474b556b5030456b62395330584c4a57
    634753473561556e484a585237696e7834635a6c666f4c6e7245516536685
    578734d710a6230644878644844424d644766565777674b6f6a4f6a70532f
    39386d4555793756422f3661326c7265676c766a632f326e4b434b7459373
    744376454716c47460a787a414261577538364d435a342f5131334c762b42
    6566627174493973715a5a776a7264556851483856437872793251564d515
    751696e57684174364d7154340a53425354726f6c5a7a7772716a65384d50
    4a393175614e4d6458474c63484c49323673587a76374b53514b426751447
    66377735055557641395a325a583958350a6d49784d54424e6445467a5662
    5550754b4b413179576e31554d444e63556a71682b7a652f376b337946786
    b68305146333162713630654c393047495369414f0a354b4f574d39454b6f
    2b7841513262614b314d664f5931472b386a7a42585570427339346b35335
    3383879586d4b366e796467763730424a385a6835666b55710a5732306f53
    62686b686a5264537a48326b52476972672b5553774b426751445a4a4d6e7
    279324578612f3345713750626f737841504d69596e6b354a415053470a79
    327a305a375455622b7548514f2f2b78504d376e433075794c494d44396c6
    1544d48776e3673372f4c62476f455031575267706f59482f4231346b2f52
    6e360a667577524e3632496f397463392b41434c745542377674476179332
    b675277597453433262356564386c4969656774546b656130683075445352
    7841745673330a6e356b796132513976514b4267464a75467a4f5a742b746
    7596e576e51554567573850304f494a45484d45345554644f637743784b72
    48527239334a6a7546320a453377644b6f546969375072774f59496f614a5
    468706a50634a62626462664b792b6e735170315947763977644a724d6156
    774a6376497077563676315570660a56744c61646d316c6b6c76707173364
    74e4d386a6e4d30587833616a6d6d6e66655739794758453570684d727a4c
    4a6c394630396349324c416f4742414e58760a75675658727032627354316
    f6b6436755361427367704a6a5065774e526433635a4b397a306153503144
    544131504e6b7065517748672f2b36665361564f487a0a794178447339683
    55272627852614e6673542b7241554837783153594456565159564d685552
    62546f5a6536472f6a716e544333664e6648563178745a666f740a306c6f4
    d4867776570362b53494d436f6565325a6374755a5633326c634961663972
    62484f633764416f47416551386b3853494c4e4736444f413331544535500
    a6d3031414a49597737416c5233756f2f524e61432b78596450553354736b
    75414c78786944522f57734c455142436a6b46576d6d4a41576e515544746
    26e594e0a536377523847324a36466e72454374627479733733574156476f
    6f465a6e636d504c50386c784c79626c534244454c79615a762f624173506
    c4d4f39624435630a4a2b4e534261612b6f694c6c31776d4361354d43666c
    633d0a2d2d2d2d2d454e442050524956415445204b45592d2d2d2d2d0a
    pkS: 30820152303d06092a864886f70d01010a3030a00d300b0609608648
    016503040202a11a301806092a864886f70d010108300b060960864801650
    3040202a2030201300382010f003082010a0282010100cb1aed6b6a95f5b1
    ce013a4cfcab25b94b2e64a23034e4250a7eab43c0df3a8c12993af12b111
    908d4b471bec31d4b6c9ad9cdda90612a2ee903523e6de5a224d6b02f09e5
    c374d0cfe01d8f529c500a78a2f67908fa682b5a2b430c81eaf1af72d7b5e
    794fc98a3139276879757ce453b526ef9bf6ceb99979b8423b90f4461a22a
    f37aab0cf5733f7597abe44d31c732db68a181c6cbbe607d8c0e52e0655fd
    9996dc584eca0be87afbcd78a337d17b1dba9e828bbd81e291317144e7ff8
    9f55619709b096cbb9ea474cead264c2073fe49740c01f00e109106066983
    d21e5f83f086e2e823c879cd43cef700d2a352a9babd612d03cad02db134b
    7e225a5f0203010001
    token_challenge: 0002000e6973737565722e6578616d706c65205de58a
    52fcdaef25ca3f65448d04e040fb1924e8264acfccfc6c5ad451d582b3000
    e6f726967696e2e6578616d706c65
    nonce: f1386ab3fae0c39831a93ad95a6849c0ba16c6f0a6e70cb0136d3e
    e7bba0bfdd
    blind: 9bd73f519aa5da3a1cafe68a9016d4e488580e9a8794dbc8d1109d
    94b2815fdcd6bea9fe62565d83c3a69a7520c3a6ad1a4aacf4f053c43369c
    359efa26a1b010654575c4b5db8e6423ee02a9e7b7f8a43dbd756b34eda26
    822cef3d05d77cefbefb26a30118a6d23e6d90c5aa9a248e2f0c32672edcf
    98c497c1a84137b9e9bca317554c5e3389159e80f0c148aa61e1e489d95b3
    85a0e8af7eb67abb1a479f3ed1fb1cc409572b22e3d95257c88305ca8a753
    fca2ef8d4bda7b2a2505287f56d92566afa33ad11314785c9581c681ba96d
    23345078933d43c32de74df38b9e8bffe5d04745a0b7d3a13fb10fbcd3f36
    bd805877eaafbc739344e746b630dc1
    token: 0002f1386ab3fae0c39831a93ad95a6849c0ba16c6f0a6e70cb013
    6d3ee7bba0bfdd820fc64e2630a0d5166c36696b663ff34518338263383ec
    92b3347ea30bddae4ca572f8982a9ca248a3056186322d93ca147266121dd
    eb5632c07f1f71cd27083c6ec9a93af05b3e17e5a73092c37559f08e1ed3e
    00712645b8d50cce62abece1f922da19e2f9fc39674a0ad1108d69041c7ab
    06215dc217dc4d842087000ae6614b1e236520b4adbd14280d3e1391d2366
    acb5a65488c0dde86b1d70284d96b717af76eb903d6690fb77c236e12561a
    242b610b900c0a216d308fbb5f4ae98de3d4ee34b012fd8151d9879551b04
    97d8c5664956181bd76ea68fcc2aa3566b0bed0a3479e3b3b7fc4524a054f
    eeedc25039e62c87219a77e476c2a9260b19a7966a1e21eee97c96152b56b
    73ca016343bc8d90258423d7ccbb95c97c4e3b1915414eab559475d2af2ea
    cf4861ac34b29cea78261d31c6b6b9177de61215e773
token_request: 413b00340001f402bb653921035ff16c4be3216f6e18d061b8
13a00022e83a0c6ea97698ebe6f0d6874451856e5b0571315f90fb5e2a402f010
300020830d4e823b8505e9c7b47d18a6febc16c17c467db5b85411ebc5398a731
376f3e4684e3d190a819f10c18950eac631e3595ae5450145c1f8f2645e4a5f0b
a95c25b97f70389bfb167aef225da1f36a0e46d0b9160fd73e9bc00e217a4408b
e7e636acec8ac16d96e715af71cc12fd1885aa77e6509f1b9d90975bdaa4d1c7c
41633db74ec85102a72729250f65b49b038522d4ae810cec21a4c777586f9691f
4aa664830618476cd6492415c06b81d37846bbf65edf3b2832d1c32f1bc893330
d71182f5a807640504597518423e425aad89a5982d49fd35c3fbcdefb8fbc4e96
4d8c8e553b02f1e25bb5670c7a4167413b28ad6f1ed5df315a903f808055753a
token_response: 419500910221de7fb4055a36b696771d119f608650f9f4669
400add3447edd53dfc9b3813caf4010e93bfdb771d2b5d3551283900eb00fd737
259347af348e2ae20ce125d94727c5cc1f98a64dafd643a86bb0db62cc630cdaf
df4a66a3f9f3fc8218f7ac86c3b5bd3b995a2c079b99ef9cd62dafcd358bb338d
71900c4381666c8cb07c878674832651c9278e5d8906a1cbf3de2401003121275
4a0ce008d55426a248ef85c78ed1c778b4fa1028d2a51035816409fae365e9c76
277ad2b4442ba614b4370a9f47715bbb5b72ba538d850c882ee1485215e007d32
474318ae266693b6715a8ffba1755d35ee099c50f30448a774bf851a1ef63cf27
c12bcc6a7829b129e8031bb202b14b90c8e0f9c17891149efa13ce55e2d4b9a95
256807d3d549efdc05645c249f008947addee2f38646d1441971c204162c81a8f
7ac2ba0bcaaa693194e1e7ef5d364fd9e8c39f9d9dc65ad402731eb081388acbd
b53c3a598afa1e496fea5a2bd6dc52a1af68bc6869e98bcaba8575936accebfeb
f99c8effe8a4c0e03ffcd561b1ef6186c4ae610c56b9df8abf

// Test vector 6:
issuance:
  - type: 0005
    skS: 120806797808de49868e5ea9e4d9fbe245b9b1179e8cc142425c211e
    056bc800
    pkS: 0aa7b85a0bfa010093f1537bc1f065d803ec5763527ef9d41eabf4b6
    2692d279
    token_challenge: 0005000e6973737565722e6578616d706c65205de58a
    52fcdaef25ca3f65448d04e040fb1924e8264acfccfc6c5ad451d582b3000
    e6f726967696e2e6578616d706c65
    nonces:
      - 1957894aa08558d99a1ba37843bf0d3c0f0a3a00887187d1cfa2a7713
      5513107
      - 2f13148ba8ceb594c8d26ffc2ce5d25cd6b8e4788da664380c2aac0eb
      79f8c77
      - 1af33893836bff0661352e16e01e14195006dbb92da543c440a333e77
      3cfe120
    blinds:
      - c96fadb8cb9c053363bebc66c372d4da80da745eaac120f3801fa3edb
      395c10d
      - bba2f1cbef59de987c476720146dfc6dec8ce9ea69a39b3f2f5d63772
      5aa1705
      - fe56db04e5f098ebcf18bfaed7e82acd6b944f9592f9d262a695b6703
      d5fe10b
    tokens:
      - 00051957894aa08558d99a1ba37843bf0d3c0f0a3a00887187d1cfa2a
      771355131079c3b6b7738473a90a1f6193f5a6f11c9d04e2c2bb58f2cea
      5d152b94097a1bcb62acde1e6a9a78c07723df55cc8a2fa3fcce41fff34
      7c96b1cbbeec3602e3b6fda579c8dbeab0b817f35db4efaab84ef63014d
      e330d908e07fdf8103706f7ad09f63a0a8f8e03d1ce9a36e750f9404d11
      1b884ac776310de427d944ca272af0c
      - 00052f13148ba8ceb594c8d26ffc2ce5d25cd6b8e4788da664380c2aa
      c0eb79f8c779c3b6b7738473a90a1f6193f5a6f11c9d04e2c2bb58f2cea
      5d152b94097a1bcb62acde1e6a9a78c07723df55cc8a2fa3fcce41fff34
      7c96b1cbbeec3602e3b6fcaf9a4f421d40f6e7c5ba1dee195e7fe2c58c6
      3c6e6b4e9c2ba6887db9ae0977c6abcae17ddbe6b32b3ac6709016ff6d6
      f1f55bded01ad808ba35c90d5bc8e27
      - 00051af33893836bff0661352e16e01e14195006dbb92da543c440a33
      3e773cfe1209c3b6b7738473a90a1f6193f5a6f11c9d04e2c2bb58f2cea
      5d152b94097a1bcb62acde1e6a9a78c07723df55cc8a2fa3fcce41fff34
      7c96b1cbbeec3602e3b6f483c9058dc852f14e0c1555e2f92cd576a1785
      71a796020223890fdecc743bbd024abc1cd95e47751c3c69a992903c347
      6b1f8b6775b7b70f1ad6585f18dbf3e
token_request: 4067006500056f40607e2562c4d64b98a9afa9b07d9476b8ea
b20a84261cd32fff8276ff020784490eb2614767b59ef7e04deb176ed2df29527
b218c93761c552c78733d44aaeabb3ffeab61a7a69eeb10730dc0d98a6eb25210
1a57a219f1c2efac75ddf2aaaf240a
token_response: 40a400a24060a464359a54251cbfab66a19855d17f761e910
129559651373eb4d2d50ff1ef609c5b6e9f86e7b55646d1af26342fd79b30a298
e63b3192c36122b3b0ab7411618aa6e4df3c5e40317679c4f23a80e150dbf7dd4
858ef936ecd0a3c6009fc640f949ef79ce8ac9287f54fb8d614fb43af1475766b
ec727b1e2de777e10d753a0f4ca1cd4625ca558232da989ec5f0f93687c7c28ef
fd04ab90216dbe20123db0d

// Test vector 7:
issuance:
  - type: 0001
    skS: 39b0d04d3732459288fc5edb89bb02c2aa42e06709f201d6c518871d
    518114910bee3c919bed1bbffe3fc1b87d53240a
    pkS: 02d45bf522425cdd2227d3f27d245d9d563008829252172d34e48469
    290c21da1a46d42ca38f7beabdf05c074aee1455bf
    token_challenge: 0001000e6973737565722e6578616d706c65205de58a
    52fcdaef25ca3f65448d04e040fb1924e8264acfccfc6c5ad451d582b3000
    e6f726967696e2e6578616d706c65
    nonce: 681add656e50e2b06cb7bfa55a104d2699829d0a3f0650f99ea5a8
    a2e4bf63c6
    blind: c0f8121a70122c7cd1710490e2f213049e339d95521e0410eabdda
    a8204a467afa3abc0c3dbef901e3b99b939d90d18e
    token: 0001681add656e50e2b06cb7bfa55a104d2699829d0a3f0650f99e
    a5a8a2e4bf63c6501370b494089dc462802af545e63809581ee6ef57890a1
    2105c28368169514bf260d0792bf7f46c9866a6d37c3032d8714415f87f5f
    6903d7fb071e253be2f4219f1a4ab65f7922767f51a301b3ac10732542441
    1374458d4fd941033ddbc0768bea8d9685bb0bae055dee6144531c4
  - type: 0002
    skS: 2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d0a
    4d494945765149424144414e42676b71686b6947397730424151454641415
    343424b63776767536a41674541416f49424151444c477531726170583173
    6334420a4f6b7a38717957355379356b6f6a41303543554b66717444774e3
    8366a424b5a4f76457245526b49314c527876734d6453327961326333616b
    4745714c756b440a556a35743561496b3172417643655844644e445034423
    25055707851436e6969396e6b492b6d677257697444444948713861397931
    37586e6c5079596f784f530a646f6558563835464f314a752b62397336356
    d586d34516a7551394559614971383371724450567a50335758712b524e4d
    636379323269686763624c766d42390a6a41355334475666325a6c7478595
    4736f4c364872377a58696a4e39463748627165676f753967654b524d5846
    45352f2b4a3956595a634a734a624c756570480a544f72535a4d4948502b5
    358514d4166414f454a4547426d6d4430683566672f43473475676a79486e
    4e51383733414e4b6a55716d3676574574413872514c620a4530742b496c7
    06641674d4241414543676745414c7a4362647a69316a506435384d6b562b
    434c6679665351322b7266486e7266724665502f566344787275690a32703
    16153584a596962653645532b4d622f4d4655646c485067414c7731785134
    57657266366336444373686c6c784c57535638477342737663386f3647503
    20a6359366f777042447763626168474b556b5030456b62395330584c4a57
    634753473561556e484a585237696e7834635a6c666f4c6e7245516536685
    578734d710a6230644878644844424d644766565777674b6f6a4f6a70532f
    39386d4555793756422f3661326c7265676c766a632f326e4b434b7459373
    744376454716c47460a787a414261577538364d435a342f5131334c762b42
    6566627174493973715a5a776a7264556851483856437872793251564d515
    751696e57684174364d7154340a53425354726f6c5a7a7772716a65384d50
    4a393175614e4d6458474c63484c49323673587a76374b53514b426751447
    66377735055557641395a325a583958350a6d49784d54424e6445467a5662
    5550754b4b413179576e31554d444e63556a71682b7a652f376b337946786
    b68305146333162713630654c393047495369414f0a354b4f574d39454b6f
    2b7841513262614b314d664f5931472b386a7a42585570427339346b35335
    3383879586d4b366e796467763730424a385a6835666b55710a5732306f53
    62686b686a5264537a48326b52476972672b5553774b426751445a4a4d6e7
    279324578612f3345713750626f737841504d69596e6b354a415053470a79
    327a305a375455622b7548514f2f2b78504d376e433075794c494d44396c6
    1544d48776e3673372f4c62476f455031575267706f59482f4231346b2f52
    6e360a667577524e3632496f397463392b41434c745542377674476179332
    b675277597453433262356564386c4969656774546b656130683075445352
    7841745673330a6e356b796132513976514b4267464a75467a4f5a742b746
    7596e576e51554567573850304f494a45484d45345554644f637743784b72
    48527239334a6a7546320a453377644b6f546969375072774f59496f614a5
    468706a50634a62626462664b792b6e735170315947763977644a724d6156
    774a6376497077563676315570660a56744c61646d316c6b6c76707173364
    74e4d386a6e4d30587833616a6d6d6e66655739794758453570684d727a4c
    4a6c394630396349324c416f4742414e58760a75675658727032627354316
    f6b6436755361427367704a6a5065774e526433635a4b397a306153503144
    544131504e6b7065517748672f2b36665361564f487a0a794178447339683
    55272627852614e6673542b7241554837783153594456565159564d685552
    62546f5a6536472f6a716e544333664e6648563178745a666f740a306c6f4
    d4867776570362b53494d436f6565325a6374755a5633326c634961663972
    62484f633764416f47416551386b3853494c4e4736444f413331544535500
    a6d3031414a49597737416c5233756f2f524e61432b78596450553354736b
    75414c78786944522f57734c455142436a6b46576d6d4a41576e515544746
    26e594e0a536377523847324a36466e72454374627479733733574156476f
    6f465a6e636d504c50386c784c79626c534244454c79615a762f624173506
    c4d4f39624435630a4a2b4e534261612b6f694c6c31776d4361354d43666c
    633d0a2d2d2d2d2d454e442050524956415445204b45592d2d2d2d2d0a
    pkS: 30820152303d06092a864886f70d01010a3030a00d300b0609608648
    016503040202a11a301806092a864886f70d010108300b060960864801650
    3040202a2030201300382010f003082010a0282010100cb1aed6b6a95f5b1
    ce013a4cfcab25b94b2e64a23034e4250a7eab43c0df3a8c12993af12b111
    908d4b471bec31d4b6c9ad9cdda90612a2ee903523e6de5a224d6b02f09e5
    c374d0cfe01d8f529c500a78a2f67908fa682b5a2b430c81eaf1af72d7b5e
    794fc98a3139276879757ce453b526ef9bf6ceb99979b8423b90f4461a22a
    f37aab0cf5733f7597abe44d31c732db68a181c6cbbe607d8c0e52e0655fd
    9996dc584eca0be87afbcd78a337d17b1dba9e828bbd81e291317144e7ff8
    9f55619709b096cbb9ea474cead264c2073fe49740c01f00e109106066983
    d21e5f83f086e2e823c879cd43cef700d2a352a9babd612d03cad02db134b
    7e225a5f0203010001
    token_challenge: 0002000e6973737565722e6578616d706c65205de58a
    52fcdaef25ca3f65448d04e040fb1924e8264acfccfc6c5ad451d582b3000
    e6f726967696e2e6578616d706c65
    nonce: 4a59e2dc076a07708977cc6a4d63be80ca47f8892fad4a21d42b0d
    7fda0d4d3a
    blind: 1d08b7f008bf8fc4b3883ff69700d565dd4bb0a2a8edf6ffc242b1
    d4d011c97357f4067e09d09969df16535f26935e700fca049d784f5dcb409
    831f65d6e1177b2e46053e62301ff48ec5ab5fae76a9216bb0610a5ccdb35
    14638d0a4192c217d7bb4193df502c0b620f94f1f0bcecd36e239138e0830
    cc19b2142c48561c4e6a318010df189211ded18f23246bdb6917ccb6eb323
    6cc977f98ed0942c7a3235efb40de5f191dd87ad55a538b9d646b66813fb3
    ad77fdce9a386115af0f6674d3a6108b91edbf0f866b531a68791c7c77046
    1e7ade707d8bcbea6782a94863bdec29600a1fa49a42bd6ef4f1756753d20
    efab946851bc7055952f5640a5c07c5
    token: 00024a59e2dc076a07708977cc6a4d63be80ca47f8892fad4a21d4
    2b0d7fda0d4d3a820fc64e2630a0d5166c36696b663ff34518338263383ec
    92b3347ea30bddae4ca572f8982a9ca248a3056186322d93ca147266121dd
    eb5632c07f1f71cd27084b46d2e80196d5ae383699d78fe35db81d19b6e52
    93ef19f6dec82ef1f4f04c2a739b05017804cf81ef0aaf32ea5e158ef6e0d
    1014da09fd2b179b93217afb7225c8e62246fc74274c74868991a1a1d94d5
    5f7a08a4c061923d1bb331a6e01cb9c37a47360681472e1ababd624b0da71
    99c0bfefa46a65dff67fe9d4969f18558673ffc138904f87f8898ff65e13e
    d789d03236735bc88b260cd0502f63ce5de0d3f512ff08cdbe62fe09afd94
    dd89ac784ccd8a58a3c5cd0ad093c61e0b0c42fb44fcf461ef5440c386639
    3d570136f248a3162a322950ad7b4f924a48a1ad2c8eed0cfdd06a888a099
    0f526acff015b2d5a2b7aa985385fb59d3cbdd2e916f
  - type: 0005
    skS: 120806797808de49868e5ea9e4d9fbe245b9b1179e8cc142425c211e
    056bc800
    pkS: 0aa7b85a0bfa010093f1537bc1f065d803ec5763527ef9d41eabf4b6
    2692d279
    token_challenge: 0005000e6973737565722e6578616d706c65205de58a
    52fcdaef25ca3f65448d04e040fb1924e8264acfccfc6c5ad451d582b3000
    e6f726967696e2e6578616d706c65
    nonces:
      - f5c70649149e418f3d86a9c3e248b203a24bae704d57335bc9b4aa0d5
      1821411
      - a965df7c4f16efb7629250bdf0c4f892638053bd27a0468fe3bd2e808
      32a98eb
      - 01538def40b7e029c54e01becbb00a2ff301d50b85ff6eaa169a6ffcc
      47b455c
    blinds:
      - e3f331f4f46cfdde3319ad1a6568755f0da7e28ab2554514e9dc4f9a2
      ea52802
      - 5326701f22fc25fc3455a06461937645ff1c75618cd45d4aecaa1ed0d
      d32e208
      - 363e7eb253cb8682ab1e76126bd2dc757b5556770eddd36edc5e73012
      1187f0d
    tokens:
      - 0005f5c70649149e418f3d86a9c3e248b203a24bae704d57335bc9b4a
      a0d518214119c3b6b7738473a90a1f6193f5a6f11c9d04e2c2bb58f2cea
      5d152b94097a1bcb62acde1e6a9a78c07723df55cc8a2fa3fcce41fff34
      7c96b1cbbeec3602e3b6f6fabba8fd638fd6b426125814f62e98ba85c6f
      9bdb77ae58e7e233b457cfdb690ab38753052fd70fdc1102b2dea5abab1
      78ad61e38e3e4b309b2bf23a5f133c5
      - 0005a965df7c4f16efb7629250bdf0c4f892638053bd27a0468fe3bd2
      e80832a98eb9c3b6b7738473a90a1f6193f5a6f11c9d04e2c2bb58f2cea
      5d152b94097a1bcb62acde1e6a9a78c07723df55cc8a2fa3fcce41fff34
      7c96b1cbbeec3602e3b6f2eb68767d88d02098c687424f8259dd9229967
      3da15d7738383190a2b6a6aafb56138ad8947583bc0957e56acd9f67fd9
      a13d484aa4579bfd17f363d9be20e2a
      - 000501538def40b7e029c54e01becbb00a2ff301d50b85ff6eaa169a6
      ffcc47b455c9c3b6b7738473a90a1f6193f5a6f11c9d04e2c2bb58f2cea
      5d152b94097a1bcb62acde1e6a9a78c07723df55cc8a2fa3fcce41fff34
      7c96b1cbbeec3602e3b6f95e1974836478341fdd101f140e644c1c0b359
      aeb3292675ba9f1ce4b6a619db8539ff4507648cbc27a678a069588cb68
      f287e22bb060b7d2d1fec1856329a2c
token_request: 41a200340001f4036f5fdbe51f329822dd5fc1172ca27f3a61
2c78760670afeb3279dadca1b1c5417c3ca60ae98bb87f7ff635fdfc85adae010
3000208c573ea7823a27be2d780927d8b0978824ded3b518e12e4d7d7cfb097fd
cc5893b54f66bf9fbe512e8ed9c673bda7e64839ca04ab33ecb8a9a65dc341453
f65388e72b381d13b1aef1183f02de0faeb39cc0d5280ad20d1c2bb5657bb9b70
b145744299294e04644a9728c4c99af0c1b64264663271991aa41484c96d91db1
246104837a009a9c9a4c6a0137cc2d2a0873f1f087a79e077b3539fcebac81cf1
30cbf3ae6f94f0156eb54c7d261990194d12f42279b14cdef852a95c76f235fdc
e898fdc78d025c9854fc7c9e0ea94e386b3bb0b23f37f32395e2b35dd5ea0af5f
856fd8ac2dd33ee88a5469d5c99c99337f03b6302f6e285400faa67434f231670
06500056f4060da32f0f5d76f27c67499f78c0944e3041cacd784145af50e6a96
823428769b230097caacade0fbd17560a897a5063c9be4a3e3d08531288bdde49
90c4b633c4eb86fece30561a0adf216e96c6db41b2062a4693f614cbbaf023be3
374dd1b11e
token_response: 423900910328aeea93c374792cee1f3153f9ef5b9830f9fc0
d02f991699721eb2186cd28b8f59c5472fbf62a693e1402cae61f56bc9bcc9f81
64ce33f421ca181efeb4dc16726d3168c158ab5310afa578532528d0e339e3283
1fd4cd85182d53153ef07f00bece4786d4e1b264de0d3e4d7b19dbe255173482f
11a3cd7d6b0bf63de5de1d6c55773a0f9ed12352de61f9ef6682cb01008053a7f
b089d59824bf65c77acdb0cc20759276b66a1e8f90b6be867dbc9158edc81058b
52d0f7c1997ec4f82147b34270e19b57c31deb4a9ad805bccf77dc806535afbf0
c00c788af211c8d7004bb7fb691f42a42a699de581cbd33a4b056d8198e088b1e
70a92cdbef9b1239eb77336c81bda851325c617347c3037649e1de233d807a5f2
356fb311d40772e7e5c796652ea66363940faa981cc14e9f4b44dc1137d1cb8f0
ee47134b529fd9c7e3de4902b12faeb7ff12a6ebb25601351a2f7af7d41d88161
28d2d461d3726aa38dafd58c824292191380f491c78870113f9e14c567c4122cc
10c690434f47915f0ac0e25a87a4cdcea14b9eef2bf535b4a800a24060f4ac4cf
68617212549b8e098a76db35fa11e9526bf054813d1c929a9d1ee2e7aa416ce70
68fcdd7abd256f06675876a73fe51ec67bcd204fee5136be98d2a002a4204fbd9
597cc7719a23686b62dccd6b2763e0ef248e50ee798e4624783562c4aac040562
7c4fb23590cb719fe1669804347d629dce521cc6e5ee1133ee2c0ace75cdf1895
02a69cc1b68835536dcbbec28cdfd42611447f881b2c079e7d200
~~~
