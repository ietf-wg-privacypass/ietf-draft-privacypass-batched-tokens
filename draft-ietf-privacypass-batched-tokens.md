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
- pkS: The Issuer Public Key, serialized according to the encoding in {{private-token-type}}.
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
7b7f66026a644ce50d3fb0f7ceb14689afd80e499485724f2c9dbf0aec127602
pkS:
ba7c0b26f8c6b291ddc8372db652352e267816b26d1102ff895b06485d9ff02c
token_challenge: f91a000e6973737565722e6578616d706c6520df13e893d0
7ef91c1f753f98f087f057af7955d6f01a886ef5b03326f3b82e55000e6f72696
7696e2e6578616d706c65
nonces:
  - afac61db95b0478799ab316f5b9fd58f96fd0e4de84b6395e54d7fe3d2e90
  73a
  - 92a54429a9720d73ce8f0bd4114633040a3f168495b1140a15fdb8c27cdf4
  dfd
  - c6885276094521417e0bad01bb25d12d242c3c4c6a70f5d0a6797f05526cf
  f24
blinds:
  - f28a2dbc642e506fa804cff01ea1759b8ee5629b46a5913cf4025c98b728a
  b0a
  - 11ad62612e030a89bb02dc9738904e69a1468dfa3e1608fbae311eb956490
  009
  - a368816e720ea798e96f1548f64cf7809579b6721fbd052f73babe8338b76
  e0f
token_request: f91a490060ecc68b730f07af398ea3aa457d381e3bc3abac76
d59088878240f88a2c94b9160c3f5f18b625cc47fd204c3e3d8fad0f7d1621963
dd27000769ddb409c6c8f51866a1465757cab90b9fc814f13387678b6a0f16004
b4d123f9266d39eed4ff71
token_response: 006002932dbe96d9d182ce5af817b895942dceeab7b4475d5
20a0623ed7ebf6557389026e69711d2d9b38016975a25212565b0d4b55abb8dca
80624d965a6200793d1a0705553e43ce255abb44ff28fe51cac31554202957f17
51512548719ca777d167eb8441905d4a7b2f0511a85ef0b5fdf4a44ec34f5bc5f
daf98773f063b008b5f5583556584cbba66be8050a1328e2067ed958a92836ace
de1e6a4f76c560f
tokens:
  - f91aafac61db95b0478799ab316f5b9fd58f96fd0e4de84b6395e54d7fe3d
  2e9073a12a2ff55084af39adafbdb0a5d07312c2dec28e80c083881d75d955a
  69faeb6e8aa56e6c48676dc541d223972f1f3ef798c00ff367abc11f4d448dd
  a42ff4f4941d7c4ee7a0e1f5401d305ca0f7f2e230d695df52d7516abe3f1fe
  fca8acac9534cef2b5d0c8246e7d28775c9eeab1e0b23cfbd0274a937a597af
  e930afe05bf
  - f91a92a54429a9720d73ce8f0bd4114633040a3f168495b1140a15fdb8c27
  cdf4dfd12a2ff55084af39adafbdb0a5d07312c2dec28e80c083881d75d955a
  69faeb6e8aa56e6c48676dc541d223972f1f3ef798c00ff367abc11f4d448dd
  a42ff4f49d5e9639ed6c46c639e9e9c9df1dd6b4cb535e40be65025478314b3
  9a38f3c8f593cd2e8bb6986dac4dc7072848809738b50411481dd02049f4082
  37792200c17
  - f91ac6885276094521417e0bad01bb25d12d242c3c4c6a70f5d0a6797f055
  26cff2412a2ff55084af39adafbdb0a5d07312c2dec28e80c083881d75d955a
  69faeb6e8aa56e6c48676dc541d223972f1f3ef798c00ff367abc11f4d448dd
  a42ff4f4950ebd5db989ff94e468c30f4ecb3bd15ccd996f0f7e85a21b753eb
  b5c2fa613d57abf40fae9cbacf3daf57ad85e1c786685ad7fd28863d9abf166
  61a969934ef

// Test vector 2:
skS:
480c5b8324634df123041af0e73adf21e20286e405ce868665e320a099885d0e
pkS:
3293493ea35c13958cc20a5c43074a1eeab30f2fad00a65fc85ea568f85f2515
token_challenge: f91a000e6973737565722e6578616d706c6500000e6f7269
67696e2e6578616d706c65
nonces:
  - 20e32fee44ad66aef0274732f43c98f6e9e679bf2328dbd2a59a0fb9df29b
  c46
  - 169e0b2a99173834bf9769d45e75e0f8b8d147b26170dd51906d46dd1fc1e
  0ec
  - 71619ab34df5fa19e9332a182685f17190bfacae50a954ce6a0a504c113ef
  2ae
blinds:
  - c933aac2714ec8f80876da52c77ef2024ab955c7150a5bc8e20a955ca57c7
  d0d
  - dbf19424c3b9122ec25a2281b1292a4d1dc6f0dcabafae0b3bbf0b3b2b0b0
  b00
  - 776a65371308a7239b87224ecb2d1c636527f6b8ceecf22c325bee8654348
  604
token_request: f91a5200608e30d6b82e7a460543576b603b2e75b186a9446e
d528e3c3ddfe90e589461b016ec416fafef1e0c5f492582a575529e62d1f29824
afdf3c18d21e91cf8b777636ec90ce2425974fce6888a12f194dd50feb7c8b3fc
cf23a718f535cc6a305d51
token_response: 0060f82226150d3e210624d306778c7dcebafe9d8f44bb888
e839485fac02ea30719620339842d4b183888333a99774656eab903088a3811db
b14a578021d03582687216d133ac20bf646d6b11570fca3cf798ffb9bb2b1c325
d450212ce6690f051a229e54efe99b0c7320f98bded2aee6e4b307b60530b997d
5c4e5f8bf17b7f06dcab5d47b7453b3fbc79cc4dd030839d7d7dd2d28f11ce553
a9849ab77e6f90f
tokens:
  - f91a20e32fee44ad66aef0274732f43c98f6e9e679bf2328dbd2a59a0fb9d
  f29bc461accaaf08678b097d0dc027c1f94e0766b30637649b7341f47da88b0
  9192220656986bebbfcfb9406241e4badf4e3d0d7f19bd4c333ad60f5754a27
  3b338335265a531ee6f4fc3ce67fcc0f9f2d9dc0aeb31a034ce42b166d6ef65
  c45ef3835876e21c1789beb9092506573f6aae81bfe9a2eaedf62b4b965def7
  f4add1131fc
  - f91a169e0b2a99173834bf9769d45e75e0f8b8d147b26170dd51906d46dd1
  fc1e0ec1accaaf08678b097d0dc027c1f94e0766b30637649b7341f47da88b0
  9192220656986bebbfcfb9406241e4badf4e3d0d7f19bd4c333ad60f5754a27
  3b33833525f70d7680041441994a63dce26f01329240b9b44f0a55423c9c235
  3f1475f88ff3b0f77eba36108694cbdfb42c67cb17e422f4d7afc08294b2621
  f11ed25097b
  - f91a71619ab34df5fa19e9332a182685f17190bfacae50a954ce6a0a504c1
  13ef2ae1accaaf08678b097d0dc027c1f94e0766b30637649b7341f47da88b0
  9192220656986bebbfcfb9406241e4badf4e3d0d7f19bd4c333ad60f5754a27
  3b3383352de36e18d013400e34c7fa214429a8063bc1953a007b47cd14d039c
  24e6e59225ef7eba8916604118b95032be9e15406d49aaa83d6398b18fb7241
  03902fb85b7

// Test vector 3:
skS:
2679e0260cf822dd70d7537f93018e1b3692d5dcda0768d8a1310b626c7fc606
pkS:
76842dadcf2b6dceb0575a4011c21a04732bca1fed1c1ef3ffebbf2ad9aaf518
token_challenge: f91a000e6973737565722e6578616d706c65000017666f6f
2e6578616d706c652c6261722e6578616d706c65
nonces:
  - 6f40ddd1b752f7d2bb3466562731f4685b41626652ef8058133d6f1d2c9e3
  cc0
  - 7b01dbb384720f696f6a01ce4c93b0e5038d773fc27ace8d5b29211ff8a07
  d91
  - c8bdd8378f98d722cffbf271e1ec5bf1dfe0917fc20c3e05e974eb1b20a67
  479
blinds:
  - 630a1662bbe64fe9e0fe437ed8871439df4428c7ea764da80d10b04691dad
  c08
  - 6bb8046667385852303af7f71184ad48bb6ab2a8659e0b8a69307473a4972
  b03
  - c15e4887b9e094c93f47f1d5818b1f4740f720115ae58454dfb3f3f6f82b9
  508
token_request: f91a180060f60e89012c543250dedde15fffb7ffccd7d9954d
1bf03f5808b27b067ca50075727a2b105aef91c27de1308a23414fdc5ef4eef41
c72951806453014e772623936c9f058d6d9de898790d0237458e73253acf09673
4a29682d41b9b756830f32
token_response: 006030494984f8aca9712811c98666a1c0d96e691c65c0841
b3c383d44738b03b61ed2fae3b1cebf2fdfdc3efb4562d427002faa7ea9e353f2
35116768f82aa703572e0bd241eb8050e430ee503119ace9070b75caac3bad392
0e4bc2619b296502f58ffde0a93cb4cfe5ad94e9b5ef6777ceb1c1091d0a31a89
8749512a6d7d1a00f85bb804dbeb460f8f8dd90079546410b17ed3dc3ffd54eec
034b6f342de1206
tokens:
  - f91a6f40ddd1b752f7d2bb3466562731f4685b41626652ef8058133d6f1d2
  c9e3cc0740be8b58a8886280f48e6e096fbc6e3a0bab2fca811c133165edf99
  b20857e2e1ca77ff843d862d1667085101c646971332dc6a4adb1ddc897a74c
  1289a781846d6fc3ab5e61c325e310e99d21efacff31893cc88683289e53473
  4635954c18eb2d63e78798d15354ac996fd1984d2c1fb0f35db3119a6d8e9e8
  98a67ed3280
  - f91a7b01dbb384720f696f6a01ce4c93b0e5038d773fc27ace8d5b29211ff
  8a07d91740be8b58a8886280f48e6e096fbc6e3a0bab2fca811c133165edf99
  b20857e2e1ca77ff843d862d1667085101c646971332dc6a4adb1ddc897a74c
  1289a7818ba6ec1294d674d1e53d310ed5c97b61799f45610c4f81ee337c266
  0e625adba364ffe869fbefa749a21d49d78652dc7037eeea6e8e4c3bddff5ed
  0e230e9a92b
  - f91ac8bdd8378f98d722cffbf271e1ec5bf1dfe0917fc20c3e05e974eb1b2
  0a67479740be8b58a8886280f48e6e096fbc6e3a0bab2fca811c133165edf99
  b20857e2e1ca77ff843d862d1667085101c646971332dc6a4adb1ddc897a74c
  1289a7818592637973e88ff9db55c5bbf9c12e4c600a842d2d9bb3882e2b0f8
  1ba4edb0c27dfafa4014af58dae5e585a0168bcc30c46f94924c946dbd5ddda
  3e534bebc5a

// Test vector 4:
skS:
b34c3b5a9160e796e45c0a1c6c9a96c986a780daa3d65e0dbec91720cbc3160b
pkS:
36e5e29f20b3874db1f362d77cf03bc788f5f2ab19ef4bcff5c6db97d5c3ed79
token_challenge: f91a000e6973737565722e6578616d706c65000000
nonces:
  - a44487947557f6a301ae189f24e3b39ce940b45ee9b7f9f3c73ba4856d1e5
  b9f
  - b4eb5298156a0ad36f914a589a7c327249d8e5707e5d24f7982a18d09360c
  395
  - 7da98852c5ea7b84a93a9c76cdf4391ee2644bb4aaebec76ab3f214f05ae3
  1d4
blinds:
  - 1c9974a70ad574e308ba609eb0d5b87ae94c3b9275bcf147da0dd16b34713
  80a
  - e1f6614ebd44e1ad0a765e7693253cfc0e7f9403ee4b080a9af9135bcbe94
  d06
  - a479cf86d29bbac2146601ebdcd3b0e3fbbf3005ee030b1aeab6499485e84
  a03
token_request: f91a350060ce252909fa720f3a302dae769b6d498785ce1d16
f355cea3aad3cc1ce837e1043022a541f03aeb2667925e53e65c542af0145cf77
cca4322d9ab7cc3b295852cb091dabe630c1d056ad2764d0aa99a5d8d7d15cd73
2d1e10bfad7dbe0065581b
token_response: 006044cdf9ab207540584510fde65363c19e216d8504b0bb4
dedf40bb97b7e529e7f508c9ce28f21917096ba1b7f644348783685ac693127eb
9d9c6bb9341164c81df69596653adeb717cc2e142ed689969583dcf2d674ce5b4
7f383190fa772930b40677e76f0006e1dec507901931593ff0ee6ea52c09b2b10
3bb124512ff1070652a4cbdb49dd4746195f033c1df47be1536be4c779e4eff1c
1255705c98a4d0b
tokens:
  - f91aa44487947557f6a301ae189f24e3b39ce940b45ee9b7f9f3c73ba4856
  d1e5b9f2750769753882c26f0076c8de57dc2414ef82353469fe5bc404c3ad3
  53ba0937035e8cba98d47fcf2d7cd553d85405ef037011e4970a7059b9d27f9
  debb98e35bdf0ec099e4bb838867db3e54de4544b2c2e7ecd02675f8eb5b07c
  8d0658da289d6619dd6f6d5a6c43442d466391ffda82f279e915d83b0533197
  19e485e0a0b
  - f91ab4eb5298156a0ad36f914a589a7c327249d8e5707e5d24f7982a18d09
  360c3952750769753882c26f0076c8de57dc2414ef82353469fe5bc404c3ad3
  53ba0937035e8cba98d47fcf2d7cd553d85405ef037011e4970a7059b9d27f9
  debb98e35ee5b28743e22d674ef8c0f00ae923aca58080c9b5ddb435ff9e41e
  e4cf7bdca98f69eb9461a8621fbf23140cfc86ce6a2c9cc0afe69841a87e7e6
  cb4a9bd4ab0
  - f91a7da98852c5ea7b84a93a9c76cdf4391ee2644bb4aaebec76ab3f214f0
  5ae31d42750769753882c26f0076c8de57dc2414ef82353469fe5bc404c3ad3
  53ba0937035e8cba98d47fcf2d7cd553d85405ef037011e4970a7059b9d27f9
  debb98e35339c6ac2d14d9f11557f8d5b35619c5417d6cb710411572905fa13
  7fd94f35f14cd5c32698c834cb01bb286cb897e6cf5b6e9011fa09f08845ab5
  1ea8a3ae18c

// Test vector 5:
skS:
9c88eb0e99bb313fe2491366f3b1777799c027fcad52fb8782e60d89a91e1a0a
pkS:
948283b178fc82638caa7888c228700d5f2d2f0b00b50354df4c18a0b69eba21
token_challenge: f91a000e6973737565722e6578616d706c6520df13e893d0
7ef91c1f753f98f087f057af7955d6f01a886ef5b03326f3b82e550000
nonces:
  - a4bfe29fc36a0fe0b5dd547e01ecb065b30dde5b46b29f95eba3f966b4c45
  644
  - 0ab64fef25495e1f6734033f560dbd2c1c10a334ccd94ba368e84e92a2f48
  3e9
  - 0bed992c03f77df17c637b7ea93d08f59e675b82218619169115d69824ac3
  357
blinds:
  - 974ec0025f4651a2fd12e4190dee37e204924420d2b389de91a6993692386
  207
  - a10ea90dc6c3e5ac91bfd23dc9aee2269a5154bf47779c02ffa306bb2a164
  604
  - f57dea9f1e2f8ab7f8d972e629a5be72dea11358ec6a5f7f6482d5e585e25
  201
token_request: f91a5e0060a0f82248e124c6964daf1af246cf300e6c60e671
95687f06c10dcbf00d421a60a4a631e95f4b4e3c304d8979884d6a198e9a0f5af
d42f0d91897b4a801547435700bb8318d6e5f4843050ce653fda7af5af5c91529
17f64ecbb4f538b546a660
token_response: 00600cc042b8526f042471eced2c9544d232fe36d98cf4056
f4e2b1e10cd18dfb37268df5c3a4236af835dc3bdf4b957dac6c4d13150e1467d
6888432839071761126ace8bdc25be89132aecb112765541cf0f040efb986c85f
2ede2b77387e2a524b4b8688866d42dbae5fdb92f5ffa50f22f3320403d631055
afdc63899f7d4c0452229dea1681da9e4e7480580a43b480da07901bb28809290
eff553644da2d01
tokens:
  - f91aa4bfe29fc36a0fe0b5dd547e01ecb065b30dde5b46b29f95eba3f966b
  4c45644de9250a0d5054e5b4f19bf6d88632a2b4276fcffaed69f8cdd007dbc
  c864fa07867d3061e318cb1ca6d210272190d38340584de9015027afee1eee7
  3d52de25e5b6b134da14bad1ab329c4259337eea2d794348bfcb7e391ee2e1e
  793b27635d3364e5bff6efa491971f205fe552b762592a54f859ce10cb32495
  35e79134aa4
  - f91a0ab64fef25495e1f6734033f560dbd2c1c10a334ccd94ba368e84e92a
  2f483e9de9250a0d5054e5b4f19bf6d88632a2b4276fcffaed69f8cdd007dbc
  c864fa07867d3061e318cb1ca6d210272190d38340584de9015027afee1eee7
  3d52de25ef0d0c759ead7d7ea13eadef1c7a78a6b610327449193e0b69b198a
  40455696d9e54afe9307da49221bb85e19871ac9d4f85f4f0013ba61f5bbeca
  9e8e9218cf2
  - f91a0bed992c03f77df17c637b7ea93d08f59e675b82218619169115d6982
  4ac3357de9250a0d5054e5b4f19bf6d88632a2b4276fcffaed69f8cdd007dbc
  c864fa07867d3061e318cb1ca6d210272190d38340584de9015027afee1eee7
  3d52de25e838c13fdeaad908779d044b6928a12caf02403834891a9a8eb3c65
  bbf787e041a399555bdb5f4054126d6a620da7eb7783983619e28e51f395bf9
  ea6a10fc749
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
  - pkS: The Issuer Public Key, serialized according to the encoding in {{private-token-type}}.
  - token_challenge: A randomly generated TokenChallenge structure, represented
    as a hexadecimal string.
  - nonce: The 32-byte client nonce generated according to {{private-request}},
    represented as a hexadecimal string.
  - blind: The blind used when computing the OPRF blinded message, serialized
    using SerializeScalar from {{Section 2.1 of OPRF}} and represented as a
    hexadecimal string.
  - token: The output Token from the protocol, represented as a hexadecimal
    string.

  type 0x0002
  - skS: The PEM-encoded PKCS#8 RSA Issuer Private Key used for signing tokens,
    represented as a hexadecimal string.
  - pkS: The Issuer Public Key, serialized according to the encoding in {{public-token-type}}.
  - token_challenge: A randomly generated TokenChallenge structure, represented
    as a hexadecimal string.
  - nonce: The 32-byte client nonce generated according to {{public-request}},
    represented as a hexadecimal string.
  - blind: The blind used when computing the blind RSA blinded message,
    represented as a hexadecimal string.
  - salt: The randomly generated 48-byte salt used when encoding the blinded
    token request message, represented as a hexadecimal string.
  - token: The output Token from the protocol, represented as a hexadecimal
    string.
  
  type 0xf91a
  - skS: The Issuer Private Key, serialized using SerializeScalar from
  {{Section 2.1 of OPRF}} and represented as a hexadecimal string.
  - pkS: The Issuer Public Key, serialized according to the encoding in {{private-token-type}}.
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
- Test vector 6: [0xf91a]
- Test vector 7: [0x0001, 0x0002, 0xf91a]

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
    nonce: d7d17c5374d0315effac489eb62600ae79c0ced48353ce67ffc48d
    f027e0b355
    blind: 1c19a1f1b817256afeb9af4cc61b8289ca976d90ca6b82a218b5d1
    5814b87c75cd8be36a3eb7071fbbae5c749d717e31
    token: 0001d7d17c5374d0315effac489eb62600ae79c0ced48353ce67ff
    c48df027e0b355501370b494089dc462802af545e63809581ee6ef57890a1
    2105c28368169514bf260d0792bf7f46c9866a6d37c3032d8714415f87f5f
    6903d7fb071e253be2f4196f2340df38515191bacb389340430cb8be08831
    ad0b111e663d6856b3bb0852934a62f3ebd0a1a1f94a7d3bcdb7e81
token_request: 003600340001f402cbca978346552389dc267afcc582e409b9
9c040eb2bf5c5d1be6c2987ff4416feb1c2e9331ddfc292d741a3fef1383e3
token_response: 00930091039a33b012e8927c80dbc427273aa75a76795b1a0
12fca81a191639169bd14318d260190a899e2e475832a6016e9c4264690a23aab
98fbc8eafc379e8b0b2fda3ff4f0a5e421e1aba7e24497d41ac9de9dc31a68ff2
5f94b9be8bf8153b962007c6fedbade09616c39f6801a8ddd41a5e658049bf27f
53e318c306d48ab2867b00a27078566815c264ecc60919f0b5292a

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
    nonce: 96793ab3d131d383178bc9b09ef52b3306aae4fed6e7cb129a0333
    9b7e8a339e
    blind: bee571130ca800c97fc260063b393bb450eb84e7472998a11823aa
    78176feccdc1099dfcf9f0fe22e5f2a8b36962aac006047ea3784438054e9
    a731049153a923d58728354d7b9b14b64e59b170c507cf6f3d396e156a665
    a84604cdce2227b67befc1e813e33f41b8f1d9395a19aae5f538bd4a562be
    acada926cc815273839f482e6a2c82cd34782cf1b10fb33860dd2c98fef32
    374462ddd68c311ae52cca298bdb68dad0bfbc157e44500975fcebe7eee55
    7ae217e7eee4ceb8792bf09edea9a6ee5c9dbeddb3e0cb1d351174d179c55
    7f2b2884dd4066944dbcd874394d21cddf2edcab73cbc231485323adc6467
    148b788285786827a76fd32f59735a0
    token: 000296793ab3d131d383178bc9b09ef52b3306aae4fed6e7cb129a
    03339b7e8a339e820fc64e2630a0d5166c36696b663ff34518338263383ec
    92b3347ea30bddae4ca572f8982a9ca248a3056186322d93ca147266121dd
    eb5632c07f1f71cd2708390e915dcd1bdd030bc262bd8c8f40ad3d7015d91
    2664ea07401c13bb8f34a17e2a97354801cc879aae8b78b860a5397c69bc8
    bbb109db03a958d6882313c1cd819a362302ca51367f66d25457d8493eb8f
    81931b0daf9552384353af19f0cdaade36941de2e281d40cbc4b8784dd248
    ac582d62118ea56a3fb7611e8af17ebbf9bace9f58c0e621963cd1683a7b5
    36feaaf7f8c3f2d55329392cf89e123600707569bfaf1915dbae38c435e0a
    fb6ee2502bae84919e3875ec747705b99ae2ccf3d03258c5273e8657f4168
    8d65889825949b1cf0445ee6d54333c47c40a5dc8c8064cdf20fc40b5adad
    e7cb05efed36aa7bc1bbceecd4fb06090cf91e4f67b5
token_request: 0105010300020838c5a5e9e081c098f08be902c7b140f91b02
72e21c31de06137a9c0684bc1616fec6fcf5413b89bf2f585eeff7cc4ab58fd42
5abc5bcfe49d7be55242872dd25a01b0d12b3cdf22663af197bf661757d910cb1
04e283c57e32dd32d02bba92a15d4518d5abf2d4d56527af4017e817b01af1916
8beb2d43ce5d017259fa6b75c503cccc6dc54ee3a7e3b99c6e4ce0fc7496e9340
8f9716805f101ec34aa1a4f78be4e792e34d0a84d9c377ef96dcddc548f436e3e
27673a80829ef6706971537d5858fe5dd2363a3c74a58ec84295de594f31e7d3b
0f954024f3881273bff1f8d111015645aac8a8f9a959459b30297f24863fd9e3e
8a5bdc7aa3490ca9cad20
token_response: 01020100680091b3a23f2ef28886d41f720505d603fb570da
c9fa7d1e08768b87a7bc332fca37505dd596d3217a12fbb1d00b7e9e46efc9991
90f94a6eb21cc2ca0455180782bc23367b6bb7063cfcb87470e229344c1b7a0f1
5b9967f68412ab12285eeac1e7093beb81f43317200e976049e6845b06da271f4
799a91ecea1061845c483a3708643600c9e3c1401710c05efa3e97c2615e7e5e4
fd19451a5c90feafbd388dbc91a0e4cd6602efed944720d882b431e1679fd76f0
4ccdda6f8c2f1fc60a0da1195588b4caf414661ad5a292b316ead5893facc1163
e0a3d3c222f1395aa7c589661fcfc7a8df9be72e5104e447ed876ca21c18f2422
1582bd2e6e8bf651

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
    nonce: 591132196f81d659862883c35e8707c6d852d0aabb961b6965f14f
    f7e4f0efe8
    blind: d129f7e17b21fe11c2de98792f171cc56878bc4571cc8bdd207c0b
    8e7674e4b63b794fb98b0c3cc60e39391c32dc4f7e
    token: 0001591132196f81d659862883c35e8707c6d852d0aabb961b6965
    f14ff7e4f0efe8501370b494089dc462802af545e63809581ee6ef57890a1
    2105c28368169514bf260d0792bf7f46c9866a6d37c3032d8714415f87f5f
    6903d7fb071e253be2f4a255dde3b051f3df92de77979447bae518ebd5f4e
    e0c56809fd3a0629a87b709e1309deb118c2e6d955b23b7c9b8a0fb
  - type: 0001
    skS: 39efed331527cc4ddff9722ab5cd35aeafe7c27520b0cfa2eedbdc29
    8dc3b12bc8298afcc46558af1e2eeacc5307d865
    pkS: 038017e005904c6146b37109d6c2a72b95a183aaa9ed951b8d8fb1ed
    9033f68033284d175e7df89849475cd67a86bfbf4e
    token_challenge: 0001000e6973737565722e6578616d706c6500000e6f
    726967696e2e6578616d706c65
    nonce: dd0dd06921489c03d0ba484ad3c065c5838a7725c7258a20792c85
    2b441e3264
    blind: b97d2a60e88834ba42b03dd2e515c1535776607c023a171ae2ed20
    955dcc2e7eb3f73bb2de87b1cb718a96fd87e35e1b
    token: 0001dd0dd06921489c03d0ba484ad3c065c5838a7725c7258a2079
    2c852b441e3264c994f7d5cdc2fb970b13d4e8eb6e6d8f9dcdaa65851fb09
    1025dfe134bd5a62a116477bc9e1a205cca95d0c92335ca7a3e71063b2ac0
    20bdd231c66097f12333dd017d506d713931c4cd10b9ebbae38806bff5827
    a2412ea317f7c55e8b7b6ef0fd839dac79e1d12ffed4795da4f1d1f
token_request: 006c00340001f40230baa826a1edeeae787766c9812d236873
fcf9ce30b08f1192972303da7c5bcbff03ee0d25b47cd9c3cff9fb0961f328003
400013302d8bcdfb14175bd87b28bbf32623472e08c93c6f82d69b81a2781bbcd
7b6e422c4ffb0a86d8b1919b5b8be7c9fe11fe68
token_response: 0126009102bf2019ee24ef5feabcd5735424599fa8ad7cb94
87d9850246580a233bbc2177c521fc4318d45fccfe52841bd68e58fba00e8f708
b05296bbdf0a5dc65d008186f41de7d00d6deb9420529887e009186e4b79fec49
75f1e0f183594e09c2b842d5ed591dadc9df4bf63099c9e5b97c6a32291d7100c
2e81b5f447d6bcdb87214e6323b3c19f3fc7ff776047ea0679d3b40091029c5fd
501cef18f741a5bfb2e4cd8733d5e5d7f6f89939228fe547623d7b7b25c70a7e5
5efa628328454a1b232571af3524d0ac92ebb4a70ef8e74d5425e93cb14a61992
dcde1f468b7969b03435f04728a67c395af4f8ec7e1bcafd44446dac150f34fb3
00dde71b7188bb05a21138a48f0354442c7e015cb997463f33053f16970464794
2797bdf6eb6e6e635ebb704

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
    nonce: 7db7018671f8f95c81e075a9a3d7278ca82885d716abc9a8955938
    66c1f48aa2
    blind: 7657c94378deb818a74df14e3181419e068c83a52c4a2b2b89ca35
    a945866769706bb66899df32d7421478da636240c2f40925eb09db9b25ff2
    f1c3ccd7ee1341abf1486b14ff99b0184fe9a1648f7a030059ca4f56ac87c
    ff17e00f29f2a617a8c4ca8c038c1c3cf27b569a5f2e6ba44f13e6b3f2513
    7c8061546d197cac97126063ca696ccf1d22ca05cce820521e909062e8b11
    5f74a0e8a24e92701abfa5a4d37cae2a979e380c83dca9c137e49c50aa6d0
    944b2f9487b50b754fa7cf247b8cf5f81b29aabe493dd85a56687634fc1ac
    59bc85d451ef10b4b87d48f2e0ae0f59a0d7791e1a935091052a0ead3cff8
    00a27b9e90342e479357995e147b9ff
    token: 00027db7018671f8f95c81e075a9a3d7278ca82885d716abc9a895
    593866c1f48aa2820fc64e2630a0d5166c36696b663ff34518338263383ec
    92b3347ea30bddae4ca572f8982a9ca248a3056186322d93ca147266121dd
    eb5632c07f1f71cd2708c293db1ec9abfe5da4586bda1da30cf277674859d
    84785bffb6d019ff92298e229e4cbfc55065dbaa2fca02b0aa4f08b72be44
    c217c527f9f459606850b4dacb0ea87f86ed396a2bb32b51c11357b9a877b
    93b441a1ff0a42b91fae6fb7b6116e6a615d7016ece120a25b12e8fbb0983
    0c7dcd6e6d6764ad783997f1742ebcc25640f5f797022e3e15d43cfa90d9e
    7a1b5163aeb454db82e1f4a80d6b37e109cfecb1ae60c20c570ad7c1f6e3b
    9565b85a6fa227762e8eb4e6b66404d1b0dde806ea143f0ce2637eb6d658b
    490c6d6750ea51915193196895825a9e135718f9710798cbcf4f367a473cd
    4fb44e6275a0abb0c9d83bffff3e84e599db6148e4ed
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
    nonce: 6dd2165b8a8bee8d48aa761e2931be58ae1d338c9d52ff52eb9197
    cb49f6606b
    blind: 032de552162a317672dfe3e831f941ec010ac87e060a5dc723d1fc
    451e9203da30990458a4206abb33e50b0411e6b73688e0417ad269db89892
    74e493b9fc035e0cd95c270e9b81b4da63980d3f2d4c5183371ba566e48ff
    28657d495928007bb76db35ac85eccbe4902e901286f14ca303ae7a338b49
    174ec5b660ccd669a5b1be00350c9e537e369924ab9bc6b5463b6459b944c
    61c2391c8a4542853ee11a23630e3a8f4f6667dde467cfde1c3fa208edf60
    44b0e7228e92d254f4fcf046334f5af9abfbba8383bea577e4b0c5eab4f28
    889a2c8e97b64c951be0d120b216a15cadbb11b953ef5c4533a38d1bd5f47
    a364293628033363480db5e891cfd9c
    token: 00026dd2165b8a8bee8d48aa761e2931be58ae1d338c9d52ff52eb
    9197cb49f6606b11e15c91a7c2ad02abd66645802373db1d823bea80f08d4
    52541fb2b62b5898bca572f8982a9ca248a3056186322d93ca147266121dd
    eb5632c07f1f71cd27087771fd38128094b0133acf2a0dac395ed3fed8689
    72ceb804f30841e05dae806c98a345c66de2c2653f7cf44c01f872e00c23d
    6fbb59e80bbc118c8ade3a121e2ae7fa93fe198a3f639f5724dc351e415fe
    bb0ddd31805e3c8424126a48aa6fcd4563a8e253802c0200efaa2171db9a2
    408f7d6d44a19a86276523cc606876f9434e196ec7ec726b6ca01bdbaac1e
    2b919e5e88d22e03c7a3aa6da4f84bd0a04928acdae44b82da545654a464c
    094e523f6765c12aef5a5a2dc5f9ed2ac67804e18c06a13a462cc3f54ece1
    b39ef57b7729a8fd57e0a85dd1f18b9cb1d76bb6d16b5e4f615ce510e53b9
    2020dc666d84952091c1cd2857e876ed5237b1461867
token_request: 020a0103000208654db8b78703764f6981faaa73b2657fceab
a04a81af405a23251d6c8f91804d04e9784e768f2033fe9506e75faf2c388da99
db6ba735e9e540352df8b41407f8975d480f356b28e2fed7a5d55fa9363e9b35d
a55c0f221c5e1aa3a7adbe41849e464e6e70f2131a4b925c32b07d3ad099bf066
79d7ea5bf14304922495826128b383b5ce83d3442730f6c1b5ecff9382a980c6e
9b1d2e2ce8d5ef3982f7b43c731d23c65fb7554d61ca7f9afd9a1e7e00f0b53a8
ce0bad9f30a8cb233bbab5f405add52f082e622be1c11ad79aecb651b609dafa3
3bdb6a3d34269d3addf43d109d4a586f2dd6b1b6bebf7f5b2a2c0f274100ad9b9
20354d7e5cc4931bc086b01030002082a1018de19d37a5d033ae5f00b283cd992
fa03aea5808b845e18b547593e63e41ae998d22d60341b88b152db8dfd18fca87
29af801720ac2d17b58ae18fae5e850646a90241cb9b34529ef91a774e8756d80
de3301730dd3a8ae1a9327698d8647215edcb739f62499d3221d37930c9178944
b3261552e532c340d6bd58eb76e67ebea9c9697f0b928459a81fbf943e0bb0efb
a886cb8f0372a83693a56196febf57c487cc11de841689960f66f1917192baf98
7b4d9a00ffaec5101651e50a7dcf0d763227efa2c4467258fde315908c17fe6a9
17a29c5e4d63f6bf6934af1b3d38cc235d959b45884debf18f782b05ad756270a
f7834bd264b129e3054c4d1
token_response: 02040100449a32a236e581cfe476ced2f816acdaa0c8c1d05
fac03519b78e015274cd5f82def7b36f5090fafd0d665ca64d9b2da2c9dc9f6a9
bf57e7446bb228634f56533fbf86c27a761c07763cf17f70849b62e72ea751922
bd3f0f22df5443380a2b429d18f7e2824b92b59d25258ba37f2a920e079861194
9fe1c88a6caf6df8018734490f6a17a671bb34d756a1c0aff173fc7cab73dc541
d2842ca783bd3a1c757c13ae85535e42fef03ebbd51613f21e67970e68743e7f2
a90861688feea589200afcb9431b30525bf5486e9cf50ee05946cd0c35c0023e2
9a23985f9c45ab4a69da53678adc650767d5854e8ad22057c35484fdcc055897f
612e3b9cd25edcba0100aab9fe22c46fd034ce24f144b46122b60b5e1e5917703
219142cfed77792e496795bae0e8e911b59b7977f91e72a88ded28c37b658cd3a
4c838c13065df64db67cbb4489f924d714a42b2c9d5529da1112dc20828771999
c8e1c8124e8a15a2b6dde4d177d8ad7c93f30bcd0ee9131a97084960443827bde
e952941c797fc247a8d2033a038c794c78d5e74d439bd738132d96a91b9fb4a9e
4e5357fae9b1299daccf3c066b0db290db84b3408b56c3a7d66837d778cc0ff31
7d715cd728863290ef06e0ec3f5b5bb17f4763f056892f5c849eed91a41bf6f07
f2e219626d7b36d1ed88ecc8dd1e84ec2439f549a7c5c2a428574a52c2c05b867
4bdc5a123aaf

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
    nonce: 115134ad5ae5a292972661f98a305f0aefe2d7aa5752fba57bf995
    3ee0cc5961
    blind: 7e8ce87a2ce112af384729c37091a3956552f4e5df655e5231316f
    1c21e796c386f753fd1328807058e60374bd117a96
    token: 0001115134ad5ae5a292972661f98a305f0aefe2d7aa5752fba57b
    f9953ee0cc5961501370b494089dc462802af545e63809581ee6ef57890a1
    2105c28368169514bf260d0792bf7f46c9866a6d37c3032d8714415f87f5f
    6903d7fb071e253be2f4396c9622d0f95897ac5d02fc5ff712a9f8716a764
    590eacbc9dff2e56f4308be8e7426d2ec236e4df02c60a6152788e4
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
    nonce: 3ba1eb43af2d4116646dae46e4c0436ee9a49380efd3b8e8757fca
    1b9a360f45
    blind: 6ce2167f12f2bd523a82b005447311af0798a724dc2ffa2df4aae8
    e7789c39af7603b962e01cd6d11f1d941c641ebb39e505b073c33bf85a893
    d5a944fe36fc45d1d8e5dab137cc255b4aac582081ab723a0f7585b8eb4d4
    686ba930b18dbfb1e4ab69a529d7f00db63a1afbeed6dcd57baf4aa2f7b7d
    ae470deb027ac6e65df47abffa5121affa9029b0b8a6fc55f4ddf2e09f2eb
    646b64adf9c1fe415e4ad5d36df42fc3c98bd234e10da825ee6bfb2bf7e21
    c33d3d2eab2ded97683291b335b2ccfd3992c7d96666d45ff3aedb5f4f9db
    d9bbfd1d0e510fb219530b3702c6aa1acf5744e3a6ba9fd36ba1d211a223b
    01ee648b847b47539e1ba55a1d7c89c
    token: 00023ba1eb43af2d4116646dae46e4c0436ee9a49380efd3b8e875
    7fca1b9a360f45820fc64e2630a0d5166c36696b663ff34518338263383ec
    92b3347ea30bddae4ca572f8982a9ca248a3056186322d93ca147266121dd
    eb5632c07f1f71cd270855ac588a42ad0d0af0a1d275f8da801e73becb4c8
    134c0094db5c93644f3a84a01bfd18489835e26ddf66288ba718cb7484696
    df34e98bc72d79520902e13c31235cc738a13f96e40d010788cdc61f8cbaa
    567217a5ff8eded3128095a2ecd7d3d002fcbec997633a485a41720504845
    422448b35dee12d5fb67b5dbbd0cac385c35c9ad4c777e1ab4416f309e894
    7c404bff7530e2b5363c978ae8cbd34d2f65b77da490e0253b0183515c7ae
    8c3bee13bf2e3a96bb54a4fe7a462f7c0923cbb364f8d593688f220f42750
    31ffd1e8f442d02657f38183f7a441eb32e5dc259a7ce0a0442cfd4a6ac11
    bae63944db713f8e653490fd71122728c2aa43ab3b0f
token_request: 013b00340001f402df5ba933932167043b32be869d7d240838
6df918b1992e48e411cc5b511e43e298b8ff749e0bc6135a8541794f7aa4aa010
30002084e64a726706ce4ba63f24ad1cd5e5042996f90afc06a2dfa9f83edcb50
d8da35833626588602ae48f909bd3abb4d49e1a822bc0d0a6553165a9d514946e
9401419f0a79f2aa51de972a0e4d799259466b05e6d3663a7ae9d7d160868cb2d
4bccdfb1c906a339f54fa08f382c6518f1f2640f6fda609ba66271256801e26ca
06221aa3a4f990c686f64d0c682e2147b3f69e9e5ec85221cdf6cda277329c3a3
5c313c2697f452c7d71b943593410f3f3c6bad2ad071f25d1e9b6e1d1c2f1df60
acc7ed50da9db7a0062b5fe1b640bffafd30819f81ac77a8261decf03d4a99d03
b1fc96c8b595dfda10fe3eff7b6ac2009a48ef943b3485ae99b3dabc9b8e4300
token_response: 019500910387cff9cfdc2fc78268a33b199581413ffde52f7
83784debebee02d1180dff15e66359f0cc5a0d069d00ac3747f9eab7f63194077
1100faa4e0277d07d9565ce61fd1758b58cfcf13fccc2622c97464e1a2cb7fa19
013dd51586b6c86ee1ce4344a28b8411750b8d13f5cdab247b89cbd7510b5ad1a
9d86e44e2168c56e99e78913fe2fa97e395cc5ff88a9ee15b8ac080100332cac4
8ca1e0db5d6c61ff546cba62facb3e016d4f88d45b6e4506f47f4b7d3e669f694
be7ee2ee0d79b4722819988d96e3d9f2396895a9b6db15e3d989edfdade1ef4fa
b25d45a404fc223b2dc8776943cfd198da0b056177c580a5928fabd4782447a63
9cc23666665ada1100dc95ac608a2b9b679a6d665bbeda5b65a3b0ce1a59c6797
c0c405cbfdd18463bb0f91be03d0a4e86cc9a32eeb8e51dd3287e01dfd1ed1181
47e531c87116eb9470f0ce420ff2aac23224bf5103c48911fe987f83f70c29bbe
9b311c20971ced997e794041e414bc550e1a36b929bab628066154122fad7d2e5
ca177cfd9932f8eba108837617d6a7702c9bc2592a69ab39cd

// Test vector 6:
issuance:
  - type: f91a
    skS: 0a95fe52043e9a2eb0faa62315639cab871f6d16c4468a0236bee6b0
    f49efd09
    pkS: 4e63f055daf2049e756207524c80eb96a2fe2a76c4452acae8b64033
    b6ab8f30
    token_challenge: f91a000e6973737565722e6578616d706c65205de58a
    52fcdaef25ca3f65448d04e040fb1924e8264acfccfc6c5ad451d582b3000
    e6f726967696e2e6578616d706c65
    nonces:
      - 7518e35b5fe70c1086168efe90c439ad4c25a4429286a9635a4dd0beb
      9b592c9
      - 53e9250ab25fe2571d87526c88c94ad5f3b408d7569fc01536a61e965
      feb8372
      - 20a34d6db129a0af419cd64aabd02477b15758cbab916d5176fb62ab4
      b525978
    blinds:
      - ea277cab32fbc81486099ddfd4b7087fc328e2bb6a709ce8c212932d9
      a4a9b0e
      - 3ade58a822508a6d8d7e42d748cad77b0bbdf8c64dc2000faf55389b1
      2332404
      - 16f281ac7778be80b39b9358be2182b4593a2884e4b8df1d0affb4be3
      25e0408
    tokens:
      - f91a7518e35b5fe70c1086168efe90c439ad4c25a4429286a9635a4dd
      0beb9b592c920384eda537199609bfc1d9d0daeaa47154f6c90825920a9
      5acb03307fd6b2bd2e3e753ccc0d90b22ceab05279fac73450bf22d996c
      b90b8ad0b7c605a9e6d9da67684555ebfb62c3ed9b69aae1a3827971b2c
      55732794d79c73642e07b13ac05d4610ede11e92dbe18271c07d6ef2263
      9fcf6ff3124f7e827ad7788f9c186d9
      - f91a53e9250ab25fe2571d87526c88c94ad5f3b408d7569fc01536a61
      e965feb837220384eda537199609bfc1d9d0daeaa47154f6c90825920a9
      5acb03307fd6b2bd2e3e753ccc0d90b22ceab05279fac73450bf22d996c
      b90b8ad0b7c605a9e6d9df5ff4a649f8e66a602de7981b9af11c2fa9fb4
      5fa2732cb91fa7c84f86275d5a78490b3da2e946c1df8d42af781d6ec8f
      682d497b8630b5b41a3d6211e8a192a
      - f91a20a34d6db129a0af419cd64aabd02477b15758cbab916d5176fb6
      2ab4b52597820384eda537199609bfc1d9d0daeaa47154f6c90825920a9
      5acb03307fd6b2bd2e3e753ccc0d90b22ceab05279fac73450bf22d996c
      b90b8ad0b7c605a9e6d9dc0ccacc6bdd968e0596147ab7e2991891c42f5
      2e09438b36a19a1c989793dd43afcda5f42c0f8550dc0017dbb8813bc55
      dc51da73b52614f35c7f7e30fe29300
token_request: 00670065f91a9d006016822fabe243f3b3d15f60936697677a
d01440deaadb8896fa33dac82fed180406f5658e90aa8aaa7fc411039676dd05c
b7fa7de014bb5aff0c7e0882285461dae44a5a0a2d84a9faccd5312a36fcd03c5
51dbb16d0136974c3e72f7ccd95e4c
token_response: 00a400a2006004a3e2cb36b534d7272c052ae34673da4da21
f48448c3b6bd6a1737d5112f02e10daa87ceba57da286f796075c23d41d19aa7e
7b49a087c7a36891d39a12dd6392629bc2de75df87768f601a4fc81a00169c885
53128cf65658e9df6f9229476e3307dfb9032df88f1751974fd5432c552b173ba
0f905aade483d2b71a3a94059150ecdec45b4c6ad410dd81b604b448e16cd70fa
af5fbf2450b0d83ba5caf0c

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
    nonce: a34dba020110320a960562c67f32a743d21c841ca2bd6a2c93070b
    cbac1f7ffc
    blind: a0e6de545ed2ae78b404beb85aa9c8a71d54b2defe596beffc1bf6
    096d1f8b67f6c9571592655998eb7c4b54ad89e975
    token: 0001a34dba020110320a960562c67f32a743d21c841ca2bd6a2c93
    070bcbac1f7ffc501370b494089dc462802af545e63809581ee6ef57890a1
    2105c28368169514bf260d0792bf7f46c9866a6d37c3032d8714415f87f5f
    6903d7fb071e253be2f477f2fa276ad1ec24ade1f3decdfdb45ac2b97912e
    3c78fd75f8f94ad7b12b5dabc7ccfa5f18b59c1338952d7f3f67176
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
    nonce: 0db3d829e49997077d1eab6ace4677132372c441faa107e19e7f0f
    e6433a87b3
    blind: c481f0672426bc9892dde794b239090ada1b10c0f0f024f2a89cf9
    d13d2d0eddd0fa29f1af6ee607a2b2acee5488b4a792fef0cbf750f54893e
    bb56bcf173fa924c4583dfabd18428aa976ac287fdd27ba0b3a589d44453c
    877a6115953eac5fc7a9db6dd7125d1ad1e1bd7b79646973d3003cbf3951c
    8c2c4e4e9335cc804da9d4768c37fcb38772f71c0cf909899e0ed73642a66
    6e95959d605682854ffcf658b4f2e08ebea9e55a518ab8aa4ae9a18a1da5d
    340136d6aaa5606d8383b3f5f278ff2f76a817509e62ff40011433ae34a22
    4f9d5d1b2cdd24a730c49b7eaa16a5038c61fe779ce328fe1898faeea8fde
    f675809a49452cc64aa7cd64fc47287
    token: 00020db3d829e49997077d1eab6ace4677132372c441faa107e19e
    7f0fe6433a87b3820fc64e2630a0d5166c36696b663ff34518338263383ec
    92b3347ea30bddae4ca572f8982a9ca248a3056186322d93ca147266121dd
    eb5632c07f1f71cd2708bddb6c57f93e0af60f50c08d5ee2c4c4c66439ab7
    ca1d8dac74701cabfcbc089105a59eebbfbde9b4bac703ed3f2c0f0573dfe
    a655980ecc31f316151413009d13bc9510a40f9c9ebcf054d31cc25bbf65f
    923293451e99e60ec3db082cfbe7d04f05b8d24928f75eed8eda8667f7b37
    ae8ffb7ef85a0b0943a7e478087794da766c480a7b6f25884ce0a38df0ee3
    fa38888cfb85af9cad8eaca8464d23509500ad72ae4ba2ae4b3e9b0ca5300
    564f7d59781c5b5061816d7cce6b28f0a674c9ce54b4f04aeb6dbf005f3b5
    c96b4d28d85f9c4edb627e40c090644f51664a5e182cf1d04c0bff3918c4e
    0151750840c06ee198258cdd3afcb6de03166c8c9cda
  - type: f91a
    skS: 0a95fe52043e9a2eb0faa62315639cab871f6d16c4468a0236bee6b0
    f49efd09
    pkS: 4e63f055daf2049e756207524c80eb96a2fe2a76c4452acae8b64033
    b6ab8f30
    token_challenge: f91a000e6973737565722e6578616d706c65205de58a
    52fcdaef25ca3f65448d04e040fb1924e8264acfccfc6c5ad451d582b3000
    e6f726967696e2e6578616d706c65
    nonces:
      - 11608216c4e5c2f1367d82459552354f684f3b309588842a6c398da6b
      03dedc4
      - 014efed7c9d814b283f633e07cc52f6291de9ef210f006f6e2013f696
      944a953
      - 185889f9cb6704098722d717dd44a6ecf847ac33ae93ff59a88ae7e31
      d23b4af
    blinds:
      - d0c08b34b15f17b6ffa2cf61b07723c055f79d2c4fe98ac35ba65f1c3
      c45bb0e
      - a8d0293e4708f3eec9d01c1a46d2eeafdfd406c2b6341e00138ce3bc8
      30b2509
      - 8c27c6705574f52d112f94d89090cb394ae832da2b8ab71152622a0a2
      6b11707
    tokens:
      - f91a11608216c4e5c2f1367d82459552354f684f3b309588842a6c398
      da6b03dedc420384eda537199609bfc1d9d0daeaa47154f6c90825920a9
      5acb03307fd6b2bd2e3e753ccc0d90b22ceab05279fac73450bf22d996c
      b90b8ad0b7c605a9e6d9dee90d394999fed8d7754553b672a4afee7dfd3
      45c17b50ca437e0ac321d0f1269997b101dddb524ab21a4696ce1eb927e
      d95038844cb3a36005d8c740fa0e343
      - f91a014efed7c9d814b283f633e07cc52f6291de9ef210f006f6e2013
      f696944a95320384eda537199609bfc1d9d0daeaa47154f6c90825920a9
      5acb03307fd6b2bd2e3e753ccc0d90b22ceab05279fac73450bf22d996c
      b90b8ad0b7c605a9e6d9ddd648e00d2772b33d88142992f5481521fc046
      7fd2252481c7a2551485626f1be393699492543c1b6e18d821bdc11dadd
      d300f5159c2585a36a93eef147ffd14
      - f91a185889f9cb6704098722d717dd44a6ecf847ac33ae93ff59a88ae
      7e31d23b4af20384eda537199609bfc1d9d0daeaa47154f6c90825920a9
      5acb03307fd6b2bd2e3e753ccc0d90b22ceab05279fac73450bf22d996c
      b90b8ad0b7c605a9e6d9d8bb454ad55b3193efe7fbc0f2fd367ed2651c7
      f05edd09460e3deb25d7ed7ccefbaab85436f73e8929403e81a182bd1fc
      9ea351b41487b6b76a0cff2b1a40253
token_request: 01a200340001f4032d8210f2c802be3f37abb94384e0bfcab9
cc4430782542c9a6bd77a7765079721022652763d4a59ecc606e507c9a0582010
3000208aa844a230a66a43fd595ca5d4323b28022276b05d25cad425bc6ddcde3
3f39516def8581f734e0abe3e39a32f9fdc3ad5cc2e6c02bbb9d9ca5469cb13f1
b4c90c37dc9b2bd691fe6da9ee8125ce19bc6c020ef416648780cad701d5c6114
dd23e99815eef698c02d5721da356170f729aa032359dead96407ec8ae7ea934c
35748e85882339b57f7c54c30901d1029c9cf85e8c3e8ae1a97b3f0ea49b7d44d
3821a88917383badee2c2e8c9faab2390382c4c86b317c56bce48ff8eea6d3b01
89beae8a6e538b26a53778d2f419845631c7e3059e09ca83d6b55ec971fdd29f6
0622af02a0f8228fd948920ab44065240a5a192a1bb3ce6ebe585f9ece53d8ba0
065f91a9d006014464b4c4b5daefe0ad0dba11daf05f928f79ec8ae304747cfad
357ded8b034d7227fa643e1b4f7dc2e72f70ec4fd8663021984b96df3867ae23e
c5917c5da10a6b6687d5620b3bed5c818379189f1565db2f73598e230c6e7c158
262aa66d26
token_response: 0239009103c4d1602633768d0ec2afbb2931810a7e86e4014
5dd8c59fe22671e58c302cc8feedbdf9acf2fd0bf940c47b68c2218bd7be5d5a3
34eb4033f0717b339cf368e2efae00f360b575bffbf982c9de501727b508ca8ef
ea40c6a11dea8ee1ec2d8bd39ebccd50bf9d9cb82363f6aa5d25d4086be81e61c
6cb19943f10a5303e398d583206a2b8ced4e2a78b89b4baf7e6d8d010048a0c76
77083153fbb192f186aedd6a05d6bb79815d406eb9095bb3488067a6f3bc64e19
6cf02b68129ad9ce000f3b0a30d8d88d7700b90254d957b168c47aa687582bd9b
30564b9b2d8ab5c99112a3c6f84581659af76d98906355cfa1af2880123ab31bf
b8461fcd2303f6f9a8cc6425e46423a23a4a1a1d65e264706a48bace7bbdc7b8a
35f3b1ec023e44d44c39028e6be46050d0cb74e8997bfe45adc6e3cf4f919d8a0
5bacc159f45df6c09908180f7382eb4cd8c11dc7a9eac7b2ee5c286476938ccfa
57475d5d5144b4e0abc0910ed3bb339577eb94bc49a4fc623f30894cf71bd8e01
442ef9d8ce1c4610b878ebde6bd1a81742623f5b3fdb39fcf900a20060a2a7338
43ecf9c5cfd6b519bf7c40b7619de9353aede9096d53dd7ec7c5ae918886d47a8
3952a93d7526c4e845befc15285ceebd6810794497f21d6e417bc31954b243ffe
7f5b07ee7d337fd4f831574f2852da46807bafc71027e683d01945f615cf3af99
0a587793d5c8b0ad7f2c407f8cfeda1f8378c52616de05fc7431062da55e5d3ba
3a12f156d04d59dec5739313462c21ae29108841f304c44862707
~~~
