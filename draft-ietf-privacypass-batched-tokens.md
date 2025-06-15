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
    nonce: 332897fa11779e9594b096e5cfc5e43b1405338717bf27b49e9956
    c1f212fcbf
    blind: 6572ac688f2a37a1e6b9ba7a84a6034d9cb82673723e2a2d1413de
    60ea296a7ce0ea351b6dfa6e63a1b390460567f903
    token: 0001332897fa11779e9594b096e5cfc5e43b1405338717bf27b49e
    9956c1f212fcbf501370b494089dc462802af545e63809581ee6ef57890a1
    2105c28368169514bf260d0792bf7f46c9866a6d37c3032d8714415f87f5f
    6903d7fb071e253be2f41077848f52b6bdd765ec802dadae854edff52d167
    7c444fe222146fe425e751c826b4eccf4c4983b840af2f73a07027d
token_request: 340001f4036e7830ee395c3e0f9d63ea6791db427062f77387
2ef64bc4a0935e4c95803558c4743f2b8626fbd655b0e2fac742e217
token_response: 409401000103ea1ec6b484c65905806dd80e159bee70451eb
f99e4e74059da8cb4efc1129292ebaf28a690df8f7f73dc8afe6628c48ead526d
157aeb36848554fa0559afa23378163844098eceed1b30d73a6681a387fed082a
933bd3597bc1f76a0a77ccf7cb65d20dc14499fb4cb97d883f7b6f5e49ef6e016
861fff4a294a620f83d3ce26dd52f6d62cb974d0aa76c23752dc5c24

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
    nonce: 215c56ebf1bce65aff6f99833be25082a9f308f4d39a4cf9b0fd44
    18a9ca1882
    blind: 8e023c5f212462a34c03cc59b7316c2f5901bf56695d6e6f05c3f6
    08ec588da686dfd48d200c6953c75b69cda3e19ff48556c23c32dbebc39f7
    2b5fd8cfd8230af807c0dec3eb86b7bbe490767ef6056aeb828b2316fd4b6
    70d087ddde5ace55f6ef2e78b76bb83a79ed462ae150a923d19772a6c8de4
    7e376626c25732e7a66de5ca92a63f93b4dcd7ecd680bb3fec230951df790
    8c253556af29409dd3c037d5cb16b0861b723d1839090e882463ac10e7cf3
    a78c12e7664c68aec7a33fde219ab7a0068d32265bfc211476a462c034209
    2b08f96804e0b83a3ebe93b516db9ddde3d97344a52f3d90302c2e136a39b
    660f035db44543c15348fd91da04d01
    token: 0002215c56ebf1bce65aff6f99833be25082a9f308f4d39a4cf9b0
    fd4418a9ca1882820fc64e2630a0d5166c36696b663ff34518338263383ec
    92b3347ea30bddae4ca572f8982a9ca248a3056186322d93ca147266121dd
    eb5632c07f1f71cd27082bbead86719e39ee60b224ba39aed396e7b28cfb9
    cbbd8b654887fc04921f76dc92ef72cb47650cd95bebd277162ab0ea03e60
    ddf9cced0d8e076ad065e29a04ef8c69fd880a5cf58db7b3f9153ee5a7382
    685d1b4d1712ee944a92fae4fba32ff4d9288a37f6db1eb29ea7cfc9ea2cc
    b4aa1c729c0b4b95c5a40e66d9b9f8fee7d87ff8e8513b7ac1e934b74d68b
    8551e102fbd1fb0404bc1904ada8684aa0afca6275877b33224cd15ad1b77
    1ba9af7821385017ca34e2eb9644a88c204675cbb1bf3b7cd7cdf9055b3b3
    77057faec7a36e81652e6d0654280c017723e878f0c9d993bace51a51685c
    62ff22f0ea37c244a6478077e914539e65f95372e4cf
token_request: 4103000208a84566ca40ac42d01bc0e0ad10d2d8f9bf45bb30
326ce3a3ad0f2b56589c1e9260679876a1271c83fbb5dfa9433c72a0a6362dbee
06f96f3e3591c3ca8dad240e1c9696fa7a41b79306a868cd1cfe66432129ab209
02be6a8214d11f8863a74b2ece62de4fc75b4968b87216471e6b719cf6c91c99a
bb83bc98fabae802aa09868b1bdae58a73023bdb83c54d6bebfabbef837c9d4ef
88a7a0e742e32a860e05cb798b4d09d8eb1336da49d8d83fb619ae556617246b6
24b5a0fd55f16e27150c96b6b4d645d897d04443bfb5f519eabada7b8b4d9013e
8f6f954356231dfea1e8e7121eb52a5157fe10381689b7f343cd4380e77727ac9
6a126f097b5f79758
token_response: 410301000212093795bb6bde21df488d56d18ac4efc280d6a
493528fb180ff6204ad2c2e6396ad19c348103c7adee2c254bb4ee4f0c0015ac0
70bf41d23a78856880f1b506ba28ca3d370e262216e68ffdc6be57bcb0e03d7c3
e112b63a5695dbbfb220ccdd68a601d829821ffa19b5ddb2da6da3f71e308d702
53f43b7b52d2739f2380ad5150be14db16ef39ca9c475255b0879ddee0f1147e9
230e12e20b5ca7e2069e9ed87db7507f3eb78d9fbf2a957f8410cc80114e9006d
1d6c61d3712b04935d62356b0e7540b10189394eed8206e65631e77e7f75ba076
8bdbace3ffae1bc70ca86303c3e0d3268bf4dbe3225a618926cf3f2f4ca2c80a9
a2f95bf638699792b8

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
    nonce: 79f68dbc610a490d940367f0de8a008c5f429c535dd758afa59965
    d7be6d8753
    blind: 4581461cfd525cd59babb8abbcacafd69c8a6da3fdeffc209be423
    23d2884c09c15beef67287112bec9f674f6e3ef523
    token: 000179f68dbc610a490d940367f0de8a008c5f429c535dd758afa5
    9965d7be6d8753501370b494089dc462802af545e63809581ee6ef57890a1
    2105c28368169514bf260d0792bf7f46c9866a6d37c3032d8714415f87f5f
    6903d7fb071e253be2f4a18606ab08b9d569d144f8944655cda17c6ec74d2
    4a11ebd7622a56d551e223a776fa9650dc2a4a00e083444160e27e5
  - type: 0001
    skS: 39efed331527cc4ddff9722ab5cd35aeafe7c27520b0cfa2eedbdc29
    8dc3b12bc8298afcc46558af1e2eeacc5307d865
    pkS: 038017e005904c6146b37109d6c2a72b95a183aaa9ed951b8d8fb1ed
    9033f68033284d175e7df89849475cd67a86bfbf4e
    token_challenge: 0001000e6973737565722e6578616d706c6500000e6f
    726967696e2e6578616d706c65
    nonce: 5d0d763f6e9da102fdb9e1a7f95a1b096391f02ac87f65888233e9
    415df05c56
    blind: fdef8385c0ea23299a8b52b59b23ffa9f1a0f25c3a4c93d9579237
    2910091cd47ec89b14321b3e00a8d3eb0949e7bbd6
    token: 00015d0d763f6e9da102fdb9e1a7f95a1b096391f02ac87f658882
    33e9415df05c56c994f7d5cdc2fb970b13d4e8eb6e6d8f9dcdaa65851fb09
    1025dfe134bd5a62a116477bc9e1a205cca95d0c92335ca7a3e71063b2ac0
    20bdd231c66097f12333a13b1c96dbe522e6e94e0ecba8c3abad7fac579bd
    dae7233e8f0ad13192b3c895fc7f4229e9156314a71c338ff74baba
token_request: 40680001f403f509ce89b5e1012f47b34af3a33a120556a5f9
771764c33c8bf330076cfd668fc09d0bd7a740f74852d258cbb1a8b49a0001330
27cd2c1b2552ae7bf9282c4eed9aaf03a7e99969ad4af29e615be378f9d944006
2bdf296f39ec999ab9c7a94f62f9df7a
token_response: 41280100010229c3174c22f284bf32ea4f5c2e76b4b969be9
e5d8e163861e77eb673ce0c7af96c2745064749fd59edbe9b4b4e7e80e522d72d
28882d9b60434ab5c7ed142d8da3465291a04dcb1c3ea1a8444dcb09206a4f3ee
92ac498753ec042da0fd72602c679bf7a994f9fbca0fae57740fd47772e237569
fdcfa587874f0e1a538abc3333f8ee486809347eef1e49a83381317201000103b
027ff354e5b1728d6dae0de169816ad92912d96a057e80363b697e253a0a74aad
1513efbeff7356e75c6989863191af7be62c4c0251b441088a2221e96f2273222
33e1b4e3785ddc98bd3f310f69a51e8268478bc080fac60032c63da2332f230e3
f04497959469593e2fac77cd6d58dd3e59081d1279f87ea9cd81c87e38d218093
590d6ec8f8caaf4581a9fece56b

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
    nonce: e7615e63a25a89c13ad49ce0249c8d75ec481dc95e005454563ede
    8c6b0f1f46
    blind: 30465e67d38960c99589a56a8b965191aa709b91fd2a56c101120b
    4453e9a561f2bd041d49ec895684018fa6aba34ab3dd2137777f9e9829a0a
    0d0a678a06e16a3aed47a7e9652ff99fafb5e86a6807f8ddf5b50fcde11b4
    bf7dac7ee5e4f200776eba2c33d6eb187ccb109999e8c9c67595b5464f1ed
    2948b19c04689fe9c29c6863208a2e15b70b0e456ab4f8369569bdb14a903
    bacde57b6ce0bfa21ada35d52c4fea231b40c26254d5130b41f71a21eadff
    dc60e41ab3c072236cb2d1926cb21eb873bb66365a72d619a58cfdfa963d3
    8cdf4cb54db1fc2b42731ba207ad9a897092e8bfc9be2a1f4551da3452a22
    926cc98971da1e2d6287e2c8c013006
    token: 0002e7615e63a25a89c13ad49ce0249c8d75ec481dc95e00545456
    3ede8c6b0f1f46820fc64e2630a0d5166c36696b663ff34518338263383ec
    92b3347ea30bddae4ca572f8982a9ca248a3056186322d93ca147266121dd
    eb5632c07f1f71cd2708baa04e4e9511d5e1b49ad181913b67498a06d54ee
    d0bb7ad9a8caa4a1c46dfabc6dc456b1be1fa49d8a630925cb124b3dcf38e
    4a7fef67bc1cb8b25c4d1f78e341fe7c5f03d7e8ef193602a79d9c11cdb9c
    758e86d6a2ce5d6bbc6ebab3c1ac426202300a752f9adaf8f0ce3ff60fc7a
    ce0d5a2fdcc29f0161495d8953aa7fd6c27c94ca3609b4981cf07f9e2d006
    74b5e7ee0701925b7845a7702d9193178594a659eccebfcd12a505bd28c58
    efdee3dc6b971339dfa24b83f0a24e3197d51218175bf5dcdf7ae6d03a8d2
    74734b40af38680a2bdfd375febd2fb436f00f66c709f89996ad4bd8b28f9
    2b8110036f4df03f3cbf7b8673c37db31f925ea69c15
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
    nonce: d17d88fb4f63d0b3b38d1159bef67ac6d60f649aba512b8e382d49
    7530727577
    blind: 4e192daf9edea831f3c82a274c5648d758f6930991334d820a2a24
    e96101023a86de1d18836222c42dcb0eb39a9153ada0b4eea7d3395d55114
    d8ec972655b47bebb3e66f72f6bfadb5cb976c98907fea985eb13bd5675c9
    c39144381d0b0038c12f6ff9fd598ab8eaef47a878da4fa10d3bd3e4c7e86
    a60ce15e07f5de0501c65d653d20f6dd83763f152ec7beecba6ca51914ddf
    00f79f5143d6854bdefd3032ced824066b8586f6e5d3ecafcb268c99c103c
    d4fab99eeb3afbe550690172ebe09edb533fec7095c357180439c2c32f8af
    85ba77b85cba091f3eae542d01a3de3cdabf57439fe6f41fb2d3c15c23a5b
    c23b3be8fe0140944a76760a7b38301
    token: 0002d17d88fb4f63d0b3b38d1159bef67ac6d60f649aba512b8e38
    2d49753072757711e15c91a7c2ad02abd66645802373db1d823bea80f08d4
    52541fb2b62b5898bca572f8982a9ca248a3056186322d93ca147266121dd
    eb5632c07f1f71cd2708bb7df188c0ed5642312cb5152735825a75d982d17
    a705843b9dc59847cae233b3e69a8500978d1fb360794c4223fcf7483e844
    a1db3e316656456e2d06262e0b051f22e91b4e912cee082b87b40e01a5b70
    734de93f739e6c0abf05a935a8de4bddecb977bd2dbb27f9680ec61068f8d
    c09bcce8f82885a1820275e0a049e566a73b8b8f6050d34866281fb58761c
    7560f0ad32899ad8545d8e633642364155aa6fb397547fb9f1bbfb0bcdfa3
    401750edc31e6f42cb64a931b87032f51cf22d201d8c477135644044b9003
    814117e9313cbd45eb76fcd89f5af4200fdacde27fef511279616748b9ddd
    7fa23e6937047d0ae33ce0572430b9fb793788c1ebbe
token_request: 4206000208bb3699eb03b73b43d87960140ba6e77a9a18ab6a
9492176c420096872a88b15b4bbda37f43bb22ff0e6c730fcda255c4158ce10c8
bb66995a67b2fe1992059cf6d686e1e696e8a6375bb6e77d73570cf30fadf94f4
5f5131550bcf556722c9b62912766b17a828ea69fa3e048d5d46ac70bac8cdd8d
86330c719e734874c00fcf23dd25a1294c9610689e59cbf0805b5d9adef2ffa5a
9e31902bc6b8dafb39b0aad2c520cbc9c1c55696f9e96a5db2b32dbbd2b4f75c7
481499a31ae2df1cc879475bd7ce402ee5dbaf624d87bb7c88f5b243c4094004b
b145f71f6d98da7899ff566398468b99e41ce25f1a88ed49fb4ef26d817d6a152
0ec0aaea6bf0d93360002089cfb2feafef5b7bf534a945daa929e87756bc8a997
2202995b10eebfd476c81fdede8a017513ee84259fcd475330f2379d5d7b578bf
181f9df9246fdf4b594c1d989650cde9e040c3aac7c476c2e6c87d20a3381ae04
55e21e03b6957670219d7af3a295c932ad7735dbfd43b7c464ca82d293d1910b2
5c2d6f293af2f46b30396de4f009e0e2ba05f431802b2d4b5fbd8e17a01b58757
1e06382b5d26895b53327ce2ab9055e0825cf297909f6d3993a516dc9fc69824a
7361deaadc3c7a133c129fd93f11906b4b2f88170c80fc5e6596c3ee550da51c1
b69835f4f127a71f5d44a94d954fa056c6bc4e5ea1f49f4175eebae188a85a2e6
80291fd4f441377
token_response: 420601000206b0e6922469eb5587c12bacfda4ff18a732049
b35fae442431344d136ee8be0c1080b2ad2e0ae379ac39abe3aacdb88b52614ed
9c0c1aa3ae10edd9cdd1f776e67c3aeebcc0656cd4c4b109861904b48e9b902f5
84565125dd97f7ed013b12f5412fbc3378234a904f1621a5b67790f6f677bd6d4
682ab5285a342ed4d4a508360ed9b73907451e6690e88313d4f132034a1f76916
aeceb43051b5f294303bb03de91c9b12022b1493f3b8019219134d214ab09906d
d395e282f255940a411eda4cf0b8ab2121f802b62ce891d84fe3b2c5b32e00fef
88a8756ad015ded4a3dcaf45657597f0677e792c250bdfe809edbb567d526e8cd
9e9c94ad67c0486139010002baa9791c04572ce81c4b02909cafd1dc248a0ea53
b6fa3237b98ddc3fb970bae23733d980846fd7f53a7b90655939678fac4353604
1bfb99dd4891add3bbd7cd05d363e5142b9917ec0c195724c62d7ae6b7e657388
70ad9ccaea0e7415cb268ba21acc141939e4853f9f5e1fab60edad58eee3eabfc
a317a581534f3666aed5420e984dd74c655f32611315e0af4bb1d37165bd20a55
a0c19b1e930516d83d1c2841e382aff16de515cce34cdb1191809e2cc8678b087
539e085942be0e50f6e17d81af48c9bc94ffe4f8a6311a8537c1ed911ad88fb86
1fac00cda3fedfab48fbb073aa05e544acc976ff6368364f5b0c6245e0a7167fb
1af485fc90f73729

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
    nonce: 0d399a51a32286661e8ecd6b601cccace4f45e8f41b05d6fae4782
    6d46142139
    blind: 43dfc280832318de5d86c6626303628b13b62670d8b134ffd008e1
    226df79dccbeaaf3ac555a9f544db50497757a0a2a
    token: 00010d399a51a32286661e8ecd6b601cccace4f45e8f41b05d6fae
    47826d46142139501370b494089dc462802af545e63809581ee6ef57890a1
    2105c28368169514bf260d0792bf7f46c9866a6d37c3032d8714415f87f5f
    6903d7fb071e253be2f429a429ebcef6ada26a201fdbc171f7c2739590085
    581237586e468660f6fdeec5ecd5e39cb3c908d1312a8baf8484450
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
    nonce: 1a89803678132b4328084be9547b3e1ab0b88ebc7b9e84acca4794
    7dbc6b14a7
    blind: 1c761ba8872e29390be3a2c1328b4f9ccc0012be0c2b09bf558ac0
    b334f84d0646ab2f89cca0c65f859a78b32b2407a90eec56f54c55916bdf5
    ad0dbaf5064e5899e18b282e10940f73917771058a0b1c992f679b3ed4f9b
    b8a2d6a6561e85a86e7a78a6d1345bdbf8a02d58ab92bc458852e8c961d90
    a14cae721728fd221737f711ae28b49c4b4eb6b76f8b58541630bf78f6fe3
    51c98da801d246f8b54787046610f136489cc8ca28dad8377983c3fc2e28e
    7ae09365b7516f1cba21b7a0d9ff87608c5cd91fbec89f978053512083bfb
    0adf22c74f0a96256e26c6d9f9436469972580e60a1104c9672b668910924
    17870d82eae4fab3c76caca50eaf5ac
    token: 00021a89803678132b4328084be9547b3e1ab0b88ebc7b9e84acca
    47947dbc6b14a7820fc64e2630a0d5166c36696b663ff34518338263383ec
    92b3347ea30bddae4ca572f8982a9ca248a3056186322d93ca147266121dd
    eb5632c07f1f71cd2708ad0995b4e273a9c7d825c7b2d7293a42f71221692
    5639a276b1a5c358120f6afb5a28c6319647b47ffef79dc39ba0eeb42f4cf
    22bcbbad7d774a5df9904f80c0826f12b8542291c53c20f6c6f05bed4146c
    2b09a2b5e424d4622ba40531b84d026ab202d01940c154ab47c6a9b377f28
    4462bea8a6285383efac6ea8b302e4bcb8855d133396fa2a5532a1dc3f280
    a101770d8f2e5d8142d7c573c9f9e29f160624b7c95811687f678a7994295
    695c14b1899c06f60e6a0fa04cfc6b8184e59f1f40babbf0dbbc3cb91047a
    659723c800b574cadc0491ea40f15e45a0337a3e7cd109de3b4e3517d4637
    059a9ab3c4a218e052d15479116d3c437e4962ce07c3
token_request: 41370001f4021addfdbb3234410241c073cb66734cac677334
930d7741cb973731f19b0e500e80dc6619d11c754b9f8909da8d2c3ca60002084
9309ffde4f288fa5fd2e32c68aad9630adabbd51f273814d7583a27136527e8d7
7fa89c8798e945b833ca9d7ef20233e55de142519891fea24222122feef56c7e3
f7319f012e77e247b2ba1c9ae501196a82f8e3bb3039513c79f77bb0014e1666c
a09113565bb88dd65729e8377dadba084c3adae744b7f0b6e7a66f7715c4677bf
e364cf08f808eef5c607fe716a8509b00b688bb874e90badd7781c9f3e32d9178
070103874ddbb94f7f8d44893ea97c869334f9ec54ad421fdedcbe264d4732da0
b54ad25901895248df6cc75a70e9fc06fa1f7c9bfecabd45eec42e22239eb76f1
765a1a5de3bcf12b5e4d8737ff8b54f911778038fd74fb8b3e4a3e3d
token_response: 419701000103f46a70859a87727ade7ee8534c42b676c28e2
2fa906a669f03172331cc85e1157097214f482a0744fa9d5083a85db2b208e4c0
3bd4c9540fd5f183ec590aaeefafc849ff51c169149b653af450b53b830f587c8
5bdf500074467db6bcd155b6657ad915e4e94d28642173be93a8c6c99a3ee2ee9
ee46686f01d5f9b8208593240cf7db7a9cde0c79ce818720313344470100029e2
15a04d99389aa9ed15f2df507d9fcb88819b989705fcb779d6af8bff5d5c56319
0ba2267c58c49a923cd4d80277eb72d287bb224771bf2dd245018195a8eec6a6e
e454e7f7600fa2f974a2feb8638620702332225288776a8b183bb30f251194df9
55018bdb31cf992b8e37e8dcfee22a2dab536ed0a3c918cb74b0568b100df7ca9
7bb15b6641819d0db806ab9bb67b295a3ecaf1cd07576598166051ddfed98d6d4
30b176081e41432a4607213b1291ef2becaaa337961139bee6a57e0aa8b42d192
bf468f4d187e72f7cedc6393720c34030fa809c62dd9b4ef79aaf7af950a284c9
df77cfcd17f6f5eb022963ffa1d57d4394d24f3204db260dad97ce
~~~
