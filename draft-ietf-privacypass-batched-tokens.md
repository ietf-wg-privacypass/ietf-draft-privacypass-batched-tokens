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
  - 427b206cf2709cfb267e35c194e2b3d3ed646ef96ba689d3ee1b7cbe82707
  4d4
  - 9df1e3d61d27aa23c99ae3fb314ebc13cd6476e6fcc7eef8e2c5a6dd23967
  ea9
  - d24a301516b8c5aca88b8e8b1e08e3c048eb1f85a73756ce66cf74dcd28b7
  896
blinds:
  - 0558b6ba91e4a2de400abe5d7fecba5be5849d0cec4f72308c09ca026b28f
  50e
  - cb5389c419692f8e88c66a19e1f3623be6a6a26c402a270a7c18726fe6498
  403
  - 39e5b2094cf02bad65191b5abe6b0b62fb577d25ea4922eb92e13363e2abd
  505
token_request: 00052d0060ee54353fcfc4dbb3e830680fb2b603dc3ea8d31e
a2e859c96380140fc4a426547227b7fb52f2edb2276924cc6d9eb6010910d32d7
102fc764a42bd0dc798020764d63f2fb6c586b24442d8f89930755d8521dbe531
f7348a34fd4952c0ddde62
token_response: 0060dc9a867c7ef4686d490f04f59c79fa5999a7135a8a094
1ffc5159cdd4b59f249aaf23a3180c3ddd09054dd7505273d418eb072c7cc76a1
0b4e95022a2678bc48bc9622491b7dec4f8b28ee9308411c96bcd0df170fdcbe2
6836efca9b3709373ea8b6ea228a728399ec3e6303bb446017b85abb496a4cd6c
765def52ef145a0ce73ec3b7299b7f70c2c8f5c7377d07d2ab32ae26ef243eb70
1b0fadcc3b79a04
tokens:
  - 0005427b206cf2709cfb267e35c194e2b3d3ed646ef96ba689d3ee1b7cbe8
  27074d4ead0d1e696ccbef94da0dd33e0e265d97a8015532f429d968fa41fb0
  af0cb385ba9dc18997fcf0439475b67cb5a534250d2d25f9c402f5b4f17d9c2
  d37049f2d9f2f7df232f52366f8988415742bbe63f7cb87ecfa50ace4c9d573
  fc7887acab0d93c4e7dd0b08d4d42bcb45578d04627e5c9aa9d65eae26a5fb0
  06389f63bd2
  - 00059df1e3d61d27aa23c99ae3fb314ebc13cd6476e6fcc7eef8e2c5a6dd2
  3967ea9ead0d1e696ccbef94da0dd33e0e265d97a8015532f429d968fa41fb0
  af0cb385ba9dc18997fcf0439475b67cb5a534250d2d25f9c402f5b4f17d9c2
  d37049f2db08981a9fa2603bce983578c00d61e8d7b0505fb7f09338e6e5cbd
  3032103dd89a89f042ff49600cd51a02ace67a8f2470950e97d60476652c309
  a722ed0a889
  - 0005d24a301516b8c5aca88b8e8b1e08e3c048eb1f85a73756ce66cf74dcd
  28b7896ead0d1e696ccbef94da0dd33e0e265d97a8015532f429d968fa41fb0
  af0cb385ba9dc18997fcf0439475b67cb5a534250d2d25f9c402f5b4f17d9c2
  d37049f2dc2bc48028483dbcf5160a5673dbeb56f8f2a8ce37d1c6ce3fb8027
  340926346c65f6dbdeb4d1d746887a0b8ec453784b1e6e8efc7ae475943ec06
  b19df38c46f

// Test vector 2:
skS:
3435c4a17cec27459c6761248b4768b6a580a1ee2cd58ac31fca4af85a171208
pkS:
f448c01ff45ee2140d7fa97a4c5944df4aa862408e5134bfc468d40072b9537d
token_challenge: 0005000e6973737565722e6578616d706c6500000e6f7269
67696e2e6578616d706c65
nonces:
  - 8ec2ddc4c723a50e3d420d5b585200f17841306049fccc253803b879905a7
  80c
  - dc80113875d8a0bad3e1d3122504b127370b7219f8e8c658195e708e0c844
  e13
  - 3a1690ee0c54cdcaad884c940833a115855fcfb0f46d2702a5d389b01ea19
  fb8
blinds:
  - 09747afbce3f6dcdb73eacff77f99178023b606c732d7556c8eadebc3a7ed
  00e
  - 10a39740159633a3241d083ab70337a389a5da2382cfe3ba189dbb8363be9
  20d
  - a5ca54365274a272ab4e5ff296f903d1b0ba5ed873b17519198ac8eb3912e
  a04
token_request: 00056d006094b6328a36255459a4e10368f1223d08bed1006f
bf1d116dc7ec491e519f8629582107a20724e7ab6499af6271fe8b9ea035c9dfd
39f4f21110720f7aab34b020ca2e6c8ba6b750414914a1f2ab50d345eea80e9f0
850878e72a255d9e62203d
token_response: 00600ec9ce73aebb4b8ecc885ce187c3a95e32bcfa8be94f0
58e44a332924a98215066ef112554236d11658cab97e5149800fd0eedbaac179f
c3ac51b6b69906c73aa281f19ea44e56381cd91457033e66e9cf4342346226625
67a19a16eb4f6866c8d149418b584d7257aae37428b7aee946ac4802b0ef7dd47
a27815a91d24bf03b8f5b744cfaa2b47664919be385cecc93bed397407c7bae2d
5c9101668e6c303
tokens:
  - 00058ec2ddc4c723a50e3d420d5b585200f17841306049fccc253803b8799
  05a780c69b53830c9e88ce2285efc18a8bdc36d2225a41c4afdd0ce1337411f
  9e7ec0ae5560277b39ac96f35076570711615a322cb2f8f3674e64e173873fd
  9f6d6b16d3661f85843376c592dd506996a8e83b1e8391940f780542d66ddbd
  45e4dd5d21ffc170a3059dfedb8bb46d05ba8877e2e2a7f284bd2003c962387
  e54d4c7ece8
  - 0005dc80113875d8a0bad3e1d3122504b127370b7219f8e8c658195e708e0
  c844e1369b53830c9e88ce2285efc18a8bdc36d2225a41c4afdd0ce1337411f
  9e7ec0ae5560277b39ac96f35076570711615a322cb2f8f3674e64e173873fd
  9f6d6b16d198b3b6461740e47d969e4c5d852e4eddce4b3f0c53a0642242eb1
  f5e962db9297541fa110a26c9346395703c10520ad26bb31c67f88b562cd991
  4ba7b356121
  - 00053a1690ee0c54cdcaad884c940833a115855fcfb0f46d2702a5d389b01
  ea19fb869b53830c9e88ce2285efc18a8bdc36d2225a41c4afdd0ce1337411f
  9e7ec0ae5560277b39ac96f35076570711615a322cb2f8f3674e64e173873fd
  9f6d6b16d18faa715a22546cd8b9751a7a70e2ecc14d36cf2587e51ec118367
  5cc82386d0bd73599c11281caa501967b35ec4a05324d9df220aef47258947f
  06109903a20

// Test vector 3:
skS:
d53e857d8c589ee11a175a4d880e498d0433e439a72c6ac7f8222873dfd89e03
pkS:
7255025c90d76238ced53cc4473787ea167a7017ae0c1d63e864d599ae5db452
token_challenge: 0005000e6973737565722e6578616d706c65000017666f6f
2e6578616d706c652c6261722e6578616d706c65
nonces:
  - 9f2b621e702fd4f3e1749ed89e0404b55fab124639bea32a9937a2a8bd421
  819
  - 7aa1e3b1520055cdcb54d4f70b07c600d248a17bc20424c93c836fe51e28b
  4fb
  - e9ab9898b19b970256b5e6447e5a40948f29e3a5472921adf6d805c95e13f
  01d
blinds:
  - b043723a1e69c521b5dd59746716095309282b1894eba5907e1330ba8ea7b
  d0a
  - 04cf9f881ad561219f6ec8d741144d762470f3e52eadc0bf855cac48993d2
  f0f
  - 426cc69b1e3c8561963368815c5080ffac3f69c7136feaa9955938506f4bf
  c02
token_request: 00055c00607a5110b0d2d1c7c2aad52413af8f4dd47ce1eedc
32de657f0669bf4bd4b063528e6df255819ee3c9c0d9cc3e6f8ce48e33e5c28cd
ce951eb853210d505976f1cc22e468fc805c471a346bbcb726d0cd8048d83b531
1831fcb11053fab2643b42
token_response: 00609651f92b2fe4f27df4e4642ed98bf158be677334fdead
095281979a663507a563ccf2855887595c87255328d3c3ddaf55e71bc0214dd2d
6ddb92b669399c0504ecf3086d598a29b9adb33faef9d2cf7c4879b6bb7534b7d
5b23a8d19f73281666dd26583e7e6d4debcb1b845d5271cff0bcbcf939a370479
54b357daffae6d0d36a8fc2e4da3853dc8e4e06df8bdf9a45b3c53ec6c8261c23
99766f326dfcb07
tokens:
  - 00059f2b621e702fd4f3e1749ed89e0404b55fab124639bea32a9937a2a8b
  d4218198a73b15843d93251b73e17d484d3e5467e6db28a74a042d83a311005
  dfdb9c61af60e2f82acdafaa9d3c6b8debb3b1b4385b3357f0cf60441f97901
  91fb9865c555971a4ab3bd1e12b267fbb618207201478fc3c00de2b523f4865
  fa5cea0121839c8b847b9841b1d90efb8b1af3a1a2b02ee8cee75915f257c2e
  eb3032284b0
  - 00057aa1e3b1520055cdcb54d4f70b07c600d248a17bc20424c93c836fe51
  e28b4fb8a73b15843d93251b73e17d484d3e5467e6db28a74a042d83a311005
  dfdb9c61af60e2f82acdafaa9d3c6b8debb3b1b4385b3357f0cf60441f97901
  91fb9865c7e195c34123eb1a0384abc721d853d0da1ff31c80f4e4ca930f47b
  22f889d7506a37ab0cef34d81a38f71a960523cd4b1ea1934a8a4878dfa60a3
  9069821f1c6
  - 0005e9ab9898b19b970256b5e6447e5a40948f29e3a5472921adf6d805c95
  e13f01d8a73b15843d93251b73e17d484d3e5467e6db28a74a042d83a311005
  dfdb9c61af60e2f82acdafaa9d3c6b8debb3b1b4385b3357f0cf60441f97901
  91fb9865c85ea7f0ba0b67262ff85dadb5cdabaa6a6ac528ef78d5e03937a3b
  e09a1e56d792204e4e655fddbef98eb0bd5864d6bf2e47a9f13e5fa5b8ffa68
  3514f12c6d0

// Test vector 4:
skS:
7f52844968e3b9ebeb82f8930bc02af1ae35a91e9d699949a629f351e7b3c00d
pkS:
182d797eaec74157c6911f105fc7d99fb08d567e3da7bfefd50340594c603345
token_challenge: 0005000e6973737565722e6578616d706c65000000
nonces:
  - c48b1cf29aa0ef65431308fe6bb71ec265732c7a3bd9df9429c1e7312ec31
  477
  - 74da0f2926a6a9e5887d1ccb7b1f9855bbc1c8bbe8a6b2a83bec38c4b55c9
  ee2
  - 777b1fbdf0b03a563995944851da65868b489bbe42ae1a649d0331f9fa82e
  fcc
blinds:
  - 6afdcf3b3f8d5ccbb422d6b5c4604b131c6097b9c90a278a922874ff3581b
  905
  - cec1c4b86813e8c26a09cdf282b88b02fe23abfa884df512eec86e75f4a39
  200
  - 830bdb7105b818cd7925ad8bda76d854c53b4f8954fe294b0197cbd61eda2
  c03
token_request: 0005dc0060c6b9e5f0433e6108d44bdf7aa948b87c053212b0
b12a0bde1372ead84abb9f787873dbe77a5a255ac0d8dbbad3eb3b353969e5e13
1ad6dab054d912005062048640fadcee905f7d5e17eb61837becb11db469a8517
f054f3c48f34d06fac4514
token_response: 0060522c75d7487e5eacc6b3ae9b280c3f5c70afc8c070117
26609b5ca252f749f32d4bff1e99e67d5ca33c659a317c34cc2b1122ea29b1b3b
55b87d7dac0120f22a5a49318e1ae6b52e5549c8d4ce9c5195210dfd01e5d5114
018d34f930a67e060b424eaebf2a7a54390890d11c2d25254595b657b9e759da3
349affda98a40709f65edafcf1ecd7dc8989eef4c876274aba8b249fc6112344d
2208cab8d65f909
tokens:
  - 0005c48b1cf29aa0ef65431308fe6bb71ec265732c7a3bd9df9429c1e7312
  ec31477b2174d8c51b010f2f8d73a85a8595138f02c4082a27c5348a4767945
  6d9e350fba3d0d2cdfdcfa32ba7e5a520cfeaf05057cacfc374fd400493067c
  1e85e79dc9f5a40a639c2930756b302d3f22f16fb1a517cb14794bc7b5fac2f
  a47d041d426dde8d49c4ae0b0c49c0bb7e4cddda9af9d951cb2ea3ee2a603bf
  8d4cef5ea13
  - 000574da0f2926a6a9e5887d1ccb7b1f9855bbc1c8bbe8a6b2a83bec38c4b
  55c9ee2b2174d8c51b010f2f8d73a85a8595138f02c4082a27c5348a4767945
  6d9e350fba3d0d2cdfdcfa32ba7e5a520cfeaf05057cacfc374fd400493067c
  1e85e79dc8a4e2fb4745c9f80b83bcbf28ea41d2ea7c41e1cb3df6de005c05a
  c9059086b4c0c59ba20e4060adef057e0f31b381f278083748732dad4f3c343
  d7fa55574df
  - 0005777b1fbdf0b03a563995944851da65868b489bbe42ae1a649d0331f9f
  a82efccb2174d8c51b010f2f8d73a85a8595138f02c4082a27c5348a4767945
  6d9e350fba3d0d2cdfdcfa32ba7e5a520cfeaf05057cacfc374fd400493067c
  1e85e79dc32933f3cbed45cf0bfe7cd0c2125efeb56eb643642ff58e0271202
  b9be7bf8c34cd8e2ca2f462f034bfdc5fe9410251deefe6281848b736940ee8
  e3f95afd38a

// Test vector 5:
skS:
5f6b12eaa6bc82618be24bacad324ddf88bb2ed80ea05e1c09c78ebb33ca2f04
pkS:
0af469e5ebe48eaf5ecc30d2a33e715f15aa18f65c72ba7f729331b1f4fb847e
token_challenge: 0005000e6973737565722e6578616d706c65208278149d30
94c9138347d7a2bcbf1188a262a10b1a5696c41549eabed84c129d0000
nonces:
  - 7fb874a476c983a98b0adb27f848d723c84e56222c9f2a8cb65e15c7cce7e
  9b1
  - 9aab0d4195c8bfa5a84d347a8fa18a0c486190b5aaf44e3bd93444c1c45d3
  62d
  - 5d738aae77d0465a5e3d2fcbdd19d13f6d0f2e7ab85ded67b80bbc275c3af
  4e0
blinds:
  - ae9fcdca73fb4e924e7396b1be8bb77f0380f0cd7ee8e99cad2d47d3ce3a4
  b01
  - 45cf2de7f431cc43d62f77846347a811f187d4ac365caab41b949b1f8547b
  900
  - e7b50d3d95f3212b8ecca3926598a3005fba5f8c6b5aa1ced8cfbf7bdd6ef
  400
token_request: 0005810060eea295b648d7349232a1f4150cd2ff5fdad39fc0
bd5effff0caece8f67415b54fef1e0c8f10580241637f8a778cb072c139a24f80
ba8eb89bbf4bf6206e93405809a630b4ca8d9108fae3c735a97e79d5c6d40c507
2d577abb36d3f516d76c7c
token_response: 0060167792bc653006aff9d1780997811117fcfe6647f0da4
c7dcb3ab390d9009f2bee1096fe5e8d04015ee30ed91d8c78a5fdf49c67c26b8e
7ca939aa1dcc3a1206123c0f97705d2cef7ac31c6eb40683ab44fbcaa792500d7
bafc9386a6fb4316438f785e171cc24b7ad0bd6384b8df851ddaa830d2a9d1383
215994b959dc4c01a6e0ff38777655b9a77ffc6f97598fffeed589c80003ab8dc
ce7aeb16c5b950d
tokens:
  - 00057fb874a476c983a98b0adb27f848d723c84e56222c9f2a8cb65e15c7c
  ce7e9b176ee4d34d93248d8759177310d19ff8690ccc42f86793cdac0698466
  c3c70da43a9b33fc1983a678ae21c1d544a7340ba7a82a180a9b34ae30db22b
  9ef18a98166386be9180154b3c8a1e39703ab4db3c1eeeb7cb74adc9b524c4a
  a56db715a3827439585ce9ed488dff6c435b4da37bdb057aa71a0448786f1f0
  180420b408f
  - 00059aab0d4195c8bfa5a84d347a8fa18a0c486190b5aaf44e3bd93444c1c
  45d362d76ee4d34d93248d8759177310d19ff8690ccc42f86793cdac0698466
  c3c70da43a9b33fc1983a678ae21c1d544a7340ba7a82a180a9b34ae30db22b
  9ef18a98127b4d13eb4e33b35990cf61e317c80c325d943cb5d24859d3d2334
  b06d7d9201f90ad925e330300b511bbd4e2bc61d3392376d164375bef35f46e
  51590e05f72
  - 00055d738aae77d0465a5e3d2fcbdd19d13f6d0f2e7ab85ded67b80bbc275
  c3af4e076ee4d34d93248d8759177310d19ff8690ccc42f86793cdac0698466
  c3c70da43a9b33fc1983a678ae21c1d544a7340ba7a82a180a9b34ae30db22b
  9ef18a981a2b6ad4ec6e21cfcd620fd7da03d69bae684c3eb8012a7b62cd560
  da1f392cb16ee6cc7c715ff398c3abe7a44cc119915a216ba4a9078ed7677e0
  6c10c6c8708
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
    nonce: 3860427ea9a5229d24b91ab85af0d517e96b39fef44bccad4cdd83
    955b411f5b
    blind: 014374fa07c6c4f296d859f380182fe27136430df2b4983dcfef10
    d45a87d8798984a61dd4ec436afe9e65fd2fbbe5ea
    token: 00013860427ea9a5229d24b91ab85af0d517e96b39fef44bccad4c
    dd83955b411f5b501370b494089dc462802af545e63809581ee6ef57890a1
    2105c28368169514bf260d0792bf7f46c9866a6d37c3032d8714415f87f5f
    6903d7fb071e253be2f46f3c12a177d2ad97e0f0dfd01f834589b0ccabeab
    7c7fbab745916b3d04e40f06301b598fd3aa9a10264729f0a8a21d9
token_request: 003600340001f4033b4bd7625f054943a66f4def32f7107d35
ffeb5948805d916160c85ab29d2c165dc9926c322cfa45a0f905e0f74919f2
token_response: 0093009103bbd4cb60566239b2bb87a1865ad6de1b9dff824
80ffe625a0ea88c915fc533a12dc92f93e2610cfcdf6f22528947cac00cde3bec
11ac9ca53e35e7da201beb1fa3fa54a40f007a1cf3382d8e3e34ec6ea846cfaca
8604ccc3d1fd9b9f84d1aa1955cead60968334befc1030dc55799d9176e7ec53e
82dc618cdaf80c12e0ba94d5987f8f5e6450da0b36ff2c69d5323b

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
    nonce: 17cc3ec14c6f8f491774b7e2f514ce66c4af6ddb013c9b31d4e98f
    c55411bb77
    blind: 9f44fd354973bb626a633662d4a1189185333e5f4fdacea6a8aad5
    f56047f3c7fd98d716073887dc3e63c1f64392c6a212665e844a7788a59d7
    d354cb3d09b7894662e5772fac3ff148c2987c241b5717dd11c0b4cb029f6
    8db42715b16f65e6711410e0ece21a24b8d6c0d9def82d86611755f8f6445
    e2e69bfb65dfb3e6705b3db67a63beeea5df96298c10b61e5068b45f7ca1d
    daa65adb2c0f118375701253342ed4a8d888cb9507a15aa40584e5b215ffe
    94664d3e7a8b9e4f65aabea84a05e79379fd259df709f3214eeb1f4778a8b
    15729e69b611a3682932617608f5216c0f13732a634f23183bb7e5a0809f2
    e95a72aa005e4953ec45a21c94314a6
    token: 000217cc3ec14c6f8f491774b7e2f514ce66c4af6ddb013c9b31d4
    e98fc55411bb77820fc64e2630a0d5166c36696b663ff34518338263383ec
    92b3347ea30bddae4ca572f8982a9ca248a3056186322d93ca147266121dd
    eb5632c07f1f71cd27083d8b436e2a2ad23ae61c53d8dfc2f364682ef9d21
    0b48baf5e4bcb3d9c29c9bf72b5ee43e0b38b62b506f8d71c199251f81d1f
    c0f363fda7a6cff6ebbe9169a724e7008a00b7a07b1babe4e7bba7443df9c
    e8638c80677ea303c27b9b18d82d95f6043bbe11b0eec70905f8719b9c821
    a4ff5041c321015b23506b3f46d75e18d9838006523e9740655a2213aaf11
    e9e6cee775002a28328b0bb093a9a7f23e928052fcdbe5afe287c5815b755
    d5ba52a74c52397e2d309d9ee3b79c877851729bdb5e70c09f1bf4a767ad8
    50e6e0eaf7111fbfc92e15caa69dd85b8286e854d3d4c1a6ff02594318bc1
    b366b48b68c7b40326f09d01c35a6ebcc984d419b20e
token_request: 0105010300020897c161d7e058b01ecc1f64a421e6bf023dbb
f671e2a07a87ba3f83ec2cb45b59d54366135db9549793561c396628b3ae24aed
d613525f8b0d0f9965b4f92394fb0e9467ca89656427d72d37bbede68be499bed
559b99999ec3078c06133419715c1e25ea71ac168575b2dad8dab710d50f3cbda
8b241a47c98f07c0173d6945fa003125eee108c409e55e3f76a1d7a0bb6b122e9
b44644e1c963b88b98ad27caa5bce8225efd199fc422a3df7d31498140a57950f
ed36cb1807811c2123be0d866c3d3ba757ff8f6ebb3a28c46fe0e628d2a3ac19c
3b26742012e09f3e2ee14ac12d31c5dc1a16f62599c0f5b5768400edc41c89069
6ac6075f586c82dd4f081
token_response: 010201001be87b4b871ef19584ad06a61a9425c33a42442fc
76bc2ee2c7b9d6b335513355130cbd2ea298880f70330e0c43efc26fe7decd5e4
f598daf760c14ab05e7e97fed2ce20fe83ec2a0f98935396f632f91dc2d8c6eb2
4bd189c0f0c31d61932d068609a64b9fa3d0c9a34c21e57eb4ac910c692e248a5
515674d42a7d3c7d0a5476fefe374d353a63edc064bd4da19fa46ab4168d700af
2e4bc2ba825fc89fd3ff79e457f5314efff3b0b4a1f2d67633da55aade190861a
eca0c298ff909103e398448ad5e550c5c30e9719dc81d8141f22e6c1428d736d7
ab55c614427bde2f03eeb674bbdca8de6b8226f80cdf0d5a7995f4f837d369f9d
10119e96890f607e

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
    nonce: acd556a638886fb8f9c0716e3e2abeb392693749eb8c36b06d568b
    32bbb70593
    blind: 8673af378cc01a2a62318a91defc06bfbfb38fd6f8ccbeefc9a7ce
    82ba9f8ee8155c9fa32115d8cf908e723012bf7293
    token: 0001acd556a638886fb8f9c0716e3e2abeb392693749eb8c36b06d
    568b32bbb70593501370b494089dc462802af545e63809581ee6ef57890a1
    2105c28368169514bf260d0792bf7f46c9866a6d37c3032d8714415f87f5f
    6903d7fb071e253be2f4bff92e9dfd1567cac8583cca8c74d0764bf9deb31
    7660532d483071c2aed84a516ad4ed1c75fa12e8c9df987c27160ed
  - type: 0001
    skS: 39efed331527cc4ddff9722ab5cd35aeafe7c27520b0cfa2eedbdc29
    8dc3b12bc8298afcc46558af1e2eeacc5307d865
    pkS: 038017e005904c6146b37109d6c2a72b95a183aaa9ed951b8d8fb1ed
    9033f68033284d175e7df89849475cd67a86bfbf4e
    token_challenge: 0001000e6973737565722e6578616d706c6500000e6f
    726967696e2e6578616d706c65
    nonce: 8a04df465fd0d5ffd9186949df379f644bb278eb4bddf7fcc255d3
    a99a7f6fa0
    blind: 00bb93fd585c3036681f0046adfa8e7783f52b5e966caaa0725eb1
    11e3759543b9b5825504b7b73d9b209121439d46a5
    token: 00018a04df465fd0d5ffd9186949df379f644bb278eb4bddf7fcc2
    55d3a99a7f6fa0c994f7d5cdc2fb970b13d4e8eb6e6d8f9dcdaa65851fb09
    1025dfe134bd5a62a116477bc9e1a205cca95d0c92335ca7a3e71063b2ac0
    20bdd231c66097f123332935540277fc342cc9b20d350edfeed667eb7d7d6
    f612db69ddc578594683831536e47f8a5f86bd113b909ec7b12093f
token_request: 006c00340001f4030dcca74b0133df903c6b9885d1c99df100
ee951ae68b62f221f197f35156a8cc284c025d2bddf1e899fab46a7a2fa235003
400013302eaca1582552e11432eb8c622452825d135e00fb702daf1bd15e37970
0fdce6c6d96cfbce0ccdd19ac6e56e816715fa78
token_response: 012600910208dec18ea431d49266a956bea98b225c418470e
4b3981c8ad995afd685223ed38fecc295393100adcce97d2f791edf2581c482f5
9ed73790913af9884c4a55b7aa83469d9a5312c3ac29cad549657d2540fb0e5f6
bbfc070a6bdafa371d2a521dffbf3141e198cab5bb5b6b2d7bf296320f3899e60
ac6f568251c9ac86b38a18e9381a092d162b995b485d1774ef23a5009102a6b5e
14e52e9420ed45a99b21ea3796151010f7c3b75f18dd173419c5d35b2393c56df
51774a19b28b4de2af7a6a1884a0caf853d0a1b364ad994381df4120584d9c1f5
adb54f12de5b3996d5306f228d995cceb085a5093cc357fc5f2aea7e116916f0c
45f1a072f8fd06c486f38d203e3fdb84a3dbefa1812a0cc45905229f49676fd08
6f9cebd0780a66aa2396a15

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
    nonce: e0ddf246f2af8a7f29f0c8a862dd18d95d61acfbe05ccced2451d3
    671c3e6504
    blind: 72840ae428ebe0ed1b6f3f52ad583ac9db262e9bbafabaa103a2b5
    197126e344f293b882d92269863b4e60c7d9fe5482f95d31d3cf24d4e0f3b
    822488dec8fe76a60a3eafd5f15e4e2e87ae9953aad7f0578dd837b753443
    9e771ad52868f85bd6620921771d44bdd92c14d19e003a7b7b33db3481a9e
    39c8b6438bbc27ca9e66af33ebd7bdcc38d8c630e32c8da4f8d665814dbf9
    eb008ca7ab4a5676d21551e720c8a0e99b38842f3869c22867b6bad6d6599
    c8b25d08738ec337fec6a71a96fa8b67b741c027901f36ac57903cb52cb4f
    b07ecfb0c5b17887fb62020043f155b79b71ee01b289bdc8addfed7c94108
    e84f1611bd49a7395909361fcebd08a
    token: 0002e0ddf246f2af8a7f29f0c8a862dd18d95d61acfbe05ccced24
    51d3671c3e6504820fc64e2630a0d5166c36696b663ff34518338263383ec
    92b3347ea30bddae4ca572f8982a9ca248a3056186322d93ca147266121dd
    eb5632c07f1f71cd27083ea4ad82e5a850528f1024572e1a5330eaa616ff9
    92675d1280feadf346b7fa70750b09687f1135316969017467dbf40d2baca
    02eab7fd3e731734240acbe6e7229def357e6948673f0a4480a12e2962bd8
    dcfd3ccb466656a3732603371aa9503a62ea06468f80ef79aea9526504df5
    f04c4e4df634a103d77ac9a9306f3febb8a5de89542eb271e5efeeb3ad83a
    c854819a8226062bd3c3b89b070b6de6019cfbfaf50718a32872c5a815d1c
    a2924ccb47a980c0678310790041f07344d11ba0c7c13bf4b878fcf148631
    c445359b6886ec07cd47a6493e3ff3fe77880ae34f0cd14efc705a1ad5bfb
    3082dbc05c5005e95b95f7741c88260bdb34a8c45093
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
    nonce: 0fa3f89c84774bffd00672de7b10eb4a7d39048fec3bfff8a676a6
    435cfc29ae
    blind: 7def998ac0551d34f0d421fe3d67b5b090ddaef79d65f3795e2b3f
    f300a3186842dddab24d525ced84f7e49ad65d24a102c6d27752c315c66d1
    1c52acee0cb20a5f514dec3f55e83533ef77dae5a1744dd3431e33c69dd1e
    f50478c3f37f3ffcccc6ab2740f274ae49f964e67fd751d6e2adbfe1a4670
    b8b6fdca0eb349e996f5a561afcc24956e0b3aee6148a7b0a0581d16f9e89
    269b54669710e495e2452aae0b1730166ebd4b35fcc5ca8697453c8264f25
    0c21b01653216b4abef8525470d908f00a91b013c767268148b9d1fbb7461
    bdb05b32605dbe51a564c6fdeed485201abd7d221513963d0754e0a8ecf11
    33b6e9af5d8876450c2d25e3198e6b0
    token: 00020fa3f89c84774bffd00672de7b10eb4a7d39048fec3bfff8a6
    76a6435cfc29ae11e15c91a7c2ad02abd66645802373db1d823bea80f08d4
    52541fb2b62b5898bca572f8982a9ca248a3056186322d93ca147266121dd
    eb5632c07f1f71cd270896f69b61a4841d49c4b74f04dbd8ff9c5fe419406
    bd7fc850884f13037a9418e2a683a6fe52d3b9e30fca0464b6a736baf7b8c
    43dc60893d25562e04264e0904234e8172ed4811589d4e66394054d3f552a
    5917814c4a8979a2ee4b09655cc731c25e8a47ad14178b430052c60664cc3
    395c6a5e7b122b795dc77a529bf4e5708e8687fa93de015cdffca8e4076bf
    843249ed400844ad0dc2fc9f67bf2959880f7aad4d2bd1e5595e302561906
    2a363e672682140ea2cebf6e6304ef009d7a376cd522872bfe8fb1acabe32
    83b0bb849c36577cf0bce90533a0ede534531a9ccb62b57669d0f1d0ed77a
    3b366165d0af8eaf64431efc3ff2d9772a8e9eecafc4
token_request: 020a01030002082529c3792e4b8b8ac888d0993dfc0f704336
f8cb30d880c397120b2367f93dcba7261ec3527d892a6ba745ec9f2cbc3456150
cab9dce7c1aba87a9d19b0aac85f205c8d60a49905e9c0d6f16553fc592397f20
e99d1a11e678bf32e42b171ad7e4512820631ac02e797d524ec47f2ab537d2ec0
02263d42ed8e4cc4907a9c11f1920859ea7a2b3a6e016bd616308a50cce4aa370
48f3c5f4d812e9b73c5599fe90e7a31ae2b316133440a915f57413ea9045ab005
b1ee57a05e179dc7960167dd4f895a15693774dd5d0678a4d7af05b6133e94925
e3dfb66d565ef935d2177156940dbef831af2015b8a246f11015f2b33232b026e
0d345aa4f1d014a229a6b01030002087915f237d62799ba6ddf5187bcc85dfa1c
368b3f90a3ea556029181c34ae40e5cfadd921629d2240111a1215b48f300ea4f
a7839bfeef97ad5fba52e1f13814c4cd76360d0667057cde44f8857d35162846d
be6378d64aaebfc4e23267e616d5272179c2a5a6b4ae8ce0e37cfeb4db51dc35f
aca6aa4c1fa4d61b84b3c1cc8a92318cb2ee1c73aad968ef3b30b8fd9da3155f9
aad943976339f8630ebfec8e1c823764fd264073a012acb7cd6c848ad56ce3709
b690ff9aacadf6940bb4d18c9cd87ee7fe30dd73ed8ba7d5ec0848ec34af9de29
28275ef971f7e919062020002be3983f61b4ac96fca10815c9b3bc338dfd42d35
0f86b623c5e713ea16cbb6f
token_response: 02040100535862731cbfa734e5acc5c96ba506a623d3b62bf
47799920a72b53069cebaca6f64c8b787c63bb96186516475f9080f0494a7e2df
9736e1ac325d0e18a80dc88ff33f40e31e97b4a680ff15f09a0d7e9ba8956bc2e
ead7692f41eb570257ef8498d10cb7e83a4495a9e9c028e104d0da0732abf3ed7
6576f6f36e0a0cd7ce2d57d780d013d1bce29f705467461a54471cd3711f5e3ac
8c5b88db6cebfd7f38ec10839c2c7debfa1c22970144122c6f45f90e91822c3c4
d030aa858eeaf9cb07dbe3aa4e67e0e267101ab1061a7d28b6182ff58a8a801b3
41b78b932891612f2d90ee538860d7a0ed698ad70715be1e1ad38cf63a13121af
744283e2e197d0500100458ff71df79c33d3ea4e49a9520e5ddb56fbf3c2ed8e6
aca8c45256dfc4a1627392db578d429bb4abfc0ca9c9b9ef857c6c5bffb0824c4
0833f2aad4b0cf418290971ad79adf42c3fd63d26bf5a803e09a8e05e493b9eb2
454fb26bdf52694f3d13b53dfd77eae98b347921be378a2b6850ea523f567aa01
e176d96ccee64c7180835f1ef4fcb6b0eb9234e346cb5cb774164dc90f7df4d15
8cbc0f96d00cb31c7c65e36bd84e298d41d50bd449001ccd8f1c8c1b08fe8a0c3
520e874487c1e23cc04afb8573c73abb5a248e628a99b6bd749ffd8e0614fd5da
7bdc664a121b325361b6acd5a2f0fd831bcf65bdaa4fa6202bf2715bbea72e3bd
b444094c6820

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
    nonce: 58e755b64f662fc6b031776bce354fb92b7108507584ab716af0c8
    4d34e90fc8
    blind: e3e527fb19f4aaccbebfc93064fd5bff4fb494e8f75524aff0f55c
    85e8376f55a6043cc17550b79d5c37355928070f93
    token: 000158e755b64f662fc6b031776bce354fb92b7108507584ab716a
    f0c84d34e90fc8501370b494089dc462802af545e63809581ee6ef57890a1
    2105c28368169514bf260d0792bf7f46c9866a6d37c3032d8714415f87f5f
    6903d7fb071e253be2f4b074e09aa8e45e48266cc1e3dc247834d43e552f5
    fd608ecc38a19ecfe7154a36dfc1ce796d3a6e9f8879126a5f964ae
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
    nonce: 4b238bc80fefb66284c08e8d116f3ea5841913acbd9ba9b01c4f06
    c6cf6d494e
    blind: b7f881324237b51c5ad9f89b0413399e8e48eaea80799366e620c2
    b27014b81f77ce084328e60ae85b7c99256e2aab3845cc04472afa18e7b2a
    a036d3c6d0d55036a4e9729c1f3a1ef66df001d8dcc1ab74fc4ba6cde3ee2
    b7946590697122ce857064184f9d585389ba9214baee6d371d79c8480f014
    9cba5e4e755ede55a919d97a5cb0b15d4042405be37912461dd48123f31c3
    59b0c917d6827fd19b86b7167e45c281e3475fedc33de9decfb51e4e1f164
    87e4337f56b04cf049d85723f14486af6e90f286aa8cf53e15b6b27f1b8a9
    8404039dcd243a10ea492f87f5b95e4942469ca88fee952e4e64fd2e3105c
    2d2c299bc085682a930e2a6a607fe4a
    token: 00024b238bc80fefb66284c08e8d116f3ea5841913acbd9ba9b01c
    4f06c6cf6d494e820fc64e2630a0d5166c36696b663ff34518338263383ec
    92b3347ea30bddae4ca572f8982a9ca248a3056186322d93ca147266121dd
    eb5632c07f1f71cd27088b17ea9ce1cb450846daf1c5c251d0e0c5d73aa4f
    08e247fddd3d20a9fb00b4443e22068af0b94b5aee88e89aba46616b0fa85
    91a65d24eb7608d7c5feb9d29e58c07a127cf46211337e6acfec08ae871ef
    8d244ad2195943975fa0cf1d710ff08de6dd088eef264515ab885f862b5ee
    3cff098b7da54db3a0fdede507609751bc93e932417cc645ccceff9d1d45f
    de884005bbcbad8bf371b516407d6af8f0077feca0bb63a960afe0073e063
    bd70695dd6aa70798ce2dbe7af9ed778d8dc191b98976496b8a021f5601bf
    9fca18945d129a70c91e00666f0742ccd742fbe5c65a233cfee51361b8dcb
    8a338817144ae4c96b9d35cf66b34efbea0f8558c993
token_request: 013b00340001f403cd9bc214019409cde949edb2a426befbb7
dad4abaf961790478828856ec7fc9831845f1bb6a63197d32ca2628ec0853b010
30002081ba291968afd67db0d6fa721f4f84e58c7279909cb7e8afa64ad50e84c
b4aa6eed87ba5295dd61d4113fc1e25859e1b84d4a30a98f144b4da8e5006ea2d
c9bbeb630b543f75db30cf75b2651e953e670d9ba54be427f13fe075f06b55105
5cc5e994c62a4f90ffac63f08e743054c3294c98bfaf06d9493a696c22c594ac3
d6a5de43e2725ca95dc4621d3ee196a1709cf8916a1986ab64cb513c191407f04
4896e65c807cc60cd8d358808a59e597264ea3f18900f532f388467e62248ab71
48cce36b27cb8740752fae29803901f2a60b72d2a7f9c40f8802a4d9591f27c67
1658e99c94758c18eaad361430166e7853e32da828f391d2eedad3bbe5a22dad
token_response: 0195009102e8f31089c7027ef6b2d11aed27c6bfe9db2f425
400fa38e92b35b48d7b09886c58a1fbf2e03ced7a2ced438b7e7e0034f1a26b46
bbb78146661e5949cd6206f0619560006efd8b771ec516618806865c2da0b58ae
21af641798bee315ea6dceba188d8ca81ec8dc50a9316ccececcc0001d33951c0
f46c300368af64763d7224a7431e51bfc35cad88144d68eb6e8eba0100277586f
4e4851d476f84658fe8122694d65753e8e63fa2fda16accc5b59fd17f827ab9a9
9bfdaaba6f0feb6f8ffc083d677466d549ded63bcf335aee8a9e65f5936074a02
802f7f14f3152ad0a4fdf612b6efb1bc3eb676f5d7f764ae2c932dbcb991e5489
2dfd107d3e54447abf4d107d28af4057a47441469758f4f222777f4866e6475a7
38533ae36a7dc925d09a36425a0816b77269a1819627d033b6ae6268aca6f40bc
b232ceeddc45fa2e52e3b1d93163a67e3efa01ad4041c8527fa4357186f629be8
c4b4294a2915257fba42384dbf949eb9a59a30dd28e7c2f2dc6ed6dd756abca18
5c80f460f513a4712ca00d103c541737700aa1105e99268cb9

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
      - 8bf4fd870ffc4ab1ee356d4e8323f2a8304f5b10ea00000dcdf562b77
      717ca63
      - fccde2b0cbcc40c9e2ef744ce23e25fa52f4e908a5add65e1003ca240
      d10a3be
      - 4d32c2ff1435ff41a34ce4215974a32d9ab955c373b49d295913da397
      dee0f52
    blinds:
      - 1aa9553afb8f66a61bfbe18e54077f88640e4ae317796c371f180cd9b
      df9e50e
      - 4b616a43b57735a28fe4bf4dffdebf953441d8fa3a92759fa2b1ed858
      af72a08
      - 6e7da945b5ae8fcd3dbf7c51de8b89d94196027ab2b5a6f0cd1d89b65
      cfbd80a
    tokens:
      - 00058bf4fd870ffc4ab1ee356d4e8323f2a8304f5b10ea00000dcdf56
      2b77717ca639c3b6b7738473a90a1f6193f5a6f11c9d04e2c2bb58f2cea
      5d152b94097a1bcb62acde1e6a9a78c07723df55cc8a2fa3fcce41fff34
      7c96b1cbbeec3602e3b6f31c0de0cf88a333e3982a43822a9845d0c1cd4
      307dd657faeebff01983a0614d57e9db60374814db01bd8bd0e2e73d66a
      ee6e166b3aea5fea98702d238e42fd2
      - 0005fccde2b0cbcc40c9e2ef744ce23e25fa52f4e908a5add65e1003c
      a240d10a3be9c3b6b7738473a90a1f6193f5a6f11c9d04e2c2bb58f2cea
      5d152b94097a1bcb62acde1e6a9a78c07723df55cc8a2fa3fcce41fff34
      7c96b1cbbeec3602e3b6f4ebbd2b2b0e8584ea8a0f7f3424b7adc3febb2
      45ea22fcbc8cfd79f730b71ad219037592b554307ca08581060ed92c7ac
      cbd329b19ac2c0bd683e6343383df68
      - 00054d32c2ff1435ff41a34ce4215974a32d9ab955c373b49d295913d
      a397dee0f529c3b6b7738473a90a1f6193f5a6f11c9d04e2c2bb58f2cea
      5d152b94097a1bcb62acde1e6a9a78c07723df55cc8a2fa3fcce41fff34
      7c96b1cbbeec3602e3b6f86dad1b4ee7aff5084dbc4fd8fe36343221f2d
      c66da1704cc846f09848ed10ed3450c7bb872ee41fad1da0876d6dc50a1
      bde4d9f337cbcbf5e513ae16e15226d
token_request: 0067006500056f0060304162ffea1dcf6308bedef9a379f18f
f49bdeb45c27cf49a15439961f7806281621ad80ea44acaeaa642f5f7f48f104c
65dea7bb8ce8fce51ebef2e1a0a525f108251b031c8d7dc570ef17fa6e8c56de6
6b157d23c2aecd7ca1993d65b98b50
token_response: 00a400a20060028bda67384173bbedbcf1814e6114af0bafe
88b4806485f3ca4f39270d525582c20a45c8f8bee54d4c08655e3318423a2dadc
c76d0228789aa85f4d88ac450a58c58e47e813c3da510c3c9c5563ee85a74f082
2bf0983a01a88fe3efcf4503f70e9d76421865133662dde01637778820fa2d176
cf4342933d8d58b5dfec760015692e453c90777c19583720daddeccc20c151bc0
4386ceae44b897dedfb6d00

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
    nonce: fb903b49f946e404ef2c7a6cd4428957cc61dd20bde2076955a975
    9b5c0cea85
    blind: f3080c6618c6e55338fcd9f91a6188ce373fdf5a3ec2e795e3ad98
    6de8b1bb99ea3972cf009fc0530818958fd56833ae
    token: 0001fb903b49f946e404ef2c7a6cd4428957cc61dd20bde2076955
    a9759b5c0cea85501370b494089dc462802af545e63809581ee6ef57890a1
    2105c28368169514bf260d0792bf7f46c9866a6d37c3032d8714415f87f5f
    6903d7fb071e253be2f4c5091879918dfef87c2cfb5d4a4a5a7c141556da5
    c81ef7172dc59a4a253b5a5d8e462e786b440bb6deda07507255cec
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
    nonce: d700b9e62c32572e1a1a481890aedb9654b88b71bb83803ccf4a9c
    bcfc055bea
    blind: 7c5a8d8b8c0b34f7f1b16d302c6f3c2a8aeedc240ef37994fed14d
    60b6b9396dd80b348f8c6cbbe36a365504390c18ff9cd596d09f0385e5ac6
    91c0d6d2e2c35440689cc4fa7482ebfe3315b034eee104d3f58d9a5c79369
    461ba4263fed1657c27e8393f64b705cbc4e7f9cfddec9fc0f7d4b460eb80
    cc81063c0dda7ddf790343dce21f003bbe1dd04b175b6528420f3c5909b1c
    bd29fbf4a4457dd3643bf1e9996bbd3a1ec9589032aa46f9e1fe492db8ac5
    503b2ee37c347790554a5c0318f78124cca471b147075c08d3d02713e293c
    eceae7bd9f283fab3bbd377db10baacc7656ad13b5fed37154f37a20d7436
    f1df4c7daa22b6e1146ab30ca88beab
    token: 0002d700b9e62c32572e1a1a481890aedb9654b88b71bb83803ccf
    4a9cbcfc055bea820fc64e2630a0d5166c36696b663ff34518338263383ec
    92b3347ea30bddae4ca572f8982a9ca248a3056186322d93ca147266121dd
    eb5632c07f1f71cd27085ecd4c8f23e551432e0ee342b63fc931a586321ca
    26c3096b0ac5dd3d43bd72756fcbdf8aebe6fcd767cadf6268b73d41750ac
    c93100e6cf6abaae7059155cd450abd3d3bc14ff06c18cfa1f1b26a9592a6
    eaac5955758625122749a4a087ad044266db454bc83aa30253aaf9c91a663
    76ec76f4de366785d1948506c66556660c24beb05024fcdd3fe831a688f49
    29fbad3b1e34f8f59e7f30d48576ac824db1b7c8255b71b002209e87326f2
    9c76199f8e29c6aa7e2ada4846b13b5c17361311c07f6822b2ef1f43fd80b
    14d7ee0dc1dc8738df5c8b5109734a67c59306c094c7a323128e1a20711d8
    2d4adbe71a77c9047d27a01037c8d584749dcd34127d
  - type: 0005
    skS: 120806797808de49868e5ea9e4d9fbe245b9b1179e8cc142425c211e
    056bc800
    pkS: 0aa7b85a0bfa010093f1537bc1f065d803ec5763527ef9d41eabf4b6
    2692d279
    token_challenge: 0005000e6973737565722e6578616d706c65205de58a
    52fcdaef25ca3f65448d04e040fb1924e8264acfccfc6c5ad451d582b3000
    e6f726967696e2e6578616d706c65
    nonces:
      - 5849b2d23898261e16bbab7ca1990e6cbec944728124b770404a4a8ad
      e1e10cd
      - eee2bb5b3a172b26ece411f5db90a5f228b75723c10541a8686895248
      cd218ed
      - 35020c847955c6abbf6e102d20933f4968ed703fd363c3f33c562407e
      d40f23c
    blinds:
      - 5f2831fa8de2f4e4d0c91a80be90bf41bb2d8a85385c187bc05cf1c9a
      2b96003
      - 2886d4611cbd5afc724d17bbc2f26939fd7d242efd118996acebe6406
      fa24b08
      - a4c2eecce0ab682002a25a99e998c2a65646b446108f8a28e38981fce
      5b6b108
    tokens:
      - 00055849b2d23898261e16bbab7ca1990e6cbec944728124b770404a4
      a8ade1e10cd9c3b6b7738473a90a1f6193f5a6f11c9d04e2c2bb58f2cea
      5d152b94097a1bcb62acde1e6a9a78c07723df55cc8a2fa3fcce41fff34
      7c96b1cbbeec3602e3b6f75406d4e794944c17a34e312c5895889f6c150
      8e16ff163da80cf1c2ad3e2e498166e22cee67222da248c4c856dddfad4
      6602d471358932abcb45a9f43ddf999
      - 0005eee2bb5b3a172b26ece411f5db90a5f228b75723c10541a868689
      5248cd218ed9c3b6b7738473a90a1f6193f5a6f11c9d04e2c2bb58f2cea
      5d152b94097a1bcb62acde1e6a9a78c07723df55cc8a2fa3fcce41fff34
      7c96b1cbbeec3602e3b6f4668327812ebf889e6fd9fc0a9aafe3ad37287
      cd597e59b287c17ef1fa76eb82827165fb090effd770959816a440c5728
      f9d7dcce1c6b5a5359f85805eeef6d7
      - 000535020c847955c6abbf6e102d20933f4968ed703fd363c3f33c562
      407ed40f23c9c3b6b7738473a90a1f6193f5a6f11c9d04e2c2bb58f2cea
      5d152b94097a1bcb62acde1e6a9a78c07723df55cc8a2fa3fcce41fff34
      7c96b1cbbeec3602e3b6fa0d6c61dc192e76732d584323acf3ea146778e
      00428da644cfb04c3e6d21e2286f8bec0a07334bdec585ca9a45ef8af77
      9a32b0534bc7c2f6b72198850857bd8
token_request: 01a200340001f40304aa1c138fe7d812f7e377aa534d15b41a
6aaacaf53d2f5800d72e1c2a9db14d54e7fe928c31c634cbf692165510e714010
30002088ef2abebd0498d07908081168cd675becd7d7cd9e0f0f7201e4053c02d
43abab4503d183967929b9e58f60220ef1789095280147bff6a30e040ff5c9a9e
bdb22e56cf0a8f1edaf3f94a6f8895c4ea8109e73d42c5b2be8c3349b93aee326
52672b34bdff60c8941d6175c6ed2c1ce8454466a5156aaf2c76896c5f423fda9
489a4c5fe0c0f462db0494b47295034a5db654ec0cecb8204a23065e507678eee
9660233d721e5428972fcf9e562979add2e239f220be262a1511e4e951f3ca7f6
b9ccb90dbd3873d93dea7604228064d0e796a209cc3b6b65f45e03fde9f7f2198
41c15356f3d06e999e52d566b07e04e8483127f4631c6acb32ba5f047a3872f60
06500056f0060e42fce2a4e1b34d65500a5a8dd487177bda51f4823a386948d08
91ba1c163b60b6877e92603efd8ca332972b90e96ddd685981c8e50d1fe3ab673
f78432856640802d29851cd229da16a434a367a5c3cbcd1b74f69c602f2d85d43
fb4587b815
token_response: 0239009102c495d8a1445d030d64dd8c68f3ac0dada2dabcc
2363d538003f98eb61c00c3882bdad4ac52410c08c8bdbe64a5593dfb90bcbc79
c240d7ccbda654604c8c318d074efe4279d23258f4d6bd7417c5bf4777fa72e72
517f59ee6df3d8f51187b5bb037646fe576371042aeab4bee431f7ffac979df0c
f993ddcef23208532fe1699387a77b98b0eec1973eda190ea63f0a0100a7e0f11
0d72129eeeb46bfad07856337006ff33e3a5818b73d37b5fd1765a9586486ac10
f531f3f77fd7ef587bb1672ad962a7743d5dde22f193f5a6ee86efab10c794eec
f078c47570b3807994af1ae761a0c1bd623fdd28553d9a001824d99acb74447de
ec1fc09f3b1b31d5f0ff507f444c2eadb31c7acf15aa4173da73e6c4ec7503467
58ef334cd08e1bb47a741ebac630ec2f82a9eadf4a471130d6e3d225297a4d59f
05db7bad93edfbd7f03dc7bbf55ca09f4182afe9cbee1165e7d9d6b4c3c7bc8bc
6169dd725b4f64527a32189badfc0f62022cefc88f250abc1b55f89cd01b6d718
174f086cc623c93515ccc26f92db882b2f1f4ce05dd73bb85400a20060aeef375
161b839fc9061db52046303e1958c637d85dfe4d109de123d9c6ee12c68505468
5fefc70c61ff55e698211d7ee57244f3fe0e6fec183a073ba65296253ac7848b7
870c55b3abbd82826a217a31da0bb83041a4f446a70fdb0a4a983570adc2b65f7
21c22147ce6df026528d9760507187f72c115a506ac910374fca0668904dbf3a7
a3f82f55b953f45d60607bd5729d4561ac2b1a082334e26d3d000
~~~
