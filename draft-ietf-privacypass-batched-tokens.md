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

This document specifies two Privacy Pass issuance protocols (as
defined in {{!RFC9576=I-D.ietf-privacypass-architecture}}) that allow for batched
issuance of tokens. This allows clients to request more than one token at a time
and for issuers to issue more than one token at a time.

The base Privacy Pass issuance protocol
{{!RFC9578=I-D.ietf-privacypass-protocol}} defines stateless anonymous tokens,
which can either be publicly verifiable or not. While it is possible to run
multiple instances of the issuance protocol in parallel, e.g., over a
multiplexed transport such as HTTP/3 {{?HTTP3=RFC9114}} or by orchestrating multiple
HTTP requests, these ad-hoc solutions vary based on transport protocol support. In
addition, in some cases, they cannot take advantage of cryptographic optimizations.

The first variant of the issuance protocol builds upon the privately verifiable
issuance protocol in {{RFC9578}} that uses VOPRF {{!OPRF=I-D.irtf-cfrg-voprf}},
and allows for batched issuance of tokens. This allows clients to request more
than one token at a time and for issuers to issue more than one token at a
time. In effect, private batched issuance performance scales better than linearly.

The second variant of the issuance protocol introduces a new Client-Issuer communication method,
which allows for batched issuance of arbitrary token types. This allows clients to request more
than one token at a time and for issuers to issue more than one token at a
time. This variant has no other effect than batching requests and responses and the issuance performance remains linear.

This batched issuance protocol registers one new token type ({{iana-token-type}}),
to be used with the PrivateToken HTTP authentication scheme defined in
{{!AUTHSCHEME=I-D.ietf-privacypass-auth-scheme}}.

# Motivation

Privacy Pass tokens (as defined in {{RFC9576}} and
{{!RFC9578=I-D.ietf-privacypass-protocol}}) are unlinkable during issuance and redemption.
The basic issuance protocols defined in {{RFC9578}} however only allow for a single
token to be issued at a time for every challenge. In some cases, especially
where a large number of clients need to fetch a large number of tokens, this may
introduce performance bottlenecks.
Batched token issuance improves
upon the basic Privately Verifiable Token issuance protocol in the following key
ways:

1. Issuing multiple tokens at once in response to a single TokenChallenge,
   thereby reducing the size of the proofs required for multiple tokens.
1. Improving server and client issuance efficiency by amortizing the cost of the
   VOPRF proof generation and verification, respectively.

For all Verifiable Token issuance protocol, it allows for a single TokenRequest
to be sent that encompasses multiple token requests.
This enables the issuance of tokens for more than one key in one round trip between the Client and the Issuer.
The cost remains linear.

# Batched Privately Verifiable Token

This section describes a batched issuance protocol for select token types, including 0x0001 (defined in {{RFC9578}}) and 0xF91A (defined in this document).
This variant is more efficient than Arbitary Batch Token Issuance defined below. It does so by requiring the same key to be used by all token requests.

## Client-to-Issuer Request {#client-to-issuer-request}

Except where specified otherwise, the client follows the same protocol as
described in {{RFC9578, Section 5.1}}.

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
is "application/private-token-privately-verifiable-batch-request". An example request for the Issuer
Request URL "https://issuer.example.net/request" is shown below.

~~~
POST /request HTTP/1.1
Host: issuer.example.net
Accept: application/private-token-privately-verifiable-batch-response
Content-Type: application/private-token-privately-verifiable-batch-request
Content-Length: <Length of BatchTokenRequest>

<Bytes containing the BatchTokenRequest>
~~~

## Issuer-to-Client Response {#issuer-to-client-response}

Except where specified otherwise, the client follows the same protocol as
described in {{RFC9578, Section 5.2}}.

Upon receipt of the request, the Issuer validates the following conditions:

- The BatchTokenRequest contains a supported token_type equal to one of the batched
  token types defined in this document.
- The BatchTokenRequest.truncated_token_key_id corresponds to a key ID of a Public
  Key owned by the issuer.
- Nr, as determined based on the size of BatchTokenRequest.blinded_elements, is
  less than or equal to the number of tokens that the issuer can issue in a
  single batch.

If any of these conditions is not met, the Issuer MUST return an HTTP 422
(Unprocessable Content) error to the client.

The Issuer then tries to deseralize the i-th element of
BatchTokenRequest.blinded_elements using DeserializeElement from {{Section 2.1
of OPRF}}, yielding `blinded_element_i` of type `Element`. If this fails for any
of the BatchTokenRequest.blinded_elements values, the Issuer MUST return an HTTP
422 (Unprocessable Content) error to the client. Otherwise, if the Issuer is
willing to produce a token to the Client, the issuer forms a list of `Element`
values, denoted `blinded_elements`, and computes a blinded response as follows:

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
"application/private-token-privately-verifiable-batch-response".

~~~
HTTP/1.1 200 OK
Content-Type: application/private-token-privately-verifiable-batch-response
Content-Length: <Length of BatchTokenResponse>

<Bytes containing the BatchTokenResponse>
~~~

## Finalization {#finalization}

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
verification works exactly as specified in {{RFC9578}}.

# Arbitrary Batched Token Issuance

This section describes an issuance protocol mechanism for issuing multiple tokens in one round trip between Client and Issuer. An arbitrary batched token request can contain token requests for any token type.

## Client-to-Issuer Request {#arbitrary-client-to-issuer-request}

The Client first creates all TokenRequest it wants to batch. To do so, the client follows
protocol describing issuance, such as {{RFC9578, Section 5.1}} or {{RFC9578, Section 6.1}}.

The Client then creates a BatchedTokenRequest structured as follows:

~~~tls
struct {
   uint16_t token_type;
   select (token_type) {
      case (0x0001): /* Type VOPRF(P-384, SHA-384), RFC 9578 */
         uint8_t truncated_token_key_id;
         uint8_t blinded_msg[Ne];
      case (0x0002): /* Type Blind RSA (2048-bit), RFC 9578 */
         uint8_t truncated_token_key_id;
         uint8_t blinded_msg[Nk];
   }
} TokenRequest;

struct {
  TokenRequest token_requests<0..2^16-1>;
} BatchTokenRequest
~~~

The structure fields are defined as follows:

- "token_type" is a 2-octet integer. TokenRequest MUST be prefixed with a uint16 "token_type" indicating the token type. The rest of the structure follows based on that type, within the inner opaque token_request attribute. The above definition corresponds to TokenRequest from {{RFC9578}}. For TokenRequest not defined in {{RFC9578}}, they MAY be used as long as they are prefixed with a 2-octet token_type.

- "token_requests" are serialized TokenRequests, in network byte order. The number of token_requests, as a 2-octet integer, is prepended to the serialized TokenRequests. In addition, the 2-octet integer length of each TokenRequest is prepended to the serialized TokenRequests.


The Client then generates an HTTP POST request to send to the Issuer Request
URL, with the BatchTokenRequest as the content. The media type for this request
is "application/private-token-arbitrary-batch-request". An example request for the Issuer
Request URL "https://issuer.example.net/request" is shown below.

~~~
POST /request HTTP/1.1
Host: issuer.example.net
Accept: application/private-token-arbitrary-batch-response
Content-Type: application/private-token-arbitrary-batch-request
Content-Length: <Length of BatchTokenRequest>

<Bytes containing the BatchTokenRequest>
~~~

## Issuer-to-Client Response {#arbitrary-issuer-to-client-response}

Upon receipt of the request, the Issuer validates the following conditions:

- The Content-Type is application/private-token-arbitrary-batch-request as registered with IANA.

If this condition is not met, the Issuer MUST return an HTTP 422 (Unprocessable Content) error
to the client.

The Issuer then tries to deserialize the first 2 bytes of the i-th element of
BatchTokenRequest.token_requests. If this is not a token type registered with
IANA, the Issuer MUST return an HTTP 422 (Unprocessable Content) error to the
client. The issuer creates a BatchTokenResponse structured as follows:

~~~tls
struct {
  TokenResponse token_response<0..2^16-1>; /* Defined by token_type */
} OptionalTokenResponse;

struct {
  OptionalTokenResponse token_responses<0..2^16-1>;
} BatchTokenResponse
~~~

BatchTokenResponse.token_responses is a vector of OptionalTokenResponses, length
prefixed with two bytes. OptionalTokenResponse.token_response is a length-prefix-encoded
TokenResponse, where a length of 0 indicates that the Issuer failed or refused to issue the
associated TokenRequest.

The Issuer generates an HTTP response with status code 200 whose content
consists of TokenResponse, with the content type set as
"application/private-token-arbitrary-batch-response".

If the Issuer issues some tokens but not all,
it MUST return an HTTP 206 to the client and continue processing further requests.

~~~
HTTP/1.1 200 OK
Content-Type: application/private-token-arbitrary-batch-response
Content-Length: <Length of BatchTokenResponse>

<Bytes containing the BatchTokenResponse>
~~~



## Finalization {#arbitrary-finalization}

The Client tries to deserialize the i-th element
of BatchTokenResponse.token_responses using the protocol associated to BatchTokenRequest.token_type.
If the element has a size of 0, the Client MUST ignore this token, and continue processing the next token.
The Client finalizes each deserialized TokenResponse using the matching TokenRequest according
to the corresponding finalization procedure defined by the token type.

# Security considerations {#security-considerations}

## Batched Privately Verifiable Tokens

Implementors SHOULD be aware of the security considerations described in {{OPRF,
Section 6.2.3}} and implement mitigation mechanisms. Application can mitigate
this issue by limiting the number of clients and limiting the number of token
requests per client per key.

## Arbitrary Batched Verifiable Tokens

Implementors SHOULD be aware of the inherent linear cost of this token type.
An Issuer MAY ignore TokenRequest if the number of tokens per request past a limit.

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
* Reference: {{RFC9578, Section 5}}
* Notes: None

## Media Types

The following entries should be added to the IANA "media types"
registry:

- "application/private-token-privately-verifiable-batch-request"
- "application/private-token-privately-verifiable-batch-response"
- "application/private-token-arbitrary-batch-request"
- "application/private-token-arbitrary-batch-response"

The templates for these entries are listed below and the
reference should be this RFC.

### "application/private-token-privately-verifiable-batch-request" media type

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

### "application/private-token-privately-verifiable-batch-response" media type

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

### "application/private-token-arbitrary-batch-request" media type

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

### "application/private-token-arbitrary-batch-response" media type

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
