# Distributed Identity Protocol (Work in Progress)

| Authenticate and validate information even without direct connection to an authentication node. AKA Descentralized authentication

Think of it as a secure and flexible authentication mechanism with cache for offline use.

In identity systems most of times we have a central authentication system, this system can be the server in client-server architectures or directly a user in descentralized ones. On those scenarios we can use simetric algorithms, asymetric algorithms or both for achieving authentication and content validation.

But in distributed networks or local networks with unreliable global connection sometimes we need a way for authenticating users offline, so this is the purpose of this protocol.

We provide here both a documentation and a TypeScript implementation of the protocol. I choose a pure TS implementation because my use case is over the Web Platform / Node.js Platform and TS types offer good tooling and detection of a certain kind of bugs.

## General Design

This protocol is channel agnostic and encription algorithm agnostic but our Web implementation has 2 sets of algorithms we can use for 2 use cases.

Actors:

- Nodes: Applications using this protocol.
- Users: People that have credentials on a Node and can be authenticated directly with any Node and then authenticate  via this protocol.

Artifacts:

- Node (N)
  - id: Public key (Identity)
  - pass: Primary hash of the password
  - sk: Secret key (Identity) encrypted with secondary hashed Password
  - ct: Creation timestamp (ms)
  - ddt?: Due Date Timestamp (ms)
  - nsig: Node Signature with PK
  - pid (optional): Parent Node id
  - psig (optional): Parent Node signature
- Transferable Object (T)
  - id: Public key (Identity)
  - pass: Hash of the user password using the primary alg
  - pk: Transferable public key
  - sk: Transferable private key, encrypted with Secret key and secondary hashed Password
  - nid: Node Id
  - ct: Creation timestamp (ms)
  - ddt?: Due Date Timestamp (ms)
  - pid (optional): Parent Node id
  - tsig: Signature with Transferable PK
  - nsig: Signature with Node PK
- Documents (Docs): Document that need authenticacion and validation
- LogChain: A chain of logs that provides validation of a document, object or certain data. Used for validation of author, editions and integrity

Algorithms:

- Signing algorithm: A public key algorithm used for key-pair generation
- Password hash algorithm: Used for hashing user password when introduced by it
- Hash algorithm: Used for hashing Node pass

Scenarios:

- Create Node P
- P create other Node Object called A
- P create a Transferable Pt
- P create a Transferable for A called At
- Pt verify A throught At
- Pt create Node B
- Pt verify B

## TS Implementation

Is made using TypeScript, here are the design choices:

- Signing algorithm: ED25519 using supercop.js
- Password primary hash algorithm: MD5 (recommended) -> SHA512
- Password secondary hash algorithm: SHA256 using built-in nodejs crypto, for browsers can be shimmed using crypto-browserify

Tasks:

- Update Docs
- Test Environment

## Ideas

- Implement authentication delegation, can be implemented with the actual protocol?
