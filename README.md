# Distributed Identity Protocol

| Authenticate and validate information even without direct connection to the provider

Think of it as a secure and flexible authentication mechanism with cache for offline use.

In identity systems most of times we have a central authentication system, this system can be the server in client-server architectures or directly a user in descentralized ones. On those scenarios we can use simetric algorithms, asymetric algorithms or both for achieving authentication and content validation.

But in distributed networks or local networks with unreliable global connection sometimes we need a way for authenticating users offline, so this is the purpose of this protocol.

We provide here both a documentation and a TypeScript implementation of the protocol. I choose a pure TS implementation because my use case is over the Web Platform and TS types offer good tooling and detection of a certain kind of bugs.

## General Design

This protocol is channel agnostic and encription algorithm agnostic but our Web implementation has 2 sets of algorithms we can use for 2 use cases.

Actors:

- Nodes: Applications using this protocol.
- Users: People that have credentials on a Node and can be authenticated directly with any Node and then authenticate  via this protocol.

Artifacts:

- Id: Unique id
- Endpoint: Information to have direct conection with the actor
- Node Object (PO)
    - Id: unique id
    - Endpoint
    - Data: An object with any kind of data
    - PassHash: Hash of the providers password
    - Private key (Identity) encrypted with PassHash
    - Public key (Identity)
    - LogChain
- Users Vault: This contains and own User Objects
- User Object (UO)
    - Id: unique id
    - Data: An object with any kind of data
    - PassHash: Hash of the providers password
    - Delegate Identity Flag:
        - If true, means the User has its own Identity, is a Node
        - The Private key is encrypted using their own user private key
        - PassHash is copied from the Node
    - Private key (Identity) encrypted with PassHash
    - Public key (Identity)
    - Node Id
    - Node Signature
    - LogChain
- Node Transferable Object (PTO)
    - Id: unique id
    - Endpoint
    - Data: An object with any kind of data
    - Public key (Identity)
    - LogChain
- User Transferable Object (UTO)
    - Id: unique id
    - Data: An object with any kind of data
    - PassHash: Hash of the providers password
    - Public key (Identity)
    - Transferable private key, encrypted with User Private key and PassHash
    - Node Id
    - Node Signature
    - Due Date (timestamp)
    - LogChain
- Documents (Docs): Document that need authenticacion and validation
- LogChain: A chain of logs that provides validation of a document, object or certain data. Used for validation of author, editions and integrity

Scenarios:

- Create a Node
- Registering a user with a Node using a password
- Becoming a Consumer
- Handling auth requests as a Consumer
    - 

## Web Implementation

Is made using TypeScript, here are the design choices:

- H

Tasks:

- Dev Environment
- Test Environment
- Integration Testing Environment
- Implement Artifact Builders:
    - Node Object
    - User Object
    - 
- Authentication mechanism
- Artifacts Validation with LogChain
