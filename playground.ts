import { createNode, createTransferable, auth, verify } from './index'
import { hash } from 'ts-crypto'

let parentPass = '123'
let childPass = '111'

let parent = createNode({ email: 'parent' }, hash('MD5', parentPass))
let child = createNode({ email: 'child' }, hash('MD5', childPass), undefined, parent, hash('MD5', parentPass))

let ddt = Date.now() + 5000000 // So long life
let tParent = createTransferable(parent, hash('MD5', parentPass), ddt)
let tChild = createTransferable(child, hash('MD5', childPass), ddt)

let res

res = auth(parent, hash('MD5', parentPass))
console.log('Parent secret key', res ? res : 'Failed', parent.email)

res = auth(tParent, hash('MD5', parentPass))
console.log('Parent transferable secret key', res ? res : 'Failed', tParent.email)

res = auth(child, hash('MD5', childPass))
console.log('Child secret key', res ? res : 'Failed', child.email)

res = auth(tChild, hash('MD5', childPass))
console.log('Child transferable secret key', res ? res : 'Failed', tChild.email)

// Verify

res = verify(parent, hash('MD5', parentPass))
console.log('Parent secret key', res ? res : 'Failed', parent.email)

res = verify(tParent, hash('MD5', parentPass))
console.log('Parent transferable secret key', res ? res : 'Failed', tParent.email)

res = verify(child, hash('MD5', childPass))
console.log('Child secret key', res ? res : 'Failed', child.email)

res = verify(tChild, hash('MD5', childPass))
console.log('Child transferable secret key', res ? res : 'Failed', tChild.email)

