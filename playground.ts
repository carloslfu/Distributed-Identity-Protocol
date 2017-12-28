import { createNode, createTransferable } from './index'

let parentPass = '123'
let childPass = '111'

let parent = createNode({ email: 'parent' }, parentPass)
let child = createNode({ email: 'child' }, childPass, parent, parentPass)

let ddt = Date.now() / 1000 + 10000000 // So long life
let tParent = createTransferable(parent, parentPass, ddt)
let tChild = createTransferable(child, childPass, ddt)

let res = authNode(tChild, childPass, tParent)
console.log('tP auth tC?', res)
