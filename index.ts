import * as ed from 'supercop.js'
import * as stringify from 'json-stable-stringify'
import { hash, encryptText, hmac, decryptText } from 'ts-crypto'

// Definitions acording the protocol

export interface Node {
  id: string
  pass: string
  sk: string
  d: any
  nsig: string
  psig?: string
}

export interface Transferable {
  id: string
  pass: string
  tpk: string
  tsk: string
  d: any
  ddt: number
  nsig: string
}

export const createNode = (data: any, pass: string, parentNode?: Node, parentPass?: string): Node => {
  let keys = ed.createKeyPair(ed.createSeed())
  let hashedPass = hash('md5', pass)
  let pk = keys.publicKey.toString('hex')
  let sk = keys.secretKey.toString('hex')
  let node: any = {
    id: pk,
    sk: encryptText(sk, hmac('SHA256', hashedPass, pk)),
    pass: hashedPass,
    d: data,
  }
  node.nsig = ed.sign(new Buffer(stringify(node), 'hex'), keys.publicKey, keys.secretKey).toString('hex')
  if (parentNode) {
    let parentSK = decryptText(parentNode.sk, hmac('SHA256', hash('MD5', parentPass), parentNode.id))
    let msg = new Buffer(stringify(node), 'hex')
    node.psig = ed.sign(msg, new Buffer(parentNode.id, 'hex'), new Buffer(parentSK, 'hex')).toString('hex')
  }
  return node
}

export const createTransferable = (node: Node, pass: string, ddt: number): Transferable => {
  let keys = ed.createKeyPair(ed.createSeed())
  let hashedPass = hash('md5', pass)
  let tpk = keys.publicKey.toString('hex')
  let tsk = keys.secretKey.toString('hex')
  let sk = decryptText(node.sk, hmac('SHA256', hashedPass, node.id))
  let trans: any = {
    id: node.id,
    pass: hashedPass,
    tpk,
    tsk: encryptText(tsk, hmac('SHA512', hashedPass, tpk)),
    d: node.d,
    ddt,
  }
  trans.nsig = ed.sign(new Buffer(stringify(trans), 'hex'), new Buffer(node.id, 'hex'), new Buffer(sk, 'hex')).toString('hex')
  return trans
}

export const authNode = (node: Node, pass: string, parentNodeId?: string): string => {
  let hashedPass = hash('md5', pass)
  try {
    if (parentNodeId) {
      return parent
    }
    let sk = decryptText(node.sk, hmac('SHA256', hashedPass, node.id))
    return sk
  } catch (err) {
    console.log(err)
    return ''
  }
}

export const authTrans = (node: Transferable, pass: string, parentNodeId: string): string => {
  try {

    return true
  } catch (err) {
    console.log(err)
    return false
  }
}

