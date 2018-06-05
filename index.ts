import * as ed from 'supercop.js'
import * as stringify from 'json-stable-stringify'
import { hash, encryptText, hmac, decryptText } from 'ts-crypto'

// Definitions acording to the protocol

export interface Node {
  /** Public Key */
  id: string
  /** Primary hashed pass, udes for faster authentication denial */
  pass: string
  /** Secret Key encrypted with secondary hashed pass */
  sk: string
  /** Creation Timestamp in milliseconds */
  ct: number
  /** Due Date Timestamp in milliseconds */
  ddt?: number
  /** Node Signature */
  nsig: string
  /** Parent Node id */
  pid?: string
  /** Parent Signature */
  psig?: string
  /** Data props */
  [prop: string]: any
}

export interface Transferable {
  id: string
  pass: string
  pk: string
  sk: string
  ct: number
  ddt?: number
  pid: string
  nsig: string
  [prop: string]: any
}

export const createNode = (data: any, hashedPass: string, ddt?: number, parentNode?: Node, hashedParentPass?: string): Node => {
  let keys = ed.createKeyPair(ed.createSeed())
  let pk = keys.publicKey.toString('base64')
  let sk = keys.secretKey.toString('base64')
  let primaryHashedPass = hmac('SHA512', hashedPass, pk)
  let secondaryHashedPass = hmac('SHA256', hashedPass, pk)
  let node: any = {
    id: pk,
    pass: primaryHashedPass,
    ...data,
    ct: Date.now(),
  }
  if (ddt !== undefined) {
    if (!parentNode || parentNode && !parentNode.hasOwnProperty('ddt')) {
      node.ddt = ddt
    } else if (parentNode && parentNode.hasOwnProperty('ddt')) {
      node.ddt = parentNode.ddt < ddt ? parentNode.ddt : ddt
    }
  } else if (parentNode && parentNode.hasOwnProperty('ddt')) {
    node.ddt = parentNode.ddt
  }
  node.nsig = ed.sign(base64(stringify(node)), base64(keys.publicKey), base64(keys.secretKey)).toString('base64')
  if (parentNode) {
    let parentSK = decryptText(parentNode.sk, hmac('SHA256', hashedParentPass, parentNode.id))
    node.pid = parentNode.id
    node.psig = ed.sign(base64(stringify(node)), base64(parentNode.id), base64(parentSK)).toString('base64')
  }
  node.sk = encryptText(sk, secondaryHashedPass)
  return node
}

export const createTransferable = (node: Node, hashedPass: string, ddt?: number): Transferable => {
  let keys = ed.createKeyPair(ed.createSeed())
  let primaryHashedPass = hmac('SHA512', hashedPass, node.id)
  let secondaryHashedPass = hmac('SHA256', hashedPass, node.id)
  let pk = keys.publicKey.toString('base64')
  let sk = keys.secretKey.toString('base64')
  let psk = decryptText(node.sk, secondaryHashedPass)
  let trans: any = {
    ...node,
    id: node.id,
    pass: primaryHashedPass,
    pk,
    pid: node.pid,
    tct: Date.now(),
  }
  if (ddt !== undefined) {
    if (!node || node && !node.hasOwnProperty('ddt')) {
      trans.ddt = ddt
    } else if (node && node.hasOwnProperty('ddt')) {
      trans.ddt = node.ddt < ddt ? node.ddt : ddt
    }
  } else if (node && node.hasOwnProperty('ddt')) {
    trans.ddt = node.ddt
  }
  trans.tsig = ed.sign(base64(stringify(trans)), base64(pk), base64(sk)).toString('base64')
  let nsig = ed.sign(base64(stringify(trans)), base64(node.id), base64(psk)).toString('base64')
  trans.sk = encryptText(sk, secondaryHashedPass)
  trans.nsig = nsig
  return trans
}

export const auth = (node: Node | Transferable, hashedPass: string): string => {
  if (node.hasOwnProperty('ddt') && (Date.now() > node.ddt)) return ''
  let primaryHashedPass = hmac('SHA512', hashedPass, node.id)
  if (primaryHashedPass !== node.pass) return ''
  let secondaryHashedPass = hmac('SHA256', hashedPass, node.id)
  try {
    let sk = decryptText(node.sk, secondaryHashedPass)
    return sk
  } catch (err) {
    return ''
  }
}

export const verify = (node: Node | Transferable, hashedPass: string): string => {
  if (node.hasOwnProperty('ddt') && (Date.now() > node.ddt)) return ''
  let primaryHashedPass = hmac('SHA512', hashedPass, node.id)
  if (primaryHashedPass !== node.pass) return ''
  let secondaryHashedPass = hmac('SHA256', hashedPass, node.id)
  try {
    let valid = ed.verify(base64(node.nsig), base64(stringify(noSig(node))), base64(node.id))
    if (!valid) return ''
    let psig = (node as any).psig
    if (psig) {
      valid = ed.verify(base64(psig), base64(stringify(noPsig(node))), base64(node.pid))
      if (!valid) return ''
    }
    let sk = decryptText(node.sk, secondaryHashedPass)
    return sk
  } catch (err) {
    return ''
  }
}

export const noSig = obj => objNoKeys(['nsig', 'psig', 'sk'], obj)
export const noPsig = obj => objNoKeys(['psig', 'tsig', 'ddt', 'pk', 'sk', 'tct'], obj)

export const objNoKeys = (keys: string[], obj: any): any => {
  let res = {}
  let key
  for (key in obj) {
    if (keys.indexOf(key) === -1) {
      res[key] = obj[key]
    }
  }
  return res
}

export const base64 = (str: string) => Buffer.from(str, 'base64')
