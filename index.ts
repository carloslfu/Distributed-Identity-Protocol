import * as ed from 'supercop.js'
import * as stringify from 'json-stable-stringify'
import { hash, encryptText, hmac, decryptText } from 'ts-crypto'

// Definitions acording the protocol

export interface Node {
  id: string
  pass: string
  sk: string
  ct: number
  ddt?: number
  pid: string
  nsig: string
  psig?: string
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

export const createNode = (data: any, pass: string, ddt?: number, parentNode?: Node, hashedParentPass?: string): Node => {
  let keys = ed.createKeyPair(ed.createSeed())
  let hashedPass = hash('MD5', pass)
  let pk = keys.publicKey.toString('hex')
  let sk = keys.secretKey.toString('hex')
  let primaryHashedPass = hmac('SHA512', hashedPass, pk)
  let secondaryHashedPass = hmac('SHA256', hashedPass, pk)
  let node: any = {
    id: pk,
    sk: encryptText(sk, secondaryHashedPass),
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
  node.nsig = ed.sign(hex(stringify(node)), keys.publicKey, keys.secretKey).toString('hex')
  if (parentNode) {
    let parentSK = decryptText(parentNode.sk, hmac('SHA256', hashedParentPass, parentNode.id))
    let msg = hex(stringify(node))
    node.pid = parentNode.id
    node.psig = ed.sign(msg, hex(parentNode.id), hex(parentSK)).toString('hex')
  }
  return node
}

export const createTransferable = (node: Node, hashedPass: string, ddt?: number): Transferable => {
  let keys = ed.createKeyPair(ed.createSeed())
  let primaryHashedPass = hmac('SHA512', hashedPass, node.id)
  let secondaryHashedPass = hmac('SHA256', hashedPass, node.id)
  let pk = keys.publicKey.toString('hex')
  let sk = keys.secretKey.toString('hex')
  let psk = decryptText(node.sk, secondaryHashedPass)
  let trans: any = {
    ...node,
    id: node.id,
    pass: primaryHashedPass,
    pk,
    sk: encryptText(sk, secondaryHashedPass),
    pid: node.pid,
    ct: Date.now(),
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
  trans.tsig = ed.sign(hex(stringify(trans)), hex(pk), hex(sk)).toString('hex')
  let nsig = ed.sign(hex(stringify(trans)), hex(node.id), hex(psk)).toString('hex')
  trans.nsig = nsig
  return trans
}

export const auth = (node: Node | Transferable, hashedPass: string): string => {
  if (node.hasOwnProperty('ddt') && (Date.now() > node.ddt)) return ''
  let primaryHashedPass = hmac('SHA512', hashedPass, node.id)
  if (primaryHashedPass !== node.pass) return ''
  let secondaryHashedPass = hmac('SHA256', hashedPass, node.id)
  try {
    let valid = ed.verify(hex(node.nsig), hex(stringify(noSig(node))), hex(node.id))
    if (!valid) return ''
    let psig = (node as any).psig
    if (psig) {
      valid = ed.verify(hex(psig), hex(stringify(noPsig(node))), hex(node.pid))
      if (!valid) return ''
    }
    let sk = decryptText(node.sk, secondaryHashedPass)
    return sk
  } catch (err) {
    return ''
  }
}

export const noSig = obj => objNoKeys(['nsig', 'psig'], obj)
export const noPsig = obj => objNoKeys(['psig'], obj)

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

export const hex = (str: string) => new Buffer(str, 'hex')
