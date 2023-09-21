const CONF = './config/'
require('dotenv').config({ path: CONF + '.env' })

const axios = require('axios')
const crypto = require('crypto')
const fs = require('fs').promises
const jose = require('jose')
const { CompactSign, importPKCS8 } = require('jose')
const canonize = require('jsonld').canonize

const SD_PATH = process.argv.slice(2)[0] || CONF 
const selfDescription = require(SD_PATH + 'self-description.json')
const TermsAndConditions = require(SD_PATH + 'tandc.json')
const registrationNumber = require(SD_PATH + 'registrationnumber.json')
const CURRENT_TIME = new Date().getTime()
const BASE_URL = process.env.BASE_URL || 'https://compliance.gaia-x.eu'
const BASE_URL_REGISTRATION = process.env.BASE_URL_REGISTRATION || 'https://registrationnumber.notary.gaia-x.eu'
const API_VERSION = process.env.API_VERSION

const OUTPUT_DIR = process.argv.slice(2)[1] || './output/'
createOutputFolder(OUTPUT_DIR)


const signVerifiableCredential = async (pemPrivateKey, verifiableCredential, verificationMethod) => {
  // Step 1: Import key from the PEM format
  const rsaPrivateKey = await importPKCS8(pemPrivateKey, 'PS256')
  // Step 2: Compute the hash of the normalized verifiable credential
  const credentialNormalized = await normalize(verifiableCredential)
  const credentialHashed = await hash(credentialNormalized)
  const credentialEncoded = new TextEncoder().encode(credentialHashed)

  // Step 3: Sign
  const credentialJws = await new CompactSign(credentialEncoded).setProtectedHeader({ alg: 'PS256', b64: false, crit: ['b64'] }).sign(rsaPrivateKey)

  // Step 4: Add the signature to the verifiable credential
  return {
    ...verifiableCredential,
    proof: {
      type: 'JsonWebSignature2020',
      created: new Date().toISOString(),
      proofPurpose: 'assertionMethod',
      verificationMethod: verificationMethod,
      jws: credentialJws
    }
  }
}

async function normalize(payload) {
  return await canonize(payload, {
    algorithm: 'URDNA2015',
    format: 'application/n-quads'
  })
}

function hash(payload) {
  return computePayloadHash(payload)
}

async function computePayloadHash(payload) {
  const encoder = new TextEncoder()
  const data = encoder.encode(payload)
  const digestBuffer = await crypto.subtle.digest('SHA-256', data)
  const digestArray = new Uint8Array(digestBuffer)
  return Array.from(digestArray)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}


function getApiVersionedUrl() {
  return `${BASE_URL}${API_VERSION ? '/'+ API_VERSION : ''}/api`
}
function getApiVersionedUrlRN() {
  return `${BASE_URL_REGISTRATION}${API_VERSION ? '/' + API_VERSION : ''}`
}
/*
async function canonize(selfDescription) {
  const URL = `${getApiVersionedUrl()}/normalize`
  const { data } = await axios.post(URL, selfDescription)

  return data
}*/
function fillInTandC(TermsAndConditions) {
  TermsAndConditions.issuanceDate = new Date(CURRENT_TIME).toISOString()
  TermsAndConditions.issuer = process.env.CONTROLLER

  return TermsAndConditions
}


function sha256(input) {
  return crypto.createHash('sha256').update(input).digest('hex')
}

async function sign(hash) {
  const algorithm = 'PS256'
  const rsaPrivateKey = await jose.importPKCS8(
    process.env.PRIVATE_KEY,
    algorithm
  )

  try {
    const jws = await new jose.CompactSign(new TextEncoder().encode(hash))
      .setProtectedHeader({ alg: 'PS256', b64: false, crit: ['b64'] })
      .sign(rsaPrivateKey)

    return jws
  } catch (error) {
    console.error(error)
  }
}

async function createProof(hash) {
  const proof = {
    type: 'JsonWebSignature2020',
    created: new Date(CURRENT_TIME).toISOString(),
    proofPurpose: 'assertionMethod',
    verificationMethod:
      process.env.VERIFICATION_METHOD ?? 'did:web:compliance.lab.gaia-x.eu',
    jws: await sign(hash),
  }

  return proof
}

async function verify(jws) {
  const algorithm = 'PS256'
  const x509 = await jose.importX509(process.env.CERTIFICATE, algorithm)
  const publicKeyJwk = await jose.exportJWK(x509)

  const pubkey = await jose.importJWK(publicKeyJwk, 'PS256')

  try {
    const result = await jose.compactVerify(jws, pubkey)

    return {
      protectedHeader: result.protectedHeader,
      content: new TextDecoder().decode(result.payload),
    }
  } catch (error) {
    return {}
  }
}

async function createSignedSdFile(selfDescription) {
  const status = selfDescription.proof ? 'self-signed' : 'complete'
  const type = selfDescription.credentialSubject['type'].slice(3)
  const data = JSON.stringify(selfDescription, null, 2)
  const filename = `${OUTPUT_DIR}${CURRENT_TIME}_${status}_${type}.json`

  await fs.writeFile(filename, data)

  return filename
}

async function createDIDFile() {
  const algorithm = 'PS256'
  const x509 = await jose.importX509(process.env.CERTIFICATE, algorithm)
  const publicKeyJwk = await jose.exportJWK(x509)
  publicKeyJwk.alg = algorithm
  publicKeyJwk.x5u = process.env.X5U_URL

  const did = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: process.env.VERIFICATION_METHOD,
    verificationMethod: [
      {
        id: process.env.VERIFICATION_METHOD,
        type: 'JsonWebKey2020',
        controller: process.env.CONTROLLER,
        publicKeyJwk,
      },
    ],
    assertionMethod: [process.env.VERIFICATION_METHOD + '#JWK2020-RSA'],
  }

  const data = JSON.stringify(did, null, 2)
  const filename = `${OUTPUT_DIR}${CURRENT_TIME}_did.json`

  await fs.writeFile(filename, data)

  return filename
}

function logger(...msg) {
  console.log(msg.join(' '))
}

//!!only vatID, leiCode and EORI!!
async function createRegistrationNumberFile(registrationNumber) {
  /*const RN = {
    '@context': ["https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/participant"],
    type: 'gx:legalRegistrationNumber',
    id: process.env.verificationMethod + ':legalRegistraionNumber'
  }
  for (const {key, value} of Object.entries(registrationNumber)) {
    RN[`gx:${key}`] = value
  }*/
  const vcid = encodeURI(registrationNumber.id)

  URL = `${getApiVersionedUrlRN()}/registrationNumberVC?vcid=${vcid}`
  const { data } = await axios.post(URL, registrationNumber)
  
  const filename = `${OUTPUT_DIR}${CURRENT_TIME}_registrationNumberVC.json`

  await fs.writeFile(filename, JSON.stringify(data, null, 2))

  return {filenameRegistrationNumber: filename, RN: data}
}

async function signSd(VP) {
  const URL = `${getApiVersionedUrl()}/credential-offers`
  const { data } = await axios.post(URL, VP)

  return data
}

async function createOutputFolder(dir) {
  try {
    await fs.access(dir)
  } catch (e) {
    await fs.mkdir(dir)
  }
}

function buildVP(VC1, VC2, VC3){
    const VP = {
      "@context": "https://www.w3.org/2018/credentials/v1",
      type: "VerifiablePresentation",
      verifiableCredential: [VC1, VC2, VC3]
    }
  return VP 
}

async function main() {
  logger(`📝 Loaded ${SD_PATH}`)

  try {
    //Participant
    const participant = await signVerifiableCredential(process.env.PRIVATE_KEY, selfDescription, process.env.VERIFICATION_METHOD ?? 'did:web:compliance.lab.gaia-x.eu')
    
    const filenameSignedSd = await createSignedSdFile(participant)
    logger(`📁 ${filenameSignedSd} saved`)
    
    //TandC
    const filledTandC = fillInTandC(TermsAndConditions)

    const TandC = await signVerifiableCredential(process.env.PRIVATE_KEY, filledTandC, process.env.VERIFICATION_METHOD ?? 'did:web:compliance.lab.gaia-x.eu')
    
    const filenameTandC = `${OUTPUT_DIR}${CURRENT_TIME}_tandc_self-signed.json`
    await fs.writeFile(filenameTandC, JSON.stringify(TandC, null, 2))
    logger(`📁 ${filenameTandC} saved`, '\n')

    //RegistrationNumber
    const {filenameRegistrationNumber, RN} = await createRegistrationNumberFile(registrationNumber)
    logger(`📁 ${filenameRegistrationNumber} saved`, '\n')

    //DID
    const filenameDid = await createDIDFile()
    logger(`📁 ${filenameDid} saved`, '\n')

    // the following code only works if you hosted your created did.json
    logger('🔍 Checking Self Description with the Compliance Service...')
    
    const VP = buildVP(RN, participant, TandC)
    const complianceCredential = await signSd(VP)
    logger(
      complianceCredential
        ? '🔒 SD signed successfully (compliance service)'
        : '❌ SD signing failed (compliance service)'
    )
    
    if (complianceCredential) {
      const filenameVP = `${OUTPUT_DIR}${CURRENT_TIME}_participant_complete.json`
      await fs.writeFile(filenameVP, JSON.stringify(VP, null, 2))
      logger(`📁 ${filenameVP} saved`)

      const filenameComplianceCredential = `${OUTPUT_DIR}${CURRENT_TIME}_participant_complianceCredential.json`
      await fs.writeFile(filenameComplianceCredential, JSON.stringify(complianceCredential, null, 2))
      logger(`📁 ${filenameComplianceCredential} saved`)
    } else {
      const filenameVP = `${OUTPUT_DIR}${CURRENT_TIME}_participant_self-signed.json`
      logger(`📁 ${filenameVP} saved`)
    }
  } catch (error) {
    console.dir('Something went wrong:')
    console.dir(error?.response?.data, { depth: null, colors: true })
  }
}

main()
