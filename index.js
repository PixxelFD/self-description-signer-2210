const CONF = './config/'
require('dotenv').config({ path: CONF + '.env' })

const axios = require('axios')
const crypto = require('crypto')
const fs = require('fs').promises
const jose = require('jose')
const { CompactSign, importPKCS8 } = require('jose')
const canonize = require('jsonld').canonize

const SD_PATH = process.argv.slice(2)[0] || CONF

const CURRENT_TIME = new Date().getTime()
const BASE_URL = process.env.BASE_URL || 'https://compliance.gaia-x.eu'
const BASE_URL_REGISTRATION = process.env.BASE_URL_REGISTRATION || 'https://registrationnumber.notary.gaia-x.eu'
const API_VERSION = process.env.API_VERSION

const OUTPUT_DIR = process.argv.slice(2)[1] || './output/'
createOutputFolder(OUTPUT_DIR)

function checkInputFilenames(files) {
  const regex = /.*(?:(?<rn>registrationnumber)|(?<sd>self-description)|(?<tandc>tandc)|(?<so>service-offering)|(?<part>participant))(?!_complianceCredential)(?:.*(?!_complianceCredential))(?:\.json)/gi
  const foundFiles = {
    selfDescription: false,
    registrationNumber: false,
    tandc: false,
    serviceOffering: false,
    participant: false
  }
  files.forEach((file) => {
    while ((m = regex.exec(file)) !== null) {
      // This is necessary to avoid infinite loops with zero-width matches
      if (m.index === regex.lastIndex) {
          regex.lastIndex++;
      }
      // The result can be accessed through the `m`-variable.
      if (m.groups.rn) {
        foundFiles.registrationNumber = m[0]
      } else if (m.groups.sd) {
        foundFiles.selfDescription = m[0]
      } else if (m.groups.tandc) {
        foundFiles.tandc = m[0]
      } else if (m.groups.so) {
        foundFiles.serviceOffering = m[0]
      } else if (m.groups.part) {
        foundFiles.participant = m[0]
      } else {
        throw new Error(`Found match: ${m[0]}, that is not of group rn, sd, tandc, so or part`)
      }
    }
  })
  return foundFiles
}

async function signVerifiableCredential (pemPrivateKey, verifiableCredential, verificationMethod) {
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
  const status = selfDescription.proof ? 'self-signed' : 'unsigned'
  const type = selfDescription.credentialSubject['type'].slice(3)
  const data = JSON.stringify(selfDescription, null, 2)
  const filename = `${OUTPUT_DIR}${CURRENT_TIME}_${type}_${status}.json`

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
    id: process.env.verificationMethod + ':legalRegistrationNumber'
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

function buildVP(VCs, VP){
    if (arguments.length === 1) {
      const VP = {
        "@context": "https://www.w3.org/2018/credentials/v1",
        type: "VerifiablePresentation",
        verifiableCredential: [...VCs]
      }
      return VP
    } else {
      if (!VP.type.includes('VerifiablePresentation')) {
        throw new Error ('The second input has to be a Verifiable Presentation')
      }
      VP.verifiableCredential = [...VP.verifiableCredential, ...VCs] 
      return VP
    } 
}

async function main() {
  //TO-DO:  automatisierte Abfrage der TandC (registry API)
  //        Verkettung von mehreren Service Offerings (Resource und Service Offering (z.B. über depends on)) [id ist wichtig]

  logger(`📝 Loaded ${SD_PATH}`)
  const files = await fs.readdir(SD_PATH)
  const foundFiles = checkInputFilenames(files)

  if (Object.values(foundFiles).every((v) => v === false)) {
    logger(`📝 No files found in the given directory. Creating DID File...`, '\n')
    //DID
    const filenameDid = await createDIDFile()
    logger(`📁 ${filenameDid} saved`, '\n')
  } else if (foundFiles.tandc && foundFiles.selfDescription && foundFiles.registrationNumber) {
    logger(`📝 Found Self-Description, Registration number and Terms and Conditions. Creating Participant VP...`, '\n')
    try {
      const selfDescription = require(SD_PATH + foundFiles.selfDescription)
      const TermsAndConditions = require(SD_PATH + foundFiles.tandc)
      const registrationNumber = require(SD_PATH + foundFiles.registrationNumber)

      //Participant
      const signedSD = await signVerifiableCredential(process.env.PRIVATE_KEY, selfDescription, process.env.VERIFICATION_METHOD ?? 'did:web:compliance.lab.gaia-x.eu')
      
      const filenameSignedSd = await createSignedSdFile(signedSD)
      logger(`📁 ${filenameSignedSd} saved`)
      
      //TandC
      const filledTandC = fillInTandC(TermsAndConditions)

      const signedTandC = await signVerifiableCredential(process.env.PRIVATE_KEY, filledTandC, process.env.VERIFICATION_METHOD ?? 'did:web:compliance.lab.gaia-x.eu')
      
      const filenameTandC = `${OUTPUT_DIR}${CURRENT_TIME}_tandc_self-signed.json`
      await fs.writeFile(filenameTandC, JSON.stringify(signedTandC, null, 2))
      logger(`📁 ${filenameTandC} saved`)

      //RegistrationNumber
      const {filenameRegistrationNumber, RN} = await createRegistrationNumberFile(registrationNumber)
      logger(`📁 ${filenameRegistrationNumber} saved`, '\n')

      // the following code only works if you hosted your created did.json
      logger('🔍 Checking Self Description with the Compliance Service...')
      
      const VP = buildVP([RN, signedSD, signedTandC])
      const complianceCredential = await signSd(VP)
      logger(
        complianceCredential
          ? '🔒 SD signed successfully (compliance service)'
          : '❌ SD signing failed (compliance service)'
      )
      
      if (complianceCredential) {
        const filenameVP = `${OUTPUT_DIR}${CURRENT_TIME}_participantVP_complete.json`
        await fs.writeFile(filenameVP, JSON.stringify(VP, null, 2))
        logger(`📁 ${filenameVP} saved`)

        const filenameComplianceCredential = `${OUTPUT_DIR}${CURRENT_TIME}_participantVP_complianceCredential.json`
        await fs.writeFile(filenameComplianceCredential, JSON.stringify(complianceCredential, null, 2))
        logger(`📁 ${filenameComplianceCredential} saved`)
      } else {
        const filenameVP = `${OUTPUT_DIR}${CURRENT_TIME}_participantVP_self-signed.json`
        await fs.writeFile(filenameVP, JSON.stringify(VP, null, 2))
        logger(`📁 ${filenameVP} saved`)
      }
    } catch (error) {
      console.dir('Something went wrong:')
      console.dir(error?.response?.data, { depth: null, colors: true })
    }
  } else if (foundFiles.participant && foundFiles.serviceOffering) {
    logger(`📝 Found Participant and Service. Creating Service-Offering VP...`)
    try {
      const participant = require(SD_PATH + foundFiles.participant)
      const service = require(SD_PATH + foundFiles.serviceOffering)
      
      const signedService = await signVerifiableCredential(process.env.PRIVATE_KEY, service, process.env.VERIFICATION_METHOD ?? 'did:web:compliance.lab.gaia-x.eu')
      const filenameSignedSd = await createSignedSdFile(serviceOfferingVP)
      logger(`📁 ${filenameSignedSd} saved`)

      // the following code only works if you hosted your created did.json
      logger('🔍 Checking Service Offering with the Compliance Service...')

      const serviceOfferingVP = buildVP(signedService, participant)
      const complianceCredential = await signSd(VP)
      logger(
        complianceCredential
          ? '🔒 SD signed successfully (compliance service)'
          : '❌ SD signing failed (compliance service)'
      )

      if (complianceCredential) {
        const filenameVP = `${OUTPUT_DIR}${CURRENT_TIME}_service-offeringVP_complete.json`
        await fs.writeFile(filenameVP, JSON.stringify(VP, null, 2))
        logger(`📁 ${filenameVP} saved`)

        const filenameComplianceCredential = `${OUTPUT_DIR}${CURRENT_TIME}_service-offeringVP_complianceCredential.json`
        await fs.writeFile(filenameComplianceCredential, JSON.stringify(complianceCredential, null, 2))
        logger(`📁 ${filenameComplianceCredential} saved`)
      } else {
        const filenameVP = `${OUTPUT_DIR}${CURRENT_TIME}_service-offeringVP_self-signed.json`
        await fs.writeFile(filenameVP, JSON.stringify(serviceOfferingVP, null, 2))
        logger(`📁 ${filenameVP} saved`)
      }
    } catch (error) {
      console.dir('Something went wrong:')
      console.dir(error?.response?.data, { depth: null, colors: true })
    }
  } else {
    throw new Error('Not the right combination of files was provided for participant or service-offering')
  }
}

main()
