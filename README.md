<h1 align="center"> Self-Description-Signer</h1>

- [How To Use](#how-to-use)
  - [Scenarios](#scenarios)
    - [DID](#did)
    - [Participant Self-Description](#participant-self-description)
    - [Service Offering](#service-offering)
- [How it Works](#how-it-works)
- [Environment variables for self-issued certificates (This is for test-setups only)](#environment-variables-for-self-issued-certificates-this-is-for-test-setups-only)

## How To Use

1. Create a new `.env` file in the `/config` directory with `PRIVATE_KEY`, `CERTIFICATE`, `CONTROLLER`, `VERIFICATION_METHOD` and `X5U_URL` as properties. Feel free to use the example file `example.env` located in the `/config` directory. You could quickly copy the file with the following command:

   ```sh
   cp config/example.env config/.env
   ```

   Make sure to provide your own values for the above mentioned properties in the newly created `.env` file.

   **IMPORTANT:** You need to create your own `CERTIFICATE` and `PRIVATE_KEY` and put it into the created `/config/.env` file. This certificate needs to be issued by a Gaia-X endorsed trust anchor. You can find the list of endorsed trust anchors here: https://gaia-x.gitlab.io/policy-rules-committee/trust-framework/trust_anchors/

   **NOTE:** It is not sufficient to simply create create a new local key pair which is not issued by a trust anchor because verification will fail and the trust servcie won't sign your Self Description!

   > You can find more information on setting up your own certificate here:
   >
   > - https://gitlab.com/gaia-x/lab/compliance/gx-compliance#how-to-setup-certificates

   `X5U_URL` - You need to generate a `.pem` file with the certificate chain of your certificate and upload it to your server (make it accessible via URI). You can find an example here: https://www.delta-dao.com/.well-known/x509CertificateChain.pem

   You can use [whatsmychaincert.com](https://whatsmychaincert.com/) as a helper tool to generate your certificate chain using metadata from your certificate. Make sure to check "Include Root Certificate" checkbox.

   `VERIFICATION_METHOD` - The `did:web` has to resolve to the path of your `did.json`. It defaults to `your-domain.com/.well-known/did.json` if you enter `did:web:your-domain.com`. You can also specify a specific path, check the `did:web` [specifications](https://w3c-ccg.github.io/did-method-web/#optional-path-considerations) for this.

   > More info on x5u: https://www.rfc-editor.org/rfc/rfc7517#section-4.6

2. Update/copy the self-description-examples in the config folder for self description in `self-description.json`, the registration number in `registrationnumber.json`, the Gaia-X Terms and Conditions in `tandc.json` and/or the service-offerings in `service-offering_resource.json`/`service-offering_service.json` into the config folder depending on the intended signing [Scenario](#scenarios). See details in the [Architecture Document](https://gaia-x.gitlab.io/policy-rules-committee/trust-framework/participant/)

3. Install dependencies `npm i` and execute the script `node index.js` (node@16 or higher required).
   - Alternatively, the script can be run with docker
     1. Build the container with `docker build -t self-description-signer .`
     2. Run the script with `docker run -it --mount src="$(pwd)/config",target=/usr/src/app/config,type=bind self-description-signer`

### Scenarios
The signer executes different operations depending on the existing files in the defined `src`-Folder.

#### DID
If no compatible JSON-Files are given, a `did.json` will be created based on the provided `CERTIFICATE` and `VERIFICATION_METHOD`

   **Example `did.json`:**

   ```json
   {
     "@context": ["https://www.w3.org/ns/did/v1"],
     "id": "did:web:compliance.gaia-x.eu",
     "verificationMethod": [
       {
         "@context": "https://w3c-ccg.github.io/lds-jws2020/contexts/v1/",
         "id": "did:web:compliance.gaia-x.eu",
         "type": "JsonWebKey2020",
         "controller": "did:web:compliance.gaia-x.eu#JWK2020-RSA",
         "publicKeyJwk": {
           "kty": "RSA",
           "n": "ulmXEa0nehbR338h6QaWLjMqfXE7mKA9PXoC_6_8d26xKQuBKAXa5k0uHhzQfNlAlxO-IpCDgf9cVzxIP-tkkefsjrXc8uvkdKNK6TY9kUxgUnOviiOLpHe88FB5dMTH6KUUGkjiPfq3P0F9fXHDEoQkGSpWui7eD897qSEdXFre_086ns3I8hSVCxoxlW9guXa_sRISIawCKT4UA3ZUKYyjtu0xRy7mRxNFh2wH0iSTQfqf4DWUUThX3S-jeRCRxqOGQdQlZoHym2pynJ1IYiiIOMO9L2IQrQl35kx94LGHiF8r8CRpLrgYXTVd9U17-nglrUmJmryECxW-555ppQ",
           "e": "AQAB",
           "alg": "PS256",
           "x5u": "https://compliance.gaia-x.eu/.well-known/x509CertificateChain.pem"
         }
       }
     ],
     "assertionMethod": ["did:web:compliance.gaia-x.eu#JWK2020-RSA"]
   }
   ```

Upload this did.json to your domain (e.g. `https://your_domain.com/.well-known/did.json`), which is a requirement for successful signing in the following two scenarios.
#### Participant Self-Description
If a `registrationnumber.json`, a `tandc.json` and a `self-description.json` are given, the credentials will be signed and new files containing credential + proof called `{timestamp}_{type}_self-signed.json` will be created.

   **Example self-signed Self Description:**

   ```json
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/termsandconditions#",
        "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/participant#"
      ],
      "type": [
        "VerifiableCredential"
      ],
      "id": "https://ptw.tu-darmstadt.euprogigant.io/sd/participant.json",
      "issuer": "did:web:ptw.tu-darmstadt.euprogigant.io",
      "issuanceDate": "2023-07-25T11:33:14.113Z",
      "credentialSubject": {
        "id": "https://ptw.tu-darmstadt.euprogigant.io/sd/participant.json",
        "type": "gx:LegalParticipant",
        "gx:name": "Institut für Produktionsmanagement, Technologie und Werkzeugmaschinen",
        "gx:legalName": "Technische Universität Darmstadt",
        "gx:legalRegistrationNumber": {
          "id": "https://ptw.tu-darmstadt.euprogigant.io/sd/2210_gx_registrationnumber.json"
        },
        "gx:headquarterAddress": {
          "gx:countrySubdivisionCode": "DE-HE",
          "gx:addressCountryCode": "DE",
          "gx:locality": "Darmstadt",
          "gx:postalCode": "64297",
          "gx:streetAddress": "Otto-Berndt-Strasse 2"
        },
        "gx:legalAddress": {
          "gx:countrySubdivisionCode": "DE-HE",
          "gx:addressCountryCode": "DE",
          "gx:locality": "Darmstadt",
          "gx:postalCode": "64289",
          "gx:streetAddress": "Karolinenplatz 5"
        },
        "gx:website": "https://ptw.tu-darmstadt.de",
        "gx:blockchainAccountId": [
          {
            "gx:blockchainId": "100",
            "gx:blockchainName": "GEN-X",
            "gx:blockchainAccountId": "0x4A806a4851472F7cFd579d3FF5465F03c3c2B5d4"
          }
        ]
      },
      "proof": {
        "type": "JsonWebSignature2020",
        "created": "2023-09-25T17:58:58.338Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:web:ptw.tu-darmstadt.euprogigant.io",
        "jws": "eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..KIoZbDIcURcXY7x2yb-WvVbsHm2ld0XfycsFVKk8nH8Oyo7RgL9JORvWI5E5aRN7a4Df7NjU3tLKx9aOxw0eNKXA79aKTwgXcSVhD7RYgRkwP2viZBiVHrEWozTAZ6rFnDT_ij0Ms_7d2SmgH-nSR0rwmdmfIbGKB93LzBWVjXM2P9Q3KaQ8LsNut1sXUDBcn4ZxYij81FC7dCLUApK5_RwCNTyVTmEz6kQ3i3-R0029rs1sbIAgVTp-nwPDt2eturukM-qZ-FHKugymCaB0BfXkoDbl-EujOPksO5y4StH1Dpvv7acZ6sezNsf6UyJCqtcCbmCQeL51xFIq5Y8NVA"
      }
    }
   ```

From these three credentials a Verifiable Presentation (VP) `participantVP` is created.

If the did.json(important) was uploaded finally, the compliance service is used to sign the locally signed VP. It returns a compliance credential if the final result is successfully verified against the compliance service. The result is stored in a new file called `{timestamp}_{type}_complianceCredential.json`

   **Compliance Credential for the participantVP signed by the Compliance Service:**

   ```json
   {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
      "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#"
    ],
    "type": [
      "VerifiableCredential"
    ],
    "id": "https://compliance.lab.gaia-x.eu/development/credential-offers/a41ca623-2063-4164-85d5-4406ae4ab789",
    "issuer": "did:web:compliance.lab.gaia-x.eu:development",
    "issuanceDate": "2023-09-25T17:59:05.740Z",
    "expirationDate": "2023-12-24T17:59:05.740Z",
    "credentialSubject": [
      {
        "type": "gx:compliance",
        "id": "https://ptw.tu-darmstadt.euprogigant.io/sd/2210_gx_registrationnumber.json",
        "gx:integrity": "sha256-636a1f78dd2dfd5ae23e866a095074fea5ee2e21a6922df102213690b4d681e3",
        "gx:integrityNormalization": "RFC8785:JCS",
        "gx:version": "22.10",
        "gx:type": "gx:legalRegistrationNumber"
      },
      {
        "type": "gx:compliance",
        "id": "https://ptw.tu-darmstadt.euprogigant.io/sd/participant.json",
        "gx:integrity": "sha256-480b2cfa4a5402d8f922b1e64d5bf9e840ce42228dc83ec8e5af37696393b561",
        "gx:integrityNormalization": "RFC8785:JCS",
        "gx:version": "22.10",
        "gx:type": "gx:LegalParticipant"
      },
      {
        "type": "gx:compliance",
        "id": "https://ptw.tu-darmstadt.euprogigant.io/sd/2210_gx_tandc.json",
        "gx:integrity": "sha256-704b0e7b453534830f8551e842a9a9c68ba954a97e37d21a9e102a05a3f58517",
        "gx:integrityNormalization": "RFC8785:JCS",
        "gx:version": "22.10",
        "gx:type": "gx:GaiaXTermsAndConditions"
      }
    ],
    "proof": {
      "type": "JsonWebSignature2020",
      "created": "2023-09-25T17:59:05.750Z",
      "proofPurpose": "assertionMethod",
      "jws": "eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..CCruW_bjh7d5tsEUtTFwZcw0GlgRrtywF5M9Y4sNYqWhfzu6NmUGaqKcIb0dckK5iujO3uHTwqMq5CoirGrbIZUN6Umof7n9bByjopb-zOwIWdNiiGpfy3wSYrKPEYepXxmFw2DHYC7zctVGcm7bb_ogEBbaIWcGhVy9qsM1PmQ5OQQH4XlICdV1s7F2MWAPT7SoGGJ8GaQMd78OwVEK-b5RIQM3D-xBCscuul3u0P4Vic1Dfn0MNenzX16TfvoSd_f8TkOgunlRqmd7k36mFOc5kYziw8cwlEOue5vvfvmhNR1P57n9WAnCvcLjwYRZsh7LsUeWlHJkEP7oxQjoWw",
      "verificationMethod": "did:web:compliance.lab.gaia-x.eu:development#X509-JWK2020"
    }
  }
   ```

#### Service Offering
If a `participantVP.json` and one or more connected `service-offering.json` are given, the service-offerings are firstly locally signed and new files containing credential + proof called `{timestamp}_{service-offering name}_self-signed.json` will be created.
> Important: If for example one service offering links to the id of a second service-offering in the dependsOn-field the id of the credential subject of the second service-offering has to match that.

After that a Verifiable Presentation `service-offeringVP` of the participant and the service-offerings is created and checked against the compliance service. Analogous to the [participant](#participant-self-description) the VP and the potential compliance credential are saved as files. 

## How it Works

1. The given Self Description is canonized with [URDNA2015](https://json-ld.github.io/rdf-dataset-canonicalization/spec/)
2. Next the canonized output is hashed with [SHA256](https://json-ld.github.io/rdf-dataset-canonicalization/spec/#dfn-hash-algorithm).
3. That hash is then signed with the given private key and the proof is created using [JsonWebKey2020](https://w3c-ccg.github.io/lds-jws2020/#json-web-signature-2020).

## Environment variables for self-issued certificates (This is for test-setups only)

> This section is part of a bigger guide and describes environment variables needed to sign self-issued certificates. If you want to use the https://compliance.gaia-x.eu follow the instructions above and ignore this section.
> Here you can find the full guide for a local test-setup: [Using self-issued certificates for local testing](https://gitlab.com/gaia-x/lab/compliance/gx-compliance/-/tree/main#using-self-issued-certificates-for-local-testing)

How to set signer tool environment variables:

- `PRIVATE_KEY` = copy `pk8key.pem` content
- `CERTIFICATE ` = copy `cert.pem` content
- `VERIFICATION_METHOD` = `did:web:localhost%3A3000` (assuming port `3000` for the compliance service, you have to encode `:` as `%3A`)
- `X5U_URL` = `https://localhost:3000/.well-known/x509CertificateChain.pem`
- `BASE_URL` = `https://localhost:3000`

More information about environment variables can be found in the [How To Use](#how-to-use) section.

For now you can ignore the generated `did.json` since we are using for simplicity reasons the `did.json` of the compliance service also for the self-description. Usually you would host it under your own domain together with the `x509CertificateChain.pem` in the `.well-known/` directory.

If everything worked you should have 3 files generated. You can now head back to "Step 4: Verify your signed self-description" of the guide.
