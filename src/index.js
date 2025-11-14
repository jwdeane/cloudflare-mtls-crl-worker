import * as asn1js from 'asn1js'
import { Certificate, CertificateRevocationList } from 'pkijs'



// Modern Cloudflare Workers export pattern
export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env, ctx)
  }
}
   
  // Function to extract CRL Distribution Points from certificate
  function extractCRLDistributionPoints(certDerBase64) {
    try {
      // Decode base64 to binary
      const binaryString = atob(certDerBase64)
      const bytes = new Uint8Array(binaryString.length)
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i)
      }
      
      // Parse the certificate
      const asn1 = asn1js.fromBER(bytes.buffer)
      const certificate = new Certificate({ schema: asn1.result })
      
      // Find the CRL Distribution Points extension (OID: 2.5.29.31)
      const crlDistPointsExt = certificate.extensions?.find(
        ext => ext.extnID === '2.5.29.31'
      )
      
      if (!crlDistPointsExt) {
        console.log('No CRL Distribution Points extension found')
        return null
      }
      
      console.log('CRL extension found, parsing...')
      
      // Parse the extension value
      const crlDistPoints = asn1js.fromBER(crlDistPointsExt.extnValue.valueBlock.valueHex)
      
      // Extract URLs from distribution points - recursive search for URI type (tag 6)
      const urls = []
      
      function extractURIs(obj) {
        if (!obj) return
        
        // Check if this is a URI (context-specific tag 6)
        if (obj.idBlock && obj.idBlock.tagNumber === 6) {
          try {
            const url = String.fromCharCode.apply(null, new Uint8Array(obj.valueBlock.valueHex))
            if (/^https?:\/\//i.test(url)) {
              console.log('Found CRL URL:', url)
              urls.push(url)
            }
            else{
              console.log('Found non-HTTP CRL URL:', url)
            }
          } catch (e) {
            console.error('Error decoding URI:', e)
          }
        }
        
        // Recursively search in nested structures
        if (obj.valueBlock && obj.valueBlock.value) {
          if (Array.isArray(obj.valueBlock.value)) {
            for (const item of obj.valueBlock.value) {
              extractURIs(item)
            }
          } else {
            extractURIs(obj.valueBlock.value)
          }
        }
      }
      
      extractURIs(crlDistPoints.result)
      
      return urls.length > 0 ? urls : null
    } catch (error) {
      console.error('Error extracting CRL Distribution Points:', error)
      console.error('Error stack:', error.stack)
      return null
    }
  }

// Handles optional CRL refresh header, extracts CRL Distribution Points, and evaluates revocation.
// Returns a Response on failure or null to continue.
async function performCRLChecks(ctx, env, request, headers, cert) {
  // Optional header that will force the worker to get an updated CRL list
  const FORCE_CRL_REFRESH_HEADER = 'force-crl-refresh'
  // Check to see if we were asked to force a CRL refresh
  const forceCRLRefresh = request.headers.get(FORCE_CRL_REFRESH_HEADER)
    ? true
    : false

  // Extract CRL Distribution Points
  let crlDistPoints = extractCRLDistributionPoints(cert)
  
  // console.log('X-Client-Cert-CRL-URLs:', crlDistPoints)

  // Add CRL Distribution Points header if found
  if (crlDistPoints && Array.isArray(crlDistPoints) && crlDistPoints.length > 0) {
    headers.set('X-Client-Cert-CRL-URLs', crlDistPoints.join(','))
    console.log('CRL URLs added to header:', crlDistPoints.join(','))
  } else {
    console.log('No CRL Distribution Points found in certificate')
  }
  
  // Iterate over all CRL distribution points and evaluate revocation
  let loadedAnyCRL = false
  for (const dp of crlDistPoints) {
    const CRL_KV_KEY = `CRL_${btoa(dp)}` 
    const CRL_URL = dp
    try {
      const crl = await loadCRL(ctx, env, CRL_URL, CRL_KV_KEY, false)
      if (crl) {
        loadedAnyCRL = true
        // Check if the certificate the user presented is in this CRL
        if (crl.revokedSerialNumbers && crl.revokedSerialNumbers[request.cf.tlsClientAuth.certSerial]) {
          console.log('Certificate has been revoked', request.cf.tlsClientAuth.certSerial)
          return new Response('Certificate has been revoked', { status: 562 })
        }
      }
    } catch (e) {
      console.error('Failed to load CRL from distribution point:', CRL_URL, e)
      // Continue to next distribution point
    }
  }

  // If none of the CRLs could be loaded, fail open (allow request to proceed)
  if (!loadedAnyCRL) {
    console.log('failed to load CRL from any distribution point - failing open')
    return null
  }

  return null
}

// Verifies the client's CN against the per-host allowlist in KV.
// Returns a Response on failure (403) or null on success.
async function verifyClientCNAgainstAllowlist(env, request, headers, host, clientCN) {
  // KV namespace storing CN whitelist for each host
  const WL_KEY = `CN_WL_${btoa(host)}`

  // console.log('Checking CN whitelist')
  // Get the client CN allowlist from workers kv
  const clientCNAllowlistMap = await loadCNWhitelist(env, host)
  // console.log('clientCNAllowlistMap', JSON.stringify(clientCNAllowlistMap))

  // Fail closed if no allowlist configured for this host
  if (!clientCNAllowlistMap || typeof clientCNAllowlistMap !== 'object') {
    console.log('client CN allowlist not configured', clientCN)
    return new Response('client CN allowlist not configured', { status: 560 })
  }

  // Fail closed if the client CN is not in the allowlist
  if (!clientCN || clientCNAllowlistMap[clientCN] !== true) {
    console.log('client certificate not allowed', clientCN)
    return new Response('client certificate not allowed', { status: 561 })
  }

  return null
}

function extractCNFromDN(dn) {
  if (!dn || typeof dn !== 'string') return null
  const m = dn.match(/(?:^|,\s*)CN=([^,]+)(?:,|$)/i)
  return m ? m[1] : null
}

// Function that converts the base64 encoded DER certificate to PEM format
function toPem(base64) {
  let pem = '-----BEGIN CERTIFICATE-----\n'
  // Add a new line after every 64 characters
  for (let i = 0; i < base64.length; i += 64) {
    pem += base64.slice(i, i + 64) + '\n'
  }
  pem += '-----END CERTIFICATE-----\n'
  // I do not think escape(pem) actually does anything
  return pem
}

/**
 * Helper function that converts a buffer to a hex string
 * @param {*} inputBuffer
 */
function bufToHex(inputBuffer) {
  let result = ''
  for (const item of new Uint8Array(inputBuffer, 0, inputBuffer.byteLength)) {
    const str = item.toString(16).toUpperCase()
    if (str.length === 1) result += '0'
    result += str
  }
  return result.trim()
}

/**
 * Streams CRL data efficiently by reading in chunks rather than buffering the entire
 * response at once. This approach:
 * 1. Reads data incrementally from the response stream
 * 2. Checks size limits early to fail fast on oversized CRLs
 * 3. Combines chunks efficiently into a final buffer for ASN.1 parsing
 * 
 * This streaming approach helps avoid memory spikes and allows handling larger CRLs
 * than the previous buffered approach.
 */
async function streamCRL(response) {
  const reader = response.body.getReader()
  const chunks = []
  let totalBytes = 0
  
  // Maximum size: Conservative limit to ensure we stay well within Workers memory constraints
  // Cloudflare Workers have 128MB memory limit; we use 25MB to leave room for parsing overhead
  const MAX_TOTAL_SIZE = 25 * 1024 * 1024 // 25MB
  
  try {
    while (true) {
      const { done, value } = await reader.read()
      
      if (done) {
        break
      }
      
      totalBytes += value.length
      
      // Check size limit incrementally - fail fast if CRL is too large
      if (totalBytes > MAX_TOTAL_SIZE) {
        console.log(`⚠️ CRL exceeds ${(MAX_TOTAL_SIZE / 1024 / 1024).toFixed(2)} MB limit at ${(totalBytes / 1024 / 1024).toFixed(2)} MB`)
        throw new Error(`CRL too large: ${(totalBytes / 1024 / 1024).toFixed(2)} MB exceeds ${(MAX_TOTAL_SIZE / 1024 / 1024).toFixed(2)} MB limit`)
      }
      
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  
  // Efficiently combine chunks into a single ArrayBuffer for ASN.1 parsing
  const totalBuffer = new Uint8Array(totalBytes)
  let offset = 0
  for (const chunk of chunks) {
    totalBuffer.set(chunk, offset)
    offset += chunk.length
  }
  
  console.log(`Streamed CRL: ${(totalBytes / 1024 / 1024).toFixed(2)} MB in ${chunks.length} chunks`)
  return totalBuffer.buffer
}

/**
 * Fetchs a CRL list, parses out the serial numbers, and stores them into workers kv
 */
async function updateCRL(env, CRL_URL, CRL_KV_KEY) {
  console.log('Updating CRL', CRL_URL)
  const crlResp = await fetch(CRL_URL)
  if (crlResp.status !== 200) {
    throw new Error(`failed to fetch crl with status ${crlResp.status}`)
  }

  // Use streaming to fetch CRL data instead of buffering entire response
  const buf = await streamCRL(crlResp)

  let nextUpdate, thisUpdate, revokedSerialNumbers

  // Try PKI.js CertificateRevocationList.fromBER() first
  try {
    // const crlObject = CertificateRevocationList.fromBER(buf)

        // const buf = await crlResp.arrayBuffer()
    const asn1 = asn1js.fromBER(buf)
    const crlObject = new CertificateRevocationList({
      schema: asn1.result,
    })
    console.log('CRL parsed with PKI.js fromBER()')
    
    nextUpdate = crlObject.nextUpdate?.value || null
    thisUpdate = crlObject.thisUpdate?.value || null
    
    const revoked = Array.isArray(crlObject.revokedCertificates) ? crlObject.revokedCertificates : []
    revokedSerialNumbers = revoked.reduce((acc, cert) => {
      try {
        const serial = bufToHex(cert.userCertificate.valueBlock.valueHex)
        acc[serial] = true
      } catch (_) {}
      return acc
    }, {})
    
    console.log('CRL loaded via PKI.js', { 
      revokedCount: Object.keys(revokedSerialNumbers).length 
    })
    
  } catch (e) {
    console.log('PKI.js CRL parsing failed, using manual ASN.1 parsing:', e.message)
    
    // Fallback: Manual ASN.1 parsing
    const asn1 = asn1js.fromBER(buf)
    if (asn1.offset === -1 || !asn1.result) {
      throw new Error('Failed to parse CRL ASN.1')
    }
    
    const crlSeq = asn1.result
    if (!crlSeq.valueBlock?.value?.[0]) {
      throw new Error('Invalid CRL structure')
    }

    const tbsCertList = crlSeq.valueBlock.value[0]
    const tbsFields = tbsCertList.valueBlock?.value || []
    
    console.log('Manual parsing - fields:', tbsFields.length)
    
    // Debug: Log all field types
    for (let i = 0; i < tbsFields.length; i++) {
      const f = tbsFields[i]
      console.log(`Field[${i}]:`, {
        tagClass: f?.idBlock?.tagClass,
        tagNumber: f?.idBlock?.tagNumber,
        type: f?.constructor?.name,
        hasValue: !!f?.value,
        hasValueBlock: !!f?.valueBlock
      })
    }
    
    let idx = 0
    
    // Field[0]: Version (INTEGER) - always present in v2 CRLs
    if (tbsFields[idx]?.idBlock?.tagNumber === 2) {
      console.log('Skipping version at', idx)
      idx++
    }
    
    // Field[1]: Signature algorithm (SEQUENCE)
    console.log('Signature algorithm at', idx, '- tag:', tbsFields[idx]?.idBlock?.tagNumber)
    idx++
    
    // Field[2]: Issuer (SEQUENCE)
    console.log('Issuer at', idx, '- tag:', tbsFields[idx]?.idBlock?.tagNumber)
    idx++
    
    // Field[3]: thisUpdate (UTCTime or GeneralizedTime)
    const thisUpdateField = tbsFields[idx]
    thisUpdate = thisUpdateField?.toDate?.() || thisUpdateField?.valueBlock?.value?.[0] || null
    idx++
    
    // Field[4]: nextUpdate (UTCTime or GeneralizedTime, optional)
    if (idx < tbsFields.length && (tbsFields[idx]?.idBlock?.tagNumber === 23 || tbsFields[idx]?.idBlock?.tagNumber === 24)) {
      const nextUpdateField = tbsFields[idx]
      nextUpdate = nextUpdateField?.toDate?.() || nextUpdateField?.valueBlock?.value?.[0] || null
      idx++
    } else {
      nextUpdate = null
    }
    
    // revokedCertificates (optional SEQUENCE)
    console.log('Checking revokedCerts at', idx, '- tag:', tbsFields[idx]?.idBlock?.tagNumber)
    revokedSerialNumbers = {}
    if (idx < tbsFields.length && tbsFields[idx]?.idBlock?.tagNumber === 16) {
      const revokedCerts = tbsFields[idx]?.valueBlock?.value || []
      console.log('Found revoked certs:', revokedCerts.length)
      
      revokedCerts.forEach((certSeq, i) => {
        try {
          const serialField = certSeq.valueBlock?.value?.[0]
          if (serialField?.valueBlock?.valueHex) {
            const serial = bufToHex(serialField.valueBlock.valueHex)
            revokedSerialNumbers[serial] = true
            if (i < 3) console.log(`Revoked[${i}]:`, serial)
          }
        } catch (err) {
          console.log('Error extracting serial:', err.message)
        }
      })
    } else {
      console.log('No revoked certificates SEQUENCE found at', idx)
    }

    console.log('Manual parsing complete:', {
      revokedCount: Object.keys(revokedSerialNumbers).length
    })
  }

  const newCRL = {
    next_update: nextUpdate,
    this_update: thisUpdate,
    revokedSerialNumbers,
  }
  
  await env.CRL_NAMESPACE.put(CRL_KV_KEY, JSON.stringify(newCRL))
  return newCRL
}

async function loadCRL(ctx, env, crlUrl, crlKvKey, forceCRLRefresh = false) {
  console.log('Loading CRL', { url: crlUrl, kvKey: crlKvKey })
  // Force a refresh of the CRL list if needed
  if (forceCRLRefresh) {
    return await updateCRL(env, crlUrl, crlKvKey)
  }

  // attempt to get the CRL from workers kv first
  let crl = await env.CRL_NAMESPACE.get(crlKvKey, 'json')
  if (!crl) {
    // the CRL wasn't in workers kv, so go fetch it from the source
    crl = await updateCRL(env, crlUrl, crlKvKey)
  }

  // Check to see if we should refresh the CRL
  const nextUpdate = Date.parse(crl.nextUpdate)
  const now = new Date()
  if (now > nextUpdate) {
    // it is time to update the CRL. Out of band send a request to update the workers kv key
    ctx.waitUntil(updateCRL(env, crlUrl, crlKvKey))
  }

  return crl
}

// Helper to build the CN whitelist KV key for a given host header (may include port)
function cnWhitelistKeyForHost(hostHeader) {
  return `CN_WL_${btoa(hostHeader)}`
}

// Loads the CN whitelist map for the given host from KV. Returns an object map or null.
async function loadCNWhitelist(env, hostHeader) {
  const kvKey = cnWhitelistKeyForHost(hostHeader)
  const entry = await env.CN_WHITELIST.get(kvKey, 'json')
  if (!entry || !entry.common_names || typeof entry.common_names !== 'object') {
    return null
  }
  return entry.common_names
}

// Checks the request host against env.MTLS_HOST and optionally passes through.
// Returns an object { host, response } where response is a Response or null.
async function hostGateOrPassThrough(request, env, headers) {
  // Check if the host header matches the target
  let host = headers.get('host')

  console.log('host', host)
  console.log('MTLS_HOST', env.MTLS_HOST)
  if (host !== env.MTLS_HOST) {
    // Pass through without modification for other hosts
    return { host, response: await fetch(request) }
  }
  return { host, response: null }
}

// Function that handle the request
async function handleRequest(request, env, ctx) {
  if (
    request.cf &&
    request.cf.tlsClientAuth &&
    request.cf.tlsClientAuth.certPresented &&
    request.cf.tlsClientAuth.certVerified === 'SUCCESS'
  ) {
    // Create a headers object from the request headers
    let headers = new Headers(request.headers)

    const { host, response } = await hostGateOrPassThrough(request, env, headers)
    if (response) return response

    // Extract the client certificate common name and set it as a header
    const subjectDN = request.cf.tlsClientAuth.certSubjectDN
    const clientCN = extractCNFromDN(subjectDN)

    // Set the client CN as a header
    if (clientCN) {
      headers.set('X-Client-CN', clientCN)
    }

    if (env.ENABLE_CN_WHITELIST === 'true') {
      const cnCheckResponse = await verifyClientCNAgainstAllowlist(env, request, headers, host, clientCN)
      if (cnCheckResponse) return cnCheckResponse
    }



    // Get the base64 encoded DER certificate and subject
    let cert = headers.get('cf-client-cert-der-base64')
    
    


    if (env.ENABLE_CRL_CHECK === 'true') {
      try {
        const crlResponse = await performCRLChecks(ctx, env, request, headers, cert)
        if (crlResponse) return crlResponse
      } catch (e) {
        console.error('CRL check failed:', e)
        
        // Fail Open if CRL check fails
        let requestClone = new Request(request, { headers: headers })
        // Fetch the request
        return await fetch(requestClone)
      }
    }

    // Clone the request with the updated headers
    let requestClone = new Request(request, { headers: headers })
    // Fetch the request
    return await fetch(requestClone)
  }

    else {
  // return new Response('Certificate Verifications failed ', { status: 564 })
      return await fetch(request)
    }

}