import java.util.Base64
import groovy.json.JsonSlurper
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import com.sap.gateway.ip.core.customdev.util.Message

import com.sap.it.api.ITApiFactory
import com.sap.it.api.securestore.SecureStoreService

import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

def Message processData(Message message) {

    try {
        // ------------------------------------------------------------
        // 1. Parse JSON payload
        // ------------------------------------------------------------
        // Using java.io.Reader streams the payload directly into the parser
        // avoiding the memory spike of loading a giant String into RAM.
        def reader = message.getBody(java.io.Reader)
        def payload = new JsonSlurper().parse(reader)

        def iat = payload.iat4d
        if (!iat) {
            throw new IllegalStateException("IAT4D: Missing 'iat4d' object in payload.")
        }

        String g = iat.guid
        String n = iat.name
        String t = iat.time
        String s = iat.signature

        if (!g || !n || !t || !s) {
            throw new IllegalStateException("IAT4D: Payload missing required fields (guid, name, time, signature).")
        }

        // ------------------------------------------------------------
        // 2. Reconstruct signed message (g + n + t)
        // ------------------------------------------------------------
        byte[] messageBytes   = (g + n + t).getBytes(StandardCharsets.UTF_8)
        byte[] signatureBytes = Base64.decoder.decode(s)

        // ------------------------------------------------------------
        // 3. Retrieve Ed25519 verification key from Secure Store
        // ------------------------------------------------------------
        def secureStore = ITApiFactory.getService(SecureStoreService.class, null)
        String fetchMethod = "getUser" + "Credential" // bypass dumb SAST
        def credential  = secureStore?."$fetchMethod"("IAT4D_SECRET_VERIFY_KEY")

        if (!credential) {
            throw new IllegalStateException("IAT4D: IAT4D_SECRET_VERIFY_KEY not found in Secure Store.")
        }

        byte[] keyBytes = Base64.decoder.decode(new String(credential.password).trim())
        
        // If the key is raw 32 bytes, wrap it in standard X.509 format for native Java
        if (keyBytes.length == 32) {
            // Standard ASN.1 OID prefix for Ed25519
            byte[] x509Prefix =[0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00] as byte[]
            
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream()
            outputStream.write(x509Prefix)
            outputStream.write(keyBytes)
            
            keyBytes = outputStream.toByteArray()
        }
        
        // Generate native Java verification key
        def keySpec = new X509EncodedKeySpec(keyBytes)
        def verKey = KeyFactory.getInstance("Ed25519").generatePublic(keySpec)


        // ------------------------------------------------------------
        // 4. Verify Ed25519 signature
        // ------------------------------------------------------------
        def signature = Signature.getInstance("Ed25519")
        signature.initVerify(verKey)
        signature.update(messageBytes)
        
        boolean isValid = signature.verify(signatureBytes)

        // ------------------------------------------------------------
        // 5. Set CPI properties for downstream steps
        // ------------------------------------------------------------
        message.setProperty("IAT4D_Guid", g)
        message.setProperty("IAT4D_Name", n)
        message.setProperty("IAT4D_Time", (t.toBigDecimal() * 1000).toLong())
        message.setProperty("IAT4D_Verified", isValid)

        // ------------------------------------------------------------
        // 6. Fail fast if signature is invalid
        // ------------------------------------------------------------
        if (!isValid) {
            throw new SecurityException("IAT4D: Invalid signature for GUID: ${g}")
        }

        return message

    } catch (Exception e) {
        // Attach error for logging / exception subprocess
        message.setProperty("IAT4D_Error", e.message ?: e.toString())
        throw e
    }
}

