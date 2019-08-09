using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using Java.Security;
using Java.Security.Cert;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.Certificatetransparency.Ctlog;
using Org.Certificatetransparency.Ctlog.Serialization;

namespace CT.Additions
{
    public class LogSignatureVerifier
    {
        public static string X509_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";
        private LogInfo logInfo;

        /**
         * Creates a new LogSignatureVerifier which is associated with a single log.
         *
         * @param logInfo information of the log this verifier is to be associated with.
         */
        public LogSignatureVerifier(LogInfo logInfo)
        {
            this.logInfo = logInfo;
        }


        private class IssuerInformation
        {
            private X509Name name;
            private byte[] keyHash;
            private X509Extension x509authorityKeyIdentifier;
            private bool varIssuedByPreCertificateSigningCert;

            public IssuerInformation(X509Name name, byte[] keyHash, X509Extension x509authorityKeyIdentifier, bool issuedByPreCertificateSigningCert)
            {
                this.name = name;
                this.keyHash = keyHash;
                this.x509authorityKeyIdentifier = x509authorityKeyIdentifier;
                this.varIssuedByPreCertificateSigningCert = issuedByPreCertificateSigningCert;
            }

            public X509Name getName()
            {
                return name;
            }

            public byte[] GetKeyHash()
            {
                return keyHash;
            }

            public X509Extension getX509authorityKeyIdentifier()
            {
                return x509authorityKeyIdentifier;
            }

            public bool issuedByPreCertificateSigningCert()
            {
                return varIssuedByPreCertificateSigningCert;
            }
        }

        static IssuerInformation issuerInformationFromPreCertificateSigningCert(Certificate certificate, byte[] keyHash)
        {
            try
            {
                Asn1InputStream aIssuerIn = new Asn1InputStream(certificate.GetEncoded());
                X509CertificateStructure.GetInstance(aIssuerIn.ReadObject());
                CertificateList parsedIssuerCert = CertificateList.GetInstance(aIssuerIn.ReadObject());

                X509Extensions issuerExtensions = parsedIssuerCert.TbsCertList.Extensions;//.GetExtension(new DerObjectIdentifier(X509_AUTHORITY_KEY_IDENTIFIER));
                X509Extension x509authorityKeyIdentifier = null;
                if (issuerExtensions != null)
                {
                    //Org.BouncyCastle.Asn1.DerObjectIdentifier
                    x509authorityKeyIdentifier =
                        issuerExtensions.GetExtension(new DerObjectIdentifier(X509_AUTHORITY_KEY_IDENTIFIER));
                }

                return new IssuerInformation(parsedIssuerCert.Issuer, keyHash, x509authorityKeyIdentifier, true);
            }
            catch (CertificateEncodingException e)
            {
                throw new CertificateTransparencyException(
                    "Certificate could not be encoded: " + e.Message, e);
            }
            catch (Java.IO.IOException e)
            {
                throw new CertificateTransparencyException("Error during ASN.1 parsing of certificate: " + e.Message, e);
            }
        }

        // Produces issuer information in case the PreCertificate is signed by a regular CA cert,
        // not PreCertificate Signing Cert. In this case, the only thing that's needed is the
        // issuer key hash - the Precertificate will already have the right value for the issuer
        // name and K509 Authority Key Identifier extension.
        static IssuerInformation issuerInformationFromCertificateIssuer(Certificate certificate)
        {
            return new IssuerInformation(null, getKeyHash(certificate), null, false);
        }

        /**
         * Verifies the CT Log's signature over the SCT and certificate. Works for the following cases:
         *
         * <ul>
         *   <li>Ordinary X509 certificate sent to the log.
         *   <li>PreCertificate signed by an ordinary CA certificate.
         *   <li>PreCertificate signed by a PreCertificate Signing Cert. In this case the PreCertificate
         *       signing certificate must be 2nd on the chain, the CA cert itself 3rd.
         * </ul>
         *
         * @param sct SignedCertificateTimestamp received from the log.
         * @param chain The certificates chain as sent to the log.
         * @return true if the log's signature over this SCT can be verified, false otherwise.
         */
        public bool VerifySignature(SignedCertificateTimestamp sct, List<X509Certificate> chain)
        {
            if (sct != null && !logInfo.IsSameLogId(sct.Id.KeyId.ToByteArray()))
            {
                throw new CertificateTransparencyException(
                        "Log ID of SCT  does not match this log's ID .");
            }

            return true;
        }

        /**
         * Verifies the CT Log's signature over the SCT and leaf certificate.
         *
         * @param sct SignedCertificateTimestamp received from the log.
         * @param leafCert leaf certificate sent to the log.
         * @return true if the log's signature over this SCT can be verified, false otherwise.
         */
        bool verifySignature(SignedCertificateTimestamp sct, Certificate leafCert)
        {
            if (!logInfo.Equals(sct.Id))
            {
                throw new CertificateTransparencyException(
                    string.Format(
                        "Log ID of SCT () does not match this log's ID."));
            }
            byte[] toVerify = serializeSignedSCTData(leafCert, sct);

            return verifySCTSignatureOverBytes(sct, toVerify);
        }

        private List<IX509Extension> getExtensionsWithoutPoisonAndSCT(IX509Extension extensions, IX509Extension replacementX509authorityKeyIdentifier)
        {
            var extensionsOidsArray = extensions.CriticalExtensionOIDs;
            IEnumerator<DerObjectIdentifier> extensionsOids = (IEnumerator<DerObjectIdentifier>)extensionsOidsArray.GetEnumerator();

            // Order is important, which is why a list is used.
            List<IX509Extension> outputExtensions = new List<IX509Extension>();
            while (extensionsOids.MoveNext())
            {
                DerObjectIdentifier extn = extensionsOids.Current;
                string extnId = extn.Id;
                if (extnId.Equals(CTConstants.PoisonExtensionOid))
                {
                    // Do nothing - skip copying this extension
                }
                else if (extnId.Equals(CTConstants.SctCertificateOid))
                {
                    // Do nothing - skip copying this extension
                }
                else if ((extnId.Equals(X509_AUTHORITY_KEY_IDENTIFIER))
                  && (replacementX509authorityKeyIdentifier != null))
                {
                    // Use the real issuer's authority key identifier, since it's present.
                    outputExtensions.Add(replacementX509authorityKeyIdentifier);
                }
                else
                {
                    // Copy the extension as-is.
                    outputExtensions.Add(extensions);
                }
            }
            return outputExtensions;
        }

        private bool verifySCTSignatureOverBytes(SignedCertificateTimestamp sct, byte[] toVerify)
        {
            string sigAlg;
            if (logInfo.SignatureAlgorithm.Equals("EC"))
            {
                sigAlg = "SHA256withECDSA";
            }
            else if (logInfo.SignatureAlgorithm.Equals("RSA"))
            {
                sigAlg = "SHA256withRSA";
            }
            else
            {
                throw new CertificateTransparencyException("Unsupported signature algorithm %s");
            }

            try
            {
                Signature signature = Signature.GetInstance(sigAlg);

                //X509EncodedKeySpec spec = new X509EncodedKeySpec(logInfo.Key);
                //KeyFactory keyFactory = KeyFactory.GetInstance("RSA");
                //IPrivateKey pk = (IPrivateKey)keyFactory.GeneratePublic(spec);

                signature.InitSign((IPrivateKey)logInfo.Key);
                signature.Update(toVerify);
                return signature.Verify(sct.Signature.Signature.ToByteArray());
            }
            catch (SignatureException e)
            {
                throw new CertificateTransparencyException(
                    "Signature object not properly initialized or signature from SCT is improperly encoded.",
                    e);
            }
            catch (InvalidKeyException e)
            {
                throw new CertificateTransparencyException("Log's public key cannot be used", e);
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new UnsupportedCryptoPrimitiveException(sigAlg + " not supported by this JVM", e);
            }
        }

        static byte[] serializeSignedSCTData(Certificate certificate, SignedCertificateTimestamp sct)
        {
            MemoryStream bos = new MemoryStream();
            serializeCommonSCTFields(sct, bos);
            Serializer.WriteUint(bos, (long)LogEntryType.X509Entry, CTConstants.LogEntryTypeLength);
            try
            {
                Serializer.WriteVariableLength(bos, certificate.GetEncoded(), CTConstants.MaxCertificateLength);
            }
            catch (CertificateEncodingException e)
            {
                throw new CertificateTransparencyException("Error encoding certificate", e);
            }
            Serializer.WriteVariableLength(bos, sct.Extensions.ToByteArray(), CTConstants.MaxExtensionsLength);

            return bos.ToArray();
        }

        static byte[] serializeSignedSCTDataForPreCertificate(byte[] preCertBytes, byte[] issuerKeyHash, SignedCertificateTimestamp sct)
        {
            MemoryStream bos = new MemoryStream();
            serializeCommonSCTFields(sct, bos);
            Serializer.WriteUint(bos, (long)LogEntryType.PrecertEntry, CTConstants.LogEntryTypeLength);
            Serializer.WriteVariableLength(bos, issuerKeyHash, issuerKeyHash.Length);
            Serializer.WriteVariableLength(bos, preCertBytes, CTConstants.MaxCertificateLength);
            Serializer.WriteVariableLength(bos, sct.Extensions.ToByteArray(), CTConstants.MaxExtensionsLength);
            return bos.ToArray();
        }

        private static byte[] getKeyHash(Certificate signerCert)
        {
            try
            {
                MessageDigest sha256 = MessageDigest.GetInstance("SHA-256");
                return sha256.Digest(signerCert.PublicKey.GetEncoded());
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new UnsupportedCryptoPrimitiveException("SHA-256 not supported: " + e.Message, e);
            }
        }

        private static void serializeCommonSCTFields(SignedCertificateTimestamp sct, MemoryStream bos)
        {
            if (sct.Version.Equals(Version.V1)) { Debug.WriteLine("Can only serialize SCT v1 for now."); }
            Serializer.WriteUint(bos, (long)Convert.ToDouble(sct.Version), CTConstants.VersionLength); // ct::V1
            Serializer.WriteUint(bos, 0, 1); // ct::CERTIFICATE_TIMESTAMP
            Serializer.WriteUint(bos, (long)sct.Timestamp, CTConstants.TimestampLength); // Timestamp
        }
    }
}
