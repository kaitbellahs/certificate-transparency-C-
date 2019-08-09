using System;
using System.Collections.Generic;
using Java.Security;
using Org.Certificatetransparency.Ctlog;
using Org.BouncyCastle.Utilities.Encoders;
using Java.Security.Spec;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X9;
using Java.Lang;
using Javax.Net.Ssl;
using Java.Net;
using Java.IO;
using Java.Security.Cert;
using c = System.Console;
using Org.Certificatetransparency.Ctlog.Utils;
using Org.Certificatetransparency.Ctlog.Serialization;
using Base64 = Org.BouncyCastle.Utilities.Encoders.Base64;
using CT.Additions;
using System.IO;
using IOException = Java.IO.IOException;
using LogSignatureVerifier = CT.Additions.LogSignatureVerifier;
//using LogInfo = CT.Additions.LogID;
using System.Linq;
using Google.Protobuf;
using Org.BouncyCastle.Crypto.Tls;
using DigitallySigned = CT.Additions.DigitallySigned;
using Certificate = Java.Security.Cert.Certificate;
using Org.BouncyCastle.Utilities.IO;

namespace testeCTS.Droid
{
    public class teste
    {

        
        /** I want at least two different CT logs to verify the certificate */
        private static int MIN_VALID_SCTS = 1;
        private static int SCTS_TYPE = 0;

        /** A CT log's Id is created by using this hash algorithm on the CT log public key */
        private static string LOG_ID_HASH_ALGORITHM = "SHA-256";

        private static bool VERBOSE = false;

        private Dictionary<string, LogSignatureVerifier> verifiers = new Dictionary<string, LogSignatureVerifier>();

        public teste()
        {
            buildLogSignatureVerifiers();
            //checkConnection("https://invalid-expected-sbadssl.com/");
            //checkConnection("https://google.com/");
        }

        public bool CheckSCTS(string url)
        {
            return checkConnection(url);
        }




        /**
         * Check if the certificates provided by a server have good certificate transparency information
         * in them that can be verified against a trusted certificate transparency log.
         *
         * @param urlString the URL of the server to check.
         * @param shouldPass true if the server will give good certificates, false otherwise.
         */
        private bool checkConnection(string urlString)
        {
            HttpsURLConnection con = null;
            try
            {
                URL url = new URL(urlString);
                con = (HttpsURLConnection)url.OpenConnection();
                con.Connect();

                if (isGood(con.GetServerCertificates()))
                {
                    c.WriteLine("passou");
                    return true;
                }
                else
                {
                    c.WriteLine("naopassou");
                    return false;
                }
            }
            catch (SSLHandshakeException e)
            {
                c.WriteLine("naopassou: e="+e.Message);
                return false;
            }
            catch (IOException e)
            {
                c.WriteLine("naopassou: e2=" + e.Message);
                return false;
            }
            catch (Java.Lang.Exception e)
            {
                c.WriteLine("naopassou: e3=" + e.Message);
                return false;
            }
            finally
            {
                if (con != null)
                {
                    con.Disconnect();
                }
            }
        }




        /**
         * Check if the certificates provided by a server contain Signed Certificate Timestamps from a
         * trusted CT log.
         *
         * @param certificates the certificate chain provided by the server
         * @return true if the certificates can be trusted, false otherwise.
         */
        private bool isGood(Certificate[] certificates)
        {

            if (!(certificates[0] is X509Certificate)) {
                c.WriteLine("  This test only supports SCTs carried in X509 certificates, of which there are none.");
                return false;
            }

            Certificate leafCertificate = certificates[0];

            if (!CertificateInfo.HasEmbeddedSCT(leafCertificate))
            {
                c.WriteLine("  This certificate does not have any Signed Certificate Timestamps in it.");
                return false;
            }

            try
            {
                List<SignedCertificateTimestamp> sctsInCertificate = parseSCTsFromCert((X509Certificate)leafCertificate);
                if (sctsInCertificate.Count < MIN_VALID_SCTS)
                {
                    c.WriteLine(
                        "  Too few SCTs are present, I want at least "
                            + MIN_VALID_SCTS
                            + " CT logs to vouch for this certificate.");
                    return false;
                }

                List<X509Certificate> certificateList = certificates.OfType<X509Certificate>().ToList();// new List<X509Certificate>(certificates);

                int validSctCount = 0;
                foreach (SignedCertificateTimestamp sct in sctsInCertificate)
                {
                    string logId = Base64.ToBase64String(sct.Id.KeyId.ToByteArray());
                    if (verifiers.ContainsKey(logId))
                    {
                        c.WriteLine("  SCT trusted log " + logId);
                        if (verifiers[logId].VerifySignature(sct, certificateList))
                        {
                            ++validSctCount;
                        }
                    }
                    else
                    {
                        c.WriteLine("  SCT untrusted log " + logId);
                    }
                }

                if (validSctCount < MIN_VALID_SCTS)
                {
                    c.WriteLine(
                        "  Too few SCTs are present, I want at least "
                            + MIN_VALID_SCTS
                            + " CT logs to vouch for this certificate.");
                }
                return validSctCount >= MIN_VALID_SCTS;

            }
            catch (IOException e)
            {
                if (VERBOSE)
                {
                    e.PrintStackTrace();
                }
                return false;
            }
        }


        public static List<SignedCertificateTimestamp> parseSCTsFromCert(X509Certificate leafCert)
        {
            //var xcs = new new Org.BouncyCastle.Asn1.X509.X509CertificateStructure()
            //new Org.BouncyCastle.X509.X509Certificate(leafCert);
            //var leafCert2 = new System.Security.Cryptography.X509Certificates.X509Certificate2((System.Security.Cryptography.X509Certificates.X509Certificate)leafCert);
            byte[] bytes = leafCert.GetExtensionValue(CTConstants.SctCertificateOid);
            var scts = new List<SignedCertificateTimestamp>();
            
            var octets = new DerOctetString(bytes).ToAsn1Object();
            Asn1InputStream _ais = new Asn1InputStream(new MemoryStream(bytes));
            byte[] bytes2 = Asn1OctetString.GetInstance(octets).GetOctets();
            //ASN1Primitive p = (ASN1Primitive).FromByteArray(bytes2);
            //var p = _ais.ReadObject();
            //;
            //DerOctetString o = new DerOctetString(bytes);
            // These are serialized SCTs, we must de-serialize them into an array with one SCT each
            SignedCertificateTimestamp[] sctsFromCert = parseSCTsFromCertExtension(bytes2);
            foreach (SignedCertificateTimestamp signedCertificateTimestamp in sctsFromCert)
            {
                scts.Add(signedCertificateTimestamp);
            }

            return scts;

        }

        /**
         * Read a number of numBytes bytes (Assuming MSB first).
         *
         * @param inputStream byte stream of binary encoding.
         * @param numBytes exact number of bytes representing this number.
         * @return a number of at most 2^numBytes
         */
        static long ReadNumber(InputStream inputStream, int numBytes)
        {
            

            long toReturn = 0;
            try
            {
                for (int i = 0; i < numBytes; i++)
                {
                    int valRead = inputStream.Read();
                    if (valRead < 0)
                    {
                        throw new SerializationException(
                            string.Format("Missing length bytes: Expected %d, got %d.", numBytes, i));
                    }
                    toReturn = (toReturn << 8) | valRead;
                }
                return toReturn;
            }
            catch (IOException e)
            {
                throw new SerializationException("IO Error when reading number", e);
            }
        }

        public static DigitallySigned ParseDigitallySignedFromBinary(InputStream inputStream)
        {
            DigitallySigned builder = new DigitallySigned();
            int hashAlgorithmByte = (int)ReadNumber(inputStream, 1 /* single byte */);
            DigitallySigned.Types.HashAlgorithm hashAlgorithm = (DigitallySigned.Types.HashAlgorithm)hashAlgorithmByte;
            
            builder.HashAlgorithm = hashAlgorithm;

            int signatureAlgorithmByte = (int)ReadNumber(inputStream, 1 /* single byte */);
            DigitallySigned.Types.SignatureAlgorithm signatureAlgorithm = (DigitallySigned.Types.SignatureAlgorithm)signatureAlgorithmByte;
            
            builder.SigAlgorithm = signatureAlgorithm;
            //int SignatureLength = ReadUint16(inputStream);
            byte[] signature = ReadOpaque16(inputStream);
            builder.Signature = ByteString.CopyFrom(signature);

            return builder;
        }

        public static SignedCertificateTimestamp ParseSCTFromBinary(InputStream inputStream)
        {
            
            SignedCertificateTimestamp sctBuilder = new SignedCertificateTimestamp();
            int version = (int)ReadNumber(inputStream, 1);
            if (version != (int)CT.Additions.Version.V1)
            {
                throw new SerializationException(string.Format("Unknown version: %d", version));
            }
            sctBuilder.Version = (CT.Additions.Version)version;
            _ = ReadUint16(inputStream);
            byte[] keyId = ReadFixedLength(inputStream, CTConstants.KeyIdLength);
            var id_ = new LogID();
            id_.KeyId = ByteString.CopyFrom(keyId);
            sctBuilder.Id = id_;

            var timestamp = (ulong)ReadNumber(inputStream, CTConstants.TimestampLength);
            sctBuilder.Timestamp = timestamp;

            byte[] extensions = ReadVariableLength(inputStream, CTConstants.MaxExtensionsLength);
            sctBuilder.Extensions = ByteString.CopyFrom(extensions);

            sctBuilder.Signature = ParseDigitallySignedFromBinary(inputStream);
            return sctBuilder;
        }

        static byte[] ReadFixedLength(InputStream inputStream, int dataLength)
        {
            byte[] toReturn = new byte[dataLength];
            try
            {
                int bytesRead = inputStream.Read(toReturn);
                if (bytesRead < dataLength)
                {
                    throw new SerializationException(
                        string.Format("Not enough bytes: Expected %d, got %d.", dataLength, bytesRead));
                }
                return toReturn;
            }
            catch (IOException e)
            {
                throw new SerializationException("Error while reading fixed-length buffer", e);
            }
        }

        public static int BytesForDataLength(int maxDataLength)
        {
            return (int)(Java.Lang.Math.Ceil(Java.Lang.Math.Log(maxDataLength) / Java.Lang.Math.Log(2)) / 8);
        }

        static byte[] ReadVariableLength(InputStream inputStream, int maxDataLength)
        {
            int bytesForDataLength = BytesForDataLength(maxDataLength);
            long dataLength = ReadNumber(inputStream, bytesForDataLength);

            byte[] rawData = new byte[(int)dataLength];
            int bytesRead;
            try
            {
                bytesRead = inputStream.Read(rawData);
            }
            catch (IOException e)
            {
                //Note: A finer-grained exception type should be thrown if the client
                // ever cares to handle transient I/O errors.
                throw new SerializationException("Error while reading variable-length data", e);
            }

            if (bytesRead != dataLength)
            {
                throw new SerializationException(
                    string.Format("Incomplete data. Expected %d bytes, had %d.", dataLength, bytesRead));
            }

            return rawData;
        }

        

        private static bool CompareBytearrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;
            int i = 0;
            foreach (byte c in a)
            {
                if (c != b[i])
                    return false;
                i++;
            }
            return true;
        }

        private static SignedCertificateTimestamp[] parseSCTsFromCertExtension(byte[] extensionvalue)
        {
            System.Console.WriteLine("parseSCTsFromCertExtension:" + BitConverter.ToString(extensionvalue));
            List<SignedCertificateTimestamp> sctList = new List<SignedCertificateTimestamp>();
            ByteArrayInputStream bis = new ByteArrayInputStream(extensionvalue);
            int i = ReadUint16(bis);
            if (i == 1154)
            {
                SCTS_TYPE = 1;
                i = ReadUint16(bis);
            }
            i = ReadUint16(bis);
             i = ReadUint16(bis); // first one is the length of all SCTs concatenated, we don't actually need this
            while (bis.Available()>2)
            {
                byte[] sctBytes = ReadOpaque16(bis);
                sctList.Add(ParseSCTFromBinary(new ByteArrayInputStream(sctBytes)));
            }
            return sctList.ToArray();
        }

        public static int ReadFully2(InputStream inStr, byte[] buf)
        {
            return ReadFully2(inStr, buf, 0, buf.Length);
        }

        public static int ReadFully2(InputStream inStr, byte[] buf, int off, int len)
        {
            int totalRead = 0;
            while (totalRead < len)
            {
                int numRead = inStr.Read(buf, off + totalRead, len - totalRead);
                if (numRead < 1)
                    break;
                totalRead += numRead;
            }
            return totalRead;
        }

        private static void ReadFully(byte[] buf, InputStream inStr)
        {
            var rf = ReadFully2(inStr, buf, 0, buf.Length);
            if (rf < buf.Length)
                throw new EndOfStreamException();
        }

        private static byte[] ReadOpaque16(InputStream inStr)
        {
            int length = ReadUint16(inStr);
            byte[] bytes = new byte[length];
            ReadFully(bytes, inStr);
            return bytes;
        }

        private static int ReadUint16(InputStream inStr)
        {
            int i1 = inStr.Read();
            int i2 = inStr.Read();
            if ((i1 | i2) < 0)
            {
                throw new EndOfStreamException();
            }
            return i1 << 8 | i2;
        }


        /**
        * Construct LogSignatureVerifiers for each of the trusted CT logs.
        *
        * @throws InvalidKeySpecException the CT log key isn't RSA or EC, the key is probably corrupt.
        * @throws NoSuchAlgorithmException the crypto provider couldn't supply the hashing algorithm or
        *     the key algorithm. This probably means you are using an ancient or bad crypto provider.
*/
        private void buildLogSignatureVerifiers()
        {
            MessageDigest hasher = MessageDigest.GetInstance(LOG_ID_HASH_ALGORITHM);
            foreach (string trustedLogKey in TRUSTED_LOG_KEYS)
            {
                hasher.Reset();
                byte[] keyBytes = Base64.Decode(trustedLogKey);
                string logId = Base64.ToBase64String(hasher.Digest(keyBytes));
                KeyFactory keyFactory = KeyFactory.GetInstance(determineKeyAlgorithm(keyBytes));
                var publicKey = keyFactory.GeneratePublic(new X509EncodedKeySpec(keyBytes));
                verifiers.Add(logId, new LogSignatureVerifier(new LogInfo(publicKey)));
            }
        }


        /** Parses a key and determines the key algorithm (RSA or EC) based on the ASN1 OID. */
        private static string determineKeyAlgorithm(byte[] keyBytes)
        {
            var seq = Asn1Sequence.GetInstance(keyBytes).GetEnumerator();
            seq.MoveNext();
            var seq1 = ((Asn1Sequence)seq.Current).GetEnumerator();
            seq1.MoveNext();
            Asn1Object oid = (Asn1Object)seq1.Current;
            if (oid.Equals(PkcsObjectIdentifiers.RsaEncryption))
            {
                return "RSA";
            }
            else if (oid.Equals(X9ObjectIdentifiers.IdECPublicKey))
            {
                return "EC";
            }
            else
            {
                throw new IllegalArgumentException("Unsupported key type " + oid);
            }
        }


        // A collection of CT logs that are trusted for the purposes of this test. Derived from
        // https://www.certificate-transparency.org/known-logs -> https://www.gstatic.com/ct/log_list/log_list.json
        private static string[] TRUSTED_LOG_KEYS = {
    // Comodo 'Sabre' CT log : https://grahamedgecombe.com/logs/34
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8m/SiQ8/xfiHHqtls9m7FyOMBg4JVZY9CgiixXGz0akvKD6DEL8S0ERmFe9U4ZiA0M4kbT5nmuk3I85Sk4bagA==",
    //"Comodo 'Mammoth' CT log", https://mammoth.comodo.com/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7+R9dC4VFbbpuyOL+yy14ceAmEf7QGlo/EmtYU6DRzwat43f/3swtLr/L8ugFOOt1YU/RFmMjGCL17ixv66MZw==",
    // Google 'Icarus' log : https://grahamedgecombe.com/logs/25
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETtK8v7MICve56qTHHDhhBOuV4IlUaESxZryCfk9QbG9co/CqPvTsgPDbCpp6oFtyAHwlDhnvr7JijXRD9Cb2FA==",
    // Google Pilot log : https://grahamedgecombe.com/logs/1
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==",
    // Google Skydiver log : https://grahamedgecombe.com/logs/24
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEmyGDvYXsRJsNyXSrYc9DjHsIa2xzb4UR7ZxVoV6mrc9iZB7xjI6+NrOiwH+P/xxkRmOFG6Jel20q37hTh58rA==",
    //"Google 'Argon2018' log",https://googleapis.com/logs/argon2018/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0gBVBa3VR7QZu82V+ynXWD14JM3ORp37MtRxTmACJV5ZPtfUA7htQ2hofuigZQs+bnFZkje+qejxoyvk2Q1VaA==",
    //"Google 'Argon2019' log", https://googleapis.com/logs/argon2019/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEI3MQm+HzXvaYa2mVlhB4zknbtAT8cSxakmBoJcBKGqGwYS0bhxSpuvABM1kdBTDpQhXnVdcq+LSiukXJRpGHVg==",
    //"Google 'Argon2020' log", https://googleapis.com/logs/argon2020/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6Tx2p1yKY4015NyIYvdrk36es0uAc1zA4PQ+TGRY+3ZjUTIYY9Wyu+3q/147JG4vNVKLtDWarZwVqGkg6lAYzA==",
    //"Google 'Argon2021' log", https://googleapis.com/logs/argon2021/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETeBmZOrzZKo4xYktx9gI2chEce3cw/tbr5xkoQlmhB18aKfsxD+MnILgGNl0FOm0eYGilFVi85wLRIOhK8lxKw==",
    //"Google 'Aviator' log", https://googleapis.com/aviator/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I1JYP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q==",
    //"Google 'Rocketeer' log", https://googleapis.com/rocketeer/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg==",
    // Cloudflare 'Nimbus2018' Log : https://grahamedgecombe.com/logs/52
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAsVpWvrH3Ke0VRaMg9ZQoQjb5g/xh1z3DDa6IuxY5DyPsk6brlvrUNXZzoIg0DcvFiAn2kd6xmu4Obk5XA/nRg==",
    //"Cloudflare 'Nimbus2019' Log", https://cloudflare.com/logs/nimbus2019/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkZHz1v5r8a9LmXSMegYZAg4UW+Ug56GtNfJTDNFZuubEJYgWf4FcC5D+ZkYwttXTDSo4OkanG9b3AI4swIQ28g==",
    //"Cloudflare 'Nimbus2020' Log", https://cloudflare.com/logs/nimbus2020/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE01EAhx4o0zPQrXTcYjgCt4MVFsT0Pwjzb1RwrM0lhWDlxAYPP6/gyMCXNkOn/7KFsjL7rwk78tHMpY8rXn8AYg==",
    //"Cloudflare 'Nimbus2021' Log", https://cloudflare.com/logs/nimbus2021/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExpon7ipsqehIeU1bmpog9TFo4Pk8+9oN8OYHl1Q2JGVXnkVFnuuvPgSo2Ep+6vLffNLcmEbxOucz03sFiematg==",
    //"DigiCert Log Server", https://ct1.digicert-com/log/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+HCFRkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A==",
    //"DigiCert Log Server 2", https://ct2.digicert-com/log/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzF05L2a4TH/BLgOhNKPoioYCrkoRxvcmajeb8Dj4XQmNY+gxa4Zmz3mzJTwe33i0qMVp+rfwgnliQ/bM/oFmhA==",
    // DigiCert Yeti 2018 https://grahamedgecombe.com/logs/56
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESYlKFDLLFmA9JScaiaNnqlU8oWDytxIYMfswHy9Esg0aiX+WnP/yj4O0ViEHtLwbmOQeSWBGkIu9YK9CLeer+g==",
    //"DigiCert Yeti2019 Log", https://yeti2019.digicert.com/log/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkZd/ow8X+FSVWAVSf8xzkFohcPph/x6pS1JHh7g1wnCZ5y/8Hk6jzJxs6t3YMAWz2CPd4VkCdxwKexGhcFxD9A==",
    //"DigiCert Yeti2020 Log", https://yeti2020.digicert.com/log/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEURAG+Zo0ac3n37ifZKUhBFEV6jfcCzGIRz3tsq8Ca9BP/5XUHy6ZiqsPaAEbVM0uI3Tm9U24RVBHR9JxDElPmg==",
    //"DigiCert Yeti2021 Log", https://yeti2021.digicert.com/log/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6J4EbcpIAl1+AkSRsbhoY5oRTj3VoFfaf1DlQkfi7Rbe/HcjfVtrwN8jaC+tQDGjF+dqvKhWJAQ6Q6ev6q9Mew==",
    //"DigiCert Yeti2022 Log", https://yeti2022.digicert.com/log/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEn/jYHd77W1G1+131td5mEbCdX/1v/KiYW5hPLcOROvv+xA8Nw2BDjB7y+RGyutD2vKXStp/5XIeiffzUfdYTJg==",
    //"Symantec log", https://ws.symantec.com/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEluqsHEYMG1XcDfy1lCdGV0JwOmkY4r87xNuroPS2bMBTP01CEDPwWJePa75y9CrsHEKqAy8afig1dpkIPSEUhg==",
    //"Symantec 'Vega' log", https://vega.ws.symantec.com/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6pWeAv/u8TNtS4e8zf0ZF2L/lNPQWQc/Ai0ckP7IRzA78d0NuBEMXR2G3avTK0Zm+25ltzv9WWis36b4ztIYTQ==",
    //"Symantec 'Sirius' log", https://sirius.ws.symantec.com/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEowJkhCK7JewN47zCyYl93UXQ7uYVhY/Z5xcbE4Dq7bKFN61qxdglnfr0tPNuFiglN+qjN2Syxwv9UeXBBfQOtQ==",
    //"Certly.IO log", https://log.certly.io/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyPLhWKYYUgEc+tUXfPQB4wtGS2MNvXrjwFCCnyYJifBtd2Sk7Cu+Js9DNhMTh35FftHaHu6ZrclnNBKwmbbSA==",
    //"WoSign log", https://ctlog.wosign.com/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzBGIey1my66PTTBmJxklIpMhRrQvAdPG+SvVyLpzmwai8IoCnNBrRhgwhbrpJIsO0VtwKAx+8TpFf1rzgkJgMQ==",
    //"Venafi log", https://ctlog.api.venafi.com/",
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolpIHxdSlTXLo1s6H1OCdpSj/4DyHDc8wLG9wVmLqy1lk9fz4ATVmm+/1iN2Nk8jmctUKK2MFUtlWXZBSpym97M7frGlSaQXUWyA3CqQUEuIJOmlEjKTBEiQAvpfDjCHjlV2Be4qTM6jamkJbiWtgnYPhJL6ONaGTiSPm7Byy57iaz/hbckldSOIoRhYBiMzeNoA0DiRZ9KmfSeXZ1rB8y8X5urSW+iBzf2SaOfzBvDpcoTuAaWx2DPazoOl28fP1hZ+kHUYvxbcMjttjauCFx+JII0dmuZNIwjfeG/GBb9frpSX219k1O4Wi6OEbHEr8at/XQ0y7gTikOxBn/s5wQIDAQAB",
    //"Venafi Gen2 CT log", https://ctlog-gen2.api.venafi.com/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjicnerZVCXTrbEuUhGW85BXx6lrYfA43zro/bAna5ymW00VQb94etBzSg4j/KS/Oqf/fNN51D8DMGA2ULvw3AQ==",
    //"CNNIC CT log", https://ctserver.cnnic.cn/",
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv7UIYZopMgTTJWPp2IXhhuAf1l6a9zM7gBvntj5fLaFm9pVKhKYhVnno94XuXeN8EsDgiSIJIj66FpUGvai5samyetZhLocRuXhAiXXbDNyQ4KR51tVebtEq2zT0mT9liTtGwiksFQccyUsaVPhsHq9gJ2IKZdWauVA2Fm5x9h8B9xKn/L/2IaMpkIYtd967TNTP/dLPgixN1PLCLaypvurDGSVDsuWabA3FHKWL9z8wr7kBkbdpEhLlg2H+NAC+9nGKx+tQkuhZ/hWR65aX+CNUPy2OB9/u2rNPyDydb988LENXoUcMkQT0dU3aiYGkFAY0uZjD2vH97TM20xYtNQIDAQAB",
    //"StartCom log", https://startssl.com/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESPNZ8/YFGNPbsu1Gfs/IEbVXsajWTOaft0oaFIZDqUiwy1o/PErK38SCFFWa+PeOQFXc9NKv6nV0+05/YIYuUQ==",
    //"Izenpe log", https://izenpe.com/",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJ2Q5DC3cUBj4IQCiDu0s6j51up+TZAkAEcQRF6tczw90rLWXkJMAW7jr9yc92bIKgV8vDXU4lDeZHvYHduDuvg==",
  };
    }
}
