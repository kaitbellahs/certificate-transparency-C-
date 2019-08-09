using System;
using Java.IO;
using Java.Lang;

namespace Org.BouncyCastle.Asn1
{
    public abstract class ASN1Primitive : Asn1Object
    {
        public ASN1Primitive()
        {
        }

        /**
     * Create a base ASN.1 object from a byte stream.
     *
     * @param data the byte stream to parse.
     * @return the base ASN.1 object represented by the byte stream.
     * @exception IOException if there is a problem parsing the data, or parsing the stream did not exhaust the available data.
     */
        public static ASN1Primitive FromByteArray(byte[] data)
        {
            Asn1InputStream aIn = new Asn1InputStream(data);

            try
            {
                ASN1Primitive o = (ASN1Primitive)aIn.ReadObject();

               

                return o;
            }
            catch (ClassCastException)
            {
                throw new IOException("cannot recognise object in stream");
            }
        }

        public bool Equals(System.Object o)
        {
            if (this == o)
            {
                return true;
            }

            return (o is Asn1Encodable);
        }

        public ASN1Primitive ToASN1Primitive()
        {
            return this;
        }

        /**
         * Return the current object as one which encodes using Distinguished Encoding Rules.
         *
         * @return a DER version of this.
         */
        public ASN1Primitive ToDERObject()
        {
            return this;
        }

        /**
         * Return the current object as one which encodes using Definite Length encoding.
         *
         * @return a DL version of this.
         */
        public ASN1Primitive ToDLObject()
        {
            return this;
        }

        public abstract int HashCode();

        /**
         * Return true if this objected is a CONSTRUCTED one, false otherwise.
         * @return true if CONSTRUCTED bit set on object's tag, false otherwise.
         */
        public abstract bool IsConstructed();

        /**
         * Return the length of the encoding this object will produce.
         * @return the length of the object's encoding.
         * @throws IOException if the encoding length cannot be calculated.
         */
        public abstract int EncodedLength();

        public abstract void Encode(Asn1OutputStream o);

        /**
         * Equality (similarity) comparison for two ASN1Primitive objects.
         */
        public abstract bool Asn1Equals(ASN1Primitive o);
    }
}
