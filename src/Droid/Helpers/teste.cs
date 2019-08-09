using System;
using CT.Additions;
using Java.IO;
using Java.Net;
using Javax.Net.Ssl;

namespace testeCTS.Droid.Helpers
{
    public class Teste
    {

        CTLog ctlog;
        private static Teste instence;

        public static Teste GetInstence()
        {
            if (instence == null)
            {
                instence = new Teste();
            }
            return instence;
        }

        public Teste()
        {
            ctlog = new CTLog();
        }





        /**
         * Check if the certificates provided by a server have good certificate transparency information
         * in them that can be verified against a trusted certificate transparency log.
         *
         * @param urlString the URL of the server to check.
         * @param shouldPass true if the server will give good certificates, false otherwise.
         */
        public bool CheckSCTS(string urlString)
        {
            HttpsURLConnection con = null;
            try
            {
                URL url = new URL(urlString);
                con = (HttpsURLConnection)url.OpenConnection();
                con.Connect();

                if (ctlog.CheckSCTS(con.GetServerCertificates()))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (SSLHandshakeException)
            {
                return false;
            }
            catch (IOException)
            {
                return false;
            }
            catch (Exception)
            {
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

    }
}