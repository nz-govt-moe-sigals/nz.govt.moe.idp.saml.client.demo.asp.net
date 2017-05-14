using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Web;
using System.Web.SessionState;
using System.Xml;
using nz.govt.moe.idp.saml.client;
using nz.govt.moe.idp.saml.client.protocol;
using IdentityProviderDemo.Logic;
using nz.govt.moe.idp.saml.client.Bindings;
using nz.govt.moe.idp.saml.client.Schema.Protocol;
using nz.govt.moe.idp.saml.client.Utils;

namespace IdentityProviderDemo
{
    /// <summary>
    /// This handler simulates a signin endpoint for an identity provider.
    /// </summary>
    public class SigninHandler : BaseHandler
    {
        public override void ProcessRequest(HttpContext context)
        {
            if (context.Request.RequestType == "GET")
            {
                if (context.Request.Params["SAMLRequest"] == null)
                    return;

                HttpRedirectBindingParser parser = new HttpRedirectBindingParser(context.Request.Url);
                Signin(parser);                
            }
            
            // Not playing SAML2-Redirect-binding? You're on your own....
        }

        /// <summary>
        /// Verify the request and transfer the login-page.
        /// </summary>
        /// <param name="parser"></param>
        private static void Signin(HttpRedirectBindingParser parser)
        {            
            AuthnRequest req = Serialization.DeserializeFromXmlString<AuthnRequest>(parser.Message);
            
            // Retrieve metadata of requestor.
            string SPID = req.Issuer.Value;            
            Saml20MetadataDocument SPmetadata = GetMetadata(SPID);

            if (parser.IsSigned && !CheckRedirectSignature(parser, SPmetadata))
            {
                HandleUnableToVerifySignature(SPID);
                return;
            }

            HttpContext.Current.Session["authenticationrequest"] = req;
            HttpContext.Current.Server.Transfer("SignonForm.aspx");
        }
    }
}
