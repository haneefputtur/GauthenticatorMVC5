using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Configuration;
using System.Web.Mvc;
using System.Web.Security;
using GAuthenticator.Models;
using Google.Authenticator;

namespace GAuthenticator.Controllers
{
    public class LoginController : Controller
    {
        // GET: Login
        public ActionResult Index()
        {
            return View();
        }
     //   string userName = WebConfigurationManager.AppSettings["GAuthPrivateKey"]
      //  private const string key = "qazqaz12345"; //You can add your own Key
        public ActionResult Login()
        {           
            return View();
        }
        [HttpPost]
        public ActionResult Login(LoginModel login)
        {
            string message = "";
            bool status = false;
            //check UserName and password form our database here
            string GAuthPrivKey = WebConfigurationManager.AppSettings["GAuthPrivateKey"];
            string UserUniqueKey = (login.UserName + GAuthPrivKey);
            if (login.UserName == "Admin" && login.Password == "12345") // Admin as user name and 12345 as Password
            {
                status = true;
                Session["UserName"] = login.UserName;

                if (WebConfigurationManager.AppSettings["GAuthEnable"].ToString() =="1")
                {
                    HttpCookie TwoFCookie = Request.Cookies["TwoFCookie"];
                    int k = 0;
                    if (TwoFCookie == null)
                    {
                        k = 1;
                    }
                    else
                    {

                        if (!string.IsNullOrEmpty(TwoFCookie.Values["UserCode"]))
                        {
                            string UserCodeE = TwoFCookie.Values["UserCode"].ToString();
                            string UserCodeD = Encoding.UTF8.GetString(MachineKey.Unprotect(Convert.FromBase64String(UserCodeE)));


                            if (UserUniqueKey == UserCodeD)
                            {
                                FormsAuthentication.SetAuthCookie(Session["Username"].ToString(), false);
                                ViewBag.Message = "Welcome to Mr. " + Session["Username"].ToString();
                                //return View("UserProfile");
                                return RedirectToAction("UserProfile");
                            }
                            else
                            {
                                k = 1;
                            }


                        }
                    }

                    if (k == 1)
                    {

                        message = "Two Factor Authentication Verification";
                   
                        //Two Factor Authentication Setup
                        TwoFactorAuthenticator TwoFacAuth = new TwoFactorAuthenticator();

                        Session["UserUniqueKey"] = UserUniqueKey;
                        var setupInfo = TwoFacAuth.GenerateSetupCode("HaneefPuttur.com", login.UserName, UserUniqueKey, 300, 300);
                        ViewBag.BarcodeImageUrl = setupInfo.QrCodeSetupImageUrl;
                        ViewBag.SetupCode = setupInfo.ManualEntryKey;
                    }
                }
               else
                {
                    FormsAuthentication.SetAuthCookie(Session["Username"].ToString(),true);
                    ViewBag.Message = "Welcome to Mr. " + Session["Username"].ToString();
             //       return View("UserProfile");
                    return RedirectToAction("UserProfile");
                }
                
            }

            else
            {
                message = "Please Enter the Valid Credential!";
            }
            ViewBag.Message = message;
            ViewBag.Status = status;
            return View();
        }
        [Authorize]
        public ActionResult UserProfile()
        {
            //if (Session["Username"] == null || Session["IsValidTwoFactorAuthentication"] == null || !(bool)Session["IsValidTwoFactorAuthentication"])
            //{
            //    return RedirectToAction("Login");
            //}
            ViewBag.Message = "Welcome to  " + Session["Username"].ToString();
            return View();
        }

        public ActionResult TwoFactorAuthenticate()
        {
            var token = Request["CodeDigit"];
            TwoFactorAuthenticator TwoFacAuth = new TwoFactorAuthenticator();
            string UserUniqueKey = Session["UserUniqueKey"].ToString();
            bool isValid = TwoFacAuth.ValidateTwoFactorPIN(UserUniqueKey, token);
            if (isValid)
            {
                HttpCookie TwoFCookie = new HttpCookie("TwoFCookie");
                string UserCode = Convert.ToBase64String(MachineKey.Protect(Encoding.UTF8.GetBytes(UserUniqueKey)));

                TwoFCookie.Values.Add("UserCode", UserCode);
                TwoFCookie.Expires = DateTime.Now.AddDays(30);
                Response.Cookies.Add(TwoFCookie);
                Session["IsValidTwoFactorAuthentication"] = true;
                return RedirectToAction("UserProfile", "Login");
            }
            return RedirectToAction("Login", "Login");
        }
        public ActionResult Logoff()
        {
            Session["UserName"] = null;
            FormsAuthentication.SignOut();
            FormsAuthentication.RedirectToLoginPage();
          return RedirectToAction("Login");
        }
    }
}