using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PersonalPhotos.Interfaces;
using PersonalPhotos.Models;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace PersonalPhotos.Controllers
{
    public class LoginsController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmail _email;

        public LoginsController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,
            RoleManager<IdentityRole> roleManager, IEmail email)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _email = email;
        }

        [HttpGet]
        public IActionResult Index(string returnUrl = null)
        {
            var model = new LoginViewModel { ReturnUrl = returnUrl };
            return View("Login", model);
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Invalid login detils");
                return View("Login", model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !user.EmailConfirmed)
            {
                ModelState.AddModelError(string.Empty, "User not found or email is not confirmed.");
                return View();
            }

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);
            if (!result.Succeeded)
            {
                if (result == SignInResult.TwoFactorRequired)
                {
                    return RedirectToAction("MfaLogin", "Logins");
                }

                ModelState.AddModelError(string.Empty, "Username or password is incorrect.");
                return View();
            }

            var claims = new List<Claim> { new Claim("Over18Claim", "True") };
            var claimIdentity = new ClaimsIdentity(claims);
            User.AddIdentity(claimIdentity);

            if (!string.IsNullOrEmpty(model.ReturnUrl))
            {
                return Redirect(model.ReturnUrl);
            }

            return RedirectToAction("Display", "Photos");
        }

        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Logins");
        }

        [HttpGet]
        public IActionResult Create()
        {
            return View("Create");
        }

        [HttpPost]
        public async Task<IActionResult> Create(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError(string.Empty, "Invalid user details");
                return View(model);
            }

            if (!await _roleManager.RoleExistsAsync("Editor"))
            {
                await _roleManager.CreateAsync(new IdentityRole("Editor"));
            }

            var user = new IdentityUser
            {
                UserName = model.Email,
                Email = model.Email
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                //await _userManager.AddToRoleAsync(user, "Editor");

                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var url = Url.Action("Confirmation", "Logins", new { id = user.Id, token }, HttpContext.Request.Scheme);
                var emailBody = $"Please confirm your email by clicking on the link below</br>{url}";
                await _email.Send(model.Email, emailBody);

                return RedirectToAction("Index", "Logins");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, $"{error.Code}:{error.Description}");
            }

            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Confirmation(string id, string token)
        {
            var user = await _userManager.FindByIdAsync(id);
            var confirm = await _userManager.ConfirmEmailAsync(user, token);

            if (!confirm.Succeeded)
            {
                ViewBag["Error"] = "Error with validating the email address";
                return View();
            }

            var is2FaEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            return RedirectToAction(!is2FaEnabled ? "Setup2Fa" : "Index", "Logins");
        }

        [HttpGet]
        public async Task<IActionResult> ResetPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.EmailAddress);
                if (user != null && user.EmailConfirmed)
                {
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var url = Url.Action("ChangePassword", "Logins", new { id = user.Id, token },
                        HttpContext.Request.Scheme);
                    var emailBody = $"Click on the link to reset your password</br>{url}";
                    await _email.Send(model.EmailAddress, emailBody);
                }
            }

            return View();
        }

        [HttpGet]
        public async Task<IActionResult> ChangePassword(string id, string token)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user != null)
            {
                var model = new ChangePasswordViewModel();
                model.EmailAddress = user.Email;
                model.Token = token;

                return View(model);
            }

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError(string.Empty, "Error in page!");
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.EmailAddress);
            var resetPasswordResult = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);

            return RedirectToAction("Index", "Logins");
        }

        [Authorize]
        public async Task<IActionResult> Setup2Fa()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                var authKey = await _userManager.GetAuthenticatorKeyAsync(user);
                if (string.IsNullOrEmpty(authKey))
                {
                    await _userManager.ResetAuthenticatorKeyAsync(user);
                    authKey = await _userManager.GetAuthenticatorKeyAsync(user);
                }

                var model = new MfaCreateViewModel
                {
                    AuthKey = FormatAuthKey(authKey)
                };

                return View(model);
            }
            return View();
        }

        [Authorize]
        [HttpPost]
        public async Task<IActionResult> Setup2Fa(MfaCreateViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.GetUserAsync(User);
            var isCodeCorrect = await _userManager.VerifyTwoFactorTokenAsync(user,
                _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
            if (!isCodeCorrect)
            {
                ModelState.AddModelError(string.Empty, "The code did not match the auth key!");
                return View(model);
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            return RedirectToAction("Index", "Logins");
        }

        [HttpGet]
        public async Task<IActionResult> MfaLogin()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> MfaLogin(MfaLoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var result = await _signInManager.TwoFactorSignInAsync(_userManager.Options.Tokens.AuthenticatorTokenProvider,
                 model.Code, true, true);// first true - cookie, second true - I do not have to use mfa login in this browser

            if (!result.Succeeded)
            {
                ModelState.AddModelError(string.Empty, "Your code could not be validated. Try again.");
                return View(model);
            }

            return RedirectToAction("Index", "Logins");
        }

        public IActionResult ExternalLogin(string provider, string returnUrl)
        {
            var redirectUrl = Url.Action("ExternalLoginCallback", "Logins", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }

        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            if (remoteError != null)
            {
                return RedirectToAction("Index");
            }

            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction("Index");
            }

            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true, true);
            if (result.Succeeded)
            {
                return RedirectToAction("Display", "Photos");
            }

            var emailAddress = info.Principal.FindFirstValue(ClaimTypes.Email);
            var user = new IdentityUser { Email = emailAddress, UserName = emailAddress, SecurityStamp = new Guid().ToString() };

            var identityUser = await _userManager.FindByEmailAsync(emailAddress);
            if (identityUser == null)
            {
                await _userManager.CreateAsync(user);
            }

            var logins = await _userManager.GetLoginsAsync(user);
            if (logins == null || !logins.Any(x => x.LoginProvider == info.LoginProvider && info.ProviderKey == x.ProviderKey))
            {
                await _userManager.AddLoginAsync(user, info);
            }

            await _signInManager.SignInAsync(user, true);

            if (!string.IsNullOrEmpty(returnUrl))
            {
                return Redirect(returnUrl);
            }

            return RedirectToAction("Display", "Photos");
        }

        private string FormatAuthKey(string authKey)
        {
            const int chunckLength = 5;
            var builder = new StringBuilder();
            while (authKey.Length > 0)
            {
                var length = chunckLength > authKey.Length ? authKey.Length : chunckLength;
                builder.Append(authKey.Substring(0, length) + " ");
                authKey = authKey.Remove(0, length);
            }

            return builder.ToString();
        }
    }
}