using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PersonalPhotos.Interfaces;
using PersonalPhotos.Models;

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

            if (confirm.Succeeded)
            {
                return RedirectToAction("Index");
            }

            ViewBag["Error"] = "Error with validating the email address";
            return View();
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
    }
}