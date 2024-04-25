using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using Sign_Identity.Application.Services.AuthServices;
using Sign_Identity.Domain.DTOs;
using Sign_Identity.Domain.Entities.Auth;
using Sign_Identity.API.Filters;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Sign_Identity.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IAuthService _authService;

        public AuthController(SignInManager<User> signInManager, UserManager<User> userManager, RoleManager<IdentityRole> roleManager, IAuthService authService)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _roleManager = roleManager;
            _authService = authService;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterDTO registerDTO)
        {
            if (!ModelState.IsValid)
            {
                throw new Exception("Validation error");
            }
            
            User check = await _userManager.FindByEmailAsync(registerDTO.Email);

            if (check != null)
            {
                return BadRequest("You already registered");
            }

            User user = new User()
            {
                Email = registerDTO.Email,
                UserName = registerDTO.Username,
                FirstName = registerDTO.FirstName,
                LastName = registerDTO.LastName,
                Age = registerDTO.Age
            };

            IdentityResult? result = await _userManager.CreateAsync(user, registerDTO.Password);
            foreach (var role in registerDTO.Roles)
            {
                await _userManager.AddToRoleAsync(user, role);
            }
            if (!result.Succeeded)
            {
                return BadRequest("Something went wrong in Create");
            }

            return Ok(result);
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginDTO loginDTO)
        {
            if (!ModelState.IsValid)
            {
                throw new Exception("Something went wrong");
            }

            User user = await _userManager.FindByEmailAsync(loginDTO.Email);

            AuthDTO tokenDTO = await _authService.GenerateToken(user);

            HttpContext.Response.Cookies.Append("accessToken", tokenDTO.Token);

            return Ok(tokenDTO);

        }

        [HttpGet]
        [AuthorizeFilter]
        public async Task<IActionResult> GetAllUsers()
        {
                return Ok(await _userManager.Users.Where(x=>x.IsDeleted == false).ToListAsync());
        }

        [HttpGet("{id}")]
        [Authorize(Roles = "Admin, Teacher")]
        public async Task<IActionResult> GetUserById(string id)
        {
                var result = await _userManager.Users.FirstOrDefaultAsync(x => x.Id == id);

                if (result is null|| result.IsDeleted == true)
                {
                    return NotFound("Not found");
                }
                return Ok(result);
        }

        [HttpPost("Logout")]
        [Authorize(Roles = "Admin, Teacher, Student")]
        public async Task<IActionResult> LogOut()
        {
                await _signInManager.SignOutAsync();

                HttpContext.Response.Cookies.Delete("accessToken");

                return Ok("Loged Out");
        }


        [HttpDelete("{id}")]
        [DeleteActionFilter]
        [MyResultFilter]
        public async Task<IActionResult> DeleteAccount(string id)
        {
            var user = await _userManager.FindByIdAsync(id);

            if (user is null)
                throw new Exception("Not found");

            user.IsDeleted = true;
            user.DeletedDate = DateTime.UtcNow;
            IdentityResult? result = await _userManager.UpdateAsync(user);
            return Ok(result);
        }

        [HttpPut("{id}")]
        [UpdateResourceFilter]
        public async Task<IActionResult> UpdateAccount(string id, UpdateDTO updateDTO)
        {
            var user = await _userManager.FindByIdAsync(id);

            if (user is null)
                throw new Exception("Not found");

            user.FirstName = updateDTO.FirstName;
            user.LastName = updateDTO.LastName;
            user.Age = updateDTO.Age;
            user.ModifiedDate = DateTime.UtcNow;
            IdentityResult? result = await _userManager.UpdateAsync(user);

            return Ok(result);
        }
    }
}
