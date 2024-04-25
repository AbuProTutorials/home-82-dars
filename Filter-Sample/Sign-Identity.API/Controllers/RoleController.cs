using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Sign_Identity.API.Filters;
using Sign_Identity.Domain.DTOs;

namespace Sign_Identity.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class RoleController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;

        public RoleController(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }

        [HttpPost]
        public async Task<ActionResult<ResponseDTO>> CreateRole(RoleDTO role)
        {
                await _roleManager.CreateAsync(new IdentityRole(role.RoleName));

                return Ok(new ResponseDTO
                {
                    Message = "Role Created",
                    IsSuccess = true,
                    StatusCode = 201
                });
        }


        [HttpGet]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult<List<IdentityRole>>> GetAllRoles()
        {
            IEnumerable<IdentityRole> roles = await _roleManager.Roles.ToListAsync();

            return Ok(roles);
        }

        [HttpGet("{roleName}")]
        public async Task<IActionResult> GetRoleById(string  roleName)
        {
            return Ok(await _roleManager.FindByNameAsync(roleName));
        }

        [HttpDelete("{roleName}")]
        [Authorize(Roles = "Admin")]
        [AnyEndPointFilter]
        public async Task<IActionResult> DeleteRole(string roleName)
        {
            var res = await _roleManager.FindByNameAsync(roleName);

            var deletedRole = await _roleManager.DeleteAsync(res);

            return Ok(deletedRole);
        }

        [HttpPut("{roleName}")]
        [Authorize(Roles = "Admin")]
        [AnyExceptionFilter]
        public async Task<IActionResult> UpdateRole(string roleName, string updateToRoleName)
        {
            var res = await _roleManager.FindByNameAsync(roleName);
            res.Name = updateToRoleName;
            res.NormalizedName = updateToRoleName.ToUpper();

            var updatedRole = await _roleManager.UpdateAsync(res);
            return Ok();
        }

    }
}
