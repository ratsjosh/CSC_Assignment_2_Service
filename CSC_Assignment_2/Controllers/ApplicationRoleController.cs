using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using CSC_Assignment_2.Models;

namespace CSC_Assignment_2.Controllers
{
    public class ApplicationRoleController : Controller
    {
        private readonly RoleManager<ApplicationRole> roleManager;

        public ApplicationRoleController(RoleManager<ApplicationRole> roleManager)
        {
            this.roleManager = roleManager;
        }

        [HttpGet]
        public List<ApplicationRoleListViewModel> GetAll()

        {
            List<ApplicationRoleListViewModel> model = new List<ApplicationRoleListViewModel>();
            model = roleManager.Roles.Select(r => new ApplicationRoleListViewModel
            {
                RoleName = r.Name,
                Id = r.Id,
                Description = r.Description,
                NumberOfUsers = r.Users.Count
            }).ToList();
            return model;
        }

        [HttpGet]
        public async Task<ApplicationRoleViewModel> AddEditApplicationRole(string id)
        {
            ApplicationRoleViewModel model = new ApplicationRoleViewModel();
            if (!String.IsNullOrEmpty(id))
            {
                ApplicationRole applicationRole = await roleManager.FindByIdAsync(id);
                if (applicationRole != null)
                {
                    model.Id = applicationRole.Id;
                    model.RoleName = applicationRole.Name;
                    model.Description = applicationRole.Description;
                }
            }
            return model;
        }

        [HttpGet]
        public async Task<string> DeleteApplicationRole(string id)
        {
            string name = string.Empty;
            if (!String.IsNullOrEmpty(id))
            {
                ApplicationRole applicationRole = await roleManager.FindByIdAsync(id);
                if (applicationRole != null)
                {
                    name = applicationRole.Name;
                }
            }
            return name;
        }

        [HttpPost]
        public async Task<IActionResult> DeleteApplicationRole(string id, IFormCollection form)
        {
            if (!String.IsNullOrEmpty(id))
            {
                ApplicationRole applicationRole = await roleManager.FindByIdAsync(id);
                if (applicationRole != null)
                {
                    IdentityResult roleRuslt = roleManager.DeleteAsync(applicationRole).Result;
                    if (roleRuslt.Succeeded)
                    {
                        return Ok(new { Success = false, message = "Successfully delete application role" });
                    }
                }
            }
            return BadRequest(new { Success = false, message = "Failed to delete application role" });
        }

        [HttpPost]
        public async Task<IActionResult> AddEditApplicationRole(string id, ApplicationRoleViewModel model)
        {
            if (ModelState.IsValid)
            {
                bool isExist = !String.IsNullOrEmpty(id);
                ApplicationRole applicationRole = isExist ? await roleManager.FindByIdAsync(id) :
               new ApplicationRole
               {
                   CreatedDate = DateTime.UtcNow
               };
                applicationRole.Name = model.RoleName;
                applicationRole.Description = model.Description;
                applicationRole.IPAddress = Request.HttpContext.Connection.RemoteIpAddress.ToString();
                IdentityResult roleRuslt = isExist ? await roleManager.UpdateAsync(applicationRole)
                                                    : await roleManager.CreateAsync(applicationRole);

                if (roleRuslt.Succeeded)
                {
                    return Ok(new { Success = false, message = "Successfully Add/Edit application role" });
                }
            }
            return BadRequest(new { Success = false, message = "Failed to Add/Edit application role" });
        }

    }
}