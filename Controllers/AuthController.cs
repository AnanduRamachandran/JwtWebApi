using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using JwtWebApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JwtWebApi.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private static User user = new User();
        private readonly IConfiguration _configuration;
        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }


        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            user.Username = request.Username;
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<String>> Login(UserDto request)
        {
            if (user.Username != request.Username)
            {
                return BadRequest("user not present");
            }
            if(!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong password");
            }

            string token = CreateToken(user);

            var refreshToken = GetRefreshToken();
            SetRefreshToken(refreshToken);

            return Ok(token);
        }

        [HttpGet("TestAuthorize"), Authorize(Roles = "Admin")]
        public async Task<ActionResult<String>> TestGet(string request)
        {
            return Ok("Authorized user :)");
        }

        [HttpGet, Authorize]
        public ActionResult<string> GetMe()
        {
            var userName = User.Identity.Name;
            var userName2 = User.FindFirstValue(ClaimTypes.Name);
            var role = User.FindFirstValue(ClaimTypes.Role);
            return Ok(new {userName, userName2, role});
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<string>> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if (!user.RefreshToken.Equals(refreshToken))
            {
                return Unauthorized("Invalid Refresh Token");

            }
            else if (user.TokenExpires < DateTime.Now)
            {
                return Unauthorized("Token expired");
            }

            string token = CreateToken(user);
            var newRefreshToken = GetRefreshToken();
            SetRefreshToken(newRefreshToken);

            return Ok(token);
        }
        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var key = new SymmetricSecurityKey(
                System.Text.Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds);
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {

            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }

        private RefreshToken GetRefreshToken()
        {
            var refreshToken = new RefreshToken()
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddDays(7),
                Created = DateTime.Now
            };

            return refreshToken;
        }

        private void SetRefreshToken(RefreshToken newRefreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = newRefreshToken.Expires
            };

            Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);
            user.RefreshToken = newRefreshToken.Token;
            user.TokenCreated = newRefreshToken.Created;
            user.TokenExpires = newRefreshToken.Expires;
        }
    }
}
