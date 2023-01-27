using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using API.Entities;
using API.Interfaces;
using Microsoft.IdentityModel.Tokens;

namespace API.Services
{
    public class TokenService : ITokenService
    {

        private readonly SymmetricSecurityKey _key;

        public TokenService(IConfiguration configuration)
        {
            _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["TokenKey"]));

        }
        public string CreateToken(AppUser appUser)
        {

            var claims = new List<Claim>
            {
                new Claim (JwtRegisteredClaimNames.NameId, appUser.UserName)
            };

            var credentials = new SigningCredentials(_key, SecurityAlgorithms.HmacSha512Signature);
            var tokenDecriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddHours(1),
                SigningCredentials = credentials
            };
            var tokenBuilder = new JwtSecurityTokenHandler();
            var token = tokenBuilder.CreateToken(tokenDecriptor);

            return tokenBuilder.WriteToken(token);
        }
    }
}