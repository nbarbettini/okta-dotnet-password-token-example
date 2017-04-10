using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace BasicOktaPasswordTokenFlow
{
    public interface IKeyProvider
    {
        Task<IssuerSigningKeyResolver> GetSigningKeyResolver(CancellationToken cancellationToken);
    }
}
