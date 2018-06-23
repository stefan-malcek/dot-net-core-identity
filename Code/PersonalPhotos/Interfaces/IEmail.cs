using System.Threading.Tasks;

namespace PersonalPhotos.Interfaces
{
    public interface IEmail
    {
        Task Send(string emailAddress, string body);
    }
}
