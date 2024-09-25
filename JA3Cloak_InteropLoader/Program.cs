using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("JA3Cloak.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void CreateRandomizedJA3SpoofedConnection(string serverName);

    [DllImport("JA3Cloak.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void CreateCustomJA3SpoofedConnection(string serverName, string cipherSuites, string curves, string signatureAlgorithms);

    static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Please specify either -r for random or -c for custom");
            Console.WriteLine("Instructions for creating a custom JA3 spoofed connection:");
            Console.WriteLine("  -s: Specify the server name (default: example.com)");
            Console.WriteLine("  -cs: Comma-separated list of cipher suites (default: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA)");
            Console.WriteLine("  -curves: Comma-separated list of supported curves (default: X25519,P256,P384,P521)");
            Console.WriteLine("  -sigalgs: Comma-separated list of supported signature algorithms (default: ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,RSAWithSHA256,RSAWithSHA384,RSAWithSHA512)");
            return;
        }

        bool random = false;
        bool custom = false;
        string serverName = "example.com";
        string cipherSuites = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA";
        string curves = "X25519,P256,P384,P521";
        string signatureAlgorithms = "ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,RSAWithSHA256,RSAWithSHA384,RSAWithSHA512";

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-r":
                    random = true;
                    break;
                case "-c":
                    custom = true;
                    break;
                case "-s":
                    if (i + 1 < args.Length)
                    {
                        serverName = args[i + 1];
                        i++;
                    }
                    break;
                case "-cs":
                    if (i + 1 < args.Length)
                    {
                        cipherSuites = args[i + 1];
                        i++;
                    }
                    break;
                case "-curves":
                    if (i + 1 < args.Length)
                    {
                        curves = args[i + 1];
                        i++;
                    }
                    break;
                case "-sigalgs":
                    if (i + 1 < args.Length)
                    {
                        signatureAlgorithms = args[i + 1];
                        i++;
                    }
                    break;
            }
        }

        if (random)
        {
            CreateRandomizedJA3SpoofedConnection(serverName);
        }
        else if (custom)
        {
            CreateCustomJA3SpoofedConnection(serverName, cipherSuites, curves, signatureAlgorithms);
        }
        else
        {
            Console.WriteLine("Please specify either -r for random or -c for custom");
            Console.WriteLine("Instructions for creating a custom JA3 spoofed connection:");
            Console.WriteLine("  -s: Specify the server name (default: example.com)");
            Console.WriteLine("  -cs: Comma-separated list of cipher suites (default: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA)");
            Console.WriteLine("  -curves: Comma-separated list of supported curves (default: X25519,P256,P384,P521)");
            Console.WriteLine("  -sigalgs: Comma-separated list of supported signature algorithms (default: ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,RSAWithSHA256,RSAWithSHA384,RSAWithSHA512)");
        }
    }
}
