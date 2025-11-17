#include <string>
#include <iostream>
#include "version.h"
#include "miner.hpp"
#include "miner_keys.hpp"

void show_usage(std::string const& name)
{
    std::cerr << "Usage: " << name << " <option(s)> CONFIG_FILE"
              << "Options:\n"
              << "\t-h,--help\t\tShow this help message\n"
              << "\t-c,--check\t\tCheck for valid miner config file\n"
              << "\t-v,--version\t\tVersion of NexusMiner\n"
              << "\t--create-keys\t\tGenerate Falcon miner keypair for authentication"
              << std::endl;
}

int main(int argc, char **argv)
{
    nexusminer::Miner miner;

    std::string miner_config_file{"miner.conf"};
    bool run_check = false;
    bool create_keys = false;
    
    for (int i = 1; i < argc; ++i) 
    {
        std::string arg = argv[i];
        if ((arg == "-h") || (arg == "--help")) 
        {
            show_usage(argv[0]);
            return 0;
        } 
        else if ((arg == "-c") || (arg == "--check")) 
        {
            run_check = true;
        }
        else if ((arg == "-v") || (arg == "--version"))
        {
            std::cout << "NexusMiner version: " << NexusMiner_VERSION_MAJOR << "."
                << NexusMiner_VERSION_MINOR << std::endl;
            return 0;
        }
        else if (arg == "--create-keys")
        {
            create_keys = true;
        }
        else 
        {
            miner_config_file = argv[i];
        }
    }

    // Handle key generation mode
    if (create_keys)
    {
        std::cout << "\n=================================================================\n";
        std::cout << "     Falcon Miner Key Generation for NexusMiner\n";
        std::cout << "=================================================================\n\n";
        
        std::vector<uint8_t> pubkey, privkey;
        
        std::cout << "Generating Falcon-512 keypair...\n";
        
        if (!nexusminer::keys::generate_falcon_keypair(pubkey, privkey))
        {
            std::cerr << "ERROR: Failed to generate Falcon keypair!\n";
            return -1;
        }
        
        std::cout << "\n*** IMPORTANT SECURITY WARNING ***\n";
        std::cout << "The private key below must be kept SECRET and SECURE!\n";
        std::cout << "Anyone with access to your private key can impersonate your miner.\n";
        std::cout << "Store it in a secure location and never share it.\n";
        std::cout << "***********************************\n\n";
        
        std::string pubkey_hex = nexusminer::keys::to_hex(pubkey);
        std::string privkey_hex = nexusminer::keys::to_hex(privkey);
        
        std::cout << "PUBLIC KEY (share with node operator):\n";
        std::cout << pubkey_hex << "\n\n";
        
        std::cout << "PRIVATE KEY (keep secret!):\n";
        std::cout << privkey_hex << "\n\n";
        
        std::cout << "=================================================================\n";
        std::cout << "Configuration snippets:\n";
        std::cout << "=================================================================\n\n";
        
        std::cout << "Add to your miner.conf:\n";
        std::cout << "--------------------\n";
        std::cout << "\"miner_falcon_pubkey\": \"" << pubkey_hex << "\",\n";
        std::cout << "\"miner_falcon_privkey\": \"" << privkey_hex << "\"\n\n";
        
        std::cout << "Node operator should add to nexus.conf (whitelist your miner):\n";
        std::cout << "--------------------\n";
        std::cout << "-minerallowkey=" << pubkey_hex << "\n\n";
        
        std::cout << "=================================================================\n";
        std::cout << "Key generation complete!\n";
        std::cout << "=================================================================\n\n";
        
        return 0;
    }

    if(run_check)
    {
        if(!miner.check_config(miner_config_file))
        {
            return -1;
        }
    }

    if(!miner.init(miner_config_file))
    {
        return -1;
    }

    miner.run();
  
    return 0;
}
