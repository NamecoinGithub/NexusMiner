#include <string>
#include <iostream>
#include "version.h"
#include "miner.hpp"
#include "miner_keys.hpp"
#include "config/simplified_config.hpp"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

void show_usage(std::string const& name)
{
    std::cerr << "Usage: " << name << " <option(s)> CONFIG_FILE"
              << "Options:\n"
              << "\t-h,--help\t\t\t\tShow this help message\n"
              << "\t-c,--check\t\t\t\tCheck for valid miner config file\n"
              << "\t-v,--version\t\t\t\tVersion of NexusMiner\n"
              << "\t--create-keys\t\t\t\tGenerate Falcon miner keypair for authentication\n"
              << "\n"
              << "SOLO Mining Config Generation:\n"
              << "\t--create-falcon-config\t\t\tGenerate SOLO mining config with Falcon auth (falconminer.conf)\n"
              << "\t--create-falcon-config-with-privkey\tGenerate SOLO config with embedded private key (less secure)\n"
              << "\n"
              << "Simplified Config Options:\n"
              << "\t--create-config <preset> <mode> <hw>\tCreate simplified .config file\n"
              << "\t\t<preset>: beginner, intermediate, advanced\n"
              << "\t\t<mode>: hash, prime\n"
              << "\t\t<hw>: cpu, gpu\n"
              << "\t--import-config <json_file>\t\tImport legacy .conf to simplified .config\n"
              << "\t--export-config <config_file>\t\tExport simplified .config to legacy .conf"
              << std::endl;
}

int main(int argc, char **argv)
{
    nexusminer::Miner miner;

    std::string miner_config_file{"miner.conf"};
    bool run_check = false;
    bool create_keys = false;
    bool create_falcon_config = false;
    bool include_privkey = false;
    bool create_simplified_config = false;
    bool import_config = false;
    bool export_config = false;
    std::string preset_level{};
    std::string mining_mode{};
    std::string hardware_type{};
    std::string import_file{};
    std::string export_source_file{};
    
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
        else if (arg == "--create-falcon-config-with-privkey")
        {
            create_falcon_config = true;
            include_privkey = true;
        }
        else if (arg == "--create-falcon-config")
        {
            create_falcon_config = true;
        }
        else if (arg == "--create-config")
        {
            create_simplified_config = true;
            // Get next three arguments
            if (i + 3 < argc)
            {
                preset_level = argv[++i];
                mining_mode = argv[++i];
                hardware_type = argv[++i];
            }
            else
            {
                std::cerr << "Error: --create-config requires <preset> <mode> <hardware>\n";
                show_usage(argv[0]);
                return -1;
            }
        }
        else if (arg == "--import-config")
        {
            import_config = true;
            if (i + 1 < argc)
            {
                import_file = argv[++i];
            }
            else
            {
                std::cerr << "Error: --import-config requires <json_file>\n";
                return -1;
            }
        }
        else if (arg == "--export-config")
        {
            export_config = true;
            if (i + 1 < argc)
            {
                export_source_file = argv[++i];
            }
            else
            {
                std::cerr << "Error: --export-config requires <config_file>\n";
                return -1;
            }
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

    // Handle Falcon config generation mode
    if (create_falcon_config)
    {
        if (!nexusminer::keys::create_falcon_config("falconminer.conf", include_privkey))
        {
            std::cerr << "ERROR: Failed to create Falcon config file!\n";
            return -1;
        }
        
        return 0;
    }

    // Handle simplified config creation
    if (create_simplified_config)
    {
        auto console = spdlog::stdout_color_mt("console");
        nexusminer::config::Simplified_config simplified_config(console);
        
        // Parse preset level
        nexusminer::config::Preset_level level;
        if (preset_level == "beginner")
            level = nexusminer::config::Preset_level::BEGINNER;
        else if (preset_level == "intermediate")
            level = nexusminer::config::Preset_level::INTERMEDIATE;
        else if (preset_level == "advanced")
            level = nexusminer::config::Preset_level::ADVANCED;
        else
        {
            std::cerr << "Error: Invalid preset. Use: beginner, intermediate, or advanced\n";
            return -1;
        }
        
        // Normalize mining mode
        std::string mode_upper = mining_mode;
        std::transform(mode_upper.begin(), mode_upper.end(), mode_upper.begin(), ::toupper);
        if (mode_upper != "HASH" && mode_upper != "PRIME")
        {
            std::cerr << "Error: Invalid mode. Use: hash or prime\n";
            return -1;
        }
        
        // Normalize hardware type
        std::string hw_lower = hardware_type;
        std::transform(hw_lower.begin(), hw_lower.end(), hw_lower.begin(), ::tolower);
        if (hw_lower != "cpu" && hw_lower != "gpu")
        {
            std::cerr << "Error: Invalid hardware. Use: cpu or gpu\n";
            return -1;
        }
        
        simplified_config.create_preset(level, mode_upper, hw_lower);
        
        std::string output_file = preset_level + "_" + mining_mode + "_" + hardware_type + ".config";
        if (simplified_config.save(output_file))
        {
            std::cout << "Created simplified config: " << output_file << "\n";
            return 0;
        }
        else
        {
            std::cerr << "Error: Failed to create config file\n";
            return -1;
        }
    }

    // Handle config import
    if (import_config)
    {
        auto console = spdlog::stdout_color_mt("console");
        nexusminer::config::Simplified_config simplified_config(console);
        
        if (simplified_config.import_from_json(import_file))
        {
            std::string output_file = import_file + ".config";
            // Replace .conf extension if present
            size_t pos = output_file.rfind(".conf");
            if (pos != std::string::npos)
            {
                output_file = output_file.substr(0, pos) + ".config";
            }
            
            if (simplified_config.save(output_file))
            {
                std::cout << "Imported config to: " << output_file << "\n";
                return 0;
            }
        }
        std::cerr << "Error: Failed to import config\n";
        return -1;
    }

    // Handle config export
    if (export_config)
    {
        auto console = spdlog::stdout_color_mt("console");
        nexusminer::config::Simplified_config simplified_config(console);
        
        if (simplified_config.load(export_source_file))
        {
            std::string output_file = export_source_file;
            // Replace .config extension with .conf
            size_t pos = output_file.rfind(".config");
            if (pos != std::string::npos)
            {
                output_file = output_file.substr(0, pos) + ".conf";
            }
            else
            {
                output_file += ".conf";
            }
            
            if (simplified_config.export_to_json(output_file))
            {
                std::cout << "Exported config to: " << output_file << "\n";
                return 0;
            }
        }
        std::cerr << "Error: Failed to export config\n";
        return -1;
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
