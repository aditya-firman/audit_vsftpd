import re
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def print_ghxyss_logo():
    logo_lines = [
        r"  ____ _  _ __  __  _  _ ____ ",
        r" / ___/ || |  \/  |/ || | __ )",
        r"| |  _| || | |\/| | ' ||  _ \\",
        r"| |_| |__   _| |  | .  || |_) |",
        r" \____|  |_| |_|  |_||_|____/"
    ]

    print("="*36)
    print(f"{Fore.BLUE}{Style.BRIGHT}ghxyss Logo{Style.RESET_ALL}")
    print("="*36)

    for line in logo_lines:
        print(f"{Fore.GREEN}{line}{Style.RESET_ALL}")

    print("="*36)
    print(f"{Fore.CYAN}© 2024 ghxyss. All rights reserved.{Style.RESET_ALL}")
    print("="*36)
    print()  # Add extra spacing

def print_usage_banner():
    print("="*60)
    print(f"{Fore.BLUE}{Style.BRIGHT}vsftpd Configuration Auditor by ghxyss{Style.RESET_ALL}")
    print("="*60)
    print(f"{Fore.YELLOW}This script is designed to audit the vsftpd configuration file and ensure that it meets recommended security settings.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Usage: python3 audit_vsftpd.py /path/to/vsftpd.conf{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Please use this script responsibly and for the intended purpose of improving FTP server security.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Unauthorized use of this script for malicious purposes is strictly prohibited.{Style.RESET_ALL}")
    print("="*60)
    print(f"{Fore.CYAN}© 2024 ghxyss. All rights reserved.{Style.RESET_ALL}")
    print("="*60)
    print()  # Add extra spacing

# Define the recommended settings and their expected values with explanations
recommended_settings = {
    'anonymous_enable': 'NO',  # Disables anonymous FTP access, enhancing security.
    'local_enable': 'YES',  # Allows local users to log in to the FTP server.
    'write_enable': 'YES',  # Enables file uploads and modifications for authenticated users.
    'dirmessage_enable': 'YES',  # Shows messages when users enter directories.
    'use_localtime': 'YES',  # Sets the local time for log entries.
    'xferlog_enable': 'YES',  # Enables logging of file transfers.
    'connect_from_port_20': 'YES',  # Enables port 20 for data connections in active mode.
    'chown_uploads': 'NO',  # Prevents changing file ownership for uploaded files.
    'xferlog_std_format': 'YES',  # Uses a standard format for xferlog entries.
    'async_abor_enable': 'YES',  # Enables asynchronous ABOR requests for compatibility.
    'pasv_enable': 'YES',  # Allows passive mode for FTP connections, improving firewall compatibility.
    'port_enable': 'YES',  # Allows active mode for FTP connections.
    'pam_service_name': 'vsftpd',  # Sets the PAM service name for user authentication.
    'userlist_enable': 'YES',  # Enables user list for access control.
    'tcp_wrappers': 'YES',  # Enables TCP Wrappers for controlling access based on IP address.
    'ascii_upload_enable': 'NO',  # Disables ASCII mode for file uploads, enhancing security.
    'ascii_download_enable': 'NO',  # Disables ASCII mode for file downloads, enhancing security.
    'chroot_local_user': 'YES',  # Chroots local users to their home directories, improving security.
    'allow_anon_ssl': 'NO',  # Disables SSL for anonymous FTP users, enhancing security.
    'anon_mkdir_write_enable': 'NO',  # Disallows directory creation by anonymous users.
    'anon_other_write_enable': 'NO',  # Disallows file modification by anonymous users.
    'anon_upload_enable': 'NO',  # Disables file uploads for anonymous users.
    'anon_world_readable_only': 'YES',  # Sets files to read-only for anonymous users.
    'chmod_enable': 'YES',  # Allows changing file permissions for uploaded files.
    'download_enable': 'YES',  # Enables file downloads for users.
    'no_anon_password': 'YES',  # Disables password requirement for anonymous users.
    'passwd_chroot_enable': 'YES'  # Enables chrooting users based on the /etc/passwd file.
}

# Define regex patterns to match settings in the configuration file
setting_patterns = {key: re.compile(f"^{key}=(.*)$", re.IGNORECASE) for key in recommended_settings}

def audit_vsftpd_config(file_path):
    issues = []
    settings_found = {key: False for key in recommended_settings}

    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            for line in lines:
                line = line.strip()
                for setting, pattern in setting_patterns.items():
                    match = pattern.match(line)
                    if match:
                        value = match.group(1).strip()
                        settings_found[setting] = True
                        if value != recommended_settings[setting]:
                            issues.append((setting, value, recommended_settings[setting], False))
                        else:
                            issues.append((setting, value, recommended_settings[setting], True))
                        break

        for setting, found in settings_found.items():
            if not found:
                issues.append((setting, None, recommended_settings[setting], False))

    except FileNotFoundError:
        print(f"{Fore.RED}File not found: {file_path}{Style.RESET_ALL}")
        return []
    except Exception as e:
        print(f"{Fore.RED}Error reading file: {e}{Style.RESET_ALL}")
        return []

    return issues

def print_audit_banner(results):
    print("="*60)
    print(f"{Fore.BLUE}{Style.BRIGHT}vsftpd Configuration Audit Results{Style.RESET_ALL}")
    print("="*60)

    if results:
        for setting, value, recommended, is_correct in results:
            if is_correct:
                print(f"{Fore.GREEN}✔ {setting} is correctly set to {value}{Style.RESET_ALL}")
                print(f"   {Fore.CYAN}Explanation: Correctly configured as per the recommended setting.{Style.RESET_ALL}")
            else:
                if value is None:
                    print(f"{Fore.RED}✘ {setting} is missing. Recommended setting: {recommended}{Style.RESET_ALL}")
                    print(f"   {Fore.CYAN}Explanation: {setting} is missing from the configuration file. It is recommended to set it to {recommended} to enhance security and functionality.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}✘ {setting} is set to {value}. Recommended setting: {recommended}{Style.RESET_ALL}")
                    print(f"   {Fore.CYAN}Explanation: {setting} is set to {value}, which is not secure or functional. It is recommended to set it to {recommended} to enhance security and functionality.{Style.RESET_ALL}")
            print("-"*60)
    else:
        print(f"{Fore.GREEN}No issues found in vsftpd configuration.{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}Scan complete. Please review the results and update your configuration as necessary.{Style.RESET_ALL}")

# Specify the path to your vsftpd.conf file
config_file_path = '/etc/vsftpd.conf'

# Print the ghxyss logo
print_ghxyss_logo()

# Print usage banner
print_usage_banner()

# Run the audit
audit_results = audit_vsftpd_config(config_file_path)

# Print the audit results with a banner
print_audit_banner(audit_results)
