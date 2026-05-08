# 12 — Writing and Importing Modules

## Overview

When msfconsole doesn't have a module you need, you can **import** existing ExploitDB modules or **write custom modules** in Ruby. Modules are `.rb` files placed in the Metasploit directory structure.

---

## Finding Modules on ExploitDB

### Web Interface

- Go to [exploit-db.com](https://www.exploit-db.com)
- Filter by tag: **Metasploit Framework (MSF)**
- Download `.rb` files directly

### CLI — searchsploit

```bash
# Search for exploits
searchsploit nagios3

# Filter to Ruby/MSF modules only
searchsploit -t Nagios3 --exclude=".py"

# Show file path
searchsploit -p 9861
```

> `.rb` files ending in Ruby are likely MSF-compatible, but not all `.rb` scripts are valid MSF modules.

---

## Importing Modules

### Module Directories

| Location | Purpose |
|----------|---------|
| `/usr/share/metasploit-framework/modules/` | Primary system-wide modules |
| `~/.msf4/modules/` | User-level custom modules |

### Step-by-Step Import

```bash
# 1. Download the module
searchsploit -p 9861
# Copy path: /usr/share/exploitdb/exploits/unix/webapps/9861.rb

# 2. Copy to appropriate MSF directory (maintain folder structure)
cp ~/Downloads/9861.rb /usr/share/metasploit-framework/modules/exploits/unix/webapp/nagios3_command_injection.rb

# 3. Load in msfconsole (pick one method)
```

### Loading Methods

| Method | Command |
|--------|---------|
| **At startup** | `msfconsole -m /usr/share/metasploit-framework/modules/` |
| **Runtime loadpath** | `msf6 > loadpath /usr/share/metasploit-framework/modules/` |
| **Reload all** | `msf6 > reload_all` |
| **Then use** | `msf6 > use exploit/unix/webapp/nagios3_command_injection` |

### Naming Conventions

| Rule | Example |
|------|---------|
| **Snake_case** | `nagios3_command_injection.rb` |
| **Alphanumeric + underscores only** | `our_module_here.rb` |
| **No dashes** | `my-exploit.rb` → **WRONG** |
| **Match directory structure** | `modules/exploits/<os>/<service>/name.rb` |

---

## Writing Custom Modules

### Module Structure (Boilerplate)

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  # Mixins — include what you need
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::PhpEXE
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Module Name Here",
      'Description'    => %q{ Description of the vulnerability },
      'License'        => MSF_LICENSE,
      'Author'         => [
        'discoverer',    # Original discovery
        'porter'         # Metasploit module
      ],
      'References'     => [
        ['CVE', '2019-XXXXX'],
        ['URL', 'https://example.com/advisory']
      ],
      'Platform'       => 'php',
      'Arch'           => ARCH_PHP,
      'Notes'          => {
        'SideEffects' => [ IOC_IN_LOGS ],
        'Reliability' => [ REPEATABLE_SESSION ],
        'Stability'   => [ CRASH_SAFE ]
      },
      'Targets'        => [
        [ 'Target Description', {} ]
      ],
      'Privileged'     => false,
      'DisclosureDate' => "2019-10-05",
      'DefaultTarget'  => 0))

    register_options([
      OptString.new('TARGETURI', [true, 'The base path', '/']),
      OptString.new('USERNAME', [true, 'The username']),
      OptString.new('PASSWORD', [true, 'The password'])
    ])
  end

  def exploit
    # Exploit code here
  end
end
```

### Common Mixins

| Mixin | Purpose |
|-------|---------|
| `Msf::Exploit::Remote::HttpClient` | HTTP client methods for exploiting web servers |
| `Msf::Exploit::PhpEXE` | Generate first-stage PHP payloads |
| `Msf::Exploit::FileDropper` | File transfer + cleanup after session |
| `Msf::Auxiliary::Report` | Report data to the MSF database |
| `Msf::Exploit::Remote::Tcp` | Raw TCP connections |
| `Msf::Exploit::Remote::SMB` | SMB protocol interactions |

### Common Option Types

| Type | Description | Example |
|------|-------------|---------|
| `OptString.new` | String input | `OptString.new('USER', [true, 'Username'])` |
| `OptPath.new` | File path | `OptPath.new('PASSWORDS', [true, 'Wordlist path', default_path])` |
| `OptInt.new` | Integer | `OptInt.new('RPORT', [true, 'Target port', 80])` |
| `OptBool.new` | Boolean | `OptBool.new('SSL', [false, 'Use SSL', false])` |
| `OptAddress.new` | IP address | `OptAddress.new('RHOSTS', [true, 'Target host'])` |

### Rank Constants

| Rank | Description |
|------|-------------|
| `ExcellentRanking` | No typical memory corruption, works reliably |
| `GreatRanking` | Has a default target, usually auto-detects |
| `GoodRanking` | Has a default target, works in common cases |
| `NormalRanking` | Reliable but can't auto-detect |
| `AverageRanking` | Somewhat reliable |
| `LowRanking` | Difficult to exploit |
| `ManualRanking` | Basically a DoS or unreliable |

---

## Porting Workflow

```
1. Find the exploit (ExploitDB, GitHub, etc.)
2. Find a similar existing MSF module as boilerplate
3. Replace module info (Name, Description, Author, CVE, etc.)
4. Adjust mixins (include/remove as needed)
5. Adapt exploit code to MSF Ruby classes and methods
6. Register appropriate options
7. Copy to correct directory with snake_case name
8. reload_all in msfconsole
9. Test with show options → set params → check → run
```

---

## Key Takeaways

| Concept | Remember |
|---------|----------|
| **`searchsploit` for ExploitDB CLI** | Filter with `-t` for title, `--exclude` for file types |
| **`.rb` files → MSF modules** | Not all Ruby scripts are MSF-compatible — check structure |
| **Snake_case naming** | `my_exploit.rb` — no dashes, alphanumeric + underscores |
| **`reload_all` after install** | Or `loadpath` / restart msfconsole |
| **Two module directories** | System: `/usr/share/metasploit-framework/modules/` / User: `~/.msf4/modules/` |
| **Use boilerplate** | Find existing similar module, repurpose the structure |
| **Hard tabs in Ruby** | MSF convention — use tabs not spaces |
| **Always credit original authors** | Include discovery and module author in the `Author` field |
