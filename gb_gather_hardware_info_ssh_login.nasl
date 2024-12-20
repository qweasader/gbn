# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103996");
  script_version("2024-05-29T05:05:18+0000");
  script_tag(name:"last_modification", value:"2024-05-29 05:05:18 +0000 (Wed, 29 May 2024)");
  script_tag(name:"creation_date", value:"2011-04-05 14:24:03 +0200 (Tue, 05 Apr 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Gather Hardware Information (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based information gathering of the hardware
  configuration from a Linux/Unix host.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

SCRIPT_DESC = "Gather Hardware Information (Linux/Unix SSH Login)";

if( ! sock = ssh_login_or_reuse_connection() )
  exit( 0 );

# -- Get the CPU information -- #
cpuinfo = ssh_cmd( socket:sock, cmd:"cat /proc/cpuinfo" );
cpus = make_array();
cpunumber = 0;

# nb: There seems to be no real consistency what info is included as shown in the examples below.
#
# BusyBox v1.20.2 single core CPU output of cat /proc/cpuinfo:
#
# Processor       : Marvell PJ4Bv7 Processor rev 1 (v7l)
# BogoMIPS        : 1196.85
# Features        : swp half thumb fastmult vfp edsp vfpv3 vfpv3d16 tls
# CPU implementer : 0x56
# CPU architecture: 7
# CPU variant     : 0x1
# CPU part        : 0x581
# CPU revision    : 1
#
# Hardware        : Marvell Armada-370
# Revision        : 0000
# Serial          : 0000000000000000
#
# BusyBox v1.20.2 dual core CPU output of cat /proc/cpuinfo:
#
# processor       : 0
# model name      : ARMv7 Processor rev 1 (v7l)
# BogoMIPS        : 2655.84
# Features        : swp half thumb fastmult vfp edsp neon vfpv3 tls
# CPU implementer : 0x41
# CPU architecture: 7
# CPU variant     : 0x4
# CPU part        : 0xc09
# CPU revision    : 1
#
# processor       : 1
# model name      : ARMv7 Processor rev 1 (v7l)
# BogoMIPS        : 2655.84
# Features        : swp half thumb fastmult vfp edsp neon vfpv3 tls
# CPU implementer : 0x41
# CPU architecture: 7
# CPU variant     : 0x4
# CPU part        : 0xc09
# CPU revision    : 1
#
# Hardware        : Marvell Armada 380/381/382/385/388 (Device Tree)
# Revision        : 0000
# Serial          : 0000000000000000
#
# Standard-Linux Intel CPU output of cat /proc/cpuinfo:
#
# processor     : 0
# vendor_id     : GenuineIntel
# cpu family    : 6
# model         : 78
# model name    : Intel(R) Core(TM) i5-6300U CPU @ 2.40GHz
# *snip*
# processor     : 1
# vendor_id     : GenuineIntel
# cpu family    : 6
# model         : 78
# model name    : Intel(R) Core(TM) i5-6300U CPU @ 2.40GHz
# *snip*
#
# Standard-Linux AMD CPU output of cat /proc/cpuinfo:
#
# processor     : 0
# vendor_id     : AuthenticAMD
# cpu family    : 23
# model         : 49
# model name    : AMD EPYC 7452 32-Core Processor
# *snip*
# processor     : 1
# vendor_id     : AuthenticAMD
# cpu family    : 23
# model         : 49
# model name    : AMD EPYC 7452 32-Core Processor
# *snip*
#
# Further examples for ARM systems:
#
# processor       : 0
# model name      : ARMv7 Processor rev 4 (v7l)
# BogoMIPS        : 38.40
# Features        : half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm crc32
# CPU implementer : 0x41
# CPU architecture: 7
# CPU variant     : 0x0
# CPU part        : 0xd03
# CPU revision    : 4
#
# *snip*
#
# Hardware  : BCM2835
# Revision  : a02082
# Serial    : 000000008dffccd2
# Model     : Raspberry Pi 3 Model B Rev 1.2
#
# or:
#
# processor       : 0
# model name      : ARMv7 Processor rev 3 (v7l)
# BogoMIPS        : 144.00
# Features        : half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm crc32
# CPU implementer : 0x41
# CPU architecture: 7
# CPU variant     : 0x0
# CPU part        : 0xd08
# CPU revision    : 3
#
# *snip*
#
# Hardware  : BCM2711
# Revision  : c03112
# Serial    : 10000000ed30ba2e
# Model     : Raspberry Pi 4 Model B Rev 1.2
#
# or:
#
# processor       : 0
# model name      : ARMv7 Processor rev 2 (v7l)
# BogoMIPS        : 50.00
# Features        : half thumb fastmult vfp edsp thumbee vfpv3 tls idiva idivt vfpd32 lpae
# CPU implementer : 0x56
# CPU architecture: 7
# CPU variant     : 0x2
# CPU part        : 0x584
# CPU revision    : 2
#
# Sometimes the model name is not even included like e.g.:
#
# processor       : 7
# BogoMIPS        : 2.40
# Features        : fp asimd evtstrm aes pmull sha1 sha2 crc32 cpuid
# CPU implementer : 0x41
# CPU architecture: 8
# CPU variant     : 0x0
# CPU part        : 0xd03
# CPU revision    : 3
#
# or:
#
# processor       : 0
# BogoMIPS        : 200.00
# Features        : fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma dcpop asimddp asimdfhm
# CPU implementer : 0x48
# CPU architecture: 8
# CPU variant     : 0x1
# CPU part        : 0xd01
# CPU id          : 0x481fd010
# CPU revision    : 0
#
# or:
#
# processor       : 0
# BogoMIPS        : 200.00
# cpu MHz         : 2400.000
# Features        : fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma dcpop asimddp asimdfhm
# CPU implementer : 0x48
# CPU architecture: 8
# CPU variant     : 0x1
# CPU part        : 0xd01
# CPU revision    : 0

if( cpuinfo =~ "Hardware\s*: " )
  cpu_regex = "^Hardware\s*: (.+)$";
else
  cpu_regex = "^model name\s*: (.+)$";

cpu_vendor_id = ""; # nb: To make openvas-nasl-lint happy...

foreach line( split( cpuinfo ) ) {

  if( line =~ "^processor\s*: " ) {
    cpunumber++;
    continue;
  }

  line = chomp( line );

  # nb: Only checking / saving this currently for standard linux installations...
  if( ! cpu_vendor_id && line =~ "^vendor_id\s*:.+" ) {

    v_id = eregmatch( string:line, pattern:"^vendor_id\s*: (.+)$", icase:TRUE );
    if( v_id[1] ) {
      cpu_vendor_id = v_id[1];
      continue;
    }
  }

  v = eregmatch( string:line, pattern:cpu_regex, icase:TRUE );
  if( ! isnull( v ) ) {
    if( isnull( cpus[v[1]] ) ) {
      cpus[v[1]] = 1;
    } else {
      cpus[v[1]]++;
    }
  }
}

if( ! cpu_vendor_id ) {

  # model name    : ARMv7 Processor rev 1 (v7l)
  # model name  : ARMv8 Processor rev 0 (v8l)
  if( cpuinfo =~ "(model name|Processor)\s*:\s*ARM" )
    cpu_vendor_id = "ARM";

  # Processor     : Marvell PJ4Bv7 Processor rev 1 (v7l)
  else if( cpuinfo =~ "(model name|Processor)\s*:\s*Marvell" )
    cpu_vendor_id = "Marvell";

  # model name    : Intel(R) Core(TM) i5-6300U CPU @ 2.40GHz
  else if( cpuinfo =~ "(model name|Processor)\s*:\s*Intel" )
    cpu_vendor_id = "GenuineIntel";

  # model name    : AMD EPYC 7452 32-Core Processor
  else if( cpuinfo =~ "(model name|Processor)\s*:\s*AMD" )
    cpu_vendor_id = "AuthenticAMD";

  # nb: We're assuming (for now) that the vendor is always the first part up to the first space
  else if( _vendor = eregmatch( string:cpuinfo, pattern:"(model name|Processor)\s*:\s*([A-Za-z]+[^ ]*)", icase:FALSE ) )
    cpu_vendor_id = _vendor[2];
}

# -- Get the systems architecture -- #
archinfo = ssh_cmd( socket:sock, cmd:"uname -m" );
arch = "";

# nb: If adding additional architectures here make sure to also check the ARM specific pattern below
if( egrep( string:archinfo, pattern:"^(x86_64|i386|i486|i586|i686|sun4u|unknown|armv7l|armv8|aarch64|arm64|ia64|alpha|amd64|arm|armeb|armel|hppa|m32r|m68k|mips|mipsel|powerpc|ppc64|s390|s390x|sh3|sh3eb|sh4|sh4eb|sparc)$" ) ) {
  arch = archinfo;
  set_kb_item( name:"ssh/login/arch", value:arch );
}

# nb: Last fallback as some examples above are showing that on some systems none of the previously
# evaluated info is there. In this case some guessing based on the system architecture reported by
# the Kernel is done.
if( ! cpu_vendor_id && arch ) {

  if( arch =~ "^(armv7l|armv8|aarch64|arm64|arm|armeb|armel)$" )
    cpu_vendor_id = "ARM (based on the identified architecture '" + arch + "')";
}

# nb: This is used in some Linux Kernel "CPU Vulnerabilities" VTs to exit if e.g. only a specific
# Vendor is affected.
if( cpu_vendor_id ) {
  set_kb_item( name:"ssh/login/cpu_vendor_id", value:cpu_vendor_id );
  register_host_detail( name:"cpu_vendor_id", value:cpu_vendor_id, desc:SCRIPT_DESC );

  # nb: Just some "generic" KB keys for specific CPU based VTs
  if( "GenuineIntel" >< cpu_vendor_id )
    set_kb_item( name:"ssh/login/intel_cpu/detected", value:TRUE );

  else if( "AuthenticAMD" >< cpu_vendor_id )
    set_kb_item( name:"ssh/login/amd_cpu/detected", value:TRUE );

  else if( "ARM" >< cpu_vendor_id )
    set_kb_item( name:"ssh/login/arm_cpu/detected", value:TRUE );

  else if( "Marvell" >< cpu_vendor_id )
    set_kb_item( name:"ssh/login/marvell_cpu/detected", value:TRUE );
}

# -- Get the PCI information -- #
lspci = ssh_cmd( socket:sock, cmd:"/usr/bin/lspci -vmm" );
if( lspci ) {

  lspci_lines = split( lspci, keep:FALSE );
  max = max_index( lspci_lines );
  if( max > 2 ) { # Just a basic sanity check for the return of lspci

    set_kb_item( name:"ssh_or_wmi/login/pci_devices/available", value:TRUE );
    set_kb_item( name:"ssh/login/pci_devices/available", value:TRUE );

    device_infos = make_array();

    for( i = 0; i < max; i++ ) {

      if( lspci_lines[i] == "" )
        continue;

      # man lspci:
      # Verbose format (-vmm)
      # The verbose output is a sequence of records separated by blank lines. Each record describes a single device by a sequence of lines, each line containing a single `tag: value' pair. The tag and the
      # value are separated by a single tab character. Neither the records nor the lines within a record are in any particular order. Tags are case-sensitive.

      entry = split( lspci_lines[i], sep:':\t', keep:FALSE );
      device_infos[entry[0]] = entry[1];

      if( ( lspci_lines[ i + 1 ] == "" ) || ( i == max - 1 ) ) {

        deviceid = device_infos["Slot"];
        if( ! deviceid )
          deviceid = "unknown";

        set_kb_item( name:"ssh/login/pci_devices/device_ids", value:deviceid );

        foreach device_info( keys( device_infos ) ) {
          set_kb_item( name:"ssh/login/pci_devices/" + deviceid + "/" + tolower( device_info ), value:device_infos[device_info] );
        }
        device_infos = make_array(); # Throw away the previous collected information as we already have saved it into our KB.
      }
    }
  }
}

# -- Get the memory information -- #
meminfo = ssh_cmd( socket:sock, cmd:"cat /proc/meminfo" );
memtotal = "";
foreach line( split( meminfo, keep:FALSE ) ) {
  v = eregmatch( string:line, pattern:"^(MemTotal:[ ]+)([0-9]+ kB)$", icase:TRUE );
  if( ! isnull( v ) ) {
    memtotal = v[2];
    break;
  }
}

# -- Get the network interfaces information -- #
ifconfig = ssh_cmd( socket:sock, cmd:"/sbin/ifconfig" );
interfaces = split( ifconfig, sep:'\r\n\r\n', keep:FALSE );
netinfo = "";
host_ip = get_host_ip();

foreach interface( interfaces ) {

  x = 0;
  ip_str = "";

  if( "Loopback" >< interface )
    continue;

  lines = split( interface );
  foreach line( lines ) {

    v = eregmatch( string:line, pattern:"^[^ ].*|.*inet[6]? addr.*|^$" );
    if( ! isnull( v ) ) {
      netinfo += v[0];
    }

    if( "HWaddr" >< line ) {

      mac = eregmatch( pattern:"HWaddr ([0-9a-fA-F:]{17})", string:line );
      nic = eregmatch( pattern:"(^[^ ]+)", string:line );

      z = x + 1;
      while( ip = eregmatch( pattern:"inet[6]? addr:[ ]?([^ ]+)", string:lines[z] ) ) {
        if( ! isnull( ip[1] ) ) {
          ip_str += ip[1] + ';';
        }
        z++;
      }

      ip_str = substr( ip_str, 0, strlen( ip_str ) - 2 );

      if( ! isnull( mac ) ) {
        num_ifaces++;
        replace_kb_item( name:"ssh/login/net_iface/num_ifaces", value:num_ifaces );
        if( host_ip >< lines[x+1] ) {
          register_host_detail( name:"MAC", value:mac[1], desc:SCRIPT_DESC );
          set_kb_item( name:"ssh/login/net_iface/" + num_ifaces + "/iface_mac", value:mac[1] );
          if( ! isnull( nic[1] ) ) {
            target_nic = nic[1];
            register_host_detail( name:"NIC", value:nic[1], desc:SCRIPT_DESC );
            set_kb_item( name:"ssh/login/net_iface/" + num_ifaces + "/iface_name", value:nic[1] );
            if( strlen( ip_str ) > 0 ) {
              register_host_detail( name:"NIC_IPS", value:ip_str, desc:SCRIPT_DESC );
              set_kb_item( name:"ssh/login/net_iface/" + num_ifaces + "/iface_ips", value:ip_str );
            }
          }
        }

        if( ! isnull( nic[1] ) && nic[1] != target_nic ) {
          set_kb_item( name:"ssh/login/net_iface/" + num_ifaces + "/iface_mac", value:mac[1] );
          set_kb_item( name:"ssh/login/net_iface/" + num_ifaces + "/iface_name", value:nic[1] );
          set_kb_item( name:"ssh/login/net_iface/" + num_ifaces + "/iface_ips", value:ip_str );
          register_host_detail( name:"MAC-Ifaces", value:nic[1] + "|" + mac[1] + "|" + ip_str, desc:SCRIPT_DESC );
        }
      } else {
        iv_mac = eregmatch( pattern:"HWaddr ([^ \n]+)", string:line );
        if( ! isnull( iv_mac[1] ) && ! isnull( nic[1] ) ) {
          register_host_detail( name:"BROKEN_MAC-Iface", value:nic[1] + "|" + iv_mac[1] + "|" + ip_str, desc:SCRIPT_DESC );
        }
      }
    }
    x++;
  }
}

# -- Store results in the host details DB -- #
if( cpunumber ) {
  cpu_str = "";
  foreach cputype( keys( cpus ) ) {
    if( cpu_str != "" ) {
      cpu_str += '\n';
    }
    cpu_str += string( cpus[cputype], " ", cputype );
  }
  register_host_detail( name:"cpuinfo", value:cpu_str, desc:SCRIPT_DESC );
}

if( archinfo != "" ) {
  register_host_detail( name:"archinfo", value:archinfo, desc:SCRIPT_DESC );
}

if( memtotal != "" ) {
  register_host_detail( name:"meminfo", value:memtotal, desc:SCRIPT_DESC );
}

if( netinfo != "" ) {
  register_host_detail( name:"netinfo", value:netinfo, desc:SCRIPT_DESC );
}

exit( 0 );
