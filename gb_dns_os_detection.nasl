# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108014");
  script_version("2023-03-28T10:19:28+0000");
  script_tag(name:"last_modification", value:"2023-03-28 10:19:28 +0000 (Tue, 28 Mar 2023)");
  script_tag(name:"creation_date", value:"2016-11-03 14:13:48 +0100 (Thu, 03 Nov 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Operating System (OS) Detection (DNS)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("dns_server_tcp.nasl", "dns_server.nasl");
  script_mandatory_keys("dns/server/detected");

  script_tag(name:"summary", value:"DNS banner based Operating System (OS) detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");

SCRIPT_DESC = "Operating System (OS) Detection (DNS)";
BANNER_TYPE = "DNS server banner";

foreach proto( make_list( "udp", "tcp" ) ) {

  banners = get_kb_list( "DNS/" + proto + "/version_request/*" );
  if( ! banners )
    continue;

  foreach key( keys( banners ) ) {

    kb_key = "DNS/" + proto + "/version_request/";
    port   = int( key - kb_key );
    banner = banners[key];

    if( "Microsoft" >< banner || "Windows" >< banner ) {
      if( "Windows 2008 DNS Server Ready" >< banner ) {
        os_register_and_report( os:"Microsoft Windows 2008 Server", cpe:"cpe:/o:microsoft:windows_server_2008", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      } else {
        os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      }
      continue;
    }

    if( "FreeBSD" >< banner ) {
      os_register_and_report( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "SunOS DNS Server" >< banner ) {
      os_register_and_report( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "Gentoo Gnu/Linux" >< banner ) {
      os_register_and_report( os:"Gentoo", cpe:"cpe:/o:gentoo:linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    # 9.11.5-P4-5.1ubuntu2.1-Ubuntu
    if( banner =~ "ubuntu" ) {
      if( "9.11.5-P4-5.1ubuntu" >< banner )
        os_register_and_report( os:"Ubuntu", version:"19.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      else
        os_register_and_report( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    # PowerDNS Authoritative Server 3.4.11 (jenkins@autotest.powerdns.com built 20170116223245 mockbuild@buildhw-05.phx2.fedoraproject.org)
    if( "for Fedora Linux" >< banner || ( ( "PowerDNS" >< banner || "jenkins@autotest.powerdns.com" >< banner ) && ".fedoraproject.org" >< banner ) ) {
      os_register_and_report( os:"Fedora Linux", cpe:"cpe:/o:fedoraproject:fedora", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "-SuSE" >< banner ) {
      os_register_and_report( os:"SUSE Linux", cpe:"cpe:/o:novell:suse_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "-RedHat" >< banner && ".fc" >< banner ) {
      version = eregmatch( pattern:"\.fc([0-9]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        os_register_and_report( os:"Fedora Linux", version:version[1], cpe:"cpe:/o:fedoraproject:fedora", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"Fedora Linux", cpe:"cpe:/o:fedoraproject:fedora", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    # 9.9.4-RedHat-9.9.4-50.1.h2
    if( banner =~ "-RedHat.+\.h" ) {
      version = eregmatch( pattern:"[0-9.-]+\.h([1-9])", string:banner );
      if( ! isnull( version[1] ) ) {
        os_register_and_report( os:"EulerOS", version:version[1], cpe:"cpe:/o:huawei:euleros", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"EulerOS", cpe:"cpe:/o:huawei:euleros", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    if( "-RedHat" >< banner ) {
      version = eregmatch( pattern:"\.el([0-9]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        os_register_and_report( os:"Redhat Linux", version:version[1], cpe:"cpe:/o:redhat:linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"Redhat Linux", cpe:"cpe:/o:redhat:linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    # PowerDNS" "Authoritative" "Server" "3.4.11" "(jenkins@autotest.powerdns.com" "built" "20171130121213" "root@rpmb-64-centos-65)
    # PowerDNS" "Authoritative" "Server" "3.4.10" "(jenkins@autotest.powerdns.com" "built" "20170306160718" "root@rpmbuild-64-centos-7.dev.cpanel.net)
    if( ( "PowerDNS" >< banner || "jenkins@autotest.powerdns.com" >< banner ) && "-centos-" >< banner ) {
      if( "-centos-7" >< banner ) {
        os_register_and_report( os:"CentOS", version:"7", cpe:"cpe:/o:centos:centos", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "-centos-65" >< banner ) {
        os_register_and_report( os:"CentOS", version:"6.5", cpe:"cpe:/o:centos:centos", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    # 9.11.5-P4-5.1+deb10u1-Debian
    if( "-Debian" >< banner || ( "PowerDNS Authoritative Server" >< banner && "debian.org)" >< banner ) ) {
      if( "+deb8" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "9.10.3-P4-Debian" >< banner || "+deb9" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "9.11.5-P4-5.1-Debian" >< banner || "+deb10" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"10", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "9.16.33-Debian" >< banner || "9.16.27-Debian" >< banner || "9.16.37-Debian" >< banner || "+deb11" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"11", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "+deb12" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"12", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    # Those are only running on Unix-like OS variantes
    # keep at the bottom so the pattern above are evaluated first.
    # dnsmasq-pi-hole-2.79
    # dnsmasq-2.76
    # dnsmasq-pi-hole-2.87test3
    # dnsmasq-pi-hole-2.87test4-6
    # dnsmasq-pi-hole-v2.87rc1
    # dnsmasq-pi-hole-v2.89-9461807
    if( banner =~ "^dnsmasq" || banner =~ "^PowerDNS Authoritative Server" || banner =~ "^PowerDNS Recursor" || "jenkins@autotest.powerdns.com" >< banner || banner =~ "^Knot DNS" ) {
      # Doesn't have any OS info so just register Linux/Unix
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      # Only continue here for the pattern without OS info so we register an unknown OS down below if there is any additional data in the banner we want to know
      if( banner == "dnsmasq" || egrep( pattern:"^dnsmasq-(pi-hole-)?v?([0-9.]+((rc|test)?[0-9-]+)?)$", string:banner ) ||
          egrep( pattern:"^PowerDNS Authoritative Server ([0-9.]+)$", string:banner ) ||
          egrep( pattern:"^PowerDNS Recursor ([0-9.]+)$", string:banner ) ||
          egrep( pattern:"^Knot DNS ([0-9.]+)$", string:banner ) ) {
        continue;
      }
    }
    os_register_unknown_banner( banner:banner, banner_type_name:BANNER_TYPE, banner_type_short:"dns_banner", port:port, proto:proto );
  }
}

exit( 0 );
