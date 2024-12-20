# SPDX-FileCopyrightText: 2002 Michael Scheidell
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11185");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-2300");
  script_name("vxworks ftpd buffer overflow");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("Copyright (C) 2002 Michael Scheidell");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/vxftpd/detected");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/317417");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6297");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7480");
  script_xref(name:"URL", value:"http://www.secnap.net/security/nbx001.html");

  script_tag(name:"solution", value:"If you are using an embedded vxworks
  product, please contact the OEM vendor and reference WindRiver field patch
  TSR 296292. If this is the 3com NBX IP Phone call manager, contact 3com.");

  script_tag(name:"affected", value:"This affects VxWorks ftpd versions 5.4 and 5.4.2.");

  script_tag(name:"summary", value:"It might be possible to make the remote FTP server
  crash by issuing this command :

  CEL aaaa(...)aaaa

  This problem is similar to the 'aix ftpd' overflow
  but on embedded vxworks based systems like the 3com
  nbx IP phone call manager and seems to cause the server
  to crash.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);
banner = ftp_get_banner(port: port);
if(!banner)
  exit(0);

#VxWorks (5.4) FTP server ready
#220 VxWorks (5.4.2) FTP server ready
#above affected,
# below MIGHT be ok:
#220 VxWorks FTP server (VxWorks 5.4.2) ready
# and thus the banner check may be valid

# for some reason, escaping the parens causes a login failure here
#                             (5.4) or (5.4.[1-2])
if(egrep(pattern:".*xWorks .(5\.4.|5\.4\.[1-2])[^0-9].*FTP", string:banner)){
  security_message(port:port);
  exit(0);
}

exit(99);
