###############################################################################
# OpenVAS Vulnerability Test
#
# wu-ftpd MAIL_ADMIN overflow
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:washington_university:wu-ftpd";

# Ref: Adam Zabrocki <pi3ki31ny@wp.pl>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14371");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2003-1327");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8668");
  script_xref(name:"OSVDB", value:"2594");
  script_name("wu-ftpd MAIL_ADMIN overflow");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_dependencies("gb_wu-ftpd_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("wu-ftpd/installed");

  script_tag(name:"summary", value:"The remote Wu-FTPd server seems to be
  vulnerable to a remote flaw.");

  script_tag(name:"insight", value:"This version fails to properly check bounds
  on a pathname when Wu-Ftpd is compiled with MAIL_ADMIN enabled resulting in a
  buffer overflow. With a specially crafted request, an attacker can possibly
  execute arbitrary code as the user Wu-Ftpd runs as (usually root) resulting
  in a loss of integrity, and/or availability.

  It should be noted that this vulnerability is not present within the default
  installation of Wu-Ftpd.

  The server must be configured using the 'MAIL_ADMIN' option to notify an
  administrator when a file has been uploaded.");

  script_tag(name:"solution", value:"Upgrade to Wu-FTPd 2.6.3 when available.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( egrep( pattern:"^2\.6\.[012]$", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references." );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
