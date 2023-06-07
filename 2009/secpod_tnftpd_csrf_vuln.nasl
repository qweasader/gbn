# Copyright (C) 2009 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:luke_mewburn:tnftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901006");
  script_version("2022-02-22T15:13:46+0000");
  script_tag(name:"last_modification", value:"2022-02-22 15:13:46 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-7016");
  script_name("tnftpd 'ftp://' Cross-Site Request Forgery Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_tnftpd_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("tnftpd/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/31958");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/45534");
  script_xref(name:"URL", value:"http://freshmeat.net/projects/tnftpd/?branch_id=14355&release_id=285654");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code to
  perform CSRF attacks, Web cache poisoning, and other malicious activities.");
  script_tag(name:"affected", value:"NetBSD, tnftpd Version prior to 20080929");
  script_tag(name:"insight", value:"The flaw is due to the application truncating an overly long FTP
  command and improperly interpreting the remainder string as a new FTP
  command. This can be exploited via unknown vectors, probably involving a
  crafted 'ftp://' link to a tnftpd server.");
  script_tag(name:"solution", value:"Upgrade to tnftpd version 20080929 or later.");
  script_tag(name:"summary", value:"tnftpd server is prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"20080929" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"20080929" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );