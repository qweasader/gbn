###############################################################################
# OpenVAS Vulnerability Test
#
# Squid Pinger ICMP Processing Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806105");
  script_version("2022-07-20T10:33:02+0000");
  script_cve_id("CVE-2014-7141", "CVE-2014-7142", "CVE-2014-6270");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-07-20 10:33:02 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2015-09-08 15:37:01 +0530 (Tue, 08 Sep 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Squid Pinger ICMP Processing Multiple Vulnerabilities (SQUID-2014:3, SQUID-2014:4)");

  script_tag(name:"summary", value:"Squid is prone to pinger ICMP processing multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- Due to incorrect bounds checking Squid pinger binary is
  vulnerable to denial of service or information leak attack when processing larger than normal ICMP
  or ICMPv6 packets.

  - Due to incorrect input validation Squid pinger binary is vulnerable to denial of service or
  information leak attacks when processing ICMP or ICMPv6 packets.

  - Due to incorrect buffer management Squid can be caused by an attacker to write outside its
  allocated SNMP buffer.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  sensitive information or cause a denial of service (crash).");

  script_tag(name:"affected", value:"Squid versions 3.x through 3.4.7.");

  script_tag(name:"solution", value:"Update to version 3.4.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2014_4.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69688");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70022");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69686");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2014_3.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers !~ "^3\.")
  exit(99);

if(version_in_range(version:vers, test_version:"3.4", test_version2:"3.4.7")) {
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version: 3.4.8'  + '\n';
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
