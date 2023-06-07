# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:postfix:postfix";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902517");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)");
  script_cve_id("CVE-2011-1720");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Postfix SMTP Server Cyrus SASL Support Memory Corruption Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44500");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47778");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/727230");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/67359");
  script_xref(name:"URL", value:"http://www.postfix.org/CVE-2011-1720.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("SMTP problems");
  script_dependencies("sw_postfix_detect.nasl");
  script_require_ports("Services/smtp", 25, 465, 587);
  script_mandatory_keys("postfix/smtp/detected", "smtp/auth_methods/available");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a denial of
  service or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"Postfix versions before 2.5.13, 2.6.x before 2.6.10, 2.7.x before 2.7.4,
  and 2.8.x before 2.8.3.");

  script_tag(name:"insight", value:"The flaw is caused by a memory corruption error in the Cyrus SASL library
  when used with 'CRAM-MD5' or 'DIGEST-MD5' authentication mechanisms, which could allow remote attackers to
  crash an affected server or execute arbitrary code.");

  script_tag(name:"solution", value:"Upgrade to Postfix version 2.5.13, 2.6.10, 2.7.4, or 2.8.3 or later.");

  script_tag(name:"summary", value:"Postfix SMTP server is prone to a memory corruption vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("list_array_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if(version_is_less(version:vers, test_version:"2.5.13") ||
   version_in_range(version:vers, test_version:"2.6", test_version2:"2.6.9") ||
   version_in_range(version:vers, test_version:"2.7", test_version2:"2.7.3") ||
   version_in_range(version:vers, test_version:"2.8", test_version2:"2.8.2")) {

  auths = get_kb_list( "smtp/fingerprints/" + port + "/authlist" );
  if( ! auths || ! is_array( auths ) )
    exit( 0 );

  if( in_array( search:"DIGEST-MD5", array:auths, part_match:FALSE ) ||
      in_array( search:"CRAM-MD5", array:auths, part_match:FALSE ) ) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"2.5.13, 2.6.10, 2.7.4, or 2.8.3 or later");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
