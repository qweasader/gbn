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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900676");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-06-24 07:17:25 +0200 (Wed, 24 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1390");
  script_name("Mutt Security Bypass Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51068");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35288");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/06/10/2");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=504979");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_mutt_detect.nasl");
  script_mandatory_keys("Mutt/Ver");
  script_tag(name:"impact", value:"Successful exploits allow attackers to spoof SSL certificates of trusted
  servers and redirect a user to a malicious web site.");
  script_tag(name:"affected", value:"Mutt version 1.5.19 on Linux.");
  script_tag(name:"insight", value:"When Mutt is linked with OpenSSL or GnuTLS it allows connections
  only one TLS certificate in the chain instead of verifying the entire chain.");
  script_tag(name:"solution", value:"Apply the patch from the references.");

  script_tag(name:"summary", value:"Mutt is prone to a security bypass vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

muttVer = get_kb_item("Mutt/Ver");
if(!muttVer)
  exit(0);

if(version_is_equal(version:muttVer, test_version:"1.5.19")){
  report = report_fixed_ver(installed_version:muttVer, vulnerable_range:"Equal to 1.5.19");
  security_message(port: 0, data: report);
}
