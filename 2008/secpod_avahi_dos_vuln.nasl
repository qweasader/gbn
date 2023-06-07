# Copyright (C) 2008 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900415");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5081");
  script_name("Avahi Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7520");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32825");
  script_xref(name:"URL", value:"http://avahi.org/milestone/Avahi%200.6.24");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2008/12/14/1");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_avahi_detection_lin.nasl");
  script_mandatory_keys("Avahi/Linux/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute malicious arbitrary
  code or cause denial of service.");

  script_tag(name:"affected", value:"Avahi version prior to 0.6.24 on all Linux platforms.");

  script_tag(name:"insight", value:"This flaw is caused when processing multicast DNS data which causes
  the application to crash.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the latest version 0.6.24 or later.");

  script_tag(name:"summary", value:"Avahi is prone to a denial of service (DoS) vulnerability.");

  exit(0);
}

include("version_func.inc");

avahiVer = get_kb_item("Avahi/Linux/Ver");
if(!avahiVer){
  exit(0);
}

if(version_is_less_equal(version:avahiVer, test_version:"0.6.23")){
  report = report_fixed_ver(installed_version:avahiVer, vulnerable_range:"Less than or equal to 0.6.23");
  security_message(port: 0, data: report);
}
