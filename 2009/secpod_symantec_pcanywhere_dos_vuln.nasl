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
  script_oid("1.3.6.1.4.1.25623.1.0.900333");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-03-30 15:53:34 +0200 (Mon, 30 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0538");
  script_name("Symantec pcAnywhere Format String DoS Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34305");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33845");
  script_xref(name:"URL", value:"http://www.layereddefense.com/pcanywhere17mar.html");
  script_xref(name:"URL", value:"http://securityresponse.symantec.com/avcenter/security/Content/2009.03.17.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/pcAnywhere/Ver");
  script_tag(name:"impact", value:"Allows a malicious user to crash an affected application, creating a denial
  of service condition.");
  script_tag(name:"affected", value:"Symantec pcAnywhere version 12.5 and prior on Windows.");
  script_tag(name:"insight", value:"Issue exists due to improper processing of format strings within '.CHF'
  remote control file names or associated file path.");
  script_tag(name:"solution", value:"Upgrade to pcAnywhere version 12.5 SP1.");
  script_tag(name:"summary", value:"Symantec pcAnywhere is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

pcawVer = get_kb_item("Symantec/pcAnywhere/Ver");
if(!pcawVer)
  exit(0);

if(version_is_less_equal(version:pcawVer, test_version:"12.5.0.442")){
  report = report_fixed_ver(installed_version:pcawVer, vulnerable_range:"Less than or equal to 12.5.0.442");
  security_message(port: 0, data: report);
}
