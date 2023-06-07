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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900321");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2009-0658", "CVE-2009-0927");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-27 16:48:00 +0000 (Fri, 27 Sep 2019)");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_name("Adobe Reader Buffer Overflow Vulnerability (APSA09-01) - Linux");

  script_tag(name:"summary", value:"Adobe Reader is prone to a buffer overflow vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This issue is due to error in array indexing while processing JBIG2 streams
and unspecified vulnerability related to a JavaScript method.");
  script_tag(name:"impact", value:"This can be exploited to corrupt arbitrary memory via a specially crafted PDF
file, related to a non-JavaScript function call and to execute arbitrary code
in context of the affected application.");
  script_tag(name:"affected", value:"Adobe Reader version 9.x < 9.1, 8.x < 8.1.4, 7.x < 7.1.1 on Linux");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 9.1 or 8.1.4 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/33901");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33751");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34169");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34229");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-03.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-04.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa09-01.html");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/33751-PoC.pl");
  script_xref(name:"URL", value:"http://www.adobe.com/support/downloads/product.jsp?product=10&platform=Unix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE))
  exit(0);

if(readerVer =~ "^[7-9]\.")
{
  if(version_in_range(version:readerVer, test_version:"7.0", test_version2:"7.1.0")||
     version_in_range(version:readerVer, test_version:"8.0", test_version2:"8.1.3")||
     readerVer =~ "^9\.0")
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
