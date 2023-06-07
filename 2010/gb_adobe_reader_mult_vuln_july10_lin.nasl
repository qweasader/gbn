###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Reader Multiple Vulnerabilities -July10 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801366");
  script_version("2022-05-02T09:35:37+0000");
  script_cve_id("CVE-2010-1285", "CVE-2010-1295", "CVE-2010-2168", "CVE-2010-2201",
                "CVE-2010-2202", "CVE-2010-2203", "CVE-2010-2204", "CVE-2010-2205",
                "CVE-2010-2206", "CVE-2010-2207", "CVE-2010-2208", "CVE-2010-2209",
                "CVE-2010-2210", "CVE-2010-2211", "CVE-2010-2212");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-07-12 09:42:32 +0200 (Mon, 12 Jul 2010)");
  script_name("Adobe Reader Multiple Vulnerabilities -July10 (Linux)");


  script_tag(name:"summary", value:"Adobe Reader is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaws are caused by memory corruptions, invalid pointers reference,
uninitialized memory, array-indexing and use-after-free errors when processing
malformed data within a PDF document.");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to crash an affected application or
execute arbitrary code by tricking a user into opening a specially crafted PDF
document.");
  script_tag(name:"affected", value:"Adobe Reader version 8.x before 8.2.3 and 9.x before 9.3.3 on Linux.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 9.3.3 or 8.2.3 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://isc.incidents.org/diary.html?storyid=9100");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41230");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41231");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41232");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41234");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41235");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41236");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41239");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41240");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41241");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41242");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41243");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41244");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41245");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1636");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-15.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer =~ "^(8|9)")
{
  if(version_in_range(version:readerVer, test_version:"8.0", test_version2:"8.2.2") ||
     version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.3.2"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
