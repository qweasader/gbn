###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Reader Multiple Unspecified Vulnerabilities -01 May13 (Linux)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803615");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-3342", "CVE-2013-3341", "CVE-2013-3340", "CVE-2013-3339",
                "CVE-2013-3338", "CVE-2013-3337", "CVE-2013-2737", "CVE-2013-2736",
                "CVE-2013-2735", "CVE-2013-2734", "CVE-2013-2733", "CVE-2013-2732",
                "CVE-2013-2731", "CVE-2013-2730", "CVE-2013-2729", "CVE-2013-2727",
                "CVE-2013-2726", "CVE-2013-2725", "CVE-2013-2724", "CVE-2013-2723",
                "CVE-2013-2722", "CVE-2013-2721", "CVE-2013-2720", "CVE-2013-2719",
                "CVE-2013-2718", "CVE-2013-3346", "CVE-2013-2549", "CVE-2013-2550");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2013-05-28 09:55:39 +0530 (Tue, 28 May 2013)");
  script_name("Adobe Reader Multiple Unspecified Vulnerabilities -01 May13 (Linux)");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple unspecified vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code,
corrupt memory, obtain sensitive information, bypass certain security
restrictions or cause a denial of service condition.");
  script_tag(name:"affected", value:"Adobe Reader Version 9.x prior to 9.5.5 on Linux");
  script_tag(name:"solution", value:"Update to Adobe Reader Version 9.5.5 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53420");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58398");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58568");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59902");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59903");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59904");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59905");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59906");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59907");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59908");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59909");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59910");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59911");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59912");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59913");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59914");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59915");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59916");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59917");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59918");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59919");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59920");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59921");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59923");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59925");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59926");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59927");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59930");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-15.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers =~ "^9\.")
{
  if(version_in_range(version:vers, test_version:"9.0", test_version2: "9.5.4"))
  {
     report = report_fixed_ver(installed_version:vers, vulnerable_range:"9.0 - 9.5.4");
     security_message(port: 0, data: report);
     exit(0);
  }
}
