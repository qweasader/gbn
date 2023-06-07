###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Multiple Vulnerabilities - 01 Oct14 (Linux)
#
# Authors:
# Deepmala <kdeepmala@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804938");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-3200", "CVE-2014-3199", "CVE-2014-3198", "CVE-2014-3197",
                "CVE-2014-3195", "CVE-2014-3194", "CVE-2014-3193", "CVE-2014-3192",
                "CVE-2014-3191", "CVE-2014-3190", "CVE-2014-3189", "CVE-2014-3188",
                "CVE-2014-7967");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-10-16 16:48:48 +0530 (Thu, 16 Oct 2014)");

  script_name("Google Chrome Multiple Vulnerabilities - 01 Oct14 (Linux)");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Some errors related to V8 and IPC.

  - An out-of-bound read access error in PDFium.

  - Multiple use-after-free errors in Events, Rendering, DOM, and Web Workers.

  - A type confusion error in Session Management.

  - An information leak error in the V8 JavaScript engine and the XSS Auditor.

  - An error within V8 bindings.

  - Other multiple unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose potentially sensitive information, bypass certain security
  restrictions, conduct denial-of-service attacks, compromise a vulnerable system
  or possibly have unspecified other impact.");

  script_tag(name:"affected", value:"Google Chrome prior to version 38.0.2125.101
  on Linux.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome 38.0.2125.101 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/61755");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70262");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70273");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70587");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2014/10/stable-channel-update.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"38.0.2125.101"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"38.0.2125.101");
  security_message(port:0, data:report);
  exit(0);
}
