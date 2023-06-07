##############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Security Updates(stable-channel-update-for-desktop-2017-03)-MAC OS X
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810588");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-5030", "CVE-2017-5031", "CVE-2017-5032", "CVE-2017-5029",
                "CVE-2017-5034", "CVE-2017-5035", "CVE-2017-5036", "CVE-2017-5037",
                "CVE-2017-5039", "CVE-2017-5040", "CVE-2017-5041", "CVE-2017-5033",
                "CVE-2017-5042", "CVE-2017-5038", "CVE-2017-5043", "CVE-2017-5044",
                "CVE-2017-5045", "CVE-2017-5046");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-22 20:19:00 +0000 (Fri, 22 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-03-10 10:42:40 +0530 (Fri, 10 Mar 2017)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2017-03)-MAC OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A memory corruption error in V8.

  - An use after free error in ANGLE.

  - An out of bounds write error in PDFium.

  - An integer overflow error in libxslt.

  - An use after free error in PDFium.

  - An incorrect security UI in Omnibox.

  - Multiple out of bounds writes errors in ChunkDemuxer.

  - Multiple information disclosure errors in V8, XSS Auditor and Blink..

  - An address spoofing in Omnibox.

  - Bypass of Content Security Policy in Blink.

  - An incorrect handling of cookies in Cast.

  - Multiple use after free errors in GuestView.

  - A heap overflow error in Skia.

  - The various fixes from internal audits, fuzzing and other initiatives.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to execute arbitrary code, conduct
  spoofing attacks, bypass security and cause denial of service.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 57.0.2987.98 on MAC OS X");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  57.0.2987.98 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/03/stable-channel-update-for-desktop.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chr_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chr_ver, test_version:"57.0.2987.98"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"57.0.2987.98");
  security_message(data:report);
  exit(0);
}
