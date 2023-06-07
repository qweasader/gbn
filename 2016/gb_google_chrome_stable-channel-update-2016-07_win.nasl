##############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Security Updates(stable-channel-update-2016-07)-Windows
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808263");
  script_version("2021-10-14T10:01:27+0000");
  script_cve_id("CVE-2016-1706", "CVE-2016-1707", "CVE-2016-1708", "CVE-2016-1709",
                "CVE-2016-1710", "CVE-2016-1711", "CVE-2016-5127", "CVE-2016-5128",
                "CVE-2016-5129", "CVE-2016-5130", "CVE-2016-5131", "CVE-2016-5132",
                "CVE-2016-5133", "CVE-2016-5134", "CVE-2016-5135", "CVE-2016-5136",
                "CVE-2016-5137", "CVE-2016-1705");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-14 10:01:27 +0000 (Thu, 14 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-07-22 13:12:56 +0530 (Fri, 22 Jul 2016)");
  script_name("Google Chrome Security Updates(stable-channel-update-2016-07)-Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Sandbox escape in PPAPI

  - URL spoofing on iOS

  - Use-after-free in Extensions

  - Heap-buffer-overflow in sfntly

  - Same-origin bypass in Blink

  - Use-after-free in Blink

  - Same-origin bypass in V8

  - Memory corruption in V8

  - URL spoofing

  - Use-after-free in libxml

  - Limited same-origin bypass in Service Workers

  - Origin confusion in proxy authentication

  - URL leakage via PAC script

  - Content-Security-Policy bypass

  - Use after free in extensions

  - History sniffing with HSTS and CSP");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities
  will allow remote attackers to bypass security, to cause denial of service and
  some unspecified impacts.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 52.0.2743.82 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  52.0.2743.82 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2016/07/stable-channel-update.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chr_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chr_ver, test_version:"52.0.2743.82"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"52.0.2743.82");
  security_message(data:report);
  exit(0);
}
