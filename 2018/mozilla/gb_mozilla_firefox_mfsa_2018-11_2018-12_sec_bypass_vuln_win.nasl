###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox Security Bypass Vulnerability (mfsa_2018-11_2018-12)-Windows
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813364");
  script_version("2021-10-11T09:46:29+0000");
  script_cve_id("CVE-2018-5165");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-10-11 09:46:29 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-11 16:45:00 +0000 (Fri, 11 Sep 2020)");
  script_tag(name:"creation_date", value:"2018-05-11 11:54:13 +0530 (Fri, 11 May 2018)");
  script_name("Mozilla Firefox Security Bypass Vulnerability (mfsa_2018-11_2018-12)-Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because in 32-bit versions of
  Firefox, the Adobe Flash plugin setting for 'Enable Adobe Flash protected mode'
  is unchecked by default even though the Adobe Flash sandbox is actually enabled.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass security restrictions.");

  script_tag(name:"affected", value:"32-bit versions Mozilla Firefox before version 60 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 60
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-11");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_exclude_keys("Firefox64/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(get_kb_item("Firefox64/Win/Ver"))
  exit(99);

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"60")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"60", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
