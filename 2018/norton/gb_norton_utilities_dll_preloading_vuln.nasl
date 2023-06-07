###############################################################################
# OpenVAS Vulnerability Test
#
# Norton Utilities DLL Preloading Vulnerability (Windows)
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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

CPE = "cpe:/a:symantec:norton_utilities";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814309");
  script_version("2021-10-11T09:46:29+0000");
  script_cve_id("CVE-2018-5235");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-11 09:46:29 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-11-02 16:40:08 +0530 (Fri, 02 Nov 2018)");
  script_name("Norton Utilities DLL Preloading Vulnerability (SYMSA1459) - Windows");

  script_tag(name:"summary", value:"Norton Utilities is prone to a local privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because when an application looks to call a DLL
  for execution, it can accept a malicious DLL also instead. The vulnerability can be exploited by a
  simple file write (or potentially an over-write) which results in a foreign DLL running under the
  context of the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local attacker to leverage
  this issue to execute arbitrary code in the context of the affected application. Failed exploit
  attempts will result in a denial of service condition.");

  script_tag(name:"affected", value:"Norton Utilities versions prior to 16.0.3.44.");

  script_tag(name:"solution", value:"Update to version 16.0.3.44 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.symantec.com/en_US/article.SYMSA1459.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_norton_utilities_detect_win.nasl");
  script_mandatory_keys("Norton/Utilities/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"16.0.3.44")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"16.0.3.44", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);