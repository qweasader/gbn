# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807049");
  script_version("2023-03-07T10:19:54+0000");
  script_cve_id("CVE-2016-1947");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-03-07 10:19:54 +0000 (Tue, 07 Mar 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-01-29 10:26:04 +0530 (Fri, 29 Jan 2016)");
  script_name("Mozilla Firefox Application Reputation Service Vulnerability - Jan16 (Mac OS X)");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to an application reputation service disabling vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to disabling of
  Application Reputation service that leads to removal of the ability of Safe
  browsing to warn against potentially malicious downloads.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to do potentially malicious downloads.");

  script_tag(name:"affected", value:"Mozilla Firefox versions 43.x on
  Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 44
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories");
  script_xref(name:"URL", value:"http://msisac.cisecurity.org/advisories/2016/2016-018.cfm");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version =~ "^43") {
  if(version_is_less(version:version, test_version:"44.0")) {
    report = report_fixed_ver(installed_version:version, fixed_version:"44.0", install_path:location);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);