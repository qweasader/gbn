# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:microsoft:lync";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810817");
  script_version("2022-12-07T10:11:17+0000");
  script_cve_id("CVE-2017-0129");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-12-07 10:11:17 +0000 (Wed, 07 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-03-20 12:56:16 +0530 (Mon, 20 Mar 2017)");
  script_name("Microsoft Lync Certificate Validation Vulnerability-4013241 (MAC OS X)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS17-014.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when the Lync client fails
  to properly validate certificates.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to tamper the trusted communications between the server and target client.");

  script_tag(name:"affected", value:"Microsoft Lync version 2011 for MAC OS X.");

  script_tag(name:"solution", value:"Upgrade Microsoft Lync version 14.4.3.170308 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/4012487");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-014");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_lync_detect_macosx.nasl");
  script_mandatory_keys("Microsoft/Lync/MacOSX/Version");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^14\." && version_is_less(version:vers, test_version:"14.4.3.170308")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"14.4.3.170308", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
