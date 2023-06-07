###############################################################################
# OpenVAS Vulnerability Test
#
# TeamViewer Password Storage 'teamviewer.exe' Information Disclosure Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:teamviewer:teamviewer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814111");
  script_version("2023-01-19T10:10:48+0000");
  script_cve_id("CVE-2018-14333");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-19 10:10:48 +0000 (Thu, 19 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-17 19:51:00 +0000 (Mon, 17 Sep 2018)");
  script_tag(name:"creation_date", value:"2018-09-21 10:08:14 +0530 (Fri, 21 Sep 2018)");

  script_name("TeamViewer Password Storage 'teamviewer.exe' Information Disclosure Vulnerability - Windows");

  script_tag(name:"summary", value:"TeamViewer is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to TeamViewer stores a password in Unicode
  format within TeamViewer.exe process memory between '[00 88]' and '[00 00 00]' delimiters, which
  allows attackers to obtain sensitive information by leveraging an unattended workstation on which
  TeamViewer has disconnected but remains running.");

  script_tag(name:"impact", value:"Successful exploitation would allow attackers to obtain sensitive
  information");

  script_tag(name:"affected", value:"TeamViewer versions through 13.1.1548.");

  script_tag(name:"solution", value:"As a workaround disable the underlying feature by unchecking
  the checkbox Temporarily save connection passwords via the path Extras -> Options -> Advanced ->
  Advanced settings for connections to other computers.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://github.com/vah13/extractTVpasswords");
  script_xref(name:"URL", value:"https://community.teamviewer.com/t5/Announcements/Reaction-to-CVE-2018-143333/td-p/38604");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_teamviewer_win_detect.nasl");
  script_mandatory_keys("teamviewer/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"13.1.1548")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Workaround", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
