# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/o:qnap:qts";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813119");
  script_version("2022-05-25T21:46:57+0000");
  script_tag(name:"last_modification", value:"2022-05-25 21:46:57 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2018-04-20 10:36:37 +0530 (Fri, 20 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-18 15:37:00 +0000 (Wed, 18 Apr 2018)");

  script_cve_id("CVE-2017-7630");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS 'sysinfoReq.cgi' Information Disclosure Vulnerability-Apr18");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the 'sysinfoReq.cgi' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain access
  to potentially sensitive information.");

  script_tag(name:"affected", value:"QNAP QTS 4.2.x prior to 4.2.6 build 20170905 and 4.3.x
  prior to 4.3.3.0351 Build 20171023.");

  script_tag(name:"solution", value:"Upgrade to QNAP QTS 4.2.6 build 20170905 or 4.3.3.0351 Build
  20171023 or later. Please see the references for more information.");

  script_xref(name:"URL", value:"https://www.qnap.com/nl-nl/search/?q=CVE-2017-7630");
  script_xref(name:"URL", value:"https://www.qnap.com/nl-nl/releasenotes/index.php");


  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less( version: version, test_version: "4.2.6.20170905")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.6_20170905");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.3.3", test_version_up: "4.3.3_20171023")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.3_20171023");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
