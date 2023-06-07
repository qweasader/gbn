###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Lotus Domino Unspecified Cross Site Scripting Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Updated By: Shashi Kiran N <nskiran@secpod.com> on 2013-12-26
# Changed security_message to security_message
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:ibm:lotus_domino";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803976");
  script_version("2022-04-25T14:50:49+0000");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-12-09 18:18:48 +0530 (Mon, 09 Dec 2013)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2013-0595", "CVE-2013-0591", "CVE-2013-0590");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM Lotus Domino Unspecified Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"IBM Lotus Domino is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to IBM Lotus Domino version 8.5.3 FP5 or later.");

  script_tag(name:"insight", value:"The flaw is in the iNotes. No much information is publicly available about this issue");

  script_tag(name:"affected", value:"IBM Lotus Domino 8.5.3 before FP5.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject arbitrary web script.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/83814");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61991");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61993");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61996");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/83381");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21647740");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:version, test_version:"8.5.0.0", test_version2:"8.5.3.4")) {
  report = report_fixed_ver(installed_version:version, fixed_version: "8.5.3 FP5");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
