###############################################################################
# OpenVAS Vulnerability Test
#
# IBM INotes and Domino Cross-site Scripting Vulnerability - Nov16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809820");
  script_version("2021-10-07T10:01:22+0000");
  script_tag(name:"last_modification", value:"2021-10-07 10:01:22 +0000 (Thu, 07 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-11-25 17:07:04 +0530 (Fri, 25 Nov 2016)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-28 01:29:00 +0000 (Fri, 28 Jul 2017)");

  script_cve_id("CVE-2016-0282");

  script_name("IBM INotes and Domino Cross-site Scripting Vulnerability - Nov16");

  script_tag(name:"summary", value:"IBM Domino is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute script in a victim's Web browser within the security context of the
  hosting Web site, once the URL is clicked.");

  script_tag(name:"affected", value:"IBM iNotes and Domino 8.5.x before 8.5.3 FP6 IF2.");

  script_tag(name:"solution", value:"Upgrade to IBM Domino 8.5.3 FP6 IF2.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21991722");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_in_range(version:version, test_version:"8.5", test_version2:"8.5.3.6")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"8.5.3 FP6 IF2");
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
