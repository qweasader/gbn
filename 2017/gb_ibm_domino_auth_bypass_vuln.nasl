###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Domino Authentication Bypass Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809885");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2016-0270");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-15 02:29:00 +0000 (Wed, 15 Nov 2017)");
  script_tag(name:"creation_date", value:"2017-02-15 14:45:56 +0530 (Wed, 15 Feb 2017)");

  script_name("IBM Domino Authentication Bypass Vulnerability");

  script_tag(name:"summary", value:"IBM Domino is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error as for very large
  data sets, IBM Domino Web servers using 'TLS' and 'AES GCM' generate a weak nonce.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to obtain the authentication key and spoof data by leveraging the reuse of a
  nonce in a session and a 'forbidden attack'.");

  script_tag(name:"affected", value:"IBM Domino 9.0.1 Fix Pack 3 Interim Fix 2
  through 9.0.1 Fix Pack 5 Interim Fix 1.");

  script_tag(name:"solution", value:"Upgrade to IBM Domino 9.0.1 FP5 Interim Fix 2.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21979604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96062");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if (version_in_range(version:version, test_version:"9.0.1.3", test_version2:"9.0.1.5")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"9.0.1 FP5 IF2");
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
