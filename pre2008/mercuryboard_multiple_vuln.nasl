###############################################################################
# OpenVAS Vulnerability Test
#
# Multiple Vulnerabilities in MercuryBoard
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

CPE = "cpe:/a:mercuryboard:mercuryboard";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16247");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-0306", "CVE-2005-0307", "CVE-2005-0414", "CVE-2005-0460",
                "CVE-2005-0462", "CVE-2005-0662", "CVE-2005-0663", "CVE-2005-0878");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12359");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12503");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12578");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12706");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12707");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12872");

  script_name("Multiple Vulnerabilities in MercuryBoard");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("MercuryBoard_detect.nasl");
  script_mandatory_keys("MercuryBoard/detected");

  script_tag(name:"solution", value:"Upgrade to MercuryBoard version 1.1.3.");

  script_tag(name:"summary", value:"The remote host is running MercuryBoard, a message board system written inPHP.

  Multiple vulnerabilities have been discovered in the product that allow an attacker to cause numerous cross site
  scripting attacks, inject arbitrary SQL statements and disclose the path under which the product has been
  installed.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.3");
  security_message(port: port, data: report);
  exit(0);
}

exit( 99 );
