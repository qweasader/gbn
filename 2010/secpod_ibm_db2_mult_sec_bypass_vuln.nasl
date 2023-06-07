# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901156");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-09-23 08:13:58 +0200 (Thu, 23 Sep 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-3474", "CVE-2010-3475");

  script_name("IBM Db2 Multiple Security Bypass Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41444");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43291");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2425");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC68015");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC70406");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl");
  script_mandatory_keys("ibm/db2/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass security restrictions.");

  script_tag(name:"affected", value:"IBM Db2 versions prior to 9.7 Fix Pack 3.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in the application while revoking privileges on a database object
    from the 'PUBLIC' group, which does not mark the dependent functions as 'INVALID'.

  - An error in the application while compiling a compound SQL statement with
    an 'update' statement can be exploited by an unprivileged user to execute
    the query from the dynamic SQL cache.");

  script_tag(name:"solution", value:"Upgrade to IBM Db2 version 9.7 Fix Pack 3 or later.");

  script_tag(name:"summary", value:"IBM Db2 is prone to multiple security bypass vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.7.0.0", test_version2: "9.7.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.7.0.3");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
