# Copyright (C) 2012 Greenbone Networks GmbH
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

CPE = "cpe:/a:netiq:imanager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802852");
  script_version("2023-01-30T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-01-30 10:09:19 +0000 (Mon, 30 Jan 2023)");
  script_tag(name:"creation_date", value:"2012-05-11 18:09:51 +0530 (Fri, 11 May 2012)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2011-4188");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Novell iManager < 2.7.4 patch 4 Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_netiq_imanager_http_detect.nasl");
  script_mandatory_keys("netiq/imanager/detected");

  script_tag(name:"summary", value:"Novell iManager is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in the Create Attribute function in
  jclient, when handling the 'EnteredAttrName' parameter and can be exploited to cause a buffer
  overflow.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
  arbitrary code within the context of the application or cause a denial of service condition.");

  script_tag(name:"affected", value:"Novell iManager version prior to 2.7.4 before patch 4.");

  script_tag(name:"solution", value:"Apply the patch.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48672/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40485");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40480");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/74669");
  script_xref(name:"URL", value:"http://www.novell.com/support/kb/doc.php?id=7002971");
  script_xref(name:"URL", value:"http://www.coresecurity.com/content/novell-imanager-buffer-overflow-off-by-one-vulnerabilities");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version:"2.7.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply Patch.");
  security_message(port:port, data: report);
  exit(0);
}

exit(99);
