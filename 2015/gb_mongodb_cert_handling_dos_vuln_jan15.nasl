###############################################################################
# OpenVAS Vulnerability Test
#
# MongoDB mongod Malformed X.509 Certificate Handling Remote DoS Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mongodb:mongodb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805118");
  script_version("2021-10-21T13:57:32+0000");
  script_cve_id("CVE-2014-3971");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-10-21 13:57:32 +0000 (Thu, 21 Oct 2021)");
  script_tag(name:"creation_date", value:"2015-01-02 16:11:38 +0530 (Fri, 02 Jan 2015)");
  script_name("MongoDB mongod Malformed X.509 Certificate Handling Remote DoS Vulnerability");

  script_tag(name:"summary", value:"MongoDB is prone to remote denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to improper handling of
  X.509 Certificate.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (application crash).");

  script_tag(name:"affected", value:"MongoDB version 2.6.x before 2.6.2 on Windows");

  script_tag(name:"solution", value:"Upgrade to MongoDB version 2.6.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-13753");
  script_xref(name:"URL", value:"https://github.com/mongodb/mongo/commit/c151e0660b9736fe66b224f1129a16871165251b");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/mongodb", 27017);
  script_mandatory_keys("mongodb/installed", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!mbPort = get_app_port(cpe:CPE)) exit(0);

if(!ver = get_app_version(cpe:CPE, port:mbPort)) exit(0);

if(ver =~ "(^2\.6)")
{
  if(version_is_less(version:ver, test_version:"2.6.2"))
  {
    report = report_fixed_ver(installed_version:ver, fixed_version:"2.6.2");
    security_message(data:report, port:mbPort);
    exit(0);
  }
}
