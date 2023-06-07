###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Hadoop Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:apache:hadoop";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106874");
  script_version("2022-04-13T11:57:07+0000");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-06-15 16:37:17 +0700 (Thu, 15 Jun 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-03 21:15:00 +0000 (Sat, 03 Jul 2021)");

  script_cve_id("CVE-2017-3161", "CVE-2017-3162");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Hadoop Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_hadoop_detect.nasl");
  script_mandatory_keys("Apache/Hadoop/Installed");

  script_tag(name:"summary", value:"Apache Hadoop is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Apache Hadoop is prone to multiple vulnerabilities:

  - The HDFS web UI in Apache Hadoop is vulnerable to a cross-site scripting (XSS) attack through an unescaped
query parameter. (CVE-2017-3161)

  - HDFS clients interact with a servlet on the DataNode to browse the HDFS namespace. The NameNode is provided as
a query parameter that is not validated in Apache Hadoop. (CVE-2017-3162)");

  script_tag(name:"affected", value:"Apache Hadoop version 2.6.x");

  script_tag(name:"solution", value:"Update to version 2.7.0 or later.");

  script_xref(name:"URL", value:"https://s.apache.org/4MQm");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98025");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98017");
  script_xref(name:"URL", value:"https://s.apache.org/k2ss");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^2\.6\.") {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.7.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
