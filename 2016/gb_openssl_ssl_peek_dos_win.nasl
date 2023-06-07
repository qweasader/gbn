##############################################################################
# OpenVAS Vulnerability Test
# OpenSSL SSL_peek hang on empty record DoS Vulnerability (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107053");
  script_version("2021-10-08T13:01:28+0000");
  script_cve_id("CVE-2016-6305", "CVE-2016-6308", "CVE-2016-6307");

  script_tag(name:"last_modification", value:"2021-10-08 13:01:28 +0000 (Fri, 08 Oct 2021)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"creation_date", value:"2016-09-26 06:40:16 +0200 (Mon, 26 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-20 01:29:00 +0000 (Fri, 20 Apr 2018)");

  script_name("OpenSSL SSL_peek hang on empty record DoS Vulnerability (Windows)");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20160922.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to a Denial of Service (DoS) vulnerability.");

  script_tag(name:"insight", value:"OpenSSL suffers from the possibility of DoS attack through sending an empty
  record which causes SSL/TLS to hang during a call to SSL_peek().");

  script_tag(name:"impact", value:"Successful exploitation could result in service crash.");

  script_tag(name:"affected", value:"OpenSSL 1.1.0.");

  script_tag(name:"solution", value:"OpenSSL 1.1.0 users should upgrade to 1.1.0a.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_equal(version:vers, test_version:"1.1.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.1.0a", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);