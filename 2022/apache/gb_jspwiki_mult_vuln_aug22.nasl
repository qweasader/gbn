# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:jspwiki";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148572");
  script_version("2023-10-18T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-10-18 05:05:17 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-08-05 09:31:32 +0000 (Fri, 05 Aug 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-10 15:53:00 +0000 (Wed, 10 Aug 2022)");

  script_cve_id("CVE-2022-27166", "CVE-2022-28730", "CVE-2022-28731", "CVE-2022-28732",
                "CVE-2022-34158");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache JSPWiki < 2.11.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_jspwiki_http_detect.nasl");
  script_mandatory_keys("apache/jspwiki/detected");

  script_tag(name:"summary", value:"Apache JSPWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-27166: Cross-site scripting (XSS) on XHRHtml2Markup.jsp

  - CVE-2022-28730: Cross-site scripting (XSS) on AJAXPreview.jsp

  - CVE-2022-28731: Cross-site request forgery (CSRF) in UserPreferences.jsp

  - CVE-2022-28732: Cross-site scripting (XSS) on WeblogPlugin

  - CVE-2022-34158: User group privilege escalation");

  script_tag(name:"affected", value:"Apache JSPWiki version 2.11.2 and prior.");

  script_tag(name:"solution", value:"Update to version 2.11.3 or later.");

  script_xref(name:"URL", value:"https://jspwiki-wiki.apache.org/Wiki.jsp?page=CVE-2022-27166");
  script_xref(name:"URL", value:"https://jspwiki-wiki.apache.org/Wiki.jsp?page=CVE-2022-28730");
  script_xref(name:"URL", value:"https://jspwiki-wiki.apache.org/Wiki.jsp?page=CVE-2022-28731");
  script_xref(name:"URL", value:"https://jspwiki-wiki.apache.org/Wiki.jsp?page=CVE-2022-28732");
  script_xref(name:"URL", value:"https://jspwiki-wiki.apache.org/Wiki.jsp?page=CVE-2022-34158");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "2.11.3")) {
  report = report_fixed_ver(installed_version: toupper(version), fixed_version: "2.11.3",
                            install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
