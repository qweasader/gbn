###############################################################################
# OpenVAS Vulnerability Test
#
# ScrumWorks Pro Remote Code Execution Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:collabnet:scrumworkspro";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107181");
  script_version("2021-10-12T09:28:32+0000");
  script_tag(name:"last_modification", value:"2021-10-12 09:28:32 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"creation_date", value:"2017-09-25 13:57:36 +0200 (Mon, 25 Sep 2017)");

  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ScrumWorks Pro 6.7.0 RCE Vulnerability");

  script_tag(name:"summary", value:"ScrumWorks Pro is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ScrumWorks Pro is prone to a RCE vulnerability due to unsafe
  deserialization of bytes on the server side which lead to java deserialization attack.");

  script_tag(name:"impact", value:"Remote attacker is able to execute arbitrary code with the
  permissions of the ScrumWorks application server.");

  script_tag(name:"affected", value:"ScrumWorks Pro version 6.7.0.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3387");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_scrumworkspro_detect.nasl");
  script_mandatory_keys("scrumworkspro/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!ver = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_equal(version:ver, test_version:"6.7.0")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"None");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);