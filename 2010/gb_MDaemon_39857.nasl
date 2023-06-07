###############################################################################
# OpenVAS Vulnerability Test
#
# Alt-N MDaemon SUBSCRIBE Remote Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:alt-n:mdaemon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100630");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-05-06 13:19:12 +0200 (Thu, 06 May 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Alt-N MDaemon SUBSCRIBE Remote Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("SMTP problems");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_altn_mdaemon_consolidation.nasl");
  script_mandatory_keys("altn/mdaemon/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39857");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2010/May/9");

  script_tag(name:"summary", value:"MDaemon is prone to an information-disclosure vulnerability because it
  fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue may allow an attacker to gain access to
  information from arbitrary files on the vulnerable server.");

  script_tag(name:"affected", value:"MDaemon 11.0.1 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "11.0.0", test_version2: "11.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Unknown");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
