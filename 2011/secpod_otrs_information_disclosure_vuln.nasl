# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902361");
  script_version("2022-02-17T14:14:34+0000");
  script_cve_id("CVE-2011-1433");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-02-17 14:14:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)");
  script_name("Open Ticket Request System (OTRS) Information Disclosure Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain sensitive information
  by reading the _UserLogin and _UserPW fields.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the error in 'AgentInterface' and 'CustomerInterface'
  components, which place cleartext credentials into the session data in the database.");

  script_tag(name:"solution", value:"Upgrade to Open Ticket Request System (OTRS) version 3.0.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Open Ticket Request System (OTRS) is prone to an information disclosure vulnerability.");

  script_tag(name:"affected", value:"Open Ticket Request System (OTRS) version prior to 3.0.6.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://bugs.otrs.org/show_bug.cgi?id=6878");
  script_xref(name:"URL", value:"http://source.otrs.org/viewvc.cgi/otrs/CHANGES?revision=1.1807");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"3.0.6")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.0.6");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
