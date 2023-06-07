###############################################################################
# OpenVAS Vulnerability Test
#
# ejabberd 'mod_pubsub' Module Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:process-one:ejabberd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103369");
  script_cve_id("CVE-2011-4320");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("ejabberd 'mod_pubsub' Module Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50737");
  script_xref(name:"URL", value:"http://www.process-one.net/en/ejabberd/release_notes/release_note_ejabberd_2.1.9/");
  script_xref(name:"URL", value:"https://support.process-one.net/browse/EJAB-1498");

  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-12-20 11:14:21 +0100 (Tue, 20 Dec 2011)");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_ejabberd_consolidation.nasl");
  script_mandatory_keys("ejabberd/detected");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"ejabberd is prone to a vulnerability that may allow attackers to cause
  an affected application to enter an infinite loop, resulting in a denial-of-service condition.");

  script_tag(name:"affected", value:"ejabberd prior to version 2.1.9.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "2.1.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.9");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
