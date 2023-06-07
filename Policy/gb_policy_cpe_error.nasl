# Copyright (C) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108291");
  script_version("2022-07-26T10:10:42+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:42 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2017-11-20 11:42:20 +0100 (Mon, 20 Nov 2017)");
  script_name("CPE-based Policy Check Error");
  # nb: Needs to be in ACT_END because cpe_inventory.nasl is also there
  script_category(ACT_END);
  script_family("Policy");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("Policy/gb_policy_cpe.nasl", "compliance_tests.nasl");
  script_mandatory_keys("policy/cpe/invalid_line/found");

  script_tag(name:"summary", value:"Shows all CPEs from the CPE-based Policy Check which have an
  invalid syntax.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("policy_functions.inc");

invalid_lines = get_kb_list("policy/cpe/invalid_list");

if (invalid_lines) {

  # Sort to not report changes on delta reports if just the order is different
  invalid_lines = sort(invalid_lines);

  report += 'The following invalid lines where identified within the uploaded/provided CPEs:\n\n';

  foreach error(invalid_lines) {
    report += error + '\n';
  }
}

if (strlen(report) > 0) {
  # nb: If the Test should run as Policy, then report in Policy format
  if (get_kb_item("Compliance/verbose")) {
    default = "N/A";
    compliant = "incomplete";
    fixtext = "Fix the lines reported and rerun the scan.";
    type = "CPE Check";
    test = "Check if the provided information has a valid format.";
    info = ""; # nb: to make linter happy

    policy_reporting(result:report, default:default, compliant:compliant, fixtext:fixtext, type:type,
                     test:test, info:info);
  } else {
    log_message(port:0, data:report);
  }
}

exit(0);
