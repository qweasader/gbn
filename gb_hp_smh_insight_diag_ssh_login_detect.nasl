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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104177");
  script_version("2022-05-12T06:39:51+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-05-12 06:39:51 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-12 06:26:05 +0000 (Thu, 12 May 2022)");
  script_name("HP System Management Homepage (SMH) Insight Diagnostics Detection (Linux SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rpms");

  script_tag(name:"summary", value:"SSH login-based detection of HP System Management Homepage (SMH)
  Insight Diagnostics.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

rpms = get_kb_item("ssh/login/rpms");
if(!rpms || rpms !~ ";hpdiags~")
  exit(0);

set_kb_item(name:"hp/smh/insight_diagnostics/detected", value:TRUE);
set_kb_item(name:"hp/smh/insight_diagnostics/ssh-login/detected", value:TRUE);

version = "unknown";
path = "/opt/hp/hpdiags/";

# e.g.
# hpdiags~10.50.2007~2076.linux~x86_64
vers = eregmatch(pattern:";hpdiags~([0-9.]+)[^;]*", string:rpms);
if(vers[1]) {
  version = vers[1];
  concluded = str_replace(string:vers[0], find:";", replace:"");
  concluded = str_replace(string:concluded, find:"~", replace:"-");
  concluded = "RPM package query: " + concluded;
}

cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:hp:insight_diagnostics:");
if(!cpe)
  cpe = "cpe:/a:hp:insight_diagnostics";

register_product(cpe:cpe, location:path, port:0, service:"ssh-login");

log_message(data:build_detection_report(app:"HP System Management Homepage (SMH) Insight Diagnostics",
                                        version:version,
                                        install:path,
                                        cpe:cpe,
                                        concluded:concluded),
            port:0);

exit(0);
