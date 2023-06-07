# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.146148");
  script_version("2022-03-28T10:48:38+0000");
  script_tag(name:"last_modification", value:"2022-03-28 10:48:38 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"creation_date", value:"2021-06-18 03:38:00 +0000 (Fri, 18 Jun 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OpenLDAP Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of OpenLDAP detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_openldap_ssh_login_detect.nasl");
  script_mandatory_keys("openldap/detected");

  script_xref(name:"URL", value:"https://www.openldap.org/");

  exit(0);
}

if (!get_kb_item("openldap/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source (make_list("ssh-login")) {
  install_list = get_kb_list("openldap/" + source + "/*/installs");
  if (!install_list)
    continue;

  # nb: Note that sorting the array above is currently dropping the named array index
  install_list = sort(install_list);

  foreach install (install_list) {
    infos = split(install, sep: "#---#", keep: FALSE);
    if (max_index(infos) < 3)
      continue; # Something went wrong and not all required infos are there...

    port    = infos[0];
    install = infos[1];
    version = infos[2];
    concl   = infos[3];

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:openldap:openldap:");
    if (!cpe)
      cpe = "cpe:/a:openldap:openldap";

    register_product(cpe: cpe, location: install, port: port, service: source);

    if (report)
      report += '\n\n';
    report += build_detection_report(app: "OpenLDAP", version: version, install: install, cpe: cpe,
                                     concluded: concl);
  }
}

if (report)
  log_message(port: 0, data: report);

exit(0);
