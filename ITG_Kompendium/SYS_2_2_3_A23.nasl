# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.109842");
  script_version("2021-04-16T10:39:13+0000");
  script_tag(name:"last_modification", value:"2021-04-16 10:39:13 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2018-08-27 13:03:22 +0200 (Mon, 27 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name("SYS.2.2.3.A23");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");
  script_dependencies("smb_reg_service_pack.nasl", "os_detection.nasl");

  script_xref(name:"URL", value:"https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_2_3_Clients_unter_Windows_10.html");

  script_tag(name:"summary", value:"Ziel des Bausteins SYS.2.2.3 ist der Schutz von Informationen,
die durch und auf Windows 10-Clients verarbeiten werden.

Die Basis-Anforderung 'A23: Erweiterter Schutz der Anmeldeinformationen in Windows 10' beschreibt,
wie und in welchem Umfang die Anmeldeinformationen in Windows 10 geschuetzt werden sollten.");

  exit(0);
}

include("itg.inc");
include("policy_functions.inc");
include("host_details.inc");
include("os_func.inc");

if (!itg_start_requirement(level:"Basis"))
  exit(0);

title = "Erweiterter Schutz der Anmeldeinformationen in Windows 10";

if (!policy_host_runs_windows_10()) {
  result = itg_result_wrong_target();
  desc = itg_desc_wrong_target();
  itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.2.2.3.A23");
  exit(0);
}

desc = itg_no_automatic_test();
result = itg_no_automatic_test();
# Create report matching Greenbone Compliance Report requirements
report = policy_build_report(result:result, default:"None", compliant:"yes", fixtext:"None",
  type:"None", test:"None", info:desc);

itg_report(report:report);
itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.2.2.3.A23");

exit(0);