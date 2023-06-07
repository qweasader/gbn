# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.150019");
  script_version("2021-04-16T06:57:08+0000");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2019-12-13 10:19:13 +0100 (Fri, 13 Dec 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name("SYS.1.2.2.A11");
  script_xref(name:"URL", value:"https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_1_2_2_Windows_Server_2012.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");
  script_dependencies("smb_reg_service_pack.nasl", "os_detection.nasl");

  script_tag(name:"summary", value:"Ziel des Bausteins SYS.1.2.2 ist die Absicherung von Microsoft
Windows Server 2012 und Microsoft Windows Server 2012 R2.

Die Kern-Anforderung 'A11: Angriffserkennung bei Windows Server 2012' beschreibt, dass Logs an einem
zentralen Ort gespeichert und Festplatten nach einer bestimmten Anzahl an versuchen gesperrt werden
sollten.");

  exit(0);
}

include("itg.inc");
include("policy_functions.inc");
include("host_details.inc");
include("os_func.inc");

if (!itg_start_requirement(level:"Kern"))
  exit(0);

title = "Angriffserkennung bei Windows Server 2012";

if (os_host_runs("windows_server_2012") != "yes"){
  result = itg_result_wrong_target();
  desc = itg_desc_wrong_target();
  itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.1.2.2.A11");
  exit(0);
}

desc = itg_no_automatic_test();
result = itg_no_automatic_test();
# Create report matching Greenbone Compliance Report requirements
report = policy_build_report(result:result, default:"None", compliant:"yes", fixtext:"None",
  type:"None", test:"None", info:desc);

itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.1.2.2.A11");
itg_report(report:report);

exit(0);