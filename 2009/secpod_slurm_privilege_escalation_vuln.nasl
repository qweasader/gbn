# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900375");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-06-23 10:30:45 +0200 (Tue, 23 Jun 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2084");
  script_name("Privilege Escalation Vulnerability in SLURM");
  script_xref(name:"URL", value:"http://www.debian.org/security/2009/dsa-1776");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34638");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1128");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=524980");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?release_id=676055&group_id=157944");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("secpod_slurm_detect.nasl");
  script_mandatory_keys("SLURM/Ver");
  script_tag(name:"impact", value:"This can be exploited by malicious SLURM local users to gain escalated
  privileges.");
  script_tag(name:"affected", value:"SLURM all versions of 1.2 and 1.3 prior to 1.3.15 on Linux (Debian)");
  script_tag(name:"insight", value:"- Error within the sbcast implementation when establishing supplemental
    groups, which can be exploited to e.g. access files with the supplemental
    group privileges of the slurmd daemon.

  - Error in slurmctld daemon is not properly dropping supplemental groups
    when handling the 'strigger' command, which can be exploited to
    e.g. access files with the supplemental group privileges of the
    slurmctld daemon.");
  script_tag(name:"solution", value:"Upgrade to SLURM version 1.3.14 or later.");
  script_tag(name:"summary", value:"SLURM (Simple Linux Utility for Resource Management)
  is prone to a privilege escalation vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

slurmVer = get_kb_item("SLURM/Ver");
if(!slurmVer)
  exit(0);

if(version_in_range(version:slurmVer, test_version:"1.2", test_version2:"1.3.13")){
  report = report_fixed_ver(installed_version:slurmVer, vulnerable_range:"1.2 - 1.3.13");
  security_message(port: 0, data: report);
}
