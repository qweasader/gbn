# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.805759");
  script_version("2022-02-09T09:27:46+0000");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-02-09 09:27:46 +0000 (Wed, 09 Feb 2022)");
  script_tag(name:"creation_date", value:"2015-10-07 18:52:56 +0530 (Wed, 07 Oct 2015)");

  script_cve_id("CVE-2015-4241");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco ASA DoS Vulnerability (Cisco-SA-20150707-CVE-2015-4241)");

  script_tag(name:"summary", value:"This VT has been replaced by VT 'Cisco ASA OSPFv2 DoS Vulnerability'
  (OID: 1.3.6.1.4.1.25623.1.0.106027).

  Cisco ASA is prone to a denial-of-service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to improper handling of OSPFv2 packets by an
  affected system.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  denial of service attack.");

  script_tag(name:"affected", value:"Cisco ASA version 9.3.2.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/Cisco-SA-20150707-CVE-2015-4241");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CISCO");

  script_tag(name:"deprecated", value:TRUE);
  exit(0);
}

exit(66);
