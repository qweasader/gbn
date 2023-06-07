###############################################################################
# OpenVAS Vulnerability Test
#
# Elastic Logstash 'CVE-2015-4152' Directory Traversal Vulnerability (Linux)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808504");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2015-4152");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2016-06-28 18:29:19 +0530 (Tue, 28 Jun 2016)");
  script_name("Elastic Logstash 'CVE-2015-4152' Directory Traversal Vulnerability - Linux");

  script_tag(name:"summary", value:"Elastic Logstash is prone to a directory traversal vulnerability.

  This script has been merged into the VT 'Elastic Logstash 'CVE-2015-4152' Directory Traversal Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.808094)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw is due to improper validation of
  path option in file output plugin.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to write to arbitrary files.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"affected", value:"Elastic Logstash version prior to
  1.4.3.");

  script_tag(name:"solution", value:"Update to Elastic Logstash version 1.4.3,
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.elastic.co/community/security/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75112");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/535725/100/0/threaded");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);