###############################################################################
# OpenVAS Vulnerability Test
#
# Elastic Logstash 'CVE-2014-4326' Remote Code Execution Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808507");
  script_version("2021-10-05T12:25:15+0000");
  script_cve_id("CVE-2014-4326");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-05 12:25:15 +0000 (Tue, 05 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-06-28 18:49:34 +0530 (Tue, 28 Jun 2016)");
  script_name("Elastic Logstash 'CVE-2014-4326' RCE Vulnerability - Linux");

  script_tag(name:"summary", value:"Elastic Logstash is prone to a remote code execution (RCE)
  vulnerability.

  This script has been merged into the VT 'Elastic Logstash 'CVE-2014-4326' Remote Code Execution Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.808095)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw is due improper validation of
  inputs passed to 'zabbix.rb' and 'nagios_nsca.rb' outputs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to execute arbitrary commands.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"affected", value:"Elastic Logstash version prior to
  1.4.2.");

  script_tag(name:"solution", value:"Update to Elastic Logstash version
  1.4.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.elastic.co/community/security/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/532841/100/0/threaded");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);