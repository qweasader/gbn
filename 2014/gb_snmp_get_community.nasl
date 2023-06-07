# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.10264");
  script_cve_id("CVE-1999-0472", "CVE-1999-0516", "CVE-1999-0517", "CVE-1999-0792",
                "CVE-2000-0147", "CVE-2001-0380", "CVE-2001-0514", "CVE-2001-1210",
                "CVE-2002-0109", "CVE-2002-0478", "CVE-2002-1229", "CVE-2004-1474",
                "CVE-2004-1775", "CVE-2004-1776", "CVE-2011-0890", "CVE-2012-4964",
                "CVE-2014-4862", "CVE-2014-4863", "CVE-2016-1452", "CVE-2016-5645",
                "CVE-2017-7922", "CVE-2020-5364");
  # nb: CVEs about default communities. Those are currently commented out as they would
  # increase the CVSS to 10.0:
  # "CVE-1999-0186", "CVE-1999-0254", "CVE-2004-0311", "CVE-2006-4950", "CVE-2010-1574", "CVE-2010-2976", "CVE-2016-1473"
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11237");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/177");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/20125");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2112");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2896");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3758");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3795");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3797");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41436");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4330");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46981");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5030");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5965");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7081");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7212");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7317");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91756");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92428");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9681");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/973");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/986");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99083");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2022-04-14T11:24:11+0000");
  script_name("Report default community names of the SNMP Agent");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-03-12 10:10:24 +0100 (Wed, 12 Mar 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("SNMP");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("snmp_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/v12c/detected_community");

  script_tag(name:"impact", value:"If an attacker is able to guess a PUBLIC community string,
  they would be able to read SNMP data (depending on which MIBs are installed) from the remote
  device. This information might include system time, IP addresses, interfaces, processes
  running, etc.

  If an attacker is able to guess a PRIVATE community string (WRITE or 'writeall'
  access), they will have the ability to change information on the remote machine.
  This could be a huge security hole, enabling remote attackers to wreak complete
  havoc such as routing network traffic, initiating processes, etc. In essence,
  'writeall' access will give the remote attacker full administrative rights over
  the remote machine.

  Note that this test only gathers information and does not attempt to write to
  the remote device. Thus it is not possible to determine automatically whether
  the reported community is public or private.

  Also note that information made available through a guessable community string
  might or might not contain sensitive data. Please review the information
  available through the reported community string to determine the impact of this
  disclosure.");

  script_tag(name:"solution", value:"Determine if the detected community string is a private
  community string. Determine whether a public community string exposes sensitive information.
  Disable the SNMP service if you don't use it or change the default community string.");

  script_tag(name:"summary", value:"Simple Network Management Protocol (SNMP) is a protocol
  which can be used by administrators to remotely manage a computer or network device. There
  are typically 2 modes of remote SNMP monitoring. These modes are roughly 'READ' and 'WRITE'
  (or PUBLIC and PRIVATE).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port( default:161 );

cos = make_list( get_kb_list( "SNMP/" + port + "/v12c/detected_community" ) );
if( ! cos )
  exit( 99 );

# If snmp_default_communities.nasl is detecting more than four different communities there might be something wrong...
if( get_kb_item( "SNMP/" + port + "/v12c/all_communities" ) )
  exit( 0 );

report = 'SNMP Agent responded as expected when using the following community name:\n\n';

# Sort to not report changes on delta reports if just the order is different
cos = sort( cos );

foreach co( cos ) {
  report += co + '\n';
  vuln = TRUE;
}

if( vuln ) {
  security_message( port:port, data:report, proto:"udp" );
  exit( 0 );
}

exit( 99 );
