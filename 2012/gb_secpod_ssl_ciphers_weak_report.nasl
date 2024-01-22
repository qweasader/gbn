# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103440");
  script_version("2023-11-02T05:05:26+0000");
  script_cve_id("CVE-2013-2566", "CVE-2015-2808", "CVE-2015-4000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-23 19:48:00 +0000 (Mon, 23 Nov 2020)");
  script_tag(name:"creation_date", value:"2012-03-01 17:16:10 +0100 (Thu, 01 Mar 2012)");
  script_name("SSL/TLS: Report Weak Cipher Suites");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("secpod_ssl_ciphers.nasl");
  script_mandatory_keys("secpod_ssl_ciphers/weak_ciphers", "ssl_tls/port");

  script_xref(name:"URL", value:"https://www.bsi.bund.de/SharedDocs/Warnmeldungen/DE/CB/warnmeldung_cb-k16-1465_update_6.html");
  script_xref(name:"URL", value:"https://bettercrypto.org/");
  script_xref(name:"URL", value:"https://mozilla.github.io/server-side-tls/ssl-config-generator/");

  script_tag(name:"summary", value:"This routine reports all Weak SSL/TLS cipher suites accepted
  by a service.

  NOTE: No severity for SMTP services with 'Opportunistic TLS' and weak cipher suites on port
  25/tcp is reported. If too strong cipher suites are configured for this service the alternative
  would be to fall back to an even more insecure cleartext communication.");

  script_tag(name:"solution", value:"The configuration of this services should be changed so
  that it does not accept the listed weak cipher suites anymore.

  Please see the references for more resources supporting you with this task.");

  script_tag(name:"insight", value:"These rules are applied for the evaluation of the cryptographic
  strength:

  - RC4 is considered to be weak (CVE-2013-2566, CVE-2015-2808)

  - Ciphers using 64 bit or less are considered to be vulnerable to brute force methods
  and therefore considered as weak (CVE-2015-4000)

  - 1024 bit RSA authentication is considered to be insecure and therefore as weak

  - Any cipher considered to be secure for only the next 10 years is considered as medium

  - Any other cipher is considered as strong");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("misc_func.inc");
include("list_array_func.inc");
include("smtp_func.inc");
include("ssl_funcs.inc");
include("gb_print_ciphers.inc");
include("port_service_func.inc");

if( ! port = tls_ssl_get_port() )
  exit( 0 );

report = print_cipherlists( port:port, strengths:"weak" );

if( report ) {
  if( port == "25" ) {
    if( ports = smtp_get_ports( default_port_list:make_list( 25 ) ) ) {
      if( in_array( search:"25", array:ports ) ) {
        tmpreport = "NOTE: No severity for SMTP services with 'Opportunistic TLS' and weak cipher suites on port 25/tcp is reported. ";
        tmpreport += "If too strong cipher suites are configured for this service the alternative would be to fall back to an even more insecure cleartext communication.";
        log_message( port:port, data:tmpreport + '\n\n' + report );
        exit( 0 );
      }
    }
  }

  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
