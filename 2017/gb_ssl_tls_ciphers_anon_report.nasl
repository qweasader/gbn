# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108147");
  script_version("2024-09-27T05:05:23+0000");
  script_cve_id("CVE-2007-1858", "CVE-2014-0351");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-09-27 05:05:23 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"creation_date", value:"2017-04-20 06:08:04 +0200 (Thu, 20 Apr 2017)");
  script_name("SSL/TLS: Report 'Anonymous' Cipher Suites");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_ssl_tls_ciphers_gathering.nasl");
  script_mandatory_keys("ssl_tls/ciphers/anon_ciphers", "ssl_tls/port");

  script_xref(name:"URL", value:"https://bettercrypto.org/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28482");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69754");
  script_xref(name:"URL", value:"https://mozilla.github.io/server-side-tls/ssl-config-generator/");

  script_tag(name:"summary", value:"This routine reports all 'Anonymous' SSL/TLS cipher suites
  accepted by a service.");

  script_tag(name:"insight", value:"Services supporting 'Anonymous' cipher suites could allow a
  client to negotiate an SSL/TLS connection to the host without any authentication of the remote
  endpoint.");

  script_tag(name:"impact", value:"This could allow remote attackers to obtain sensitive
  information or have other, unspecified impacts.");

  script_tag(name:"solution", value:"The configuration of this services should be changed so
  that it does not accept the listed 'Anonymous' cipher suites anymore.

  Please see the references for more resources supporting you in this task.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("ssl_funcs.inc");
include("gb_print_ciphers.inc");
include("host_details.inc");

if( ! port = tls_ssl_get_port() )
  exit( 0 );

# Don't report for StartTLS services. A MitM attacker might be already in the position to
# intercept the initial request for StartTLS and force a fallback to plaintext. This avoids
# also that we're reporting this cipher suites on 'Opportunistic TLS' services like SMTP.
if( get_kb_item( "starttls_typ/" + port ) )
  exit( 0 );

report = print_cipherlists( port:port, strengths:"anon" );

if( report ) {

  # nb:
  # - Store the reference from this one to gb_ssl_tls_ciphers_report.nasl to show a cross-reference within the
  #   reports
  # - We don't want to use get_app_* functions as we're only interested in the cross-reference here
  register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.802067" ); # gb_ssl_tls_ciphers_report.nasl
  register_host_detail( name:"detected_at", value:port + "/tcp" );

  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
