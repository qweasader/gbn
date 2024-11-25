# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103997");
  script_version("2024-09-27T05:05:23+0000");
  script_tag(name:"last_modification", value:"2024-09-27 05:05:23 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"creation_date", value:"2011-03-16 12:21:12 +0100 (Wed, 16 Mar 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Host Details");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Service detection");
  # nb: Needs to run at the end of the scan because of the required info only available in this phase...
  script_category(ACT_END);
  script_dependencies("gb_wmi_get-dns_name.nasl", "netbios_name_get.nasl",
                      "sw_ssl_tls_cert_get_hostname.nasl", "host_scan_end.nasl",
                      "gb_ssl_tls_version_report.nasl", "gb_hostname_determ_reporting.nasl");

  script_tag(name:"summary", value:"This scripts aggregates the OS detection information gathered by
  several VTs and store it in a structured and unified way.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_timeout(3600); # we see some timeouts from this VT. Reason is currently unknown so use a higher timeout for the moment...

  exit(0);
}

SCRIPT_DESC = "Host Details";

include("xml.inc");
include("host_details.inc");
include("os_func.inc");

hostname = get_host_name();
hostip   = get_host_ip();

# TODO: Remove once GVM-9 is end of life and allow each of the
# plugins below registering the determied hostname via add_host_name().
if( ! isnull( hostname ) && hostname != '' && hostname != hostip ) {
  register_host_detail( name:"hostname", value:hostname, desc:SCRIPT_DESC );
  #nb: This just has duplicated the hostame above (see r30003 in trunk)
  #Maybe there is another way to differ between them so keep this commented out for now
  #Temp commented out: register_host_detail( name:"DNS-via-TargetDefinition", value:hostname, desc:SCRIPT_DESC );
}

if( hostname == hostip || hostname == "" || isnull( hostname ) ) {
  DNS_via_WMI_FQDNS = get_kb_item( "DNS-via-WMI-FQDNS" );
  if( ! isnull( DNS_via_WMI_FQDNS ) && DNS_via_WMI_FQDNS != '' && DNS_via_WMI_FQDNS != hostip ) {
    register_host_detail( name:"hostname", value:DNS_via_WMI_FQDNS, desc:SCRIPT_DESC );
  } else {
    DNS_via_WMI_DNS = get_kb_item( "DNS-via-WMI-DNS" );
    if( ! isnull( DNS_via_WMI_DNS ) && DNS_via_WMI_DNS != '' && DNS_via_WMI_DNS != hostip ) {
      register_host_detail( name:"hostname", value:DNS_via_WMI_DNS, desc:SCRIPT_DESC );
    } else {
      SMB_HOST_NAME = get_kb_item( "SMB/name" );
      if( ! isnull( SMB_HOST_NAME ) && SMB_HOST_NAME != '' && SMB_HOST_NAME != hostip ) {
        register_host_detail( name:"hostname", value:SMB_HOST_NAME, desc:SCRIPT_DESC );
      } else {
        # nb: This KB entry could contain multiple hostnames, using a get_kb_list() to avoid forking
        # TBD: Which one should we choose here? Currently its the "first" one after sorting the list
        DNS_via_SSL_TLS_Cert_List = get_kb_list( "DNS_via_SSL_TLS_Cert" );
        foreach DNS_via_SSL_TLS_Cert( DNS_via_SSL_TLS_Cert_List ) {
          if( DNS_via_SSL_TLS_Cert != '' && DNS_via_SSL_TLS_Cert != hostip ) {
            register_host_detail( name:"hostname", value:DNS_via_SSL_TLS_Cert, desc:SCRIPT_DESC );
            break;
          }
        }
      }
    }
  }
}

report_host_details = get_preference( "report_host_details" );
if( report_host_details && "yes" >< report_host_details ) {
  report_host_details();
}

exit( 0 );
