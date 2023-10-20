# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104052");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_name("Nmap NSE net: netbus-info");
  script_category(ACT_INIT);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Nmap NSE net");

  script_tag(name:"summary", value:"Opens a connection to a NetBus server and extracts information about the host and the NetBus
service itself.

The extracted host information includes a list of running applications, and the hosts sound volume
settings.

The extracted service information includes it's access control list (acl), server information, and
setup. The acl is a list of IP addresses permitted to access the service. Server information
contains details about the server installation path, restart persistence, user account that the
server is running on, and the amount of connected NetBus clients. The setup information contains
configuration details, such as the services TCP port number, traffic logging setting, password, an
email address for receiving login notifications, an email address used for sending the
notifications, and an smtp-server used for notification delivery.

SYNTAX:

netbus-info.password:  The password used for authentication");

  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
