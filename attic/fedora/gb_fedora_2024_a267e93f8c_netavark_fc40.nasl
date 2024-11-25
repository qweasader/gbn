# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886328");
  script_version("2024-09-05T12:18:35+0000");
  script_cve_id("CVE-2024-1753");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-05 12:18:35 +0000 (Thu, 05 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-03-27 02:16:13 +0000 (Wed, 27 Mar 2024)");
  script_name("Fedora: Security Advisory for netavark (FEDORA-2024-a267e93f8c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-a267e93f8c");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/46CKIXN7WZ7CDY3BFSOXGB2EHLZVQMJY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netavark'
  package(s) announced via the FEDORA-2024-a267e93f8c advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OCI network stack

Netavark is a rust based network stack for containers. It is being
designed to work with Podman but is also applicable for other OCI
container management applications.

Netavark is a tool for configuring networking for Linux containers.
Its features include:

  * Configuration of container networks via JSON configuration file

  * Creation and management of required network interfaces,
    including MACVLAN networks

  * All required firewall configuration to perform NAT and port
    forwarding as required for containers

  * Support for iptables and firewalld at present, with support
    for nftables planned in a future release

  * Support for rootless containers

  * Support for IPv4 and IPv6

  * Support for container DNS resolution via aardvark-dns.");

  script_tag(name:"affected", value:"'netavark' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
