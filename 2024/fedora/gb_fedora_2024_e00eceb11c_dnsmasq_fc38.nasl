# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885826");
  script_version("2024-03-14T05:06:59+0000");
  script_cve_id("CVE-2023-50868", "CVE-2023-50387");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-03-14 05:06:59 +0000 (Thu, 14 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-20 16:55:30 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-29 02:04:12 +0000 (Thu, 29 Feb 2024)");
  script_name("Fedora: Security Advisory for dnsmasq (FEDORA-2024-e00eceb11c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-e00eceb11c");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IGSLGKUAQTW5JPPZCMF5YPEYALLRUZZ6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsmasq'
  package(s) announced via the FEDORA-2024-e00eceb11c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dnsmasq is lightweight, easy to configure DNS forwarder and DHCP server.
It is designed to provide DNS and, optionally, DHCP, to a small network.
It can serve the names of local machines which are not in the global
DNS. The DHCP server integrates with the DNS server and allows machines
with DHCP-allocated addresses to appear in the DNS with names configured
either in each host or in a central configuration file. Dnsmasq supports
static and dynamic DHCP leases and BOOTP for network booting of disk-less
machines.");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on Fedora 38.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC38") {

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq", rpm:"dnsmasq~2.90~1.fc38", rls:"FC38"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);