# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827870");
  script_version("2023-10-12T05:05:32+0000");
  script_cve_id("CVE-2022-47184", "CVE-2023-30631", "CVE-2023-33933");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-22 04:15:00 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-24 01:07:18 +0000 (Sat, 24 Jun 2023)");
  script_name("Fedora: Security Advisory for trafficserver (FEDORA-2023-2e6bead58b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-2e6bead58b");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FGWXNAEEVRUZ5JG4EJAIIFC3CI7LFETV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'trafficserver'
  package(s) announced via the FEDORA-2023-2e6bead58b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Traffic Server is a high-performance building block for cloud services.
It&#39, s more than just a caching proxy server, it also has support for
plugins to build large scale web applications.  Key features:

Caching - Improve your response time, while reducing server load and
bandwidth needs by caching and reusing frequently-requested web pages,
images, and web service calls.

Proxying - Easily add keep-alive, filter or anonymize content
requests, or add load balancing by adding a proxy layer.

Fast - Scales well on modern SMP hardware, handling 10s of thousands
of requests per second.

Extensible - APIs to write your own plug-ins to do anything from
modifying HTTP headers to handling ESI requests to writing your own
cache algorithm.

Proven - Handling over 400TB a day at Yahoo! both as forward and
reverse proxies, Apache Traffic Server is battle hardened.");

  script_tag(name:"affected", value:"'trafficserver' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"trafficserver", rpm:"trafficserver~9.2.1~1.fc38", rls:"FC38"))) {
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