# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.876860");
  script_version("2024-10-10T07:25:31+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2019-10-01 02:25:39 +0000 (Tue, 01 Oct 2019)");
  script_name("Fedora Update for nbdkit FEDORA-2019-ac3b1d7930");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC29");

  script_xref(name:"FEDORA", value:"2019-ac3b1d7930");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZTFA4S24GCP45OR2JGEQQQJGORYXJYVY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nbdkit'
  package(s) announced via the FEDORA-2019-ac3b1d7930 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"NBD is a protocol for accessing block devices (hard disks and
disk-like things) over the network.

nbdkit is a toolkit for creating NBD servers.

The key features are:

  * Multithreaded NBD server written in C with good performance.

  * Minimal dependencies for the basic server.

  * Liberal license (BSD) allows nbdkit to be linked to proprietary
  libraries or included in proprietary code.

  * Well-documented, simple plugin API with a stable ABI guarantee.
  Lets you to export 'unconventional' block devices easily.

  * You can write plugins in C or many other languages.

  * Filters can be stacked in front of plugins to transform the output.

In Fedora, &#39, nbdkit&#39, is a meta-package which pulls in the core server
and a useful subset of plugins and filters.

If you want just the server, install &#39, nbdkit-server&#39,.

To develop plugins, install the &#39, nbdkit-devel&#39, package and start by
reading the nbdkit(1) and nbdkit-plugin(3) manual pages.");

  script_tag(name:"affected", value:"'nbdkit' package(s) on Fedora 29.");

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

if(release == "FC29") {

  if(!isnull(res = isrpmvuln(pkg:"nbdkit", rpm:"nbdkit~1.12.8~1.fc29", rls:"FC29"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
