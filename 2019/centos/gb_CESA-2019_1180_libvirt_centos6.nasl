# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883053");
  script_version("2023-05-10T09:37:12+0000");
  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-05-10 09:37:12 +0000 (Wed, 10 May 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-11 16:29:00 +0000 (Tue, 11 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-05-16 02:00:57 +0000 (Thu, 16 May 2019)");
  script_name("CentOS Update for libvirt CESA-2019:1180 centos6");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");

  script_xref(name:"CESA", value:"2019:1180");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-May/023308.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt'
  package(s) announced via the CESA-2019:1180 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The libvirt library contains a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remote management of virtualized
systems.

Security Fix(es):

  * A flaw was found in the implementation of the 'fill buffer', a mechanism
used by modern CPUs when a cache-miss is made on L1 CPU cache. If an
attacker can generate a load operation that would create a page fault, the
execution will continue speculatively with incorrect data from the fill
buffer while the data is fetched from higher level caches. This response
time can be measured to infer data in the fill buffer. (CVE-2018-12130)

  * Modern Intel microprocessors implement hardware-level micro-optimizations
to improve the performance of writing data back to CPU caches. The write
operation is split into STA (STore Address) and STD (STore Data)
sub-operations. These sub-operations allow the processor to hand-off
address generation logic into these sub-operations for optimized writes.
Both of these sub-operations write to a shared distributed processor
structure called the 'processor store buffer'. As a result, an unprivileged
attacker could use this flaw to read private data resident within the CPU's
processor store buffer. (CVE-2018-12126)

  * Microprocessors use a load port subcomponent to perform load operations
from memory or IO. During a load operation, the load port receives data
from the memory or IO subsystem and then provides the data to the CPU
registers and operations in the CPUs pipelines. Stale load operations
results are stored in the 'load port' table until overwritten by newer
operations. Certain load-port operations triggered by an attacker can be
used to reveal data about previous stale requests leaking data back to the
attacker via a timing side-channel. (CVE-2018-12127)

  * Uncacheable memory on some microprocessors utilizing speculative
execution may allow an authenticated user to potentially enable information
disclosure via a side channel with local access. (CVE-2019-11091)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'libvirt' package(s) on CentOS 6.");

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

if(release == "CentOS6") {

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.10.2~64.el6_10.1", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~0.10.2~64.el6_10.1", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.10.2~64.el6_10.1", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.10.2~64.el6_10.1", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~0.10.2~64.el6_10.1", rls:"CentOS6"))) {
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
