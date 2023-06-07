# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0173");
  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-07 15:00:36 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2019-0173)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0173");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0173.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24800");
  script_xref(name:"URL", value:"https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/mds.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode' package(s) announced via the MGASA-2019-0173 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides the Intel 20190514 microcode release that adds the
microcode side mitigations for the Microarchitectural Data Sampling (MDS,
also called ZombieLoad attack) vulnerabilities in Intel processors that
can allow attackers to retrieve data being processed inside a CPU.

The fixed / mitigated issues are:

Modern Intel microprocessors implement hardware-level micro-optimizations
to improve the performance of writing data back to CPU caches. The write
operation is split into STA (STore Address) and STD (STore Data)
sub-operations. These sub-operations allow the processor to hand-off
address generation logic into these sub-operations for optimized writes.
Both of these sub-operations write to a shared distributed processor
structure called the 'processor store buffer'. As a result, an
unprivileged attacker could use this flaw to read private data resident
within the CPU's processor store buffer. (CVE-2018-12126)

Microprocessors use a 'load port' subcomponent to perform load operations
from memory or IO. During a load operation, the load port receives data
from the memory or IO subsystem and then provides the data to the CPU
registers and operations in the CPU's pipelines. Stale load operations
results are stored in the 'load port' table until overwritten by newer
operations. Certain load-port operations triggered by an attacker can be
used to reveal data about previous stale requests leaking data back to the
attacker via a timing side-channel. (CVE-2018-12127)

A flaw was found in the implementation of the 'fill buffer', a mechanism
used by modern CPUs when a cache-miss is made on L1 CPU cache. If an
attacker can generate a load operation that would create a page fault,
the execution will continue speculatively with incorrect data from the
fill buffer while the data is fetched from higher level caches. This
response time can be measured to infer data in the fill buffer.
(CVE-2018-12130)

Uncacheable memory on some microprocessors utilizing speculative execution
may allow an authenticated user to potentially enable information disclosure
via a side channel with local access. (CVE-2019-11091)");

  script_tag(name:"affected", value:"'microcode' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"microcode", rpm:"microcode~0.20190514~1.mga6.nonfree", rls:"MAGEIA6"))) {
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
