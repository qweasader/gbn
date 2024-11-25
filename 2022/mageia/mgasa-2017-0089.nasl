# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0089");
  script_cve_id("CVE-2017-2636", "CVE-2017-6346", "CVE-2017-6347", "CVE-2017-6348");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-02 16:28:21 +0000 (Thu, 02 Mar 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0089)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0089");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0089.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20528");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.51");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.52");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.53");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.54");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.55");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-tmb' package(s) announced via the MGASA-2017-0089 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-tmb update is based on upstream 4.4.55 and fixes at least
the following security issues:

Race condition in drivers/tty/n_hdlc.c in the Linux kernel through 4.10.1
allows local users to gain privileges or cause a denial of service (double
free) by setting the HDLC line discipline (CVE-2017-2636).

Race condition in net/packet/af_packet.c in the Linux kernel before 4.9.13
allows local users to cause a denial of service (use-after-free) or possibly
have unspecified other impact via a multithreaded application that makes
PACKET_FANOUT setsockopt system calls (CVE-2017-6346).

The ip_cmsg_recv_checksum function in net/ipv4/ip_sockglue.c in the Linux
kernel before 4.10.1 has incorrect expectations about skb data layout,
which allows local users to cause a denial of service (buffer over-read)
or possibly have unspecified other impact via crafted system calls, as
demonstrated by use of the MSG_MORE flag in conjunction with loopback UDP
transmission (CVE-2017-6347).

The hashbin_delete function in net/irda/irqueue.c in the Linux kernel before
4.9.13 improperly manages lock dropping, which allows local users to cause a
denial of service (deadlock) via crafted operations on IrDA devices
(CVE-2017-6348).

For other upstream fixes in this update, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-tmb' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb", rpm:"kernel-tmb~4.4.55~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-4.4.55-1.mga5", rpm:"kernel-tmb-desktop-4.4.55-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-4.4.55-1.mga5", rpm:"kernel-tmb-desktop-devel-4.4.55-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-latest", rpm:"kernel-tmb-desktop-devel-latest~4.4.55~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-latest", rpm:"kernel-tmb-desktop-latest~4.4.55~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-4.4.55-1.mga5", rpm:"kernel-tmb-source-4.4.55-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-latest", rpm:"kernel-tmb-source-latest~4.4.55~1.mga5", rls:"MAGEIA5"))) {
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
