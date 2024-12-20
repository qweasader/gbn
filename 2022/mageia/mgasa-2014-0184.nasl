# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0184");
  script_cve_id("CVE-2013-5892", "CVE-2014-0404", "CVE-2014-0405", "CVE-2014-0406", "CVE-2014-0407", "CVE-2014-0981", "CVE-2014-0983");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2014-0184)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0184");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0184.html");
  script_xref(name:"URL", value:"http://lwn.net/Vulnerabilities/581307/");
  script_xref(name:"URL", value:"http://security.gentoo.org/glsa/glsa-201401-13.xml");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12384");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12578");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=8826");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kmod-vboxadditions, kmod-virtualbox, virtualbox' package(s) announced via the MGASA-2014-0184 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities in the Oracle VM VirtualBox component in Oracle
Virtualization VirtualBox prior to 3.2.20, 4.0.22, 4.1.30, 4.2.20, and
4.3.4 allows local users to affect integrity and availability via unknown
vectors related to Core (CVE-2013-5892, CVE-2014-0404, CVE-2014-0405,
CVE-2014-0406, CVE-2014-0407).

VBox/GuestHost/OpenGL/util/net.c in Oracle VirtualBox before 3.2.22, 4.0.x
before 4.0.24, 4.1.x before 4.1.32, 4.2.x before 4.2.24, and 4.3.x before
4.3.8, when using 3D Acceleration allows local guest OS users to execute
arbitrary code on the Chromium server via crafted Chromium network pointer
in a CR_MESSAGE_READBACK or CR_MESSAGE_WRITEBACK message to the
VBoxSharedCrOpenGL service, which triggers an arbitrary pointer
dereference and memory corruption (CVE-2014-0981).

Multiple array index errors in programs that are automatically generated by
VBox/HostServices/SharedOpenGL/crserverlib/server_dispatch.py in Oracle
VirtualBox 4.2.x through 4.2.20 and 4.3.x before 4.3.8, when using 3D
Acceleration, allow local guest OS users to execute arbitrary code on the
Chromium server via certain CR_MESSAGE_OPCODES messages with a crafted
index, which are not properly handled (CVE-2014-0983).

The virtualbox packages has been updated to 4.3.10 maintenance release that
resolves these issues and other upstream reported issues (for more info
check the referenced changelog).

This update also resolves the following:
- load virtualbox modules on install (mga#8826)
- missing GUI translations (mga#12578)");

  script_tag(name:"affected", value:"'kmod-vboxadditions, kmod-virtualbox, virtualbox' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"dkms-vboxadditions", rpm:"dkms-vboxadditions~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-virtualbox", rpm:"dkms-virtualbox~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.10.28-desktop-1.mga3", rpm:"vboxadditions-kernel-3.10.28-desktop-1.mga3~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.10.28-desktop586-1.mga3", rpm:"vboxadditions-kernel-3.10.28-desktop586-1.mga3~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.10.28-server-1.mga3", rpm:"vboxadditions-kernel-3.10.28-server-1.mga3~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-additions", rpm:"virtualbox-guest-additions~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.10.28-desktop-1.mga3", rpm:"virtualbox-kernel-3.10.28-desktop-1.mga3~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.10.28-desktop586-1.mga3", rpm:"virtualbox-kernel-3.10.28-desktop586-1.mga3~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.10.28-server-1.mga3", rpm:"virtualbox-kernel-3.10.28-server-1.mga3~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~4.3.10~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-vboxvideo", rpm:"x11-driver-video-vboxvideo~4.3.10~1.mga3", rls:"MAGEIA3"))) {
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
