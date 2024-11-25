# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2936.1");
  script_cve_id("CVE-2017-10664", "CVE-2017-10806", "CVE-2017-10911", "CVE-2017-11334", "CVE-2017-11434", "CVE-2017-12809", "CVE-2017-13672", "CVE-2017-14167", "CVE-2017-15038", "CVE-2017-15268", "CVE-2017-15289", "CVE-2017-9524");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-18 18:03:21 +0000 (Mon, 18 Sep 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2936-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2936-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172936-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2017:2936-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes several issues.
These security issues were fixed:
- CVE-2017-15268: Qemu allowed remote attackers to cause a memory leak by
 triggering slow data-channel read operations, related to
 io/channel-websock.c (bsc#1062942).
- CVE-2017-9524: The qemu-nbd server when built with the Network Block
 Device (NBD) Server support allowed remote attackers to cause a denial
 of service (segmentation fault and server crash) by leveraging failure
 to ensure that all initialization occurs talking to a client in the
 nbd_negotiate function (bsc#1043808).
- CVE-2017-15289: The mode4and5 write functions allowed local OS guest
 privileged users to cause a denial of service (out-of-bounds write
 access and Qemu process crash) via vectors related to dst calculation
 (bsc#1063122)
- CVE-2017-15038: Race condition in the v9fs_xattrwalk function local
 guest OS users to obtain sensitive information from host heap memory via
 vectors related to reading extended attributes (bsc#1062069)
- CVE-2017-10911: The make_response function in the Linux kernel allowed
 guest OS users to obtain sensitive information from host OS (or other
 guest OS) kernel memory by leveraging the copying of uninitialized
 padding fields in Xen block-interface response structures (bsc#1057378)
- CVE-2017-12809: The IDE disk and CD/DVD-ROM Emulator support allowed
 local guest OS privileged users to cause a denial of service (NULL
 pointer dereference and QEMU process crash) by flushing an empty CDROM
 device drive (bsc#1054724)
- CVE-2017-10664: qemu-nbd did not ignore SIGPIPE, which allowed remote
 attackers to cause a denial of service (daemon crash) by disconnecting
 during a server-to-client reply attempt (bsc#1046636)
- CVE-2017-10806: Stack-based buffer overflow allowed local guest OS users
 to cause a denial of service (QEMU process crash) via vectors related to
 logging debug messages (bsc#1047674)
- CVE-2017-14167: Integer overflow in the load_multiboot function allowed
 local guest OS users to execute arbitrary code on the host via crafted
 multiboot header address values, which trigger an out-of-bounds write
 (bsc#1057585)
- CVE-2017-11434: The dhcp_decode function in slirp/bootp.c allowed local
 guest OS users to cause a denial of service (out-of-bounds read) via a
 crafted DHCP options string (bsc#1049381)
- CVE-2017-11334: The address_space_write_continue function allowed local
 guest OS privileged users to cause a denial of service (out-of-bounds
 access and guest instance crash) by leveraging use of qemu_map_ram_ptr
 to access guest ram block area (bsc#1048902)
- CVE-2017-13672: The VGA display emulator support allowed local guest OS
 privileged users to cause a denial of service (out-of-bounds read and
 QEMU process crash) via vectors involving display update (bsc#1056334)
These non-security issues were fixed:
- Fixed not being able to build from rpm sources due to undefined macro
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-arm", rpm:"qemu-arm~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-arm-debuginfo", rpm:"qemu-arm-debuginfo~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl-debuginfo", rpm:"qemu-block-curl-debuginfo~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd-debuginfo", rpm:"qemu-block-rbd-debuginfo~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh", rpm:"qemu-block-ssh~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh-debuginfo", rpm:"qemu-block-ssh-debuginfo~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-debugsource", rpm:"qemu-debugsource~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent-debuginfo", rpm:"qemu-guest-agent-debuginfo~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc-debuginfo", rpm:"qemu-ppc-debuginfo~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390-debuginfo", rpm:"qemu-s390-debuginfo~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.9.1~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-sgabios", rpm:"qemu-sgabios~8~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools-debuginfo", rpm:"qemu-tools-debuginfo~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.9.1~41.22.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~2.6.2~41.22.2", rls:"SLES12.0SP2"))) {
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
