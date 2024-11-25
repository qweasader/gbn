# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1498");
  script_cve_id("CVE-2016-9754", "CVE-2016-9793", "CVE-2016-9794", "CVE-2016-9806", "CVE-2017-1000111", "CVE-2017-1000112", "CVE-2017-1000251", "CVE-2017-1000252", "CVE-2017-1000364", "CVE-2017-1000365", "CVE-2017-1000370", "CVE-2017-1000410", "CVE-2017-10661", "CVE-2017-10810", "CVE-2017-10911", "CVE-2017-11176", "CVE-2017-11473", "CVE-2017-11600", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-12188");
  script_tag(name:"creation_date", value:"2020-01-23 11:56:59 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-03 19:00:41 +0000 (Wed, 03 Jun 2020)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1498)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1498");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1498");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1498 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow vulnerability was found in the ring_buffer_resize() calculations in which a privileged user can adjust the size of the ringbuffer message size. These calculations can create an issue where the kernel memory allocator will not allocate the correct count of pages yet expect them to be usable. This can lead to the ftrace() output to appear to corrupt kernel memory and possibly be used for privileged escalation or more likely kernel panic.(CVE-2016-9754)

A flaw was found in the Linux kernel's implementation of setsockopt for the SO_{SND<pipe>RCV}BUFFORCE setsockopt() system call. Users with non-namespace CAP_NET_ADMIN are able to trigger this call and create a situation in which the sockets sendbuff data size could be negative. This could adversely affect memory allocations and create situations where the system could crash or cause memory corruption.(CVE-2016-9793)

A use-after-free vulnerability was found in ALSA pcm layer, which allows local users to cause a denial of service, memory corruption, or possibly other unspecified impact. Due to the nature of the flaw, privilege escalation cannot be fully ruled out, although we believe it is unlikely.(CVE-2016-9794)

A double free vulnerability was found in netlink_dump, which could cause a denial of service or possibly other unspecified impact. Due to the nature of the flaw, privilege escalation cannot be fully ruled out, although we believe it is unlikely.(CVE-2016-9806)

A race condition issue leading to a use-after-free flaw was found in the way the raw packet sockets are implemented in the Linux kernel networking subsystem handling synchronization. A local user able to open a raw packet socket (requires the CAP_NET_RAW capability) can use this issue to crash the system.(CVE-2017-1000111)

An exploitable memory corruption flaw was found in the Linux kernel. The append path can be erroneously switched from UFO to non-UFO in ip_ufo_append_data() when building an UFO packet with MSG_MORE option. If unprivileged user namespaces are available, this flaw can be exploited to gain root privileges.(CVE-2017-1000112)

A stack buffer overflow flaw was found in the way the Bluetooth subsystem of the Linux kernel processed pending L2CAP configuration responses from a client. On systems with the stack protection feature enabled in the kernel (CONFIG_CC_STACKPROTECTOR=y, which is enabled on all architectures other than s390x and ppc64le), an unauthenticated attacker able to initiate a connection to a system via Bluetooth could use this flaw to crash the system. Due to the nature of the stack protection feature, code execution cannot be fully ruled out, although we believe it is unlikely. On systems without the stack protection feature (ppc64le, the Bluetooth modules are not built on s390x), an unauthenticated attacker able to initiate a connection to a system via Bluetooth could use this flaw to remotely execute ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
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
