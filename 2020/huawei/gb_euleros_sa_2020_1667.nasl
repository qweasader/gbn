# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1667");
  script_cve_id("CVE-2016-3706", "CVE-2018-20796", "CVE-2019-1010023", "CVE-2019-9192", "CVE-2020-10029", "CVE-2020-1752");
  script_tag(name:"creation_date", value:"2020-06-16 05:48:52 +0000 (Tue, 16 Jun 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 20:15:00 +0000 (Mon, 16 Nov 2020)");

  script_name("Huawei EulerOS: Security Advisory for glibc (EulerOS-SA-2020-1667)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1667");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1667");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'glibc' package(s) announced via the EulerOS-SA-2020-1667 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stack-based buffer overflow in the getaddrinfo function in sysdeps/posix/getaddrinfo.c in the GNU C Library (aka glibc or libc6) allows remote attackers to cause a denial of service (crash) via vectors involving hostent conversion. NOTE: this vulnerability exists because of an incomplete fix for CVE-2013-4458.(CVE-2016-3706)

In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(<pipe>)(\\1\\1)*' in grep, a different issue than CVE-2018-20796. NOTE: the software maintainer disputes that this is a vulnerability because the behavior occurs only with a crafted pattern.(CVE-2019-9192)

In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(\227<pipe>)(\\1\\1<pipe>t1<pipe>\\\2537)+' in grep.(CVE-2018-20796)

GNU Libc current is affected by: Re-mapping current loaded library with malicious ELF file. The impact is: In worst case attacker may evaluate privileges. The component is: libld. The attack vector is: Attacker sends 2 ELF files to victim and asks to run ldd on it. ldd execute code.(CVE-2019-1010023)

A use-after-free vulnerability introduced in glibc upstream version 2.14 was found in the way the tilde expansion was carried out. Directory paths containing an initial tilde followed by a valid username were affected by this issue. A local attacker could exploit this flaw by creating a specially crafted path that, when processed by the glob function, would potentially lead to arbitrary code execution. This was fixed in version 2.32.(CVE-2020-1752)

The GNU C Library (aka glibc or libc6) before 2.32 could overflow an on-stack buffer during range reduction if an input to an 80-bit long double function contains a non-canonical bit pattern, a seen when passing a 0x5d414141414141410000 value to sinl on x86 targets. This is related to sysdeps/ieee754/ldbl-96/e_rem_pio2l.c.(CVE-2020-10029)");

  script_tag(name:"affected", value:"'glibc' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.17~111.h49", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.17~111.h49", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.17~111.h49", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.17~111.h49", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-static", rpm:"glibc-static~2.17~111.h49", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.17~111.h49", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.17~111.h49", rls:"EULEROS-2.0SP2"))) {
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
