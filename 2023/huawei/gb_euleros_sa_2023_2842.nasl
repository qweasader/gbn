# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.2842");
  script_cve_id("CVE-2023-29402", "CVE-2023-29403", "CVE-2023-29404", "CVE-2023-29405");
  script_tag(name:"creation_date", value:"2023-09-20 04:19:58 +0000 (Wed, 20 Sep 2023)");
  script_version("2024-02-05T14:36:57+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:57 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-16 13:15:55 +0000 (Fri, 16 Jun 2023)");

  script_name("Huawei EulerOS: Security Advisory for golang (EulerOS-SA-2023-2842)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-2842");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2023-2842");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'golang' package(s) announced via the EulerOS-SA-2023-2842 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The go command may execute arbitrary code at build time when using cgo. This may occur when running 'go get' on a malicious module, or when running any other command which builds untrusted code. This is can by triggered by linker flags, specified via a '#cgo LDFLAGS' directive. Flags containing embedded spaces are mishandled, allowing disallowed flags to be smuggled through the LDFLAGS sanitization by including them in the argument of another flag. This only affects usage of the gccgo compiler.(CVE-2023-29405)

The go command may execute arbitrary code at build time when using cgo. This may occur when running 'go get' on a malicious module, or when running any other command which builds untrusted code. This is can by triggered by linker flags, specified via a '#cgo LDFLAGS' directive. The arguments for a number of flags which are non-optional are incorrectly considered optional, allowing disallowed flags to be smuggled through the LDFLAGS sanitization. This affects usage of both the gc and gccgo compilers.(CVE-2023-29404)

The go command may generate unexpected code at build time when using cgo. This may result in unexpected behavior when running a go program which uses cgo. This may occur when running an untrusted module which contains directories with newline characters in their names. Modules which are retrieved using the go command, i.e. via 'go get', are not affected (modules retrieved using GOPATH-mode, i.e. GO111MODULE=off, may be affected).(CVE-2023-29402)

On Unix platforms, the Go runtime does not behave differently when a binary is run with the setuid/setgid bits. This can be dangerous in certain cases, such as when dumping memory state, or assuming the status of standard i/o file descriptors. If a setuid/setgid binary is executed with standard I/O file descriptors closed, opening any files can result in unexpected content being read or written with elevated privileges. Similarly, if a setuid/setgid program is terminated, either via panic or signal, it may leak the contents of its registers.(CVE-2023-29403)");

  script_tag(name:"affected", value:"'golang' package(s) on Huawei EulerOS V2.0SP11.");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.17.3~1.h22.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-devel", rpm:"golang-devel~1.17.3~1.h22.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-help", rpm:"golang-help~1.17.3~1.h22.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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
