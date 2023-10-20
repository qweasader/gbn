# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2587");
  script_cve_id("CVE-2022-24903");
  script_tag(name:"creation_date", value:"2022-10-12 04:41:33 +0000 (Wed, 12 Oct 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-17 14:00:00 +0000 (Tue, 17 May 2022)");

  script_name("Huawei EulerOS: Security Advisory for rsyslog (EulerOS-SA-2022-2587)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2587");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2587");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'rsyslog' package(s) announced via the EulerOS-SA-2022-2587 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rsyslog is a rocket-fast system for log processing.Modules for TCP syslog reception have a potential heap buffer overflow when octet-counted framing is used.This can result in a segfault or some other malfunction.As of our understanding, this vulnerability can not be used for remote code execution.But there may still be a slight chance for experts to do that.The bug occurs when the octet count is read.While there is a check for the maximum number of octets, digits are written to a heap buffer even when the octet count is over the maximum, This can be used to overrun the memory buffer.However, once the sequence of digits stop, no additional characters can be added to the buffer.In our opinion, this makes remote exploits impossible or at least highly complex.Octet-counted framing is one of two potential framing modes.It is relatively uncommon, but enabled by default on receivers.Modules `imtcp`, `imptcp`, `imgssapi`, and `imhttp` are used for regular syslog message reception.It is best practice not to directly expose them to the public.When this practice is followed, the risk is considerably lower.Module `imdiag` is a diagnostics module primarily intended for testbench runs.We do not expect it to be present on any production installation.Octet-counted framing is not very common.Usually, it needs to be specifically enabled at senders.If users do not need it, they can turn it off for the most important modules.This will mitigate the vulnerability.(CVE-2022-24903)");

  script_tag(name:"affected", value:"'rsyslog' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

if(release == "EULEROSVIRTARM64-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"rsyslog", rpm:"rsyslog~8.37.0~2.h32.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-gnutls", rpm:"rsyslog-gnutls~8.37.0~2.h32.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-gssapi", rpm:"rsyslog-gssapi~8.37.0~2.h32.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-mmjsonparse", rpm:"rsyslog-mmjsonparse~8.37.0~2.h32.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-mysql", rpm:"rsyslog-mysql~8.37.0~2.h32.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-relp", rpm:"rsyslog-relp~8.37.0~2.h32.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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
