# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.3066");
  script_cve_id("CVE-2023-31124", "CVE-2023-31147");
  script_tag(name:"creation_date", value:"2023-10-31 04:19:09 +0000 (Tue, 31 Oct 2023)");
  script_version("2024-02-05T14:36:57+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:57 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-02 17:44:21 +0000 (Fri, 02 Jun 2023)");

  script_name("Huawei EulerOS: Security Advisory for c-ares (EulerOS-SA-2023-3066)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=(EULEROS\-2\.0SP11\-X86_64|EULEROSVIRT\-2\.11\.0)");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-3066");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2023-3066");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'c-ares' package(s) announced via the EulerOS-SA-2023-3066 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"c-ares is an asynchronous resolver library. When cross-compiling c-ares and using the autotools build system, CARES_RANDOM_FILE will not be set, as seen when cross compiling aarch64 android. This will downgrade to using rand() as a fallback which could allow an attacker to take advantage of the lack of entropy by not using a CSPRNG.(CVE-2023-31124)

c-ares is an asynchronous resolver library. When /dev/urandom or RtlGenRandom() are unavailable, c-ares uses rand() to generate random numbers used for DNS query ids. This is not a CSPRNG, and it is also not seeded by srand() so will generate predictable output. Input from the random number generator is fed into a non-compilant RC4 implementation and may not be as strong as the original RC4 implementation. (CVE-2023-31147)");

  script_tag(name:"affected", value:"'c-ares' package(s) on Huawei EulerOS Virtualization release 2.11.0.");

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

if(release == "EULEROS-2.0SP11-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"libtommath", rpm:"libtommath~1.2.0~1.h3.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "EULEROSVIRT-2.11.0") {

  if(!isnull(res = isrpmvuln(pkg:"c-ares", rpm:"c-ares~1.18.1~1.h4.eulerosv2r11", rls:"EULEROSVIRT-2.11.0"))) {
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
