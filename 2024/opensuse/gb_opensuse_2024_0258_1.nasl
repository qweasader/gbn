# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856383");
  script_version("2024-09-06T15:39:29+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-7964", "CVE-2024-7965", "CVE-2024-7966", "CVE-2024-7967", "CVE-2024-7968", "CVE-2024-7969", "CVE-2024-7971", "CVE-2024-7972", "CVE-2024-7973", "CVE-2024-7974", "CVE-2024-7975", "CVE-2024-7976", "CVE-2024-7977", "CVE-2024-7978", "CVE-2024-7979", "CVE-2024-7980", "CVE-2024-7981", "CVE-2024-8033", "CVE-2024-8034", "CVE-2024-8035");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-06 15:39:29 +0000 (Fri, 06 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-22 17:40:27 +0000 (Thu, 22 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-24 04:00:25 +0000 (Sat, 24 Aug 2024)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2024:0258-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0258-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QKC6ROFWBIXXM5S5SYRWQ74OU24BX5KT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2024:0258-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

  - Chromium 128.0.6613.84 (boo#1229591)

  * CVE-2024-7964: Use after free in Passwords

  * CVE-2024-7965: Inappropriate implementation in V8

  * CVE-2024-7966: Out of bounds memory access in Skia

  * CVE-2024-7967: Heap buffer overflow in Fonts

  * CVE-2024-7968: Use after free in Autofill

  * CVE-2024-7969: Type Confusion in V8

  * CVE-2024-7971: Type confusion in V8

  * CVE-2024-7972: Inappropriate implementation in V8

  * CVE-2024-7973: Heap buffer overflow in PDFium

  * CVE-2024-7974: Insufficient data validation in V8 API

  * CVE-2024-7975: Inappropriate implementation in Permissions

  * CVE-2024-7976: Inappropriate implementation in FedCM

  * CVE-2024-7977: Insufficient data validation in Installer

  * CVE-2024-7978: Insufficient policy enforcement in Data Transfer

  * CVE-2024-7979: Insufficient data validation in Installer

  * CVE-2024-7980: Insufficient data validation in Installer

  * CVE-2024-7981: Inappropriate implementation in Views

  * CVE-2024-8033: Inappropriate implementation in WebApp Installs

  * CVE-2024-8034: Inappropriate implementation in Custom Tabs

  * CVE-2024-8035: Inappropriate implementation in Extensions

  * Various fixes from internal audits, fuzzing and other initiatives");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~128.0.6613.84~bp155.2.105.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~128.0.6613.84~bp155.2.105.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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