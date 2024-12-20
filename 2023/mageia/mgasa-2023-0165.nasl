# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0165");
  script_cve_id("CVE-2023-24580", "CVE-2023-31047");
  script_tag(name:"creation_date", value:"2023-05-17 04:13:46 +0000 (Wed, 17 May 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-15 16:43:47 +0000 (Mon, 15 May 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0165)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0165");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0165.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31548");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/VZS4G6NSZWPTVXMMZHJOJVQEPL3QTO77/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5868-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6054-1");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2023/feb/14/security-releases/");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2023/may/03/security-releases/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the MGASA-2023-0165 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Passing certain inputs (e.g., an excessive number of parts) to multipart
forms could result in too many open files or memory exhaustion, and
provided a potential vector for a denial-of-service attack.
(CVE-2023-24580)
Bypass of validation when using one form field to upload multiple files.
This multiple upload has never been supported by forms.FileField or
forms.ImageField (only the last uploaded file was validated). However,
Django's 'Uploading multiple files' documentation suggested otherwise.
(CVE-2023-31047)");

  script_tag(name:"affected", value:"'python-django' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"python-django", rpm:"python-django~3.2.18~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django", rpm:"python3-django~3.2.18~1.mga8", rls:"MAGEIA8"))) {
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
