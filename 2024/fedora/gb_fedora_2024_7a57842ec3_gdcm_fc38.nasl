# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886625");
  script_version("2024-06-07T05:05:42+0000");
  script_cve_id("CVE-2024-22391", "CVE-2024-22373", "CVE-2024-25569");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-07 05:05:42 +0000 (Fri, 07 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-25 15:16:03 +0000 (Thu, 25 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-05-27 10:43:39 +0000 (Mon, 27 May 2024)");
  script_name("Fedora: Security Advisory for gdcm (FEDORA-2024-7a57842ec3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-7a57842ec3");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/N5HXUKUJ7SG3TK456SGUWVZ4Z5D7JKOL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdcm'
  package(s) announced via the FEDORA-2024-7a57842ec3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Grassroots DiCoM (GDCM) is a C++ library for DICOM medical files.
It supports ACR-NEMA version 1 and 2 (huffman compression is not supported),
RAW, JPEG, JPEG 2000, JPEG-LS, RLE and deflated transfer syntax.
It comes with a super fast scanner implementation to quickly scan hundreds of
DICOM files. It supports SCU network operations (C-ECHO, C-FIND, C-STORE,
C-MOVE). PS 3.3 & 3.6 are distributed as XML files.
It also provides PS 3.15 certificates and password based mechanism to
anonymize and de-identify DICOM datasets.");

  script_tag(name:"affected", value:"'gdcm' package(s) on Fedora 38.");

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

if(release == "FC38") {

  if(!isnull(res = isrpmvuln(pkg:"gdcm", rpm:"gdcm~3.0.21~4.fc38", rls:"FC38"))) {
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