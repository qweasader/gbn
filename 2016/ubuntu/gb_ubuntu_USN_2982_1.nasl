# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842766");
  script_cve_id("CVE-2016-4353", "CVE-2016-4354", "CVE-2016-4355", "CVE-2016-4356", "CVE-2016-4574", "CVE-2016-4579");
  script_tag(name:"creation_date", value:"2016-05-18 03:19:40 +0000 (Wed, 18 May 2016)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-29 13:49:00 +0000 (Fri, 29 Nov 2019)");

  script_name("Ubuntu: Security Advisory (USN-2982-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.10|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-2982-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2982-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libksba' package(s) announced via the USN-2982-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hanno Bock discovered that Libksba incorrectly handled decoding certain BER
data. An attacker could use this issue to cause Libksba to crash, resulting
in a denial of service. This issue only applied to Ubuntu 12.04 LTS and
Ubuntu 14.04 LTS. (CVE-2016-4353)

Hanno Bock discovered that Libksba incorrectly handled decoding certain BER
data. An attacker could use this issue to cause Libksba to crash, resulting
in a denial of service, or possibly execute arbitrary code. This issue only
applied to Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2016-4354,
CVE-2016-4355)

Hanno Bock discovered that Libksba incorrectly handled incorrect utf-8
strings when decoding certain DN data. An attacker could use this issue to
cause Libksba to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only applied to Ubuntu 12.04 LTS and
Ubuntu 14.04 LTS. (CVE-2016-4356)

Pascal Cuoq discovered that Libksba incorrectly handled incorrect utf-8
strings when decoding certain DN data. An attacker could use this issue to
cause Libksba to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2016-4574)

Pascal Cuoq discovered that Libksba incorrectly handled decoding certain
data. An attacker could use this issue to cause Libksba to crash, resulting
in a denial of service. (CVE-2016-4579)");

  script_tag(name:"affected", value:"'libksba' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libksba8", ver:"1.2.0-2ubuntu0.2", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libksba8", ver:"1.3.0-3ubuntu0.14.04.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libksba8", ver:"1.3.3-1ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libksba8", ver:"1.3.3-1ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
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
