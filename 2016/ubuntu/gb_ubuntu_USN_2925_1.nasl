# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842683");
  script_cve_id("CVE-2016-1285", "CVE-2016-1286");
  script_tag(name:"creation_date", value:"2016-03-10 05:17:09 +0000 (Thu, 10 Mar 2016)");
  script_version("2023-12-04T05:06:09+0000");
  script_tag(name:"last_modification", value:"2023-12-04 05:06:09 +0000 (Mon, 04 Dec 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-30 17:08:00 +0000 (Thu, 30 Nov 2023)");

  script_name("Ubuntu: Security Advisory (USN-2925-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2925-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2925-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9' package(s) announced via the USN-2925-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Bind incorrectly handled input received by the rndc
control channel. A remote attacker could possibly use this issue to cause
Bind to crash, resulting in a denial of service. (CVE-2016-1285)

It was discovered that Bind incorrectly parsed resource record signatures
for DNAME resource records. A remote attacker could possibly use this issue
to cause Bind to crash, resulting in a denial of service. (CVE-2016-1286)");

  script_tag(name:"affected", value:"'bind9' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.8.1.dfsg.P1-4ubuntu0.16", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.9.5.dfsg-3ubuntu0.8", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.9.5.dfsg-11ubuntu1.3", rls:"UBUNTU15.10"))) {
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
