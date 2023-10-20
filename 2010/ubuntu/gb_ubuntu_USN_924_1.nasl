# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840414");
  script_cve_id("CVE-2007-5901", "CVE-2007-5902", "CVE-2007-5971", "CVE-2007-5972", "CVE-2010-0629");
  script_tag(name:"creation_date", value:"2010-04-09 09:11:25 +0000 (Fri, 09 Apr 2010)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-924-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(8\.04\ LTS|8\.10|9\.04)");

  script_xref(name:"Advisory-ID", value:"USN-924-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-924-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the USN-924-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sol Jerome discovered that the Kerberos kadmind service did not correctly
free memory. An unauthenticated remote attacker could send specially
crafted traffic to crash the kadmind process, leading to a denial of
service. (CVE-2010-0629)

It was discovered that Kerberos did not correctly free memory in
the GSSAPI library. If a remote attacker were able to manipulate an
application using GSSAPI carefully, the service could crash, leading to
a denial of service. (Ubuntu 8.10 was not affected.) (CVE-2007-5901,
CVE-2007-5971)

It was discovered that Kerberos did not correctly free memory in the
GSSAPI and kdb libraries. If a remote attacker were able to manipulate
an application using these libraries carefully, the service could crash,
leading to a denial of service. (Only Ubuntu 8.04 LTS was affected.)
(CVE-2007-5902, CVE-2007-5972)");

  script_tag(name:"affected", value:"'krb5' package(s) on Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

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

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.6.dfsg.3~beta1-2ubuntu1.4", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb53", ver:"1.6.dfsg.3~beta1-2ubuntu1.4", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.6.dfsg.4~beta1-3ubuntu0.4", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.6.dfsg.4~beta1-5ubuntu2.3", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb53", ver:"1.6.dfsg.4~beta1-5ubuntu2.3", rls:"UBUNTU9.04"))) {
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
