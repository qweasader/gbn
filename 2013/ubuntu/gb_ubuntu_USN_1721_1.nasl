# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841313");
  script_cve_id("CVE-2013-0249");
  script_tag(name:"creation_date", value:"2013-02-15 05:55:13 +0000 (Fri, 15 Feb 2013)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1721-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.10");

  script_xref(name:"Advisory-ID", value:"USN-1721-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1721-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the USN-1721-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that curl incorrectly handled SASL authentication when
communicating over POP3, SMTP or IMAP. If a user or automated system were
tricked into processing a specially crafted URL, an attacker could cause
a denial of service, or possibly execute arbitrary code. The default
compiler options for affected releases should reduce the vulnerability to a
denial of service.");

  script_tag(name:"affected", value:"'curl' package(s) on Ubuntu 12.10.");

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

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.27.0-1ubuntu1.1", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.27.0-1ubuntu1.1", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.27.0-1ubuntu1.1", rls:"UBUNTU12.10"))) {
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
