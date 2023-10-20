# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840685");
  script_cve_id("CVE-2009-2417", "CVE-2010-0734", "CVE-2011-2192");
  script_tag(name:"creation_date", value:"2011-06-24 14:46:35 +0000 (Fri, 24 Jun 2011)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1158-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|11\.04|8\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1158-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1158-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the USN-1158-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Richard Silverman discovered that when doing GSSAPI authentication,
libcurl unconditionally performs credential delegation, handing the
server a copy of the client's security credential. (CVE-2011-2192)

Wesley Miaw discovered that when zlib is enabled, libcurl does not
properly restrict the amount of callback data sent to an application
that requests automatic decompression. This might allow an attacker to
cause a denial of service via an application crash or possibly execute
arbitrary code with the privilege of the application. This issue only
affected Ubuntu 8.04 LTS and Ubuntu 10.04 LTS. (CVE-2010-0734)

USN 818-1 fixed an issue with curl's handling of SSL certificates with
zero bytes in the Common Name. Due to a packaging error, the fix for
this issue was not being applied during the build. This issue only
affected Ubuntu 8.04 LTS. We apologize for the error. (CVE-2009-2417)

Original advisory details:

 Scott Cantor discovered that curl did not correctly handle SSL
 certificates with zero bytes in the Common Name. A remote attacker
 could exploit this to perform a machine-in-the-middle attack to view
 sensitive information or alter encrypted communications.");

  script_tag(name:"affected", value:"'curl' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.19.7-1ubuntu1.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.19.7-1ubuntu1.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.21.0-1ubuntu1.1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.21.0-1ubuntu1.1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.21.3-1ubuntu1.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.21.3-1ubuntu1.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.21.3-1ubuntu1.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.18.0-1ubuntu2.3", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.18.0-1ubuntu2.3", rls:"UBUNTU8.04 LTS"))) {
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
